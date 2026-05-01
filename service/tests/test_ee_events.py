"""Tests for enterprise event ingestion endpoints (ORG-08)."""

import asyncio
import datetime
import hashlib
import os

import pytest
from fastapi.testclient import TestClient

os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-ee")
os.environ.setdefault("SKILLLEDGER_RESEND_API_KEY", "re_test_fake")

_LICENSE_KEY = "test-license-key-ee"
_LICENSE_HASH = hashlib.sha256(_LICENSE_KEY.encode()).hexdigest()

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.organization import OrgMembership, OrgRole  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db():
    async def _reset():
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_reset())
    loop.close()
    yield


def _make_app():
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    return create_app()


@pytest.fixture
def client():
    app = _make_app()
    with TestClient(app) as c:
        yield c


def _create_user(email: str) -> dict:
    holder: dict = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email=email,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            holder["id"] = user.id
            holder["email"] = user.email

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    settings = get_settings()
    token = create_access_token(holder["id"], holder["email"], settings.jwt_secret)
    holder["headers"] = {"Authorization": f"Bearer {token}"}
    return holder


def _create_org(client, headers, name="Acme Corp"):
    resp = client.post("/ee/v1/orgs", json={"name": name}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _add_membership(org_id: int, user_id: int, role: OrgRole):
    async def _insert():
        factory = get_async_session_factory()
        async with factory() as session:
            m = OrgMembership(user_id=user_id, org_id=org_id, role=role)
            session.add(m)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_insert())
    loop.close()


@pytest.fixture
def owner_user():
    return _create_user("owner-events@example.com")


@pytest.fixture
def member_user():
    return _create_user("member-events@example.com")


@pytest.fixture
def viewer_user():
    return _create_user("viewer-events@example.com")


def _make_event(type_="policy_violation", ecosystem="claude-code",
                skill_id="skill-1", rule="deny-network", severity="high"):
    return {
        "type": type_,
        "ecosystem": ecosystem,
        "skill_id": skill_id,
        "rule": rule,
        "severity": severity,
        "details": {"reason": "test"},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /events tests
# ---------------------------------------------------------------------------


def test_post_events_member_success(client, owner_user, member_user):
    """Member can post events."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    resp = client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": [_make_event()]},
        headers=member_user["headers"],
    )
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 1


def test_post_events_viewer_rejected(client, owner_user, viewer_user):
    """Viewer cannot post events."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], viewer_user["id"], OrgRole.viewer)

    resp = client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": [_make_event()]},
        headers=viewer_user["headers"],
    )
    assert resp.status_code == 403


def test_post_events_batch_limit(client, owner_user, member_user):
    """Batch > 100 events is rejected."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    events = [_make_event() for _ in range(101)]
    resp = client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": events},
        headers=member_user["headers"],
    )
    assert resp.status_code == 400
    assert "100" in resp.json()["detail"]


def test_post_events_stored_correctly(client, owner_user, member_user):
    """Events are stored and retrievable via GET."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    events = [_make_event(type_="ioc_match"), _make_event(type_="policy_violation")]
    client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": events},
        headers=member_user["headers"],
    )

    # Owner (admin+) can list events
    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/events",
        headers=owner_user["headers"],
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_post_events_non_member_rejected(client, owner_user, member_user):
    """Non-member cannot post events to an org."""
    org = _create_org(client, owner_user["headers"])
    # member_user is NOT a member of org

    resp = client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": [_make_event()]},
        headers=member_user["headers"],
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /orgs/{slug}/events tests
# ---------------------------------------------------------------------------


def test_get_events_admin_success(client, owner_user, member_user):
    """Admin can list events."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": [_make_event() for _ in range(3)]},
        headers=member_user["headers"],
    )

    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/events",
        headers=owner_user["headers"],
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_get_events_pagination(client, owner_user, member_user):
    """Events support limit/offset pagination."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": [_make_event() for _ in range(5)]},
        headers=member_user["headers"],
    )

    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/events?limit=2&offset=0",
        headers=owner_user["headers"],
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    resp2 = client.get(
        f"/ee/v1/orgs/{org['slug']}/events?limit=2&offset=2",
        headers=owner_user["headers"],
    )
    assert resp2.status_code == 200
    assert len(resp2.json()) == 2


def test_get_events_filter_by_type(client, owner_user, member_user):
    """Events can be filtered by event_type."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    events = [_make_event(type_="ioc_match"), _make_event(type_="policy_violation")]
    client.post(
        "/ee/v1/events",
        json={"org_slug": org["slug"], "events": events},
        headers=member_user["headers"],
    )

    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/events?event_type=ioc_match",
        headers=owner_user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "ioc_match"
