"""Tests for enterprise auto-profile ingestion endpoints (ORG-09)."""

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
    return _create_user("owner-profiles@example.com")


@pytest.fixture
def member_user():
    return _create_user("member-profiles@example.com")


@pytest.fixture
def viewer_user():
    return _create_user("viewer-profiles@example.com")


def _make_profile(skill_id="my-skill-1", ecosystem="claude-code"):
    return {
        "org_slug": "",  # set by caller
        "skill_id": skill_id,
        "ecosystem": ecosystem,
        "capabilities": ["network", "filesystem"],
        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# POST /profiles tests
# ---------------------------------------------------------------------------


def test_post_profile_member_success(client, owner_user, member_user):
    """Member can post auto-profile."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    body = _make_profile()
    body["org_slug"] = org["slug"]
    resp = client.post(
        "/ee/v1/profiles", json=body, headers=member_user["headers"]
    )
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 1


def test_post_profile_viewer_rejected(client, owner_user, viewer_user):
    """Viewer cannot post profiles."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], viewer_user["id"], OrgRole.viewer)

    body = _make_profile()
    body["org_slug"] = org["slug"]
    resp = client.post(
        "/ee/v1/profiles", json=body, headers=viewer_user["headers"]
    )
    assert resp.status_code == 403


def test_post_profile_stored_correctly(client, owner_user, member_user):
    """Profile is stored with correct data."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    body = _make_profile(skill_id="test-skill-xyz", ecosystem="mcp")
    body["org_slug"] = org["slug"]
    resp = client.post(
        "/ee/v1/profiles", json=body, headers=member_user["headers"]
    )
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 1


def test_post_profile_append_only(client, owner_user, member_user):
    """Multiple profiles for same skill create separate records (append-only)."""
    org = _create_org(client, owner_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    body1 = _make_profile(skill_id="skill-a")
    body1["org_slug"] = org["slug"]
    body2 = _make_profile(skill_id="skill-a")
    body2["org_slug"] = org["slug"]

    resp1 = client.post(
        "/ee/v1/profiles", json=body1, headers=member_user["headers"]
    )
    resp2 = client.post(
        "/ee/v1/profiles", json=body2, headers=member_user["headers"]
    )
    assert resp1.status_code == 201
    assert resp2.status_code == 201
    # Both accepted -- append-only means no deduplication


def test_post_profile_non_member_rejected(client, owner_user, member_user):
    """Non-member cannot post profiles to an org."""
    org = _create_org(client, owner_user["headers"])
    # member_user is NOT added as member

    body = _make_profile()
    body["org_slug"] = org["slug"]
    resp = client.post(
        "/ee/v1/profiles", json=body, headers=member_user["headers"]
    )
    assert resp.status_code == 403
