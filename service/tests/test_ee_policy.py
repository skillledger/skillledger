"""Tests for enterprise policy distribution endpoints (ORG-06)."""

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
def admin_user():
    return _create_user("admin@example.com")


@pytest.fixture
def member_user():
    return _create_user("member@example.com")


@pytest.fixture
def viewer_user():
    return _create_user("viewer@example.com")


VALID_REGO = 'package skillledger.org\n\ndefault allow = false\n'


# ---------------------------------------------------------------------------
# PUT policy tests
# ---------------------------------------------------------------------------


def test_put_policy_admin_success(client, admin_user):
    """Admin can set policy."""
    org = _create_org(client, admin_user["headers"])
    resp = client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=admin_user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["rego"] == VALID_REGO
    assert data["org_id"] == org["id"]
    assert data["created_by"] == admin_user["id"]


def test_put_policy_member_rejected(client, admin_user, member_user):
    """Member cannot set policy (admin+ required)."""
    org = _create_org(client, admin_user["headers"])
    _add_membership(org["id"], member_user["id"], OrgRole.member)

    resp = client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=member_user["headers"],
    )
    assert resp.status_code == 403


def test_put_policy_missing_package(client, admin_user):
    """Rego without package declaration is rejected."""
    org = _create_org(client, admin_user["headers"])
    resp = client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": "default allow = false"},
        headers=admin_user["headers"],
    )
    assert resp.status_code == 400
    assert "package" in resp.json()["detail"].lower()


def test_put_policy_upsert(client, admin_user):
    """Setting policy twice updates existing record."""
    org = _create_org(client, admin_user["headers"])

    resp1 = client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=admin_user["headers"],
    )
    assert resp1.status_code == 200
    policy_id = resp1.json()["id"]

    updated_rego = 'package skillledger.org\n\ndefault allow = true\n'
    resp2 = client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": updated_rego},
        headers=admin_user["headers"],
    )
    assert resp2.status_code == 200
    assert resp2.json()["id"] == policy_id  # same record
    assert resp2.json()["rego"] == updated_rego


# ---------------------------------------------------------------------------
# GET policy tests
# ---------------------------------------------------------------------------


def test_get_policy_returns_stored(client, admin_user):
    """GET returns the stored rego."""
    org = _create_org(client, admin_user["headers"])
    client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=admin_user["headers"],
    )
    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/policy",
        headers=admin_user["headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["rego"] == VALID_REGO


def test_get_policy_404_when_none(client, admin_user):
    """GET returns 404 when no policy is set."""
    org = _create_org(client, admin_user["headers"])
    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/policy",
        headers=admin_user["headers"],
    )
    assert resp.status_code == 404


def test_get_policy_etag(client, admin_user):
    """GET includes ETag header based on rego content."""
    org = _create_org(client, admin_user["headers"])
    client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=admin_user["headers"],
    )
    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/policy",
        headers=admin_user["headers"],
    )
    assert resp.status_code == 200
    etag = resp.headers.get("etag")
    assert etag is not None
    expected = hashlib.md5(VALID_REGO.encode()).hexdigest()
    assert expected in etag


def test_get_policy_viewer_access(client, admin_user, viewer_user):
    """Viewer can read policy."""
    org = _create_org(client, admin_user["headers"])
    _add_membership(org["id"], viewer_user["id"], OrgRole.viewer)

    client.put(
        f"/ee/v1/orgs/{org['slug']}/policy",
        json={"rego": VALID_REGO},
        headers=admin_user["headers"],
    )
    resp = client.get(
        f"/ee/v1/orgs/{org['slug']}/policy",
        headers=viewer_user["headers"],
    )
    assert resp.status_code == 200
