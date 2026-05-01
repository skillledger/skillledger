"""Tests for enterprise org endpoints and license gating (ORG-01..ORG-05)."""

import asyncio
import datetime
import hashlib
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Must be set before any imports
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
from skillledger_service.models.organization import (  # noqa: E402
    OrgInvite,
    OrgMembership,
    OrgRole,
)
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db():
    """Drop and recreate all tables before each test for isolation."""

    async def _reset():
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_reset())
    loop.close()
    yield


def _make_app_with_license():
    """Create app with valid license env vars."""
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    return create_app()


def _make_app_without_license():
    """Create app with license env vars removed."""
    os.environ.pop("SKILLLEDGER_EE_LICENSE_KEY", None)
    os.environ.pop("SKILLLEDGER_EE_LICENSE_HASH", None)
    get_settings.cache_clear()
    return create_app()


@pytest.fixture
def client_with_license():
    app = _make_app_with_license()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_without_license():
    app = _make_app_without_license()
    with TestClient(app) as c:
        yield c


def _create_user(email: str) -> dict:
    """Create a User in DB and return dict with id, email, and auth headers."""
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


@pytest.fixture
def user1():
    return _create_user("owner@example.com")


@pytest.fixture
def user2():
    return _create_user("member@example.com")


def _create_org(client, headers, name="Acme Corp"):
    """Helper to create an org and return the response JSON."""
    resp = client.post("/ee/v1/orgs", json={"name": name}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _add_membership(org_id: int, user_id: int, role: OrgRole):
    """Directly insert a membership into the DB."""

    async def _insert():
        factory = get_async_session_factory()
        async with factory() as session:
            m = OrgMembership(user_id=user_id, org_id=org_id, role=role)
            session.add(m)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_insert())
    loop.close()


def _create_invite_direct(org_id: int, email: str, role: OrgRole, token: str,
                          invited_by: int, expires_delta_days: int = 7):
    """Directly insert an invite into the DB, returning the invite id."""
    holder: dict = {}

    async def _insert():
        factory = get_async_session_factory()
        async with factory() as session:
            now = datetime.datetime.now(datetime.timezone.utc)
            inv = OrgInvite(
                org_id=org_id,
                email=email,
                role=role,
                invited_by=invited_by,
                token=token,
                expires_at=now + datetime.timedelta(days=expires_delta_days),
            )
            session.add(inv)
            await session.commit()
            await session.refresh(inv)
            holder["id"] = inv.id

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_insert())
    loop.close()
    return holder["id"]


# ---------------------------------------------------------------------------
# License gating tests (ORG-04, ORG-05)
# ---------------------------------------------------------------------------


def test_ee_not_loaded_without_license(client_without_license):
    """ORG-05: Without license key, ee/ routes are not registered -> 404."""
    resp = client_without_license.get("/ee/v1/orgs/nonexistent")
    assert resp.status_code == 404


def test_ee_loaded_with_license(client_with_license):
    """ORG-04: With valid license, ee/ routes exist -> 401/403 (auth required)."""
    resp = client_with_license.get("/ee/v1/orgs/nonexistent")
    # Routes are registered, so we get auth error (not 404)
    assert resp.status_code in (401, 403)


def test_ee_invalid_license_key():
    """ORG-05: Invalid license key means fail-closed -- ee/ routes NOT loaded."""
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = "wrong-key"
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/ee/v1/orgs/nonexistent")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Org CRUD tests (ORG-01)
# ---------------------------------------------------------------------------


def test_create_org(client_with_license, user1):
    """ORG-01: Create org, user becomes owner."""
    data = _create_org(client_with_license, user1["headers"])
    assert data["name"] == "Acme Corp"
    assert data["slug"] == "acme-corp"
    assert "id" in data


def test_create_org_duplicate_slug(client_with_license, user1):
    """ORG-01: Duplicate slug returns 409."""
    _create_org(client_with_license, user1["headers"])
    resp = client_with_license.post(
        "/ee/v1/orgs", json={"name": "Acme Corp"}, headers=user1["headers"]
    )
    assert resp.status_code == 409


def test_get_org(client_with_license, user1):
    """ORG-01: Get org details as member."""
    _create_org(client_with_license, user1["headers"])
    resp = client_with_license.get(
        "/ee/v1/orgs/acme-corp", headers=user1["headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["slug"] == "acme-corp"


def test_get_org_not_member(client_with_license, user1, user2):
    """ORG-02: Non-member cannot access org details -> 403."""
    _create_org(client_with_license, user1["headers"])
    resp = client_with_license.get(
        "/ee/v1/orgs/acme-corp", headers=user2["headers"]
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Member tests (ORG-02)
# ---------------------------------------------------------------------------


def test_list_members(client_with_license, user1):
    """ORG-02: List members returns the owner."""
    org = _create_org(client_with_license, user1["headers"])
    resp = client_with_license.get(
        f"/ee/v1/orgs/{org['slug']}/members", headers=user1["headers"]
    )
    assert resp.status_code == 200
    members = resp.json()
    assert len(members) == 1
    assert members[0]["role"] == "owner"
    assert members[0]["email"] == user1["email"]


def test_remove_member(client_with_license, user1, user2):
    """ORG-02: Owner can remove a member."""
    org = _create_org(client_with_license, user1["headers"])
    _add_membership(org["id"], user2["id"], OrgRole.member)

    resp = client_with_license.delete(
        f"/ee/v1/orgs/{org['slug']}/members/{user2['id']}",
        headers=user1["headers"],
    )
    assert resp.status_code == 204


def test_cannot_remove_owner(client_with_license, user1):
    """ORG-02: Cannot remove the org owner."""
    org = _create_org(client_with_license, user1["headers"])
    resp = client_with_license.delete(
        f"/ee/v1/orgs/{org['slug']}/members/{user1['id']}",
        headers=user1["headers"],
    )
    assert resp.status_code == 403
    assert "owner" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Invite tests (ORG-03)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.routers.orgs.resend.Emails.send")
def test_invite_member(mock_send, client_with_license, user1):
    """ORG-03: Admin/owner can invite a new member."""
    org = _create_org(client_with_license, user1["headers"])
    resp = client_with_license.post(
        f"/ee/v1/orgs/{org['slug']}/invites",
        json={"email": "new@example.com", "role": "member"},
        headers=user1["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "new@example.com"
    assert data["role"] == "member"
    assert data["accepted"] is False
    mock_send.assert_called_once()


def test_invite_viewer_cannot_invite(client_with_license, user1, user2):
    """ORG-02: A viewer cannot create invites -> 403."""
    org = _create_org(client_with_license, user1["headers"])
    _add_membership(org["id"], user2["id"], OrgRole.viewer)

    resp = client_with_license.post(
        f"/ee/v1/orgs/{org['slug']}/invites",
        json={"email": "another@example.com", "role": "member"},
        headers=user2["headers"],
    )
    assert resp.status_code == 403


def test_accept_invite(client_with_license, user1, user2):
    """ORG-03: Accept invite creates membership."""
    org = _create_org(client_with_license, user1["headers"])
    token = "test-invite-token-accept"
    _create_invite_direct(
        org["id"], user2["email"], OrgRole.member, token, user1["id"]
    )

    resp = client_with_license.post(
        f"/ee/v1/invites/{token}/accept", headers=user2["headers"]
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == user2["id"]
    assert data["role"] == "member"


def test_accept_expired_invite(client_with_license, user1, user2):
    """ORG-03: Expired invite returns 400."""
    org = _create_org(client_with_license, user1["headers"])
    token = "test-invite-token-expired"
    _create_invite_direct(
        org["id"], user2["email"], OrgRole.member, token, user1["id"],
        expires_delta_days=-1,
    )

    resp = client_with_license.post(
        f"/ee/v1/invites/{token}/accept", headers=user2["headers"]
    )
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()


def test_accept_invite_wrong_email(client_with_license, user1, user2):
    """ORG-03 / D-11: Invite for different email -> 403."""
    org = _create_org(client_with_license, user1["headers"])
    token = "test-invite-token-wrong"
    _create_invite_direct(
        org["id"], "other@example.com", OrgRole.member, token, user1["id"]
    )

    resp = client_with_license.post(
        f"/ee/v1/invites/{token}/accept", headers=user2["headers"]
    )
    assert resp.status_code == 403
    assert "email" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Ownership transfer (D-06)
# ---------------------------------------------------------------------------


def test_transfer_ownership(client_with_license, user1, user2):
    """D-06: Owner can transfer ownership; old owner becomes admin."""
    org = _create_org(client_with_license, user1["headers"])
    _add_membership(org["id"], user2["id"], OrgRole.admin)

    resp = client_with_license.post(
        f"/ee/v1/orgs/{org['slug']}/transfer",
        json={"new_owner_id": user2["id"]},
        headers=user1["headers"],
    )
    assert resp.status_code == 200

    # Verify roles swapped
    members_resp = client_with_license.get(
        f"/ee/v1/orgs/{org['slug']}/members", headers=user2["headers"]
    )
    assert members_resp.status_code == 200
    members = {m["user_id"]: m["role"] for m in members_resp.json()}
    assert members[user2["id"]] == "owner"
    assert members[user1["id"]] == "admin"
