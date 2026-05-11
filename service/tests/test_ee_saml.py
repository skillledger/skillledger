"""Tests for enterprise SAML SSO router (SSO-01 through SSO-05)."""

import asyncio
import datetime
import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-saml")
os.environ.setdefault("SKILLLEDGER_RESEND_API_KEY", "re_test_fake")
os.environ["SKILLLEDGER_JWT_SECRET"] = "test-secret-saml"
os.environ["SKILLLEDGER_SERVICE_URL"] = "https://app.skillledger.in"

_LICENSE_KEY = "test-license-key-saml"
_LICENSE_HASH = hashlib.sha256(_LICENSE_KEY.encode()).hexdigest()
os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.organization import (  # noqa: E402
    OrgMembership,
    OrgRole,
    Organization,
)
from skillledger_service.models.saml_config import SamlConfig  # noqa: E402
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


def _make_licensed_app():
    """Create app with valid license env vars."""
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    return create_app()


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


def _create_org_with_owner(org_name: str, owner_email: str) -> tuple[dict, dict]:
    """Create org and owner membership, return (org_dict, owner_dict)."""
    owner = _create_user(owner_email)
    holder: dict = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            slug = org_name.lower().replace(" ", "-")
            org = Organization(name=org_name, slug=slug)
            session.add(org)
            await session.commit()
            await session.refresh(org)

            membership = OrgMembership(
                user_id=owner["id"], org_id=org.id, role=OrgRole.owner
            )
            session.add(membership)
            await session.commit()
            holder["id"] = org.id
            holder["slug"] = org.slug
            holder["name"] = org.name

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return holder, owner


def _create_saml_config(org_id: int) -> int:
    """Insert a SamlConfig record for an org, return config id."""
    holder: dict = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            config = SamlConfig(
                org_id=org_id,
                entity_id="https://idp.example.com/entity",
                sso_url="https://idp.example.com/sso",
                x509_cert="MIICpDCCAYwCCQDvn4pPkitest==",
                attribute_mapping={
                    "email": "NameID",
                    "firstName": "User.FirstName",
                    "lastName": "User.LastName",
                    "role": "memberOf",
                },
            )
            session.add(config)
            await session.commit()
            await session.refresh(config)
            holder["id"] = config.id

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return holder["id"]


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


def _mock_saml_auth(
    login_url="https://idp.example.com/sso?SAMLRequest=abc",
    errors=None,
    nameid="user@example.com",
    attributes=None,
):
    """Create a mock OneLogin_Saml2_Auth instance."""
    mock_auth = MagicMock()
    mock_auth.login.return_value = login_url
    mock_auth.process_response.return_value = None
    mock_auth.get_errors.return_value = errors or []
    mock_auth.get_nameid.return_value = nameid
    mock_auth.get_attributes.return_value = attributes or {}
    return mock_auth


def _make_mock_stripe():
    """Create a properly configured mock Stripe client."""
    mock_client = MagicMock()
    mock_customer = MagicMock()
    mock_customer.id = "cus_test_saml"
    mock_client.customers.create.return_value = mock_customer
    mock_sub = MagicMock()
    mock_sub.id = "sub_test_saml"
    mock_item = MagicMock()
    mock_item.id = "si_test_saml"
    mock_sub.items = MagicMock()
    mock_sub.items.data = [mock_item]
    mock_client.subscriptions.create.return_value = mock_sub
    mock_client.subscriptions.retrieve.return_value = mock_sub
    mock_client.subscriptions.cancel.return_value = MagicMock()
    mock_client.subscription_items.update.return_value = MagicMock()
    return mock_client


# ---------------------------------------------------------------------------
# Test 1: Configure SAML via metadata XML (SSO-02)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_IdPMetadataParser")
def test_configure_saml_metadata_xml(mock_parser):
    """PUT with metadata_xml parses and stores IdP config."""
    mock_parser.parse.return_value = {
        "idp": {
            "entityId": "https://idp.example.com/entity",
            "singleSignOnService": {"url": "https://idp.example.com/sso"},
            "x509cert": "MIICpDCCAYwCCQ==",
        }
    }

    app = _make_licensed_app()
    org, owner = _create_org_with_owner("Saml Meta Org", "meta-owner@example.com")

    with TestClient(app) as client:
        resp = client.put(
            f"/ee/v1/orgs/{org['slug']}/saml",
            json={"metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"},
            headers=owner["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_id"] == "https://idp.example.com/entity"
        assert data["sso_url"] == "https://idp.example.com/sso"
        assert data["has_metadata_xml"] is True


# ---------------------------------------------------------------------------
# Test 2: Configure SAML via manual entry (SSO-02)
# ---------------------------------------------------------------------------


def test_configure_saml_manual():
    """PUT with entity_id, sso_url, x509_cert stores config directly."""
    app = _make_licensed_app()
    org, owner = _create_org_with_owner("Saml Manual Org", "manual-owner@example.com")

    with TestClient(app) as client:
        resp = client.put(
            f"/ee/v1/orgs/{org['slug']}/saml",
            json={
                "entity_id": "https://idp.manual.com/entity",
                "sso_url": "https://idp.manual.com/sso",
                "x509_cert": "-----BEGIN CERTIFICATE-----\nMIICpDCCA==\n-----END CERTIFICATE-----",
            },
            headers=owner["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_id"] == "https://idp.manual.com/entity"
        assert data["sso_url"] == "https://idp.manual.com/sso"
        assert data["has_metadata_xml"] is False


# ---------------------------------------------------------------------------
# Test 3: Configure SAML requires admin role (SSO-05)
# ---------------------------------------------------------------------------


def test_configure_saml_requires_admin():
    """PUT as viewer role returns 403."""
    app = _make_licensed_app()
    org, owner = _create_org_with_owner("Saml Admin Org", "admin-owner@example.com")
    viewer = _create_user("viewer@example.com")
    _add_membership(org["id"], viewer["id"], OrgRole.viewer)

    with TestClient(app) as client:
        resp = client.put(
            f"/ee/v1/orgs/{org['slug']}/saml",
            json={
                "entity_id": "https://idp.test.com/entity",
                "sso_url": "https://idp.test.com/sso",
                "x509_cert": "MIICpDCCA==",
            },
            headers=viewer["headers"],
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test 4: Get SAML config (SSO-05)
# ---------------------------------------------------------------------------


def test_get_saml_config():
    """GET config returns entity_id and has_metadata_xml."""
    app = _make_licensed_app()
    org, owner = _create_org_with_owner("Saml Get Org", "get-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app) as client:
        resp = client.get(
            f"/ee/v1/orgs/{org['slug']}/saml",
            headers=owner["headers"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_id"] == "https://idp.example.com/entity"
        assert data["has_metadata_xml"] is False


# ---------------------------------------------------------------------------
# Test 5: Delete SAML config (SSO-05)
# ---------------------------------------------------------------------------


def test_delete_saml_config():
    """DELETE config returns 204, subsequent GET returns 404."""
    app = _make_licensed_app()
    org, owner = _create_org_with_owner("Saml Del Org", "del-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app) as client:
        resp = client.delete(
            f"/ee/v1/orgs/{org['slug']}/saml",
            headers=owner["headers"],
        )
        assert resp.status_code == 204

        resp = client.get(
            f"/ee/v1/orgs/{org['slug']}/saml",
            headers=owner["headers"],
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 6: SAML login redirect (SSO-01)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_login_redirect(mock_auth_cls):
    """GET /saml/{slug}/login redirects to IdP SSO URL."""
    mock_auth_instance = _mock_saml_auth(
        login_url="https://idp.example.com/sso?SAMLRequest=encodedrequest"
    )
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Login Org", "login-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app, follow_redirects=False) as client:
        resp = client.get(f"/ee/v1/saml/{org['slug']}/login")
        assert resp.status_code == 302
        assert "idp.example.com/sso" in resp.headers["location"]
        mock_auth_instance.login.assert_called_once()


# ---------------------------------------------------------------------------
# Test 7: SAML ACS valid response (SSO-01, SSO-03)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_acs_valid_response(mock_auth_cls, mock_get_stripe):
    """POST /saml/{slug}/acs with valid response creates user, membership, returns JWT."""
    mock_get_stripe.return_value = _make_mock_stripe()
    mock_auth_instance = _mock_saml_auth(
        nameid="newuser@example.com",
        attributes={"User.FirstName": ["Jane"], "User.LastName": ["Doe"]},
    )
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml ACS Org", "acs-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app, follow_redirects=False) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64encodedresponse"},
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "access_token=" in location
        assert "refresh_token=" in location

        # Verify user was created by using the JWT to access a protected endpoint
        fragment = location.split("#")[1]
        params = dict(p.split("=") for p in fragment.split("&"))
        access_token = params["access_token"]

        # Use JWT to list org members -- proves user exists and has JWT
        resp2 = client.get(
            f"/ee/v1/orgs/{org['slug']}/members",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        # If user was JIT provisioned with member role, they can view members
        assert resp2.status_code == 200
        members = resp2.json()
        emails = [m["email"] for m in members]
        assert "newuser@example.com" in emails


# ---------------------------------------------------------------------------
# Test 8: SAML ACS invalid response (SSO-01)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_acs_invalid_response(mock_auth_cls, mock_get_stripe):
    """POST /saml/{slug}/acs with invalid SAML response returns 400."""
    mock_get_stripe.return_value = _make_mock_stripe()
    mock_auth_instance = _mock_saml_auth()
    mock_auth_instance.get_errors.return_value = ["invalid_signature"]
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Invalid Org", "invalid-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "baddata"},
        )
        assert resp.status_code == 400
        assert "invalid_signature" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Test 9: JIT existing user (SSO-03)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_jit_existing_user(mock_auth_cls, mock_get_stripe):
    """ACS for existing user does not create duplicate, creates membership."""
    mock_get_stripe.return_value = _make_mock_stripe()
    existing = _create_user("existing-saml@example.com")

    mock_auth_instance = _mock_saml_auth(nameid="existing-saml@example.com")
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Existing Org", "existing-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app, follow_redirects=False) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64data"},
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "access_token=" in location

        # Use returned JWT to prove the existing user got tokens and membership
        fragment = location.split("#")[1]
        params = dict(p.split("=") for p in fragment.split("&"))
        access_token = params["access_token"]

        # Existing user can now list members (proves membership was created)
        resp2 = client.get(
            f"/ee/v1/orgs/{org['slug']}/members",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp2.status_code == 200
        emails = [m["email"] for m in resp2.json()]
        assert "existing-saml@example.com" in emails


# ---------------------------------------------------------------------------
# Test 10: SAML ACS existing member (SSO-03)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_acs_existing_member(mock_auth_cls, mock_get_stripe):
    """ACS for user with existing membership succeeds without duplicate."""
    mock_get_stripe.return_value = _make_mock_stripe()
    app = _make_licensed_app()
    org, owner = _create_org_with_owner(
        "Saml Member Org", "member-owner@example.com"
    )
    _create_saml_config(org["id"])

    member = _create_user("member-saml@example.com")
    _add_membership(org["id"], member["id"], OrgRole.member)

    mock_auth_instance = _mock_saml_auth(nameid="member-saml@example.com")
    mock_auth_cls.return_value = mock_auth_instance

    with TestClient(app, follow_redirects=False) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64data"},
        )
        assert resp.status_code == 302
        assert "access_token=" in resp.headers["location"]


# ---------------------------------------------------------------------------
# Test 11: SAML metadata endpoint (SSO-01)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Settings")
def test_saml_metadata_endpoint(mock_settings_cls):
    """GET /saml/{slug}/metadata returns SP metadata XML."""
    mock_settings_inst = MagicMock()
    mock_settings_inst.get_sp_metadata.return_value = (
        '<?xml version="1.0"?><EntityDescriptor/>'
    )
    mock_settings_cls.return_value = mock_settings_inst

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Meta EP Org", "meta-ep-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app) as client:
        resp = client.get(f"/ee/v1/saml/{org['slug']}/metadata")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/xml")
        assert "EntityDescriptor" in resp.text


# ---------------------------------------------------------------------------
# Test 12: SAML login with no config returns 404 (SSO-05)
# ---------------------------------------------------------------------------


def test_saml_login_no_config():
    """GET /saml/{slug}/login for org without SAML config returns 404."""
    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml NoConf Org", "noconf-owner@example.com")

    with TestClient(app) as client:
        resp = client.get(f"/ee/v1/saml/{org['slug']}/login")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Test 13: SSO JWT works with existing token endpoint (SSO-04)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_sso_jwt_works_with_token_endpoint(mock_auth_cls, mock_get_stripe):
    """JWT from SSO login works with POST /auth/tokens to create API key."""
    mock_get_stripe.return_value = _make_mock_stripe()
    mock_auth_instance = _mock_saml_auth(nameid="sso-token-user@example.com")
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Token Org", "token-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app, follow_redirects=False) as client:
        # Do SAML ACS to get JWT
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64data"},
        )
        assert resp.status_code == 302
        location = resp.headers["location"]

        # Extract access_token from fragment
        fragment = location.split("#")[1]
        params = dict(p.split("=") for p in fragment.split("&"))
        access_token = params["access_token"]

        # Use the SSO JWT to create an API token (same TestClient to share DB)
        resp = client.post(
            "/auth/tokens",
            json={"name": "sso-ci-key"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "raw_key" in data
        assert data["name"] == "sso-ci-key"


# ---------------------------------------------------------------------------
# Test 14: JIT provision triggers seat sync (SSO-03)
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_jit_provision_seat_sync(mock_auth_cls, mock_get_stripe):
    """After JIT creates new membership via ACS, seat count is updated."""
    mock_client = MagicMock()
    mock_client.customers.create.return_value = MagicMock(id="cus_saml")
    mock_sub = MagicMock()
    mock_sub.id = "sub_saml"
    mock_sub.items = MagicMock()
    mock_sub.items.data = [MagicMock(id="si_saml")]
    mock_client.subscriptions.create.return_value = mock_sub
    mock_client.subscriptions.retrieve.return_value = mock_sub
    mock_client.subscription_items.update.return_value = MagicMock()
    mock_get_stripe.return_value = mock_client

    mock_auth_instance = _mock_saml_auth(nameid="seat-saml@example.com")
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("Saml Seat Org", "seat-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app, follow_redirects=False) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64data"},
        )
        assert resp.status_code == 302

        # Verify seat sync by checking the billing endpoint (requires viewer+ role)
        # The SAML user was JIT provisioned as member, use their token
        location = resp.headers["location"]
        fragment = location.split("#")[1]
        params = dict(p.split("=") for p in fragment.split("&"))
        access_token = params["access_token"]

        # List org members to verify count (owner + JIT user = 2)
        resp2 = client.get(
            f"/ee/v1/orgs/{org['slug']}/members",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp2.status_code == 200
        assert len(resp2.json()) == 2  # owner + JIT-provisioned user

    # Verify seat was updated via stripe mock call
    mock_client.subscription_items.update.assert_called()
