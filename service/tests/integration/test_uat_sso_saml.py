"""UAT Integration Tests: SSO/SAML Login Flow (UAT-03, D-01, D-05).

Proves end-to-end: initiate SAML login -> IdP callback with assertion ->
JIT user provisioning -> JWT issued.
"""

import asyncio
import datetime
import hashlib
import os
from unittest.mock import MagicMock, patch

from skillledger_service.db import (
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.models.organization import (
    OrgMembership,
    OrgRole,
    Organization,
)
from skillledger_service.models.saml_config import SamlConfig
from skillledger_service.models.user import User
from skillledger_service.user_auth import create_access_token

# EE license env vars (must be set for SAML endpoints to load)
_LICENSE_KEY = "test-license-key-integration"
_LICENSE_HASH = hashlib.sha256(_LICENSE_KEY.encode()).hexdigest()
os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
os.environ["SKILLLEDGER_SERVICE_URL"] = "https://app.skillledger.dev"


def _make_licensed_app():
    """Create app with valid license env vars (ensures EE routes are loaded)."""
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    from skillledger_service.main import create_app

    return create_app()


def _create_org_with_owner(org_name: str, owner_email: str) -> tuple[dict, dict]:
    """Create an org and owner membership, return (org_dict, owner_dict)."""
    holder_org: dict = {}
    holder_user: dict = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            # Create user
            user = User(
                email=owner_email,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.flush()
            holder_user["id"] = user.id
            holder_user["email"] = user.email

            # Create org
            slug = org_name.lower().replace(" ", "-")
            org = Organization(name=org_name, slug=slug)
            session.add(org)
            await session.commit()
            await session.refresh(org)
            holder_org["id"] = org.id
            holder_org["slug"] = org.slug

            # Create membership
            membership = OrgMembership(
                user_id=user.id, org_id=org.id, role=OrgRole.owner
            )
            session.add(membership)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()

    settings = get_settings()
    token = create_access_token(
        holder_user["id"], holder_user["email"], settings.jwt_secret
    )
    holder_user["headers"] = {"Authorization": f"Bearer {token}"}
    return holder_org, holder_user


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
    """Create a properly configured mock Stripe client for seat billing."""
    mock_client = MagicMock()
    mock_customer = MagicMock()
    mock_customer.id = "cus_test_saml_uat"
    mock_client.customers.create.return_value = mock_customer
    mock_sub = MagicMock()
    mock_sub.id = "sub_test_saml_uat"
    mock_item = MagicMock()
    mock_item.id = "si_test_saml_uat"
    mock_sub.items = MagicMock()
    mock_sub.items.data = [mock_item]
    mock_client.subscriptions.create.return_value = mock_sub
    mock_client.subscriptions.retrieve.return_value = mock_sub
    mock_client.subscriptions.cancel.return_value = MagicMock()
    mock_client.subscription_items.update.return_value = MagicMock()
    return mock_client


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_full_flow(mock_auth_cls, mock_get_stripe):
    """End-to-end SAML SSO: initiate -> IdP callback -> JIT provision -> JWT issued.

    Covers UAT-03: SSO/SAML login completes against mock IdP.
    """
    from fastapi.testclient import TestClient

    mock_get_stripe.return_value = _make_mock_stripe()

    # Setup: org with SAML config
    app = _make_licensed_app()
    org, owner = _create_org_with_owner("SAML UAT Org", "saml-uat-owner@example.com")
    _create_saml_config(org["id"])

    # Mock SAML auth for login redirect
    mock_login_auth = _mock_saml_auth(
        login_url="https://idp.example.com/sso?SAMLRequest=encoded"
    )
    # Mock SAML auth for ACS callback
    mock_acs_auth = _mock_saml_auth(
        nameid="saml-newuser@example.com",
        attributes={"User.FirstName": ["Jane"], "User.LastName": ["Doe"]},
    )
    mock_auth_cls.side_effect = [mock_login_auth, mock_acs_auth]

    with TestClient(app, follow_redirects=False) as client:
        # Step 1: Initiate SAML login -> redirects to IdP
        resp = client.get(f"/ee/v1/saml/{org['slug']}/login")
        assert resp.status_code == 302
        assert "idp.example.com/sso" in resp.headers["location"]

        # Step 2: Simulate IdP callback (ACS)
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "base64encodedresponse"},
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "access_token=" in location
        assert "refresh_token=" in location

        # Step 3: Verify JIT provisioning - use returned JWT to check user exists
        fragment = location.split("#")[1]
        params = dict(p.split("=") for p in fragment.split("&"))
        access_token = params["access_token"]

        resp2 = client.get(
            f"/ee/v1/orgs/{org['slug']}/members",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp2.status_code == 200
        emails = [m["email"] for m in resp2.json()]
        assert "saml-newuser@example.com" in emails


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
@patch("skillledger_service.ee.routers.saml.OneLogin_Saml2_Auth")
def test_saml_invalid_assertion_rejected(mock_auth_cls, mock_get_stripe):
    """SAML callback with invalid assertion returns 400.

    Covers UAT-03 negative path: malformed SAML responses are rejected.
    """
    from fastapi.testclient import TestClient

    mock_get_stripe.return_value = _make_mock_stripe()

    # Mock auth that returns errors
    mock_auth_instance = _mock_saml_auth()
    mock_auth_instance.get_errors.return_value = ["invalid_signature"]
    mock_auth_cls.return_value = mock_auth_instance

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("SAML Invalid Org", "saml-invalid-owner@example.com")
    _create_saml_config(org["id"])

    with TestClient(app) as client:
        resp = client.post(
            f"/ee/v1/saml/{org['slug']}/acs",
            data={"SAMLResponse": "baddata"},
        )
        assert resp.status_code == 400
        assert "invalid_signature" in resp.json()["detail"]


def test_saml_without_config_returns_404():
    """SAML login initiate on org without SAML config returns 404.

    Covers UAT-03 edge case: orgs without SAML configured return clear error.
    """
    from fastapi.testclient import TestClient

    app = _make_licensed_app()
    org, _ = _create_org_with_owner("SAML NoConf Org", "saml-noconf-owner@example.com")
    # No SAML config created for this org

    with TestClient(app) as client:
        resp = client.get(f"/ee/v1/saml/{org['slug']}/login")
        assert resp.status_code == 404
