"""Tests for Stripe billing endpoints (BILL-03, BILL-05)."""

import asyncio
import datetime
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-billing")
os.environ.setdefault("SKILLLEDGER_STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_WEBHOOK_SECRET", "whsec_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_PRICE_ID", "price_test_123")

from skillledger_service.auth import generate_api_key, hash_api_key  # noqa: E402
from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.publisher import APIKey, Publisher  # noqa: E402
from skillledger_service.models.usage import Subscription  # noqa: E402
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


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def user_auth_headers():
    """Create a User in DB and return JWT auth headers + user_id."""
    user_id_holder = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email="billing-test@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id_holder["id"] = user.id
            user_id_holder["email"] = user.email

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()

    settings = get_settings()
    token = create_access_token(
        user_id_holder["id"], user_id_holder["email"], settings.jwt_secret
    )
    return {"Authorization": f"Bearer {token}"}, user_id_holder["id"]


@pytest.fixture
def publisher_auth_headers():
    """Create a publisher with an API key and return auth headers."""
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            pub = Publisher(
                name="test-publisher-billing",
                contact_email="pub-billing@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
                active=True,
            )
            session.add(pub)
            await session.flush()
            key = APIKey(
                key_hash=hashed,
                key_prefix=raw_key[:8],
                publisher_id=pub.id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                revoked=False,
            )
            session.add(key)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return {"Authorization": f"Bearer {raw_key}"}


def _mock_stripe_client():
    """Create a mock StripeClient with common method stubs."""
    mock_client = MagicMock()
    mock_customer = MagicMock()
    mock_customer.id = "cus_test123"
    mock_client.customers.create.return_value = mock_customer

    mock_checkout_session = MagicMock()
    mock_checkout_session.url = "https://checkout.stripe.com/test"
    mock_client.checkout.sessions.create.return_value = mock_checkout_session

    mock_portal_session = MagicMock()
    mock_portal_session.url = "https://billing.stripe.com/portal/test"
    mock_client.billing_portal.sessions.create.return_value = mock_portal_session

    return mock_client


def test_checkout_creates_session(client, user_auth_headers):
    """BILL-03: POST /v1/billing/checkout creates a Checkout Session and returns URL."""
    headers, _ = user_auth_headers
    mock_client = _mock_stripe_client()

    with patch("skillledger_service.routers.billing.get_stripe_client", return_value=mock_client):
        resp = client.post("/v1/billing/checkout", headers=headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["url"] == "https://checkout.stripe.com/test"

    # Verify checkout session was created with subscription mode and price_id
    mock_client.checkout.sessions.create.assert_called_once()
    call_params = mock_client.checkout.sessions.create.call_args
    params = call_params[1]["params"] if "params" in call_params[1] else call_params[0][0]
    assert params["mode"] == "subscription"


def test_checkout_reuses_existing_customer(client, user_auth_headers):
    """BILL-03: Checkout reuses existing stripe_customer_id instead of creating new."""
    headers, user_id = user_auth_headers

    # Seed a Subscription with existing stripe_customer_id
    async def _seed():
        factory = get_async_session_factory()
        async with factory() as session:
            sub = Subscription(
                user_id=user_id,
                stripe_customer_id="cus_existing",
                plan="free",
                status="inactive",
            )
            session.add(sub)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed())
    loop.close()

    mock_client = _mock_stripe_client()

    with patch("skillledger_service.routers.billing.get_stripe_client", return_value=mock_client):
        resp = client.post("/v1/billing/checkout", headers=headers)

    assert resp.status_code == 200

    # Customer.create should NOT have been called
    mock_client.customers.create.assert_not_called()

    # Checkout session should use the existing customer
    call_params = mock_client.checkout.sessions.create.call_args
    params = call_params[1]["params"] if "params" in call_params[1] else call_params[0][0]
    assert params["customer"] == "cus_existing"


def test_portal_session(client, user_auth_headers):
    """BILL-05: POST /v1/billing/portal creates a Portal Session and returns URL."""
    headers, user_id = user_auth_headers

    # Seed Subscription with stripe_customer_id
    async def _seed():
        factory = get_async_session_factory()
        async with factory() as session:
            sub = Subscription(
                user_id=user_id,
                stripe_customer_id="cus_portal_test",
                plan="pay_as_you_go",
                status="active",
            )
            session.add(sub)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed())
    loop.close()

    mock_client = _mock_stripe_client()

    with patch("skillledger_service.routers.billing.get_stripe_client", return_value=mock_client):
        resp = client.post("/v1/billing/portal", headers=headers)

    assert resp.status_code == 200
    body = resp.json()
    assert body["url"] == "https://billing.stripe.com/portal/test"


def test_portal_no_customer_returns_400(client, user_auth_headers):
    """BILL-05: Portal returns 400 when user has no billing account."""
    headers, _ = user_auth_headers

    resp = client.post("/v1/billing/portal", headers=headers)

    assert resp.status_code == 400
    assert "No billing account" in resp.json()["detail"]


def test_billing_requires_jwt_auth(client):
    """Billing endpoints require authentication."""
    resp = client.post("/v1/billing/checkout")
    assert resp.status_code in (401, 403)


def test_billing_rejects_publisher_key(client, publisher_auth_headers):
    """Billing endpoints reject publisher API keys (T-23-06)."""
    headers = publisher_auth_headers

    resp = client.post("/v1/billing/checkout", headers=headers)
    assert resp.status_code == 401
