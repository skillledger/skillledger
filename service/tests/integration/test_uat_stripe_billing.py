"""UAT Integration Tests: Stripe Billing Flow (UAT-08, D-01, D-04).

Proves end-to-end: create checkout session -> process webhook ->
subscription created in DB.
"""

import asyncio
import datetime
import os
from unittest.mock import MagicMock, patch

from skillledger_service.db import get_async_session_factory, get_settings
from skillledger_service.models.usage import Subscription
from skillledger_service.models.user import User
from skillledger_service.user_auth import create_access_token

# Stripe env vars
os.environ.setdefault("SKILLLEDGER_STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_WEBHOOK_SECRET", "whsec_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_PRICE_ID", "price_test_123")


def _create_user_with_token(email: str = "billing-uat@example.com") -> tuple[int, str]:
    """Create a user and return (user_id, jwt_token)."""
    holder = {}

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
    return holder["id"], token


def _create_user_with_subscription(
    email: str, stripe_customer_id: str
) -> tuple[int, str]:
    """Create user + subscription record with stripe_customer_id, return (user_id, token)."""
    holder = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email=email,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.flush()
            holder["id"] = user.id
            holder["email"] = user.email

            sub = Subscription(
                user_id=user.id,
                stripe_customer_id=stripe_customer_id,
                plan="pay_as_you_go",
                status="active",
            )
            session.add(sub)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()

    settings = get_settings()
    token = create_access_token(holder["id"], holder["email"], settings.jwt_secret)
    return holder["id"], token


def _mock_stripe_client():
    """Create a mock StripeClient with checkout and portal stubs."""
    mock_client = MagicMock()
    mock_customer = MagicMock()
    mock_customer.id = "cus_uat_test"
    mock_client.customers.create.return_value = mock_customer

    mock_checkout_session = MagicMock()
    mock_checkout_session.url = "https://checkout.stripe.com/uat-test"
    mock_client.checkout.sessions.create.return_value = mock_checkout_session

    mock_portal_session = MagicMock()
    mock_portal_session.url = "https://billing.stripe.com/portal/uat-test"
    mock_client.billing_portal.sessions.create.return_value = mock_portal_session

    return mock_client


def _get_subscription_for_user(user_id: int) -> Subscription | None:
    """Query DB for Subscription record for a user."""
    holder = {"sub": None}

    async def _query():
        from sqlalchemy import select

        factory = get_async_session_factory()
        async with factory() as session:
            stmt = select(Subscription).where(Subscription.user_id == user_id)
            result = await session.execute(stmt)
            holder["sub"] = result.scalar_one_or_none()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_query())
    loop.close()
    return holder["sub"]


def test_checkout_and_webhook_flow(client):
    """End-to-end: checkout session -> webhook event -> subscription created.

    Covers UAT-08: Stripe billing creates checkout session, processes webhook,
    grants subscription.
    """
    user_id, token = _create_user_with_token("checkout-uat@example.com")
    mock_client = _mock_stripe_client()

    # Step 1: Create checkout session
    with patch(
        "skillledger_service.routers.billing.get_stripe_client",
        return_value=mock_client,
    ):
        resp = client.post(
            "/v1/billing/checkout",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "url" in data
    assert "checkout.stripe.com" in data["url"]

    # Step 2: Simulate webhook (checkout.session.completed)
    # Verify subscription was seeded during checkout (with stripe_customer_id)
    sub = _get_subscription_for_user(user_id)
    assert sub is not None
    assert sub.stripe_customer_id == "cus_uat_test"

    # Construct a fake webhook event
    event_payload = {
        "id": "evt_test_uat_checkout",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_uat_test",
                "subscription": "sub_uat_test_123",
            }
        },
    }

    with patch("stripe.Webhook.construct_event", return_value=event_payload):
        resp = client.post(
            "/v1/webhooks/stripe",
            content=b'{"fake": "payload"}',
            headers={
                "stripe-signature": "t=1234,v1=fakesig",
                "content-type": "application/json",
            },
        )

    assert resp.status_code == 200

    # Step 3: Verify subscription updated in DB
    sub = _get_subscription_for_user(user_id)
    assert sub is not None
    assert sub.stripe_subscription_id == "sub_uat_test_123"
    assert sub.plan == "pay_as_you_go"
    assert sub.status == "active"


def test_billing_portal_session(client):
    """Authenticated user with stripe_customer_id can create portal session.

    Covers UAT-08: billing portal access works for subscribed users.
    """
    user_id, token = _create_user_with_subscription(
        "portal-uat@example.com", "cus_portal_uat"
    )
    mock_client = _mock_stripe_client()

    with patch(
        "skillledger_service.routers.billing.get_stripe_client",
        return_value=mock_client,
    ):
        resp = client.post(
            "/v1/billing/portal",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "url" in data
    assert "billing.stripe.com/portal" in data["url"]


def test_webhook_invalid_signature_rejected(client):
    """POST /v1/webhooks/stripe with bad signature returns 400.

    Covers UAT-08 security: webhooks with invalid signatures are rejected.
    """
    with patch(
        "stripe.Webhook.construct_event",
        side_effect=__import__("stripe").SignatureVerificationError(
            "Invalid signature", "sig_header"
        ),
    ):
        resp = client.post(
            "/v1/webhooks/stripe",
            content=b'{"bad": "payload"}',
            headers={
                "stripe-signature": "t=bad,v1=invalid",
                "content-type": "application/json",
            },
        )

    assert resp.status_code == 400
    assert "Invalid signature" in resp.json()["detail"]
