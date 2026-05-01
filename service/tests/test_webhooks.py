"""Tests for Stripe webhook handler (BILL-04)."""

import asyncio
import datetime
import json
import os
from unittest.mock import patch

import pytest
import stripe
from fastapi.testclient import TestClient

# Must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-webhooks")
os.environ.setdefault("SKILLLEDGER_STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_WEBHOOK_SECRET", "whsec_test_fake")
os.environ.setdefault("SKILLLEDGER_STRIPE_PRICE_ID", "price_test_123")

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.usage import StripeEvent, Subscription  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from sqlalchemy import func, select  # noqa: E402


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


def _seed_user_and_subscription(stripe_customer_id="cus_123", stripe_subscription_id=None):
    """Seed a user and subscription in the database."""

    async def _seed():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email="webhook-test@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.flush()
            sub = Subscription(
                user_id=user.id,
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
                plan="free",
                status="inactive",
            )
            session.add(sub)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed())
    loop.close()


def _make_event(event_id, event_type, data_object):
    """Create a Stripe-like event dict."""
    return {
        "id": event_id,
        "type": event_type,
        "data": {"object": data_object},
    }


def _post_webhook(client, event):
    """POST a webhook event with mocked signature verification."""
    payload = json.dumps(event).encode()
    with patch(
        "skillledger_service.routers.webhooks.stripe.Webhook.construct_event",
        return_value=event,
    ):
        return client.post(
            "/v1/webhooks/stripe",
            content=payload,
            headers={
                "stripe-signature": "t=123,v1=fakesig",
                "content-type": "application/json",
            },
        )


def test_webhook_checkout_completed(client):
    """BILL-04: checkout.session.completed upserts subscription to active/pay_as_you_go."""
    _seed_user_and_subscription(stripe_customer_id="cus_123")

    event = _make_event(
        "evt_checkout_1",
        "checkout.session.completed",
        {"customer": "cus_123", "subscription": "sub_123"},
    )

    resp = _post_webhook(client, event)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # Verify subscription was updated
    async def _check():
        factory = get_async_session_factory()
        async with factory() as session:
            stmt = select(Subscription).where(
                Subscription.stripe_customer_id == "cus_123"
            )
            result = await session.execute(stmt)
            sub = result.scalar_one_or_none()
            return sub

    loop = asyncio.new_event_loop()
    sub = loop.run_until_complete(_check())
    loop.close()

    assert sub is not None
    assert sub.stripe_subscription_id == "sub_123"
    assert sub.status == "active"
    assert sub.plan == "pay_as_you_go"


def test_webhook_idempotency(client):
    """BILL-04: Duplicate events are skipped (idempotency via stripe_events table)."""
    _seed_user_and_subscription(stripe_customer_id="cus_idem")

    event = _make_event(
        "evt_idem_1",
        "checkout.session.completed",
        {"customer": "cus_idem", "subscription": "sub_idem"},
    )

    # Send same event twice
    resp1 = _post_webhook(client, event)
    resp2 = _post_webhook(client, event)

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    # Verify only one StripeEvent record exists
    async def _check():
        factory = get_async_session_factory()
        async with factory() as session:
            stmt = select(func.count()).select_from(StripeEvent).where(
                StripeEvent.stripe_event_id == "evt_idem_1"
            )
            result = await session.execute(stmt)
            return result.scalar()

    loop = asyncio.new_event_loop()
    count = loop.run_until_complete(_check())
    loop.close()

    assert count == 1


def test_webhook_subscription_updated(client):
    """customer.subscription.updated updates subscription status."""
    _seed_user_and_subscription(
        stripe_customer_id="cus_upd", stripe_subscription_id="sub_upd"
    )

    event = _make_event(
        "evt_upd_1",
        "customer.subscription.updated",
        {"id": "sub_upd", "status": "past_due"},
    )

    resp = _post_webhook(client, event)
    assert resp.status_code == 200

    async def _check():
        factory = get_async_session_factory()
        async with factory() as session:
            stmt = select(Subscription).where(
                Subscription.stripe_subscription_id == "sub_upd"
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    loop = asyncio.new_event_loop()
    sub = loop.run_until_complete(_check())
    loop.close()

    assert sub is not None
    assert sub.status == "past_due"


def test_webhook_subscription_deleted(client):
    """customer.subscription.deleted sets status to canceled."""
    _seed_user_and_subscription(
        stripe_customer_id="cus_del", stripe_subscription_id="sub_del"
    )

    event = _make_event(
        "evt_del_1",
        "customer.subscription.deleted",
        {"id": "sub_del"},
    )

    resp = _post_webhook(client, event)
    assert resp.status_code == 200

    async def _check():
        factory = get_async_session_factory()
        async with factory() as session:
            stmt = select(Subscription).where(
                Subscription.stripe_subscription_id == "sub_del"
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    loop = asyncio.new_event_loop()
    sub = loop.run_until_complete(_check())
    loop.close()

    assert sub is not None
    assert sub.status == "canceled"


def test_webhook_invalid_signature(client):
    """Invalid Stripe signature returns 400."""
    with patch(
        "skillledger_service.routers.webhooks.stripe.Webhook.construct_event",
        side_effect=stripe.SignatureVerificationError("bad sig", "sig_header"),
    ):
        resp = client.post(
            "/v1/webhooks/stripe",
            content=b'{"id": "evt_bad"}',
            headers={
                "stripe-signature": "t=123,v1=invalid",
                "content-type": "application/json",
            },
        )

    assert resp.status_code == 400
    assert "Invalid signature" in resp.json()["detail"]


def test_webhook_unknown_event_type(client):
    """Unknown event types return 200 (logged and skipped)."""
    event = _make_event(
        "evt_unknown_1",
        "invoice.paid",
        {"id": "inv_123"},
    )

    resp = _post_webhook(client, event)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
