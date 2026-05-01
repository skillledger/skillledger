"""Tests for per-seat billing service module (ORG-10)."""

import asyncio
import datetime
import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest

# Must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-seat")
os.environ.setdefault("SKILLLEDGER_RESEND_API_KEY", "re_test_fake")
os.environ["SKILLLEDGER_STRIPE_SEAT_PRICE_ID"] = "price_test_seat"

_LICENSE_KEY = "test-license-key-seat"
_LICENSE_HASH = hashlib.sha256(_LICENSE_KEY.encode()).hexdigest()
os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.organization import Organization, Seat  # noqa: E402


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


def _create_org_and_seat(org_name="Acme Corp", seat_count=0, stripe_sub_id=None,
                          stripe_cust_id=None):
    """Create an Organization and Seat record in DB, returning (org, seat)."""
    holder = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            org = Organization(
                name=org_name,
                slug=org_name.lower().replace(" ", "-"),
                stripe_customer_id=stripe_cust_id,
            )
            session.add(org)
            await session.commit()
            await session.refresh(org)

            seat = Seat(
                org_id=org.id,
                seat_count=seat_count,
                stripe_subscription_id=stripe_sub_id,
                stripe_customer_id=stripe_cust_id,
            )
            session.add(seat)
            await session.commit()
            await session.refresh(seat)
            holder["org"] = org
            holder["seat"] = seat

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return holder["org"], holder["seat"]


def _make_mock_stripe():
    """Create a mock Stripe client with common methods."""
    mock_client = MagicMock()

    # customers.create returns object with .id
    mock_customer = MagicMock()
    mock_customer.id = "cus_test_123"
    mock_client.customers.create.return_value = mock_customer

    # subscriptions.create returns object with .id and .items
    mock_sub = MagicMock()
    mock_sub.id = "sub_test_456"
    mock_item = MagicMock()
    mock_item.id = "si_test_789"
    mock_sub.items = MagicMock()
    mock_sub.items.data = [mock_item]
    mock_client.subscriptions.create.return_value = mock_sub

    # subscriptions.retrieve returns same structure
    mock_client.subscriptions.retrieve.return_value = mock_sub

    # subscriptions.cancel returns empty
    mock_client.subscriptions.cancel.return_value = MagicMock()

    # subscription_items.update returns success
    mock_client.subscription_items.update.return_value = MagicMock()

    return mock_client


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_ensure_subscription_creates_new(mock_get_stripe):
    """Test 1: ensure_subscription creates Stripe customer + subscription when none exists."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    org, seat = _create_org_and_seat()

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            # Re-load from DB
            from sqlalchemy import select
            org_row = (await session.execute(select(Organization).where(Organization.id == org.id))).scalar_one()
            seat_row = (await session.execute(select(Seat).where(Seat.id == seat.id))).scalar_one()

            from skillledger_service.ee.seat_billing import ensure_subscription
            result = await ensure_subscription(session, seat_row, org_row)

            assert result is True
            assert seat_row.stripe_subscription_id == "sub_test_456"
            assert seat_row.stripe_customer_id == "cus_test_123"
            mock_client.customers.create.assert_called_once()
            mock_client.subscriptions.create.assert_called_once()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_ensure_subscription_returns_existing(mock_get_stripe):
    """Test 2: ensure_subscription returns True when subscription already exists."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    org, seat = _create_org_and_seat(stripe_sub_id="sub_existing", stripe_cust_id="cus_existing")

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            org_row = (await session.execute(select(Organization).where(Organization.id == org.id))).scalar_one()
            seat_row = (await session.execute(select(Seat).where(Seat.id == seat.id))).scalar_one()

            from skillledger_service.ee.seat_billing import ensure_subscription
            result = await ensure_subscription(session, seat_row, org_row)

            assert result is True
            # Should NOT create new customer or subscription
            mock_client.customers.create.assert_not_called()
            mock_client.subscriptions.create.assert_not_called()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_update_seat_count_success(mock_get_stripe):
    """Test 3+4: update_seat_count calls subscription_items.update with proration, returns True, clears out_of_sync."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    org, seat = _create_org_and_seat(seat_count=3, stripe_sub_id="sub_existing", stripe_cust_id="cus_existing")

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            seat_row = (await session.execute(select(Seat).where(Seat.id == seat.id))).scalar_one()
            seat_row.out_of_sync = True

            from skillledger_service.ee.seat_billing import update_seat_count
            result = await update_seat_count(session, seat_row, 5)

            assert result is True
            assert seat_row.seat_count == 5
            assert seat_row.out_of_sync is False
            mock_client.subscription_items.update.assert_called_once()
            call_args = mock_client.subscription_items.update.call_args
            assert call_args[1]["params"]["proration_behavior"] == "create_prorations"

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_update_seat_count_stripe_failure(mock_get_stripe):
    """Test 5: update_seat_count returns False on Stripe exception, sets out_of_sync=True."""
    mock_client = _make_mock_stripe()
    mock_client.subscription_items.update.side_effect = Exception("Stripe error")
    mock_get_stripe.return_value = mock_client

    org, seat = _create_org_and_seat(seat_count=3, stripe_sub_id="sub_existing", stripe_cust_id="cus_existing")

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            seat_row = (await session.execute(select(Seat).where(Seat.id == seat.id))).scalar_one()

            from skillledger_service.ee.seat_billing import update_seat_count
            result = await update_seat_count(session, seat_row, 5)

            assert result is False
            assert seat_row.out_of_sync is True
            assert seat_row.seat_count == 5  # Count still updated locally

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_get_or_create_seat_creates_new(mock_get_stripe):
    """Test 6: get_or_create_seat creates a Seat record if none exists for org_id."""

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            org = Organization(
                name="New Org",
                slug="new-org",
            )
            session.add(org)
            await session.commit()
            await session.refresh(org)

            from skillledger_service.ee.seat_billing import get_or_create_seat
            seat = await get_or_create_seat(session, org)

            assert seat is not None
            assert seat.org_id == org.id
            assert seat.seat_count == 0

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_update_seat_count_zero_cancels_subscription(mock_get_stripe):
    """Test 7: When seat_count reaches 0, subscription is canceled."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    org, seat = _create_org_and_seat(seat_count=3, stripe_sub_id="sub_existing", stripe_cust_id="cus_existing")

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            from sqlalchemy import select
            seat_row = (await session.execute(select(Seat).where(Seat.id == seat.id))).scalar_one()

            from skillledger_service.ee.seat_billing import update_seat_count
            result = await update_seat_count(session, seat_row, 0)

            assert result is True
            assert seat_row.seat_count == 0
            mock_client.subscriptions.cancel.assert_called_once_with("sub_existing")

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()
