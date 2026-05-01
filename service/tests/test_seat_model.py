"""Tests for Seat model, migration 007, and config additions."""

import asyncio
import os

import pytest

os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-seat")
os.environ.setdefault("SKILLLEDGER_RESEND_API_KEY", "re_test_fake")

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
)
from skillledger_service.models import Base, Seat  # noqa: E402
from skillledger_service.models.organization import Organization, Seat as SeatDirect  # noqa: E402
from skillledger_service.config import Settings  # noqa: E402


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


def test_seat_model_instantiation():
    """Test 1: Seat model can be instantiated with expected fields."""
    seat = SeatDirect(
        org_id=1,
        stripe_subscription_id="sub_123",
        stripe_customer_id="cus_456",
        seat_count=5,
        out_of_sync=False,
    )
    assert seat.org_id == 1
    assert seat.stripe_subscription_id == "sub_123"
    assert seat.stripe_customer_id == "cus_456"
    assert seat.seat_count == 5
    assert seat.out_of_sync is False


def test_seat_model_unique_org_id():
    """Test 2: Seat model has unique constraint on org_id."""

    async def _test():
        factory = get_async_session_factory()
        async with factory() as session:
            org = Organization(name="Test Org", slug="test-org")
            session.add(org)
            await session.commit()
            await session.refresh(org)

            seat1 = SeatDirect(org_id=org.id, seat_count=1)
            session.add(seat1)
            await session.commit()

            seat2 = SeatDirect(org_id=org.id, seat_count=2)
            session.add(seat2)
            with pytest.raises(Exception):
                await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_test())
    loop.close()


def test_settings_stripe_seat_price_id():
    """Test 3: Settings.stripe_seat_price_id is accessible and defaults to empty string."""
    old_val = os.environ.pop("SKILLLEDGER_STRIPE_SEAT_PRICE_ID", None)
    try:
        s = Settings()
        assert hasattr(s, "stripe_seat_price_id")
        assert s.stripe_seat_price_id == ""
    finally:
        if old_val is not None:
            os.environ["SKILLLEDGER_STRIPE_SEAT_PRICE_ID"] = old_val


def test_seat_importable_from_models():
    """Test 4: Seat is importable from skillledger_service.models."""
    assert Seat is not None
    assert Seat.__tablename__ == "seats"
