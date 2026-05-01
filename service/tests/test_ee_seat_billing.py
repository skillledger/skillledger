"""Tests for per-seat billing service module (ORG-10)."""

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
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.organization import (  # noqa: E402
    OrgInvite,
    OrgMembership,
    OrgRole,
    Organization,
    Seat,
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


def _get_seat_for_org(org_id: int) -> dict | None:
    """Read seat record for the org from DB."""
    holder: dict = {"seat": None}

    async def _read():
        from sqlalchemy import select
        factory = get_async_session_factory()
        async with factory() as session:
            seat = (await session.execute(
                select(Seat).where(Seat.org_id == org_id)
            )).scalar_one_or_none()
            if seat:
                holder["seat"] = {
                    "seat_count": seat.seat_count,
                    "out_of_sync": seat.out_of_sync,
                    "stripe_subscription_id": seat.stripe_subscription_id,
                }

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_read())
    loop.close()
    return holder["seat"]


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


# ---------------------------------------------------------------------------
# Task 1: Endpoint integration tests for seat tracking on invite/remove
# ---------------------------------------------------------------------------


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_accept_invite_increments_seat(mock_get_stripe):
    """Accept invite calls update_seat_count with new member count (D-04)."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    app = _make_licensed_app()
    with TestClient(app) as client:
        owner = _create_user("owner-seat@example.com")
        invitee = _create_user("invitee-seat@example.com")

        # Create org (owner becomes first member)
        resp = client.post("/ee/v1/orgs", json={"name": "Seat Org"}, headers=owner["headers"])
        assert resp.status_code == 200
        org_data = resp.json()

        # Create invite directly in DB
        _create_invite_direct(
            org_data["id"], invitee["email"], OrgRole.member,
            "seat-invite-token", owner["id"]
        )

        # Accept invite
        resp = client.post("/ee/v1/invites/seat-invite-token/accept", headers=invitee["headers"])
        assert resp.status_code == 200

        # Verify seat was created/updated with member count (should be 2: owner + invitee)
        seat = _get_seat_for_org(org_data["id"])
        assert seat is not None
        assert seat["seat_count"] == 2


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_remove_member_decrements_seat(mock_get_stripe):
    """Remove member calls update_seat_count with decremented count (D-04)."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    app = _make_licensed_app()
    with TestClient(app) as client:
        owner = _create_user("owner-rem@example.com")
        member = _create_user("member-rem@example.com")

        # Create org
        resp = client.post("/ee/v1/orgs", json={"name": "Remove Org"}, headers=owner["headers"])
        assert resp.status_code == 200
        org_data = resp.json()

        # Add member directly
        _add_membership(org_data["id"], member["id"], OrgRole.member)

        # Remove member
        resp = client.delete(
            f"/ee/v1/orgs/{org_data['slug']}/members/{member['id']}",
            headers=owner["headers"],
        )
        assert resp.status_code == 204

        # Verify seat count is now 1 (just owner left)
        seat = _get_seat_for_org(org_data["id"])
        assert seat is not None
        assert seat["seat_count"] == 1


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_stripe_failure_doesnt_block_invite_accept(mock_get_stripe):
    """Stripe failure during invite accept does NOT prevent membership creation (D-07)."""
    mock_client = _make_mock_stripe()
    # Make Stripe calls fail
    mock_client.subscription_items.update.side_effect = Exception("Stripe down")
    mock_client.subscriptions.retrieve.side_effect = Exception("Stripe down")
    mock_get_stripe.return_value = mock_client

    app = _make_licensed_app()
    with TestClient(app) as client:
        owner = _create_user("owner-fail@example.com")
        invitee = _create_user("invitee-fail@example.com")

        # Create org
        resp = client.post("/ee/v1/orgs", json={"name": "Fail Org"}, headers=owner["headers"])
        assert resp.status_code == 200
        org_data = resp.json()

        # Create invite
        _create_invite_direct(
            org_data["id"], invitee["email"], OrgRole.member,
            "fail-invite-token", owner["id"]
        )

        # Accept invite -- should still succeed despite Stripe failure
        resp = client.post("/ee/v1/invites/fail-invite-token/accept", headers=invitee["headers"])
        assert resp.status_code == 200
        assert resp.json()["user_id"] == invitee["id"]


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_stripe_failure_doesnt_block_member_remove(mock_get_stripe):
    """Stripe failure during member remove does NOT prevent membership deletion (D-07)."""
    mock_client = _make_mock_stripe()
    mock_client.subscription_items.update.side_effect = Exception("Stripe down")
    mock_client.subscriptions.retrieve.side_effect = Exception("Stripe down")
    mock_get_stripe.return_value = mock_client

    app = _make_licensed_app()
    with TestClient(app) as client:
        owner = _create_user("owner-fail2@example.com")
        member = _create_user("member-fail2@example.com")

        # Create org and add member
        resp = client.post("/ee/v1/orgs", json={"name": "Fail2 Org"}, headers=owner["headers"])
        assert resp.status_code == 200
        org_data = resp.json()
        _add_membership(org_data["id"], member["id"], OrgRole.member)

        # Remove member -- should still succeed despite Stripe failure
        resp = client.delete(
            f"/ee/v1/orgs/{org_data['slug']}/members/{member['id']}",
            headers=owner["headers"],
        )
        assert resp.status_code == 204


@patch("skillledger_service.ee.seat_billing.get_stripe_client")
def test_first_invite_creates_seat_record(mock_get_stripe):
    """First invite accept triggers get_or_create_seat (D-03, Pitfall 3)."""
    mock_client = _make_mock_stripe()
    mock_get_stripe.return_value = mock_client

    app = _make_licensed_app()
    with TestClient(app) as client:
        owner = _create_user("owner-first@example.com")
        invitee = _create_user("invitee-first@example.com")

        # Create org
        resp = client.post("/ee/v1/orgs", json={"name": "First Org"}, headers=owner["headers"])
        assert resp.status_code == 200
        org_data = resp.json()

        # Verify no seat record exists yet
        seat_before = _get_seat_for_org(org_data["id"])
        assert seat_before is None

        # Create and accept invite
        _create_invite_direct(
            org_data["id"], invitee["email"], OrgRole.member,
            "first-invite-token", owner["id"]
        )
        resp = client.post("/ee/v1/invites/first-invite-token/accept", headers=invitee["headers"])
        assert resp.status_code == 200

        # Seat record should now exist
        seat_after = _get_seat_for_org(org_data["id"])
        assert seat_after is not None
        assert seat_after["seat_count"] == 2
