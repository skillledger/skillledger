"""Per-seat billing service module for enterprise organizations.

Provides functions for managing Stripe subscriptions tied to org seat counts.
Uses fire-and-forget pattern: Stripe failures are logged and flagged (out_of_sync)
but never raised to callers.
"""

import datetime
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_settings
from skillledger_service.models.organization import Organization, Seat
from skillledger_service.stripe_client import get_stripe_client

logger = logging.getLogger(__name__)


async def get_or_create_seat(session: AsyncSession, org: Organization) -> Seat:
    """Get or create a Seat record for the given organization.

    Uses SELECT FOR UPDATE to prevent race conditions on concurrent
    member add/remove (T-26-01).
    """
    stmt = (
        select(Seat)
        .where(Seat.org_id == org.id)
        .with_for_update()
    )
    result = await session.execute(stmt)
    seat = result.scalar_one_or_none()

    if seat is None:
        seat = Seat(
            org_id=org.id,
            seat_count=0,
        )
        session.add(seat)
        await session.flush()

    return seat


async def ensure_subscription(
    session: AsyncSession, seat: Seat, org: Organization
) -> bool:
    """Ensure a Stripe subscription exists for the seat.

    If seat already has a stripe_subscription_id, returns True immediately.
    Otherwise creates a Stripe customer (if needed) and subscription.

    Returns True on success, False on failure (fire-and-forget per D-07).
    """
    if seat.stripe_subscription_id is not None:
        return True

    try:
        settings = get_settings()
        client = get_stripe_client()

        # Create Stripe customer if org doesn't have one
        if org.stripe_customer_id:
            customer_id = org.stripe_customer_id
        else:
            customer = client.customers.create(
                params={
                    "email": org.name,
                    "metadata": {"org_id": str(org.id)},
                }
            )
            customer_id = customer.id
            org.stripe_customer_id = customer_id

        seat.stripe_customer_id = customer_id

        # Create Stripe subscription
        subscription = client.subscriptions.create(
            params={
                "customer": customer_id,
                "items": [
                    {
                        "price": settings.stripe_seat_price_id,
                        "quantity": seat.seat_count,
                    }
                ],
                "payment_behavior": "default_incomplete",
                "expand": ["latest_invoice.payment_intent"],
            }
        )
        seat.stripe_subscription_id = subscription.id
        seat.updated_at = datetime.datetime.now(datetime.timezone.utc)

        return True

    except Exception:
        logger.warning(
            "Failed to create Stripe subscription for org %s",
            org.id,
            exc_info=True,
        )
        seat.out_of_sync = True
        return False


async def update_seat_count(
    session: AsyncSession, seat: Seat, new_count: int
) -> bool:
    """Update the seat count and sync with Stripe.

    Clamps new_count to max(0, new_count). If count reaches 0, cancels
    the subscription. Uses proration for changes (D-06).

    Returns True on success, False on Stripe failure (fire-and-forget per D-07).
    """
    new_count = max(0, new_count)
    seat.seat_count = new_count
    seat.updated_at = datetime.datetime.now(datetime.timezone.utc)

    try:
        client = get_stripe_client()

        # Cancel subscription if zero seats
        if new_count == 0 and seat.stripe_subscription_id:
            client.subscriptions.cancel(seat.stripe_subscription_id)
            seat.stripe_subscription_id = None
            seat.out_of_sync = False
            return True

        # Ensure subscription exists before updating
        if seat.stripe_subscription_id is None:
            from skillledger_service.models.organization import Organization as OrgModel

            stmt = select(OrgModel).where(OrgModel.id == seat.org_id)
            result = await session.execute(stmt)
            org = result.scalar_one_or_none()
            if org is None:
                seat.out_of_sync = True
                return False
            created = await ensure_subscription(session, seat, org)
            if not created:
                return False

        # Retrieve subscription to get item ID
        subscription = client.subscriptions.retrieve(seat.stripe_subscription_id)
        item_id = subscription.items.data[0].id

        # Update quantity with proration
        client.subscription_items.update(
            item_id,
            params={
                "quantity": new_count,
                "proration_behavior": "create_prorations",
            },
        )

        seat.out_of_sync = False
        return True

    except Exception:
        logger.warning(
            "Failed to update Stripe seat count for seat %s",
            seat.id,
            exc_info=True,
        )
        seat.out_of_sync = True
        return False


async def reconcile_seat_from_webhook(
    session: AsyncSession, stripe_subscription_id: str, stripe_quantity: int
) -> None:
    """Reconcile seat count from a Stripe webhook event.

    Looks up the Seat by stripe_subscription_id and updates the local
    seat_count to match Stripe's quantity, clearing the out_of_sync flag.
    """
    stmt = select(Seat).where(
        Seat.stripe_subscription_id == stripe_subscription_id
    )
    result = await session.execute(stmt)
    seat = result.scalar_one_or_none()

    if seat is not None:
        seat.seat_count = stripe_quantity
        seat.out_of_sync = False
        seat.updated_at = datetime.datetime.now(datetime.timezone.utc)
