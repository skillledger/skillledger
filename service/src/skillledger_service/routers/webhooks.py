"""Stripe webhook handler with signature verification and idempotency."""

import datetime
import logging

import stripe
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_async_session_factory, get_settings
from skillledger_service.models.usage import StripeEvent, Subscription

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/v1/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events.

    No auth dependency -- Stripe authenticates via signature (T-23-01).
    Uses raw body bytes for signature verification (T-23-02).
    Records every event for audit trail (T-23-03).
    Idempotency via stripe_events table (T-23-05).
    """
    settings = get_settings()
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # Verify signature (T-23-01, T-23-02)
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except stripe.SignatureVerificationError:
        return JSONResponse(status_code=400, content={"detail": "Invalid signature"})

    event_id = event["id"]
    event_type = event["type"]

    factory = get_async_session_factory()
    async with factory() as session:
        # Idempotency check (T-23-05)
        stmt = select(StripeEvent).where(StripeEvent.stripe_event_id == event_id).with_for_update()
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            return {"status": "ok"}

        # Record event for audit (T-23-03)
        now = datetime.datetime.now(datetime.timezone.utc)
        stripe_event = StripeEvent(
            stripe_event_id=event_id,
            event_type=event_type,
            processed_at=now,
            payload=event.get("data", {}).get("object", {}),
        )
        session.add(stripe_event)

        # Route by event type
        await _handle_event(session, event_type, event, now)

        await session.commit()

    return {"status": "ok"}


async def _handle_event(
    session: AsyncSession,
    event_type: str,
    event: dict,
    now: datetime.datetime,
) -> None:
    """Route event to the appropriate handler."""
    data_object = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(session, data_object, now)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(session, data_object, now)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(session, data_object, now)
    else:
        logger.info("Unhandled Stripe event type: %s", event_type)


async def _handle_checkout_completed(
    session: AsyncSession, data: dict, now: datetime.datetime
) -> None:
    """Upsert subscription on checkout completion."""
    stripe_customer_id = data.get("customer")
    stripe_subscription_id = data.get("subscription")

    if not stripe_customer_id:
        logger.warning("checkout.session.completed missing customer ID")
        return

    stmt = select(Subscription).where(
        Subscription.stripe_customer_id == stripe_customer_id
    )
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is not None:
        sub.stripe_subscription_id = stripe_subscription_id
        sub.plan = "pay_as_you_go"
        sub.status = "active"
        sub.updated_at = now
        if data.get("current_period_start"):
            sub.current_period_start = datetime.datetime.fromtimestamp(
                data["current_period_start"], tz=datetime.timezone.utc
            )
        if data.get("current_period_end"):
            sub.current_period_end = datetime.datetime.fromtimestamp(
                data["current_period_end"], tz=datetime.timezone.utc
            )
    else:
        logger.warning(
            f"No subscription found for customer {stripe_customer_id} "
            "during checkout.session.completed"
        )


async def _handle_subscription_updated(
    session: AsyncSession, data: dict, now: datetime.datetime
) -> None:
    """Update subscription status on change, including seat reconciliation."""
    sub_id = data.get("id")
    if not sub_id:
        return

    # Individual subscription update
    stmt = select(Subscription).where(
        Subscription.stripe_subscription_id == sub_id
    )
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is not None:
        sub.status = data.get("status", sub.status)
        sub.updated_at = now
        if data.get("current_period_start"):
            sub.current_period_start = datetime.datetime.fromtimestamp(
                data["current_period_start"], tz=datetime.timezone.utc
            )
        if data.get("current_period_end"):
            sub.current_period_end = datetime.datetime.fromtimestamp(
                data["current_period_end"], tz=datetime.timezone.utc
            )

    # Seat subscription reconciliation
    from skillledger_service.models.organization import Seat

    seat_stmt = select(Seat).where(Seat.stripe_subscription_id == sub_id)
    seat_result = await session.execute(seat_stmt)
    seat = seat_result.scalar_one_or_none()

    if seat is not None:
        # Extract quantity from subscription items
        items_data = data.get("items", {})
        if isinstance(items_data, dict):
            items_list = items_data.get("data", [])
        else:
            items_list = []

        if items_list:
            stripe_quantity = items_list[0].get("quantity", seat.seat_count)
        else:
            stripe_quantity = seat.seat_count

        try:
            from skillledger_service.ee.seat_billing import reconcile_seat_from_webhook
            await reconcile_seat_from_webhook(session, sub_id, stripe_quantity)
        except ImportError:
            logger.warning("EE seat_billing not available, skipping seat reconciliation")


async def _handle_subscription_deleted(
    session: AsyncSession, data: dict, now: datetime.datetime
) -> None:
    """Cancel subscription on deletion."""
    sub_id = data.get("id")
    if not sub_id:
        return

    stmt = select(Subscription).where(
        Subscription.stripe_subscription_id == sub_id
    )
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is not None:
        sub.status = "canceled"
        sub.updated_at = now
