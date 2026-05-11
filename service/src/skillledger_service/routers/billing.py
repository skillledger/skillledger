"""Billing router: Checkout and Portal session endpoints."""

import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.usage import Subscription
from skillledger_service.models.user import User
from skillledger_service.stripe_client import get_stripe_client
from skillledger_service.user_auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])


@router.post("/checkout")
async def create_checkout_session(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Create a Stripe Checkout Session and return the URL.

    Reuses existing stripe_customer_id if one exists for this user.
    Uses SELECT FOR UPDATE to prevent race conditions creating duplicate customers.
    """
    settings = get_settings()
    client = get_stripe_client()

    # SELECT FOR UPDATE to prevent duplicate customer creation (T-23-07)
    stmt = (
        select(Subscription)
        .where(Subscription.user_id == user.id)
        .with_for_update()
    )
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub and sub.stripe_customer_id:
        stripe_customer_id = sub.stripe_customer_id
    else:
        # Create new Stripe customer
        customer = client.customers.create(params={"email": user.email})
        stripe_customer_id = customer.id

        if sub is None:
            sub = Subscription(
                user_id=user.id,
                stripe_customer_id=stripe_customer_id,
                plan="free",
                status="inactive",
            )
            session.add(sub)
        else:
            sub.stripe_customer_id = stripe_customer_id
            sub.updated_at = datetime.datetime.now(datetime.timezone.utc)

        await session.commit()

    checkout_session = client.checkout.sessions.create(
        params={
            "mode": "subscription",
            "customer": stripe_customer_id,
            "line_items": [{"price": settings.stripe_price_id}],
            "success_url": "https://skillledger.in/billing/success",
            "cancel_url": "https://skillledger.in/billing/cancel",
        }
    )

    return {"url": checkout_session.url}


@router.post("/portal")
async def create_portal_session(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Create a Stripe Portal Session for managing billing."""
    client = get_stripe_client()

    stmt = select(Subscription).where(Subscription.user_id == user.id)
    result = await session.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is None or not sub.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account. Run 'skillledger billing upgrade' first.",
        )

    portal_session = client.billing_portal.sessions.create(
        params={
            "customer": sub.stripe_customer_id,
            "return_url": "https://skillledger.in",
        }
    )

    return {"url": portal_session.url}
