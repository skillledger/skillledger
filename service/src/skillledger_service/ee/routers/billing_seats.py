"""Enterprise billing endpoint for per-seat subscription management.

Provides GET billing info and POST subscribe endpoints for org-level
seat billing. All endpoints are gated behind org membership via
require_org_role.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.ee.routers.orgs import require_org_role
from skillledger_service.ee.seat_billing import (
    ensure_subscription,
    get_or_create_seat,
)
from skillledger_service.models.organization import (
    OrgMembership,
    OrgRole,
    Organization,
    Seat,
)
from skillledger_service.models.user import User
from skillledger_service.stripe_client import get_stripe_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ee/v1", tags=["enterprise-billing"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class BillingInfoResponse(BaseModel):
    seat_count: int
    subscription_status: Optional[str]
    out_of_sync: bool
    portal_url: Optional[str]


class SubscribeResponse(BaseModel):
    subscription_id: Optional[str]
    seat_count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/orgs/{slug}/billing")
async def get_billing_info(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.viewer)
    ),
    session: AsyncSession = Depends(get_session),
) -> BillingInfoResponse:
    """Get billing info for an organization (any member).

    Returns seat count, subscription status, out_of_sync flag, and
    a Stripe portal URL for managing billing (T-26-05, T-26-06).
    """
    org, _, _ = ctx

    # Look up seat record
    stmt = select(Seat).where(Seat.org_id == org.id)
    result = await session.execute(stmt)
    seat = result.scalar_one_or_none()

    if seat is None:
        return BillingInfoResponse(
            seat_count=0,
            subscription_status=None,
            out_of_sync=False,
            portal_url=None,
        )

    # Get subscription status from Stripe if subscription exists
    subscription_status: Optional[str] = None
    portal_url: Optional[str] = None

    if seat.stripe_subscription_id:
        try:
            client = get_stripe_client()
            stripe_sub = client.subscriptions.retrieve(seat.stripe_subscription_id)
            subscription_status = stripe_sub.status
        except Exception:
            logger.warning(
                "Failed to retrieve Stripe subscription %s",
                seat.stripe_subscription_id,
                exc_info=True,
            )

    if seat.stripe_customer_id:
        try:
            client = get_stripe_client()
            portal_session = client.billing_portal.sessions.create(
                params={
                    "customer": seat.stripe_customer_id,
                    "return_url": "https://skillledger.dev",
                }
            )
            portal_url = portal_session.url
        except Exception:
            logger.warning(
                "Failed to create portal session for customer %s",
                seat.stripe_customer_id,
                exc_info=True,
            )

    return BillingInfoResponse(
        seat_count=seat.seat_count,
        subscription_status=subscription_status,
        out_of_sync=seat.out_of_sync,
        portal_url=portal_url,
    )


@router.post("/orgs/{slug}/billing/subscribe")
async def subscribe(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> SubscribeResponse:
    """Explicitly create a Stripe subscription for org seats (admin+).

    Counts current memberships and creates/updates seat record with
    Stripe subscription (D-03 discretion: explicit subscribe).
    """
    org, _, _ = ctx

    # Count current members
    count_result = await session.execute(
        select(func.count())
        .select_from(OrgMembership)
        .where(OrgMembership.org_id == org.id)
    )
    member_count = count_result.scalar_one()

    seat = await get_or_create_seat(session, org)
    await ensure_subscription(session, seat, org)
    seat.seat_count = member_count
    await session.commit()

    return SubscribeResponse(
        subscription_id=seat.stripe_subscription_id,
        seat_count=seat.seat_count,
    )
