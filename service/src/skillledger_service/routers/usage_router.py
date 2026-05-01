"""Usage information endpoint for authenticated users."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.models.usage import Subscription
from skillledger_service.models.user import User
from skillledger_service.usage import (
    FREE_TIER_PUBLISH_LIMIT,
    _next_month_reset,
    get_usage_count,
)
from skillledger_service.user_auth import get_current_user

router = APIRouter(prefix="/v1", tags=["usage"])


class UsageResponse(BaseModel):
    operation: str
    used: int
    limit: Optional[int] = None
    resets_at: str
    billing_status: str


@router.get("/usage", response_model=UsageResponse)
async def get_usage(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> UsageResponse:
    """Return the authenticated user's current tlog_publish usage for this month."""
    now = datetime.now(timezone.utc)
    month = now.strftime("%Y-%m")
    used = await get_usage_count(session, user.id, "tlog_publish", month)
    resets_at = _next_month_reset(now)

    # Determine billing status from subscription
    sub_stmt = select(Subscription).where(Subscription.user_id == user.id)
    sub_result = await session.execute(sub_stmt)
    subscription = sub_result.scalar_one_or_none()

    if subscription and subscription.status == "active":
        billing_status = "active"
        limit = None  # unlimited
    elif subscription and subscription.status in ("past_due", "canceled"):
        billing_status = subscription.status
        limit = FREE_TIER_PUBLISH_LIMIT
    else:
        billing_status = "free"
        limit = FREE_TIER_PUBLISH_LIMIT

    return UsageResponse(
        operation="tlog_publish",
        used=used,
        limit=limit,
        resets_at=resets_at.isoformat(),
        billing_status=billing_status,
    )
