"""Usage information endpoint for authenticated users."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
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
    limit: int
    resets_at: str


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

    return UsageResponse(
        operation="tlog_publish",
        used=used,
        limit=FREE_TIER_PUBLISH_LIMIT,
        resets_at=resets_at.isoformat(),
    )
