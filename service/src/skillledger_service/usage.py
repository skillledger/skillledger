"""Free-tier usage enforcement for the hosted transparency log.

Provides:
- get_usage_count: Query current month's usage for a user+operation
- increment_usage: Dialect-agnostic counter increment (works on SQLite + PostgreSQL)
- check_tlog_limit: FastAPI dependency that enforces 50 publishes/month for User identities
"""

import calendar
from datetime import datetime, timezone
from typing import Union

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.models.publisher import Publisher
from skillledger_service.models.usage import UsageRecord
from skillledger_service.models.user import User
from skillledger_service.user_auth import get_current_identity

FREE_TIER_PUBLISH_LIMIT = 50


async def get_usage_count(
    session: AsyncSession, user_id: int, operation: str, month: str
) -> int:
    """Return the current usage count for a user+operation+month, or 0 if no record."""
    stmt = select(UsageRecord.count).where(
        UsageRecord.user_id == user_id,
        UsageRecord.operation == operation,
        UsageRecord.month == month,
    )
    result = await session.execute(stmt)
    count = result.scalar_one_or_none()
    return count if count is not None else 0


async def increment_usage(
    session: AsyncSession, user_id: int, operation: str, month: str
) -> int:
    """Increment usage count by 1, creating a new record if needed.

    Uses SELECT + INSERT/UPDATE (dialect-agnostic, works on SQLite in tests).
    Caller is responsible for session.commit().
    Returns the new count value.
    """
    now = datetime.now(timezone.utc)
    stmt = select(UsageRecord).where(
        UsageRecord.user_id == user_id,
        UsageRecord.operation == operation,
        UsageRecord.month == month,
    )
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        record = UsageRecord(
            user_id=user_id,
            operation=operation,
            month=month,
            count=1,
            created_at=now,
            updated_at=now,
        )
        session.add(record)
    else:
        record.count += 1
        record.updated_at = now

    await session.flush()
    return record.count


def _next_month_reset(now: datetime) -> datetime:
    """Return the first instant of the next calendar month in UTC."""
    _, last_day = calendar.monthrange(now.year, now.month)
    if now.month == 12:
        return datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)


async def check_tlog_limit(
    identity: Union[User, Publisher] = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
) -> Union[User, Publisher]:
    """FastAPI dependency: enforce free-tier publish limit for User identities.

    Publishers (legacy API key auth) are exempt and pass through immediately.
    Users exceeding 50 publishes/month receive HTTP 429 with structured detail.
    """
    # Publishers are exempt (D-06)
    if isinstance(identity, Publisher):
        return identity

    now = datetime.now(timezone.utc)
    month = now.strftime("%Y-%m")
    count = await get_usage_count(session, identity.id, "tlog_publish", month)

    if count >= FREE_TIER_PUBLISH_LIMIT:
        resets_at = _next_month_reset(now)
        seconds_until_reset = max(1, int((resets_at - now).total_seconds()))
        raise HTTPException(
            status_code=429,
            detail={
                "message": (
                    f"Free tier limit reached ({count}/{FREE_TIER_PUBLISH_LIMIT} "
                    f"publishes this month). Upgrade to continue: "
                    f"https://skillledger.dev/pricing"
                ),
                "limit": FREE_TIER_PUBLISH_LIMIT,
                "used": count,
                "resets_at": resets_at.isoformat(),
            },
            headers={"Retry-After": str(seconds_until_reset)},
        )

    return identity
