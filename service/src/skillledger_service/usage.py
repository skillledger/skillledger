"""Free-tier usage enforcement for the hosted transparency log.

Provides:
- get_usage_count: Query current month's usage for a user+operation
- increment_usage: Dialect-agnostic counter increment (works on SQLite + PostgreSQL)
- check_tlog_limit: FastAPI dependency that enforces 50 publishes/month for User identities
                    (paid subscribers with active status bypass the limit)
"""

import calendar
import logging
from datetime import datetime, timezone
from typing import Union

from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.publisher import Publisher
from skillledger_service.models.usage import Subscription, UsageRecord
from skillledger_service.models.user import User
from skillledger_service.stripe_client import get_stripe_client
from skillledger_service.user_auth import get_current_identity

logger = logging.getLogger(__name__)

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
    Users with an active subscription bypass the free-tier limit.
    Users exceeding 50 publishes/month receive HTTP 429 with structured detail
    including a Stripe Checkout URL for upgrading.
    """
    # Publishers are exempt (D-06)
    if isinstance(identity, Publisher):
        return identity

    # Check for active subscription -- paid users bypass limit (D-11)
    sub_stmt = select(Subscription).where(
        Subscription.user_id == identity.id,
        Subscription.status == "active",
    )
    sub_result = await session.execute(sub_stmt)
    if sub_result.scalar_one_or_none() is not None:
        return identity  # Paid user, skip limit

    now = datetime.now(timezone.utc)
    month = now.strftime("%Y-%m")
    count = await get_usage_count(session, identity.id, "tlog_publish", month)

    if count >= FREE_TIER_PUBLISH_LIMIT:
        resets_at = _next_month_reset(now)
        seconds_until_reset = max(1, int((resets_at - now).total_seconds()))

        # Generate Stripe Checkout URL (D-03)
        checkout_url = None
        try:
            client = get_stripe_client()
            settings = get_settings()
            checkout_session = client.v1.checkout.sessions.create(
                params={
                    "mode": "subscription",
                    "customer_email": identity.email,
                    "line_items": [{"price": settings.stripe_price_id, "quantity": 1}],
                    "success_url": f"{settings.service_url}/billing/success",
                    "cancel_url": f"{settings.service_url}/billing/cancel",
                }
            )
            checkout_url = checkout_session.url
        except Exception:
            checkout_url = None  # Fallback: no URL if Stripe unavailable

        raise HTTPException(
            status_code=429,
            detail={
                "message": (
                    f"Free tier limit reached ({count}/{FREE_TIER_PUBLISH_LIMIT} "
                    f"publishes this month). Add payment to continue."
                ),
                "checkout_url": checkout_url,
                "upgrade_command": "skillledger billing upgrade",
                "limit": FREE_TIER_PUBLISH_LIMIT,
                "used": count,
                "resets_at": resets_at.isoformat(),
            },
            headers={"Retry-After": str(seconds_until_reset)},
        )

    return identity
