import logging
from datetime import datetime, timezone
from typing import Union

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.artifact import LogEntryRecord
from skillledger_service.models.publisher import Publisher
from skillledger_service.models.usage import Subscription
from skillledger_service.models.user import User
from skillledger_service.stripe_client import get_stripe_client
from skillledger_service.usage import (
    FREE_TIER_PUBLISH_LIMIT,
    _next_month_reset,
    check_tlog_limit,
    increment_usage,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/log", tags=["transparency-log"])


class ArtifactEntry(BaseModel):
    artifact_id: str = Field(..., min_length=1)
    sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    content_address: str = Field(..., min_length=1)
    # publisher is derived from authentication, not request body


class PublishResponse(BaseModel):
    log_index: int
    artifact_id: str


class LookupResponse(BaseModel):
    artifact_id: str
    sha256: str
    content_address: str
    log_index: int
    publisher: str
    published_at: str


@router.post("/publish", response_model=PublishResponse)
async def publish_entry(
    entry: ArtifactEntry,
    response: Response,
    identity: Union[User, Publisher] = Depends(check_tlog_limit),
    session: AsyncSession = Depends(get_session),
) -> PublishResponse:
    published_at = datetime.now(timezone.utc)
    # Derive publisher name from identity type
    publisher_name = identity.name if isinstance(identity, Publisher) else identity.email

    payload = {
        "artifact_id": entry.artifact_id,
        "sha256": entry.sha256,
        "content_address": entry.content_address,
        "publisher": publisher_name,
        "published_at": published_at.isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{get_settings().log_url}/add", json=payload)
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Log service unavailable")
    except httpx.TimeoutException:
        raise HTTPException(status_code=502, detail="Log service unavailable")

    if resp.status_code == 503:
        raise HTTPException(
            status_code=503, detail="Log service is busy, retry later"
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Log service returned unexpected status {resp.status_code}",
        )

    try:
        log_index = int(resp.text.strip())
    except ValueError:
        raise HTTPException(
            status_code=502, detail="Log service returned invalid index"
        )

    record = LogEntryRecord(
        artifact_id=entry.artifact_id,
        sha256=entry.sha256,
        content_address=entry.content_address,
        log_index=log_index,
        publisher=publisher_name,
        published_at=published_at,
    )
    session.add(record)
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        # Critical: log entry exists in Merkle tree but DB record failed.
        # This inconsistency requires manual reconciliation.
        logger.exception(
            "DB commit failed after log entry added",
            extra={"artifact_id": entry.artifact_id, "log_index": log_index},
        )
        raise HTTPException(
            status_code=500,
            detail="Entry added to log but metadata save failed. Contact admin.",
        )

    # Increment usage AFTER successful publish (D-10: failed publishes not counted)
    if isinstance(identity, User):
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        new_count = await increment_usage(session, identity.id, "tlog_publish", month)
        await session.commit()

        # Check subscription status for rate limit headers and meter events
        sub_stmt = select(Subscription).where(
            Subscription.user_id == identity.id,
            Subscription.status == "active",
        )
        sub_result = await session.execute(sub_stmt)
        subscription = sub_result.scalar_one_or_none()

        if subscription and subscription.status == "active":
            # Paid user: no rate limit headers (Pitfall 5)
            # Send Stripe meter event (D-10, fire-and-forget)
            if subscription.stripe_customer_id:
                try:
                    stripe_client = get_stripe_client()
                    settings = get_settings()
                    stripe_client.billing.meter_events.create(
                        params={
                            "event_name": settings.stripe_meter_event_name,
                            "payload": {
                                "stripe_customer_id": subscription.stripe_customer_id,
                                "value": "1",
                            },
                        }
                    )
                except Exception:
                    logger.warning(
                        "Failed to send Stripe meter event",
                        extra={"user_id": identity.id},
                        exc_info=True,
                    )
        else:
            # Free user: include rate limit headers
            resets_at = _next_month_reset(datetime.now(timezone.utc))
            response.headers["X-RateLimit-Limit"] = str(FREE_TIER_PUBLISH_LIMIT)
            response.headers["X-RateLimit-Remaining"] = str(
                max(0, FREE_TIER_PUBLISH_LIMIT - new_count)
            )
            response.headers["X-RateLimit-Reset"] = resets_at.isoformat()

    return PublishResponse(log_index=log_index, artifact_id=entry.artifact_id)


@router.get("/lookup/{artifact_id}", response_model=LookupResponse)
async def lookup_entry(
    artifact_id: str,
    session: AsyncSession = Depends(get_session),
) -> LookupResponse:
    stmt = (
        select(LogEntryRecord)
        .where(LogEntryRecord.artifact_id == artifact_id)
        .order_by(LogEntryRecord.log_index.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        raise HTTPException(status_code=404, detail="Artifact not found in log")

    return LookupResponse(
        artifact_id=record.artifact_id,
        sha256=record.sha256,
        content_address=record.content_address,
        log_index=record.log_index,
        publisher=record.publisher,
        published_at=record.published_at.isoformat(),
    )
