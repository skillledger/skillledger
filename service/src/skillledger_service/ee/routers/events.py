"""Enterprise event ingestion: batch violation events from team CLIs.

CLIs POST violation events (policy failures, IOC detections) which are
stored per-org for dashboard aggregation.  Batch limit of 100 events
per request enforced server-side (T-25-04).
"""

import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.ee.routers.orgs import require_org_role
from skillledger_service.models.org_event import OrgEvent
from skillledger_service.models.organization import (
    ROLE_HIERARCHY,
    Organization,
    OrgMembership,
    OrgRole,
)
from skillledger_service.models.user import User
from skillledger_service.user_auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ee/v1", tags=["enterprise"])

BATCH_LIMIT = 100


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class EventItem(BaseModel):
    type: str
    ecosystem: str
    skill_id: str
    rule: str
    severity: str
    details: dict = {}
    timestamp: datetime.datetime


class EventBatchRequest(BaseModel):
    org_slug: str
    events: list[EventItem]


class EventResponse(BaseModel):
    id: int
    event_type: str
    ecosystem: str
    skill_id: str
    rule: str
    severity: str
    details: Optional[dict] = None
    event_timestamp: datetime.datetime
    created_at: datetime.datetime


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/events", status_code=201)
async def ingest_events(
    body: EventBatchRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Ingest a batch of violation events (member+, max 100 per request)."""

    # Enforce batch limit (T-25-04)
    if len(body.events) > BATCH_LIMIT:
        raise HTTPException(
            400,
            f"Batch limit exceeded: maximum {BATCH_LIMIT} events per request",
        )

    # Resolve org and check membership (T-25-05: no enumeration)
    org = (
        await session.execute(
            select(Organization).where(Organization.slug == body.org_slug)
        )
    ).scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    membership = (
        await session.execute(
            select(OrgMembership).where(
                OrgMembership.org_id == org.id,
                OrgMembership.user_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if not membership:
        raise HTTPException(403, "Not a member of this organization")
    if ROLE_HIERARCHY[membership.role] < ROLE_HIERARCHY[OrgRole.member]:
        raise HTTPException(403, "Insufficient permissions")

    now = datetime.datetime.now(datetime.timezone.utc)
    for ev in body.events:
        event = OrgEvent(
            org_id=org.id,
            user_id=user.id,
            event_type=ev.type,
            ecosystem=ev.ecosystem,
            skill_id=ev.skill_id,
            rule=ev.rule,
            severity=ev.severity,
            details=ev.details or None,
            event_timestamp=ev.timestamp,
            created_at=now,
        )
        session.add(event)

    await session.commit()

    return {"accepted": len(body.events)}


@router.get("/orgs/{slug}/events")
async def list_events(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    since: Optional[datetime.datetime] = Query(None),
    until: Optional[datetime.datetime] = Query(None),
) -> list[EventResponse]:
    """List events for an organization with filtering and pagination (admin+)."""
    org, _, _ = ctx

    stmt = select(OrgEvent).where(OrgEvent.org_id == org.id)
    if event_type:
        stmt = stmt.where(OrgEvent.event_type == event_type)
    if since:
        stmt = stmt.where(OrgEvent.created_at >= since)
    if until:
        stmt = stmt.where(OrgEvent.created_at <= until)

    stmt = stmt.order_by(OrgEvent.created_at.desc()).offset(offset).limit(limit)

    result = await session.execute(stmt)
    events = result.scalars().all()

    return [
        EventResponse(
            id=ev.id,
            event_type=ev.event_type,
            ecosystem=ev.ecosystem,
            skill_id=ev.skill_id,
            rule=ev.rule,
            severity=ev.severity,
            details=ev.details,
            event_timestamp=ev.event_timestamp,
            created_at=ev.created_at,
        )
        for ev in events
    ]
