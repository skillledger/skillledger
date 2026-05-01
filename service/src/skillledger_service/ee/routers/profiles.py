"""Enterprise auto-profile ingestion: skill capability profiles from team CLIs.

CLIs POST auto-detected capability profiles for skills they encounter.
Profiles are stored append-only per-org -- no upserts, no deletions.
"""

import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.models.org_event import OrgProfile
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


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class ProfileRequest(BaseModel):
    org_slug: str
    skill_id: str
    ecosystem: str
    capabilities: list
    detected_at: datetime.datetime


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/profiles", status_code=201)
async def ingest_profiles(
    body: ProfileRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Ingest an auto-profile for a skill (member+, append-only)."""

    # Resolve org and check membership
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
    profile = OrgProfile(
        org_id=org.id,
        user_id=user.id,
        skill_id=body.skill_id,
        ecosystem=body.ecosystem,
        capabilities=body.capabilities,
        detected_at=body.detected_at,
        created_at=now,
    )
    session.add(profile)
    await session.commit()

    return {"accepted": 1}
