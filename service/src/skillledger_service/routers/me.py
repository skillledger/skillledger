"""User profile endpoint -- returns authenticated user info + org memberships."""

import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.models.organization import OrgMembership, OrgRole, Organization
from skillledger_service.models.user import User
from skillledger_service.user_auth import get_current_user

router = APIRouter(prefix="/v1", tags=["user"])


class OrgMembershipInfo(BaseModel):
    org_id: int
    org_name: str
    org_slug: str
    role: OrgRole
    joined_at: datetime.datetime


class MeResponse(BaseModel):
    id: int
    email: str
    created_at: datetime.datetime
    orgs: list[OrgMembershipInfo]


@router.get("/me", response_model=MeResponse)
async def get_me(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> MeResponse:
    """Return the authenticated user's profile and org memberships."""
    stmt = (
        select(OrgMembership, Organization)
        .join(Organization, OrgMembership.org_id == Organization.id)
        .where(OrgMembership.user_id == user.id)
    )
    result = await session.execute(stmt)
    rows = result.all()

    orgs = [
        OrgMembershipInfo(
            org_id=org.id,
            org_name=org.name,
            org_slug=org.slug,
            role=membership.role,
            joined_at=membership.joined_at,
        )
        for membership, org in rows
    ]

    return MeResponse(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
        orgs=orgs,
    )
