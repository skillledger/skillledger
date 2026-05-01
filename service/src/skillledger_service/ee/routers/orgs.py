"""Enterprise org management: CRUD, invites, members, ownership transfer.

All endpoints are gated behind license validation (loaded only when valid
ee_license_key is present). Role-based access uses the D-08 permission
matrix via the ``require_org_role`` dependency factory.
"""

import datetime
import logging
import secrets
from typing import Optional

import resend
from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.organization import (
    ROLE_HIERARCHY,
    Organization,
    OrgInvite,
    OrgMembership,
    OrgRole,
    slugify,
)
from skillledger_service.models.user import User
from skillledger_service.user_auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ee/v1", tags=["enterprise"])

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class CreateOrgRequest(BaseModel):
    name: str


class InviteRequest(BaseModel):
    email: str
    role: OrgRole


class TransferRequest(BaseModel):
    new_owner_id: int


class OrgResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    created_at: datetime.datetime


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: int
    email: str
    role: OrgRole
    joined_at: datetime.datetime


class InviteResponse(BaseModel):
    id: int
    email: str
    role: OrgRole
    expires_at: datetime.datetime
    accepted: bool
    created_at: datetime.datetime


# ---------------------------------------------------------------------------
# Permission dependency
# ---------------------------------------------------------------------------


def require_org_role(min_role: OrgRole):
    """Return a FastAPI dependency that enforces minimum org role."""

    async def dependency(
        slug: str = Path(...),
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> tuple[Organization, OrgMembership, User]:
        org = (
            await session.execute(
                select(Organization).where(Organization.slug == slug)
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
        if ROLE_HIERARCHY[membership.role] < ROLE_HIERARCHY[min_role]:
            raise HTTPException(403, "Insufficient permissions")
        return org, membership, user

    return dependency


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/orgs")
async def create_org(
    body: CreateOrgRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrgResponse:
    """Create a new organization. The authenticated user becomes the owner."""
    slug = slugify(body.name)
    existing = (
        await session.execute(
            select(Organization).where(Organization.slug == slug)
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "An organization with this slug already exists")

    org = Organization(name=body.name, slug=slug)
    session.add(org)
    await session.flush()

    membership = OrgMembership(user_id=user.id, org_id=org.id, role=OrgRole.owner)
    session.add(membership)
    await session.commit()
    await session.refresh(org)

    return OrgResponse.model_validate(org)


@router.get("/orgs/{slug}")
async def get_org(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.viewer)
    ),
) -> OrgResponse:
    """Get organization details (any member)."""
    org, _, _ = ctx
    return OrgResponse.model_validate(org)


@router.patch("/orgs/{slug}")
async def update_org(
    body: CreateOrgRequest,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> OrgResponse:
    """Update organization name (admin+)."""
    org, _, _ = ctx
    new_slug = slugify(body.name)

    # Check slug uniqueness if it changed
    if new_slug != org.slug:
        conflict = (
            await session.execute(
                select(Organization).where(Organization.slug == new_slug)
            )
        ).scalar_one_or_none()
        if conflict:
            raise HTTPException(409, "An organization with this slug already exists")

    org.name = body.name
    org.slug = new_slug
    org.updated_at = datetime.datetime.now(datetime.timezone.utc)
    await session.commit()
    await session.refresh(org)

    return OrgResponse.model_validate(org)


@router.get("/orgs/{slug}/members")
async def list_members(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.viewer)
    ),
    session: AsyncSession = Depends(get_session),
) -> list[MemberResponse]:
    """List organization members (any member)."""
    org, _, _ = ctx
    result = await session.execute(
        select(
            OrgMembership.user_id,
            User.email,
            OrgMembership.role,
            OrgMembership.joined_at,
        )
        .join(User, OrgMembership.user_id == User.id)
        .where(OrgMembership.org_id == org.id)
    )
    rows = result.all()
    return [
        MemberResponse(
            user_id=r.user_id, email=r.email, role=r.role, joined_at=r.joined_at
        )
        for r in rows
    ]


@router.post("/orgs/{slug}/invites")
async def create_invite(
    body: InviteRequest,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> InviteResponse:
    """Create an invite and send email (admin+). Cannot invite as owner."""
    org, _, user = ctx

    if body.role == OrgRole.owner:
        raise HTTPException(400, "Cannot invite as owner; use ownership transfer")

    token = secrets.token_urlsafe(32)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(days=7)

    invite = OrgInvite(
        org_id=org.id,
        email=body.email,
        role=body.role,
        invited_by=user.id,
        token=token,
        expires_at=expires_at,
    )
    session.add(invite)
    await session.commit()
    await session.refresh(invite)

    # Send invite email via Resend
    settings = get_settings()
    if settings.resend_api_key:
        try:
            resend.api_key = settings.resend_api_key
            resend.Emails.send(
                {
                    "from": settings.otp_from_email,
                    "to": [body.email],
                    "subject": f"You're invited to join {org.name} on SkillLedger",
                    "text": (
                        f"You've been invited to join {org.name} on SkillLedger.\n\n"
                        f"Accept: {settings.service_url}/ee/v1/invites/{token}/accept\n\n"
                        "This invite expires in 7 days.\n\n"
                        "If you don't have an account yet, please register first."
                    ),
                }
            )
        except Exception:
            logger.exception("Failed to send invite email to %s", body.email)

    return InviteResponse(
        id=invite.id,
        email=invite.email,
        role=invite.role,
        expires_at=invite.expires_at,
        accepted=invite.accepted_at is not None,
        created_at=invite.created_at,
    )


@router.get("/orgs/{slug}/invites")
async def list_invites(
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> list[InviteResponse]:
    """List pending (unaccepted, unexpired) invites (admin+)."""
    org, _, _ = ctx
    now = datetime.datetime.now(datetime.timezone.utc)
    result = await session.execute(
        select(OrgInvite).where(
            OrgInvite.org_id == org.id,
            OrgInvite.accepted_at.is_(None),
            OrgInvite.expires_at > now,
        )
    )
    invites = result.scalars().all()
    return [
        InviteResponse(
            id=inv.id,
            email=inv.email,
            role=inv.role,
            expires_at=inv.expires_at,
            accepted=False,
            created_at=inv.created_at,
        )
        for inv in invites
    ]


@router.post("/invites/{token}/accept")
async def accept_invite(
    token: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> MemberResponse:
    """Accept an invite by token. User email must match invite email."""
    invite = (
        await session.execute(
            select(OrgInvite).where(OrgInvite.token == token)
        )
    ).scalar_one_or_none()
    if not invite:
        raise HTTPException(404, "Invite not found")

    if invite.accepted_at is not None:
        raise HTTPException(400, "Already accepted")

    now = datetime.datetime.now(datetime.timezone.utc)
    expires = invite.expires_at
    # Normalize naive datetimes (e.g. from SQLite) to UTC
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    if expires <= now:
        raise HTTPException(400, "Invite expired")

    if user.email != invite.email:
        raise HTTPException(403, "Email does not match invite")

    # Check no existing membership
    existing = (
        await session.execute(
            select(OrgMembership).where(
                OrgMembership.org_id == invite.org_id,
                OrgMembership.user_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Already a member")

    membership = OrgMembership(
        user_id=user.id, org_id=invite.org_id, role=invite.role
    )
    session.add(membership)
    invite.accepted_at = now
    await session.commit()
    await session.refresh(membership)

    return MemberResponse(
        user_id=membership.user_id,
        email=user.email,
        role=membership.role,
        joined_at=membership.joined_at,
    )


@router.delete("/orgs/{slug}/members/{user_id}", status_code=204)
async def remove_member(
    user_id: int,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Remove a member from the organization (admin+). Cannot remove owner."""
    org, _, _ = ctx

    target = (
        await session.execute(
            select(OrgMembership).where(
                OrgMembership.org_id == org.id,
                OrgMembership.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Membership not found")

    if target.role == OrgRole.owner:
        raise HTTPException(403, "Cannot remove the organization owner")

    await session.delete(target)
    await session.commit()


@router.post("/orgs/{slug}/transfer")
async def transfer_ownership(
    body: TransferRequest,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.owner)
    ),
    session: AsyncSession = Depends(get_session),
):
    """Transfer ownership to another member (owner only)."""
    org, current_membership, _ = ctx

    target = (
        await session.execute(
            select(OrgMembership).where(
                OrgMembership.org_id == org.id,
                OrgMembership.user_id == body.new_owner_id,
            )
        )
    ).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target user is not a member of this organization")

    target.role = OrgRole.owner
    current_membership.role = OrgRole.admin
    await session.commit()

    return {"message": f"Ownership transferred to user {body.new_owner_id}"}
