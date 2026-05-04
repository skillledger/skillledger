"""Enterprise policy distribution: PUT/GET org Rego policies.

Admins push OPA/Rego policies for their org; team CLIs pull them at
verify time.  The service stores the raw Rego text and records metadata
(compiled_at, created_by).  Full OPA compilation happens CLI-side.
"""

import datetime
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.ee.routers.orgs import require_org_role
from skillledger_service.models.org_event import OrgPolicy
from skillledger_service.models.organization import Organization, OrgMembership, OrgRole
from skillledger_service.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ee/v1", tags=["enterprise"])


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class SetPolicyRequest(BaseModel):
    rego: str
    deploy: bool = False


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    org_id: int
    rego: Optional[str] = None
    compiled_at: Optional[datetime.datetime] = None
    created_by: Optional[int] = None
    created_at: datetime.datetime
    updated_at: Optional[datetime.datetime] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.put("/orgs/{slug}/policy")
async def set_policy(
    body: SetPolicyRequest,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.admin)
    ),
    session: AsyncSession = Depends(get_session),
) -> PolicyResponse:
    """Store or update the Rego policy for an organization (admin+)."""
    org, _, user = ctx

    # Basic Rego validation: must contain a package declaration
    if "package " not in body.rego:
        raise HTTPException(400, "Rego policy must contain a package declaration")

    now = datetime.datetime.now(datetime.timezone.utc)

    # If deploy=False, validate only — return the validated policy without persisting
    if not body.deploy:
        return PolicyResponse(
            id=0,
            org_id=org.id,
            rego=body.rego,
            compiled_at=now,
            created_by=user.id,
            created_at=now,
            updated_at=None,
        )

    # deploy=True — persist to database (existing behavior below)
    # Upsert: find existing policy for this org
    existing = (
        await session.execute(
            select(OrgPolicy).where(OrgPolicy.org_id == org.id)
        )
    ).scalar_one_or_none()

    if existing:
        existing.rego = body.rego
        existing.compiled_at = now
        existing.created_by = user.id
        existing.updated_at = now
        policy = existing
    else:
        policy = OrgPolicy(
            org_id=org.id,
            rego=body.rego,
            compiled_at=now,
            created_by=user.id,
            updated_at=now,
        )
        session.add(policy)

    await session.commit()
    await session.refresh(policy)

    return PolicyResponse.model_validate(policy)


@router.get("/orgs/{slug}/policy")
async def get_policy(
    response: Response,
    ctx: tuple[Organization, OrgMembership, User] = Depends(
        require_org_role(OrgRole.viewer)
    ),
    session: AsyncSession = Depends(get_session),
) -> PolicyResponse:
    """Retrieve the Rego policy for an organization (viewer+)."""
    org, _, _ = ctx

    policy = (
        await session.execute(
            select(OrgPolicy).where(OrgPolicy.org_id == org.id)
        )
    ).scalar_one_or_none()

    if not policy:
        raise HTTPException(404, "No policy set for this organization")

    # ETag based on rego content hash
    if policy.rego:
        etag = hashlib.md5(policy.rego.encode()).hexdigest()
        response.headers["ETag"] = f'"{etag}"'

    return PolicyResponse.model_validate(policy)
