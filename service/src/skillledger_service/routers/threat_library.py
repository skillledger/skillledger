import hashlib
import logging
from typing import Union

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session
from skillledger_service.models.publisher import Publisher
from skillledger_service.models.threat import IocDomain, IocHash, YaraRule
from skillledger_service.models.user import User
from skillledger_service.user_auth import get_current_identity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["threat-library"])


# --- Pydantic response models per D-04 ---


class IocHashItem(BaseModel):
    sha256: str
    description: str
    severity: str
    source: str
    reported_at: str | None


class IocDomainItem(BaseModel):
    domain: str
    description: str
    severity: str
    source: str
    reported_at: str | None


class IocResponse(BaseModel):
    updated_at: str | None
    count: int
    hashes: list[IocHashItem]
    domains: list[IocDomainItem]


class YaraRuleItem(BaseModel):
    name: str
    content: str
    source: str


class YaraResponse(BaseModel):
    updated_at: str | None
    count: int
    rules: list[YaraRuleItem]


def _compute_etag(body_bytes: bytes) -> str:
    """Compute ETag as SHA-256 of serialized JSON body per D-06."""
    return f'"{hashlib.sha256(body_bytes).hexdigest()}"'


def _check_etag(if_none_match: str | None, etag: str) -> bool:
    """Return True if client ETag matches (304 should be returned)."""
    if not if_none_match:
        return False
    # Handle both quoted and unquoted ETags
    return if_none_match.strip().strip('"') == etag.strip('"')


@router.get("/ioc")
async def get_ioc(
    response: Response,
    identity: Union[User, Publisher] = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
    if_none_match: str | None = Header(None),
):
    """Return all IOC hashes and domains. Per SYNC-05, D-04, D-06, D-07, D-08."""
    # Query hashes
    hash_result = await session.execute(
        select(IocHash).order_by(IocHash.id)
    )
    hashes = hash_result.scalars().all()

    # Query domains
    domain_result = await session.execute(
        select(IocDomain).order_by(IocDomain.id)
    )
    domains = domain_result.scalars().all()

    # Determine updated_at (latest updated_at or created_at across both tables)
    ts_stmt = select(func.max(IocHash.updated_at)).union_all(
        select(func.max(IocHash.created_at)),
        select(func.max(IocDomain.updated_at)),
        select(func.max(IocDomain.created_at)),
    )
    ts_result = await session.execute(ts_stmt)
    timestamps = [row[0] for row in ts_result.all() if row[0] is not None]
    latest = max(timestamps).isoformat() if timestamps else None

    # Build response body
    body = IocResponse(
        updated_at=latest,
        count=len(hashes) + len(domains),
        hashes=[IocHashItem(
            sha256=h.sha256, description=h.description,
            severity=h.severity, source=h.source, reported_at=h.reported_at,
        ) for h in hashes],
        domains=[IocDomainItem(
            domain=d.domain, description=d.description,
            severity=d.severity, source=d.source, reported_at=d.reported_at,
        ) for d in domains],
    )

    body_bytes = body.model_dump_json().encode()
    etag = _compute_etag(body_bytes)

    # ETag conditional check per D-06
    if _check_etag(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, max-age=300"  # D-07
    return body


@router.get("/yara")
async def get_yara(
    response: Response,
    identity: Union[User, Publisher] = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
    if_none_match: str | None = Header(None),
):
    """Return all YARA rules. Per SYNC-06, D-04, D-06, D-07, D-08."""
    result = await session.execute(
        select(YaraRule).order_by(YaraRule.id)
    )
    rules = result.scalars().all()

    # Determine updated_at
    ts_stmt = select(func.max(YaraRule.updated_at)).union_all(
        select(func.max(YaraRule.created_at)),
    )
    ts_result = await session.execute(ts_stmt)
    timestamps = [row[0] for row in ts_result.all() if row[0] is not None]
    latest = max(timestamps).isoformat() if timestamps else None

    body = YaraResponse(
        updated_at=latest,
        count=len(rules),
        rules=[YaraRuleItem(
            name=r.name, content=r.content, source=r.source,
        ) for r in rules],
    )

    body_bytes = body.model_dump_json().encode()
    etag = _compute_etag(body_bytes)

    if _check_etag(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, max-age=300"
    return body
