"""Admin-only ingestion endpoint for community threat library data.

Accepts IOC hashes, IOC domains, and YARA rules via a single POST
and upserts them into the database. Used by the merge-to-main CI
workflow to publish approved community contributions.
"""

import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.auth import get_admin_or_publisher
from skillledger_service.db import get_session
from skillledger_service.models.threat import IocDomain, IocHash, YaraRule

router = APIRouter(prefix="/v1/admin/threat-library", tags=["admin"])

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


# --- Pydantic request/response models ---


class IngestHashEntry(BaseModel):
    sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    description: str = Field(..., max_length=512)
    severity: str = Field(...)
    source: str = Field(..., max_length=255)
    reported_at: str | None = None


class IngestDomainEntry(BaseModel):
    domain: str = Field(..., max_length=255)
    description: str = Field(..., max_length=512)
    severity: str = Field(...)
    source: str = Field(..., max_length=255)
    reported_at: str | None = None


class IngestRuleEntry(BaseModel):
    name: str = Field(..., max_length=255)
    content: str
    source: str = Field(..., max_length=255)


class IngestRequest(BaseModel):
    hashes: list[IngestHashEntry] = []
    domains: list[IngestDomainEntry] = []
    rules: list[IngestRuleEntry] = []


class IngestResponse(BaseModel):
    hashes_upserted: int
    domains_upserted: int
    rules_upserted: int


def _validate_severity(value: str, context: str) -> None:
    """Raise 422 if severity is not in the allowed set."""
    if value not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity '{value}' for {context}. "
            f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}",
        )


@router.post("/ingest", response_model=IngestResponse)
async def ingest_threat_data(
    payload: IngestRequest,
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> IngestResponse:
    """Ingest community threat data (admin-only).

    Performs idempotent upsert: existing entries (matched by unique key)
    are updated; new entries are inserted. Uses select-then-update/insert
    pattern for SQLite compatibility in tests.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # --- Upsert hashes ---
    hashes_count = 0
    for entry in payload.hashes:
        _validate_severity(entry.severity, f"hash {entry.sha256[:16]}...")
        result = await session.execute(
            select(IocHash).where(IocHash.sha256 == entry.sha256)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.description = entry.description
            existing.severity = entry.severity
            existing.source = entry.source
            existing.reported_at = entry.reported_at
            existing.updated_at = now
        else:
            session.add(
                IocHash(
                    sha256=entry.sha256,
                    description=entry.description,
                    severity=entry.severity,
                    source=entry.source,
                    reported_at=entry.reported_at,
                )
            )
        hashes_count += 1

    # --- Upsert domains ---
    domains_count = 0
    for entry in payload.domains:
        _validate_severity(entry.severity, f"domain {entry.domain}")
        result = await session.execute(
            select(IocDomain).where(IocDomain.domain == entry.domain)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.description = entry.description
            existing.severity = entry.severity
            existing.source = entry.source
            existing.reported_at = entry.reported_at
            existing.updated_at = now
        else:
            session.add(
                IocDomain(
                    domain=entry.domain,
                    description=entry.description,
                    severity=entry.severity,
                    source=entry.source,
                    reported_at=entry.reported_at,
                )
            )
        domains_count += 1

    # --- Upsert YARA rules ---
    rules_count = 0
    for entry in payload.rules:
        result = await session.execute(
            select(YaraRule).where(YaraRule.name == entry.name)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.content = entry.content
            existing.source = entry.source
            existing.updated_at = now
        else:
            session.add(
                YaraRule(
                    name=entry.name,
                    content=entry.content,
                    source=entry.source,
                )
            )
        rules_count += 1

    # Single commit for atomicity
    await session.commit()

    return IngestResponse(
        hashes_upserted=hashes_count,
        domains_upserted=domains_count,
        rules_upserted=rules_count,
    )
