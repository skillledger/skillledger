from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.artifact import LogEntryRecord

router = APIRouter(prefix="/log", tags=["transparency-log"])


class ArtifactEntry(BaseModel):
    artifact_id: str = Field(..., min_length=1)
    sha256: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    content_address: str = Field(..., min_length=1)
    publisher: str = Field(..., min_length=1)


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
    session: AsyncSession = Depends(get_session),
) -> PublishResponse:
    published_at = datetime.now(timezone.utc)

    payload = {
        "artifact_id": entry.artifact_id,
        "sha256": entry.sha256,
        "content_address": entry.content_address,
        "publisher": entry.publisher,
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
        publisher=entry.publisher,
        published_at=published_at,
    )
    session.add(record)
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        # Critical: log entry exists in Merkle tree but DB record failed.
        # This inconsistency requires manual reconciliation.
        raise HTTPException(
            status_code=500,
            detail="Entry added to log but metadata save failed. Contact admin.",
        )

    return PublishResponse(log_index=log_index, artifact_id=entry.artifact_id)


@router.get("/lookup/{artifact_id}", response_model=LookupResponse)
async def lookup_entry(
    artifact_id: str,
    session: AsyncSession = Depends(get_session),
) -> LookupResponse:
    stmt = select(LogEntryRecord).where(LogEntryRecord.artifact_id == artifact_id)
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
