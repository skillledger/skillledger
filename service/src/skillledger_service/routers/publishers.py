import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.auth import (
    generate_api_key,
    get_admin_or_publisher,
    hash_api_key,
)
from skillledger_service.db import get_session
from skillledger_service.models.publisher import APIKey, Publisher

router = APIRouter(prefix="/publishers", tags=["publishers"])


class CreatePublisherRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    contact_email: str | None = Field(None, max_length=255)


class PublisherResponse(BaseModel):
    id: int
    name: str
    contact_email: str | None
    created_at: str
    active: bool


class CreateKeyResponse(BaseModel):
    key_prefix: str
    raw_key: str  # Only returned once at creation time
    publisher_name: str


class KeyInfo(BaseModel):
    id: int
    key_prefix: str
    created_at: str
    revoked: bool


@router.post("", response_model=PublisherResponse, status_code=201)
async def create_publisher(
    req: CreatePublisherRequest,
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> PublisherResponse:
    """Create a new publisher. Requires admin API key."""
    existing = await session.execute(
        select(Publisher).where(Publisher.name == req.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Publisher name already exists")

    pub = Publisher(
        name=req.name,
        contact_email=req.contact_email,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        active=True,
    )
    session.add(pub)
    await session.commit()
    await session.refresh(pub)

    return PublisherResponse(
        id=pub.id,
        name=pub.name,
        contact_email=pub.contact_email,
        created_at=pub.created_at.isoformat(),
        active=pub.active,
    )


@router.get("", response_model=list[PublisherResponse])
async def list_publishers(
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> list[PublisherResponse]:
    """List all publishers. Requires admin API key."""
    result = await session.execute(select(Publisher).order_by(Publisher.name))
    publishers = result.scalars().all()
    return [
        PublisherResponse(
            id=p.id,
            name=p.name,
            contact_email=p.contact_email,
            created_at=p.created_at.isoformat(),
            active=p.active,
        )
        for p in publishers
    ]


@router.post("/{publisher_id}/keys", response_model=CreateKeyResponse, status_code=201)
async def create_api_key(
    publisher_id: int,
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> CreateKeyResponse:
    """Generate a new API key for a publisher. Returns the raw key ONCE."""
    pub = await session.get(Publisher, publisher_id)
    if pub is None:
        raise HTTPException(status_code=404, detail="Publisher not found")

    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)

    key = APIKey(
        key_hash=hashed,
        key_prefix=raw_key[:8],
        publisher_id=pub.id,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        revoked=False,
    )
    session.add(key)
    await session.commit()

    return CreateKeyResponse(
        key_prefix=raw_key[:8],
        raw_key=raw_key,
        publisher_name=pub.name,
    )


@router.get("/{publisher_id}/keys", response_model=list[KeyInfo])
async def list_keys(
    publisher_id: int,
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> list[KeyInfo]:
    """List API keys for a publisher (prefix only, never full key)."""
    pub = await session.get(Publisher, publisher_id)
    if pub is None:
        raise HTTPException(status_code=404, detail="Publisher not found")

    result = await session.execute(
        select(APIKey).where(APIKey.publisher_id == publisher_id)
    )
    keys = result.scalars().all()
    return [
        KeyInfo(
            id=k.id,
            key_prefix=k.key_prefix,
            created_at=k.created_at.isoformat(),
            revoked=k.revoked,
        )
        for k in keys
    ]


@router.delete("/{publisher_id}/keys/{key_id}", status_code=204)
async def revoke_key(
    publisher_id: int,
    key_id: int,
    _admin: None = Depends(get_admin_or_publisher),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Revoke an API key (soft delete)."""
    result = await session.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.publisher_id == publisher_id)
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="Key not found")

    key.revoked = True
    await session.commit()
