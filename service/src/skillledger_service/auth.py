import hashlib
import secrets

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.db import get_session, get_settings
from skillledger_service.models.publisher import APIKey, Publisher

security = HTTPBearer()


def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256 for storage/lookup."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a cryptographically random 32-byte API key (64 hex chars)."""
    return secrets.token_hex(32)


async def get_current_publisher(
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session),
) -> Publisher:
    """Dependency that validates Bearer token and returns the associated Publisher.

    Raises HTTP 401 if token is invalid, revoked, or publisher is inactive.
    """
    token = credentials.credentials
    hashed = hash_api_key(token)

    stmt = (
        select(Publisher)
        .join(APIKey)
        .where(APIKey.key_hash == hashed, APIKey.revoked == False, Publisher.active == True)  # noqa: E712
    )
    result = await session.execute(stmt)
    publisher = result.scalar_one_or_none()

    if publisher is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    return publisher


async def get_admin_or_publisher(
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session),
) -> Publisher | None:
    """Dependency for admin endpoints. Returns Publisher if valid key, or None if admin key matches."""
    token = credentials.credentials
    settings = get_settings()

    # Check admin bootstrap key
    if settings.admin_api_key and token == settings.admin_api_key:
        return None  # None signals admin access (no publisher context)

    # Fall back to publisher key lookup
    return await get_current_publisher(credentials, session)
