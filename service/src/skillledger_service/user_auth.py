import secrets
from datetime import datetime, timedelta, timezone
from typing import Union

import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.auth import hash_api_key, security
from skillledger_service.db import get_session, get_settings
from skillledger_service.models.publisher import APIKey, Publisher
from skillledger_service.models.user import OtpCode, RefreshToken, User, UserApiKey


def generate_otp() -> str:
    """Generate a 6-digit OTP code."""
    return f"{secrets.randbelow(1000000):06d}"


def create_access_token(
    user_id: int, email: str, secret: str, algorithm: str = "HS256"
) -> str:
    """Create a JWT access token (60 min expiry)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=60),
        "type": "access",
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def create_refresh_token(
    user_id: int, secret: str, algorithm: str = "HS256"
) -> str:
    """Create a JWT refresh token (30 day expiry)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(days=30),
        "type": "refresh",
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str = "HS256") -> dict:
    """Decode and validate a JWT token. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, secret, algorithms=[algorithm])


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Dependency that validates JWT or user API key and returns the User.

    Tries JWT access token first, then falls back to user API key lookup.
    Raises HTTP 401 if neither works.
    """
    token = credentials.credentials
    settings = get_settings()

    # Try JWT access token first
    try:
        payload = decode_token(token, settings.jwt_secret, settings.jwt_algorithm)
        if payload.get("type") != "access":
            raise ValueError("Not an access token")
        user_id = int(payload["sub"])
        user = await session.get(User, user_id)
        if user is not None:
            return user
    except (jwt.PyJWTError, ValueError, KeyError):
        pass

    # Fall back to user API key
    now = datetime.now(timezone.utc)
    hashed = hash_api_key(token)
    stmt = (
        select(User)
        .join(UserApiKey)
        .where(
            UserApiKey.key_hash == hashed,
            UserApiKey.revoked == False,  # noqa: E712
            UserApiKey.expires_at > now,
        )
    )
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user is not None:
        return user

    raise HTTPException(status_code=401, detail="Invalid credentials")


async def get_current_identity(
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session),
) -> Union[User, Publisher]:
    """Unified identity dependency: tries JWT first, then user API key, then publisher API key.

    Returns either a User or a Publisher. Raises HTTP 401 if nothing matches.
    """
    token = credentials.credentials
    settings = get_settings()

    # 1. Try JWT access token
    try:
        payload = decode_token(token, settings.jwt_secret, settings.jwt_algorithm)
        if payload.get("type") == "access":
            user_id = int(payload["sub"])
            user = await session.get(User, user_id)
            if user is not None:
                return user
    except (jwt.PyJWTError, ValueError, KeyError):
        pass

    # 2. Try user API key
    now = datetime.now(timezone.utc)
    hashed = hash_api_key(token)
    stmt = (
        select(User)
        .join(UserApiKey)
        .where(
            UserApiKey.key_hash == hashed,
            UserApiKey.revoked == False,  # noqa: E712
            UserApiKey.expires_at > now,
        )
    )
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user is not None:
        return user

    # 3. Try publisher API key
    stmt = (
        select(Publisher)
        .join(APIKey)
        .where(
            APIKey.key_hash == hashed,
            APIKey.revoked == False,  # noqa: E712
            Publisher.active == True,  # noqa: E712
        )
    )
    result = await session.execute(stmt)
    publisher = result.scalar_one_or_none()
    if publisher is not None:
        return publisher

    raise HTTPException(status_code=401, detail="Invalid credentials")
