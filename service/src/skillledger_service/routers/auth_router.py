import asyncio
import datetime
import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from skillledger_service.auth import generate_api_key, hash_api_key
from skillledger_service.db import get_session, get_settings
from skillledger_service.email import send_otp_email
from skillledger_service.models.user import OtpCode, RefreshToken, User, UserApiKey
from skillledger_service.user_auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_otp,
    get_current_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# --- Pydantic models ---


class RegisterRequest(BaseModel):
    email: str = Field(..., max_length=255, pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


class VerifyRequest(BaseModel):
    email: str = Field(..., max_length=255)
    code: str = Field(..., min_length=6, max_length=6)


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    message: str


class CreateTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class TokenInfo(BaseModel):
    id: int
    name: str
    key_prefix: str
    expires_at: str
    revoked: bool
    created_at: str


class CreateTokenResponse(BaseModel):
    raw_key: str
    name: str
    key_prefix: str
    expires_at: str


# --- Endpoints ---


@router.post("/register", response_model=MessageResponse)
async def register(
    req: RegisterRequest,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Send OTP verification code to email.

    Always returns 200 regardless of whether the email exists (prevents enumeration).
    Rate limited to 3 sends per email per 15 minutes.
    """
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)
    window_start = now - datetime.timedelta(minutes=15)

    # Rate limit: max 3 OTP sends per email per 15 minutes
    count_stmt = (
        select(func.count())
        .select_from(OtpCode)
        .where(OtpCode.email == req.email, OtpCode.created_at >= window_start)
    )
    result = await session.execute(count_stmt)
    otp_count = result.scalar_one()

    if otp_count >= 3:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    # Generate and store OTP
    otp_code = generate_otp()
    hashed = hash_api_key(otp_code)
    otp = OtpCode(
        email=req.email,
        otp_hash=hashed,
        expires_at=now + datetime.timedelta(minutes=10),
        attempts=0,
    )
    session.add(otp)
    await session.commit()

    # Send email (fire and forget, don't fail the request)
    try:
        await asyncio.to_thread(
            send_otp_email, req.email, otp_code, settings.resend_api_key, settings.otp_from_email
        )
    except Exception:
        logger.exception("Failed to send OTP email to %s", req.email)

    return MessageResponse(
        message="If this email is registered, a verification code has been sent."
    )


@router.post("/verify", response_model=TokenResponse)
async def verify(
    req: VerifyRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Verify OTP code and return JWT tokens.

    Uses SELECT ... FOR UPDATE to serialize concurrent verification attempts.
    """
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)

    # Find the most recent unexpired OTP for this email (serialized with FOR UPDATE)
    stmt = (
        select(OtpCode)
        .where(OtpCode.email == req.email, OtpCode.expires_at > now)
        .order_by(OtpCode.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    result = await session.execute(stmt)
    otp = result.scalar_one_or_none()

    if otp is None:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # Check attempt limit
    if otp.attempts >= 5:
        raise HTTPException(
            status_code=429, detail="Too many attempts. Try again in 15 minutes."
        )

    # Increment attempts and check code
    otp.attempts += 1
    code_hash = hash_api_key(req.code)

    if not hmac.compare_digest(code_hash, otp.otp_hash):
        await session.commit()  # Save the incremented attempt count
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # OTP matches -- delete the OTP record
    await session.delete(otp)

    # Find or create user
    user_stmt = select(User).where(User.email == req.email)
    user_result = await session.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if user is None:
        user = User(email=req.email)
        session.add(user)
        await session.flush()

    # Create JWT tokens
    access_token = create_access_token(
        user.id, user.email, settings.jwt_secret, settings.jwt_algorithm
    )
    refresh_jwt = create_refresh_token(
        user.id, settings.jwt_secret, settings.jwt_algorithm
    )

    # Store refresh token hash for revocation/rotation lookup
    refresh_hash = hash_api_key(refresh_jwt)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=now + datetime.timedelta(days=30),
    )
    session.add(rt)
    await session.commit()

    return TokenResponse(access_token=access_token, refresh_token=refresh_jwt)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    req: RefreshRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Refresh JWT tokens with rotate-on-use.

    Accepts a refresh token, validates it, deletes the old record (rotation),
    and returns a new token pair.
    """
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)

    # Decode refresh JWT
    try:
        payload = decode_token(req.refresh_token, settings.jwt_secret, settings.jwt_algorithm)
        if payload.get("type") != "refresh":
            raise ValueError("Not a refresh token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Look up stored refresh token
    token_hash = hash_api_key(req.refresh_token)
    stmt = select(RefreshToken).where(
        RefreshToken.token_hash == token_hash,
        RefreshToken.expires_at > now,
    )
    result = await session.execute(stmt)
    stored_rt = result.scalar_one_or_none()

    if stored_rt is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = stored_rt.user_id

    # Rotate: delete old refresh token
    await session.delete(stored_rt)

    # Fetch user
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    # Issue new token pair
    access_token = create_access_token(
        user.id, user.email, settings.jwt_secret, settings.jwt_algorithm
    )
    new_refresh_jwt = create_refresh_token(
        user.id, settings.jwt_secret, settings.jwt_algorithm
    )

    # Store new refresh token
    new_refresh_hash = hash_api_key(new_refresh_jwt)
    new_rt = RefreshToken(
        user_id=user.id,
        token_hash=new_refresh_hash,
        expires_at=now + datetime.timedelta(days=30),
    )
    session.add(new_rt)
    await session.commit()

    return TokenResponse(access_token=access_token, refresh_token=new_refresh_jwt)


@router.post("/tokens", response_model=CreateTokenResponse, status_code=201)
async def create_ci_token(
    req: CreateTokenRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> CreateTokenResponse:
    """Create a CI API key with 1-year expiry. Raw key returned ONCE."""
    now = datetime.datetime.now(datetime.timezone.utc)
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    expires_at = now + datetime.timedelta(days=365)

    api_key = UserApiKey(
        user_id=user.id,
        key_hash=hashed,
        name=req.name,
        key_prefix=raw_key[:8],
        expires_at=expires_at,
        revoked=False,
    )
    session.add(api_key)
    await session.commit()

    return CreateTokenResponse(
        raw_key=raw_key,
        name=req.name,
        key_prefix=raw_key[:8],
        expires_at=expires_at.isoformat(),
    )


@router.get("/tokens", response_model=list[TokenInfo])
async def list_tokens(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[TokenInfo]:
    """List all API keys for the authenticated user."""
    stmt = select(UserApiKey).where(UserApiKey.user_id == user.id)
    result = await session.execute(stmt)
    keys = result.scalars().all()

    return [
        TokenInfo(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            expires_at=k.expires_at.isoformat(),
            revoked=k.revoked,
            created_at=k.created_at.isoformat(),
        )
        for k in keys
    ]


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Revoke a user API key (soft delete)."""
    stmt = select(UserApiKey).where(
        UserApiKey.id == token_id, UserApiKey.user_id == user.id
    )
    result = await session.execute(stmt)
    key = result.scalar_one_or_none()

    if key is None:
        raise HTTPException(status_code=404, detail="Token not found")

    key.revoked = True
    await session.commit()
