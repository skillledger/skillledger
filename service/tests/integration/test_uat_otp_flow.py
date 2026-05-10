"""UAT Integration Tests: OTP Email Authentication Flow (UAT-01, D-01, D-06).

Proves end-to-end: request OTP -> verify code -> receive JWT tokens.
"""

import asyncio
import datetime
from unittest.mock import patch

from skillledger_service.auth import hash_api_key
from skillledger_service.db import get_async_session_factory
from skillledger_service.models.user import OtpCode


def _insert_otp(email: str, code: str, expires_minutes: int = 10):
    """Insert an OTP record with a known code for testing."""
    hashed = hash_api_key(code)
    now = datetime.datetime.now(datetime.timezone.utc)

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            otp = OtpCode(
                email=email,
                otp_hash=hashed,
                expires_at=now + datetime.timedelta(minutes=expires_minutes),
                attempts=0,
            )
            session.add(otp)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


def _insert_expired_otp(email: str, code: str):
    """Insert an OTP record that has already expired."""
    hashed = hash_api_key(code)
    now = datetime.datetime.now(datetime.timezone.utc)

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            otp = OtpCode(
                email=email,
                otp_hash=hashed,
                expires_at=now - datetime.timedelta(minutes=5),  # expired 5 min ago
                attempts=0,
            )
            session.add(otp)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


@patch("skillledger_service.email.resend.Emails.send", return_value={"id": "fake-id"})
def test_otp_full_flow(mock_send, client):
    """End-to-end: request OTP, verify code, receive JWT access and refresh tokens.

    Covers UAT-01: OTP email flow completes end-to-end.
    """
    email = "otp-uat@example.com"
    code = "123456"

    # Step 1: Request OTP (sends email)
    resp = client.post("/auth/register", json={"email": email})
    assert resp.status_code == 200
    assert "verification code" in resp.json()["message"].lower()

    # Step 2: Insert known OTP (simulates what register created, but with known code)
    _insert_otp(email, code)

    # Step 3: Verify OTP code -> receive JWT tokens
    resp = client.post("/auth/verify", json={"email": email, "code": code})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20
    assert len(data["refresh_token"]) > 20


def test_otp_invalid_code_rejected(client):
    """Verify with wrong code returns 400 (invalid or expired code).

    Covers UAT-01 negative path: wrong OTP is rejected.
    """
    email = "invalid-otp@example.com"
    code = "123456"
    _insert_otp(email, code)

    # Try to verify with wrong code
    resp = client.post("/auth/verify", json={"email": email, "code": "999999"})
    assert resp.status_code == 400
    assert "invalid" in resp.json()["detail"].lower() or "expired" in resp.json()["detail"].lower()


def test_otp_expired_code_rejected(client):
    """Expired OTP code returns 400 (invalid or expired code).

    Covers UAT-01 edge case: expired codes cannot be used.
    """
    email = "expired-otp@example.com"
    code = "654321"
    _insert_expired_otp(email, code)

    # Try to verify with expired code
    resp = client.post("/auth/verify", json={"email": email, "code": code})
    assert resp.status_code == 400
    assert "invalid" in resp.json()["detail"].lower() or "expired" in resp.json()["detail"].lower()
