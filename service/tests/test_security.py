"""Security-focused tests for the SkillLedger service.

Covers revoked keys, inactive publishers, expired/tampered JWTs,
refresh-token-as-access rejection, and SQL injection in artifact_id.
"""

import asyncio
import datetime
import os
from unittest.mock import AsyncMock, patch

import httpx
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ["SKILLLEDGER_ADMIN_API_KEY"] = "test-admin-key-security"
os.environ["SKILLLEDGER_JWT_SECRET"] = "test-secret-for-security-minimum-length-32bytes!"
os.environ["SKILLLEDGER_RESEND_API_KEY"] = "re_test_fake"
os.environ["SKILLLEDGER_DEBUG"] = "true"

from skillledger_service.auth import generate_api_key, hash_api_key  # noqa: E402
from skillledger_service.db import get_async_session_factory, get_engine  # noqa: E402
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.publisher import APIKey, Publisher  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token, create_refresh_token  # noqa: E402

VALID_ENTRY = {
    "artifact_id": "test-skill-v1.0.0",
    "sha256": "a" * 64,
    "content_address": "sha256-aaaa",
}


@pytest.fixture(autouse=True)
def _reset_db():
    """Drop and recreate all tables before each test for isolation."""

    async def _reset():
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_reset())
    loop.close()
    yield


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def _mock_httpx_post():
    """Context manager that mocks httpx.AsyncClient to avoid hitting the log service."""
    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = "42"

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    return patch(
        "skillledger_service.routers.log.httpx.AsyncClient",
        return_value=mock_client,
    )


def _create_publisher_and_key(*, active=True, revoked=False):
    """Create a publisher with an API key, return (publisher_name, raw_key).

    Supports setting active/revoked flags for security test scenarios.
    """
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            pub = Publisher(
                name="sec-test-publisher",
                contact_email="sec@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
                active=active,
            )
            session.add(pub)
            await session.flush()
            key = APIKey(
                key_hash=hashed,
                key_prefix=raw_key[:8],
                publisher_id=pub.id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                revoked=revoked,
            )
            session.add(key)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return "sec-test-publisher", raw_key


def _create_user_with_jwt(email="sectest@example.com"):
    """Create a user in the DB and return (user_id, access_token)."""
    user_id = None

    async def _create():
        nonlocal user_id
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(email=email)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id = user.id

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()

    token = create_access_token(
        user_id, email, os.environ["SKILLLEDGER_JWT_SECRET"]
    )
    return user_id, token


# ---------------------------------------------------------------------------
# CR-01: Revoked API key must be rejected on publish
# ---------------------------------------------------------------------------


def test_revoked_key_rejected(client):
    """CR-01: Revoked API key must be rejected on publish."""
    _, raw_key = _create_publisher_and_key(active=True, revoked=True)

    with _mock_httpx_post():
        response = client.post(
            "/log/publish",
            json=VALID_ENTRY,
            headers={"Authorization": f"Bearer {raw_key}"},
        )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# CR-02: Deactivated publisher's keys must stop working
# ---------------------------------------------------------------------------


def test_inactive_publisher_rejected(client):
    """CR-02: Deactivated publisher's keys must stop working."""
    _, raw_key = _create_publisher_and_key(active=False, revoked=False)

    with _mock_httpx_post():
        response = client.post(
            "/log/publish",
            json=VALID_ENTRY,
            headers={"Authorization": f"Bearer {raw_key}"},
        )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# CR-03: JWT with past expiry must return 401
# ---------------------------------------------------------------------------


def test_expired_jwt_rejected(client):
    """CR-03: JWT with past expiry must return 401."""
    user_id, _ = _create_user_with_jwt("expired@example.com")

    # Create a JWT that expired 1 hour ago
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": "expired@example.com",
        "iat": now - datetime.timedelta(hours=2),
        "exp": now - datetime.timedelta(hours=1),
        "type": "access",
        "jti": "expired-jti-0001",
    }
    expired_token = pyjwt.encode(
        payload, os.environ["SKILLLEDGER_JWT_SECRET"], algorithm="HS256"
    )

    resp = client.get(
        "/auth/tokens",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# CR-04: Refresh token used as Bearer access token must be rejected
# ---------------------------------------------------------------------------


def test_refresh_token_as_access_rejected(client):
    """CR-04: Refresh token used as Bearer access token must be rejected."""
    user_id, _ = _create_user_with_jwt("refresh@example.com")

    # Create a refresh token (type=refresh, not type=access)
    refresh_token = create_refresh_token(
        user_id, os.environ["SKILLLEDGER_JWT_SECRET"]
    )

    # Use it on a protected endpoint that expects an access token
    resp = client.get(
        "/auth/tokens",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# JWT signed with wrong secret must be rejected
# ---------------------------------------------------------------------------


def test_jwt_tampered_signature_rejected(client):
    """JWT signed with wrong secret must be rejected."""
    user_id, _ = _create_user_with_jwt("tampered@example.com")

    # Create a JWT signed with a completely different secret
    wrong_secret = "this-is-the-wrong-secret-not-the-real-one!"
    tampered_token = create_access_token(
        user_id, "tampered@example.com", wrong_secret
    )

    resp = client.get(
        "/auth/tokens",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# WR-04: SQL injection payloads in artifact_id should not cause 500
# ---------------------------------------------------------------------------


def test_sql_injection_artifact_id(client):
    """WR-04: SQL injection payloads in artifact_id should not cause 500."""
    sqli_payloads = [
        "'; DROP TABLE log_entries; --",
        "1 OR 1=1",
        "\" UNION SELECT * FROM publishers --",
        "test' AND '1'='1",
        "Robert'); DROP TABLE log_entries;--",
    ]

    for payload in sqli_payloads:
        response = client.get(f"/log/lookup/{payload}")
        # Should get 404 (not found) — never 500 (server error)
        assert response.status_code == 404, (
            f"SQL injection payload caused unexpected status "
            f"{response.status_code}: {payload!r}"
        )
