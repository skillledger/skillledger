"""Tests for free-tier usage enforcement (BILL-01, BILL-07, D-02, D-03, D-06, D-10)."""

import asyncio
import datetime
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

# Must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-usage")

from skillledger_service.auth import generate_api_key, hash_api_key  # noqa: E402
from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.publisher import APIKey, Publisher  # noqa: E402
from skillledger_service.models.usage import UsageRecord  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402

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


@pytest.fixture
def publisher_auth_headers():
    """Create a publisher with an API key and return auth headers."""
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            pub = Publisher(
                name="test-publisher-usage",
                contact_email="pub@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
                active=True,
            )
            session.add(pub)
            await session.flush()
            key = APIKey(
                key_hash=hashed,
                key_prefix=raw_key[:8],
                publisher_id=pub.id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                revoked=False,
            )
            session.add(key)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    return {"Authorization": f"Bearer {raw_key}"}


@pytest.fixture
def user_auth_headers():
    """Create a User in DB and return JWT auth headers."""
    user_id_holder = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email="testuser@example.com",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id_holder["id"] = user.id
            user_id_holder["email"] = user.email

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()

    settings = get_settings()
    token = create_access_token(
        user_id_holder["id"], user_id_holder["email"], settings.jwt_secret
    )
    return {"Authorization": f"Bearer {token}"}, user_id_holder["id"]


def _mock_publish_success(status_code=200, text="42"):
    """Create a mock httpx response for successful publish."""
    resp = AsyncMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    return resp


def _do_publish(client, headers, entry=None, mock_status=200, mock_text="42"):
    """Helper: publish with mocked httpx, return response."""
    if entry is None:
        entry = VALID_ENTRY
    mock_resp = _mock_publish_success(mock_status, mock_text)
    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        return client.post("/log/publish", json=entry, headers=headers)


def test_free_tier_limit_enforced(client, user_auth_headers):
    """BILL-01: User can publish 50 times, 51st returns 429."""
    headers, _ = user_auth_headers

    # Publish 50 times -- all should succeed
    for i in range(50):
        entry = {
            "artifact_id": f"skill-{i}-v1.0.0",
            "sha256": f"{i:064x}"[-64:],
            "content_address": f"sha256-{i:04x}",
        }
        resp = _do_publish(client, headers, entry=entry, mock_text=str(i))
        assert resp.status_code == 200, f"Publish {i+1} failed: {resp.text}"

    # 51st should be 429
    entry_51 = {
        "artifact_id": "skill-51-v1.0.0",
        "sha256": "b" * 64,
        "content_address": "sha256-bbbb",
    }
    resp = _do_publish(client, headers, entry=entry_51, mock_text="999")
    assert resp.status_code == 429
    detail = resp.json()["detail"]
    assert "limit" in detail
    assert "used" in detail
    assert "resets_at" in detail


def test_publisher_exempt_from_limit(client, publisher_auth_headers):
    """D-06, BILL-07: Publisher can publish >50 times without 429."""
    headers = publisher_auth_headers

    for i in range(55):
        entry = {
            "artifact_id": f"pub-skill-{i}-v1.0.0",
            "sha256": f"{i:064x}"[-64:],
            "content_address": f"sha256-{i:04x}",
        }
        resp = _do_publish(client, headers, entry=entry, mock_text=str(i))
        assert resp.status_code == 200, f"Publisher publish {i+1} failed: {resp.text}"


def test_429_response_format(client, user_auth_headers):
    """D-03: 429 response has structured detail with limit, used, resets_at."""
    headers, user_id = user_auth_headers

    # Seed usage_records with count=50 directly
    async def _seed():
        factory = get_async_session_factory()
        async with factory() as session:
            now = datetime.datetime.now(datetime.timezone.utc)
            record = UsageRecord(
                user_id=user_id,
                operation="tlog_publish",
                month=now.strftime("%Y-%m"),
                count=50,
                created_at=now,
            )
            session.add(record)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed())
    loop.close()

    resp = _do_publish(client, headers)
    assert resp.status_code == 429

    body = resp.json()
    detail = body["detail"]
    assert isinstance(detail, dict)
    assert detail["limit"] == 50
    assert detail["used"] == 50
    assert "resets_at" in detail
    assert "Free tier limit reached" in detail["message"]

    # Check Retry-After header
    assert "retry-after" in resp.headers
    retry_after = int(resp.headers["retry-after"])
    assert retry_after > 0


def test_rate_limit_headers_on_success(client, user_auth_headers):
    """BILL-07: Successful User publish includes X-RateLimit-* headers."""
    headers, _ = user_auth_headers

    resp = _do_publish(client, headers)
    assert resp.status_code == 200

    assert resp.headers.get("x-ratelimit-limit") == "50"
    assert resp.headers.get("x-ratelimit-remaining") == "49"
    assert "x-ratelimit-reset" in resp.headers


def test_failed_publish_no_count(client, user_auth_headers):
    """D-10: Failed publishes do not increment usage counter."""
    headers, user_id = user_auth_headers

    # Mock httpx to simulate log service failure (502)
    mock_resp = _mock_publish_success(502, "error")
    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        resp = client.post("/log/publish", json=VALID_ENTRY, headers=headers)

    assert resp.status_code == 502

    # Verify no usage record was created
    async def _check():
        factory = get_async_session_factory()
        async with factory() as session:
            from sqlalchemy import select

            stmt = select(UsageRecord).where(UsageRecord.user_id == user_id)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()
            return record

    loop = asyncio.new_event_loop()
    record = loop.run_until_complete(_check())
    loop.close()
    assert record is None, "Usage should not be counted for failed publish"


def test_month_reset(client, user_auth_headers):
    """D-02: Usage counters are month-scoped; old month doesn't affect current."""
    headers, user_id = user_auth_headers

    # Insert a usage record for a past month with count=50
    async def _seed_old_month():
        factory = get_async_session_factory()
        async with factory() as session:
            record = UsageRecord(
                user_id=user_id,
                operation="tlog_publish",
                month="2025-01",  # Old month
                count=50,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(record)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed_old_month())
    loop.close()

    # Publishing in the current month should succeed
    resp = _do_publish(client, headers)
    assert resp.status_code == 200, "Old month usage should not block current month"


def test_usage_endpoint(client, user_auth_headers):
    """GET /v1/usage returns current usage for authenticated user."""
    headers, _ = user_auth_headers

    resp = client.get("/v1/usage", headers=headers)
    assert resp.status_code == 200

    body = resp.json()
    assert body["operation"] == "tlog_publish"
    assert body["used"] == 0
    assert body["limit"] == 50
    assert "resets_at" in body
