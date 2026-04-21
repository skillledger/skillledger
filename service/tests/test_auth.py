import asyncio
import hashlib
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ["SKILLLEDGER_ADMIN_API_KEY"] = "test-admin-key-12345"

from skillledger_service.auth import generate_api_key, hash_api_key  # noqa: E402
from skillledger_service.db import get_engine  # noqa: E402
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.publisher import APIKey, Publisher  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_db():
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
def publisher_with_key():
    """Create a publisher with an API key and return (publisher_name, raw_key)."""
    import datetime
    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)

    async def _create():
        from skillledger_service.db import get_async_session_factory
        factory = get_async_session_factory()
        async with factory() as session:
            pub = Publisher(
                name="test-publisher",
                contact_email="test@example.com",
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
    return "test-publisher", raw_key


def test_hash_api_key_deterministic():
    key = "test-key-abc123"
    assert hash_api_key(key) == hashlib.sha256(key.encode()).hexdigest()
    assert hash_api_key(key) == hash_api_key(key)


def test_generate_api_key_length():
    key = generate_api_key()
    assert len(key) == 64  # 32 bytes = 64 hex chars


def test_generate_api_key_unique():
    keys = {generate_api_key() for _ in range(100)}
    assert len(keys) == 100


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


def test_publish_requires_auth(client):
    """Publish endpoint must return 403 without Bearer token."""
    with _mock_httpx_post():
        response = client.post("/log/publish", json={
            "artifact_id": "test-skill-v1.0.0",
            "sha256": "a" * 64,
            "content_address": "sha256-aaaa",
        })
    # Auth is now wired to publish route (Plan 02).
    # HTTPBearer returns 401/403 when no credentials header is present.
    assert response.status_code in (401, 403)


def test_publish_rejects_invalid_key(client):
    """Publish endpoint must return 401 with invalid Bearer token."""
    with _mock_httpx_post():
        response = client.post(
            "/log/publish",
            json={
                "artifact_id": "test-skill-v1.0.0",
                "sha256": "a" * 64,
                "content_address": "sha256-aaaa",
                "publisher": "test-publisher",
            },
            headers={"Authorization": "Bearer invalid-key-xyz"},
        )
    # Auth is now wired to publish route (Plan 02).
    assert response.status_code == 401
