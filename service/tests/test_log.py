import asyncio
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

# Use in-memory SQLite for tests -- must be set before any imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"

from skillledger_service.db import engine  # noqa: E402
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402

VALID_ENTRY = {
    "artifact_id": "test-skill-v1.0.0",
    "sha256": "a" * 64,
    "content_address": "sha256:aaaa",
    "publisher": "test-publisher",
}


@pytest.fixture(autouse=True)
def _reset_db():
    """Drop and recreate all tables before each test for isolation."""

    async def _reset():
        async with engine.begin() as conn:
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


def _mock_httpx_response(status_code=200, text="42"):
    resp = AsyncMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    return resp


def _patch_httpx(mock_client_instance):
    """Return a context manager that patches httpx.AsyncClient."""
    mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_client_instance.__aexit__ = AsyncMock(return_value=False)

    p = patch("skillledger_service.routers.log.httpx.AsyncClient")

    def _start():
        mock_cls = p.start()
        mock_cls.return_value = mock_client_instance
        return p

    return _start, p.stop


def test_publish_success(client):
    mock_resp = _mock_httpx_response(200, "42")

    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        response = client.post("/log/publish", json=VALID_ENTRY)

    assert response.status_code == 200
    data = response.json()
    assert data["log_index"] == 42
    assert data["artifact_id"] == "test-skill-v1.0.0"


def test_publish_invalid_sha256(client):
    bad_entry = {**VALID_ENTRY, "sha256": "bad"}
    response = client.post("/log/publish", json=bad_entry)
    assert response.status_code == 422


def test_publish_log_unavailable(client):
    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        response = client.post("/log/publish", json=VALID_ENTRY)

    assert response.status_code == 502
    assert "unavailable" in response.json()["detail"].lower()


def test_publish_log_busy(client):
    mock_resp = _mock_httpx_response(503, "busy")

    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        response = client.post("/log/publish", json=VALID_ENTRY)

    assert response.status_code == 503
    assert "busy" in response.json()["detail"].lower()


def test_lookup_not_found(client):
    response = client.get("/log/lookup/nonexistent")
    assert response.status_code == 404


def test_lookup_after_publish(client):
    mock_resp = _mock_httpx_response(200, "99")

    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        pub_response = client.post("/log/publish", json=VALID_ENTRY)
        assert pub_response.status_code == 200

    lookup_response = client.get(f"/log/lookup/{VALID_ENTRY['artifact_id']}")
    assert lookup_response.status_code == 200
    data = lookup_response.json()
    assert data["artifact_id"] == VALID_ENTRY["artifact_id"]
    assert data["sha256"] == VALID_ENTRY["sha256"]
    assert data["log_index"] == 99
    assert data["publisher"] == VALID_ENTRY["publisher"]
