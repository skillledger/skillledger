import asyncio
import datetime
import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_ADMIN_API_KEY"] = "test-admin-key-12345"
os.environ["SKILLLEDGER_JWT_SECRET"] = "test-secret-for-tests-minimum-length-32bytes!"
os.environ["SKILLLEDGER_RESEND_API_KEY"] = "re_test_fake"
os.environ["SKILLLEDGER_DEBUG"] = "true"

from skillledger_service.db import get_async_session_factory, get_engine  # noqa: E402
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.threat import IocDomain, IocHash, YaraRule  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402


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
    # Patch seed_threat_data to prevent auto-seeding from bundled CLI data
    with patch("skillledger_service.main.seed_threat_data", new_callable=AsyncMock):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _create_user_with_jwt(email: str = "threat-test@example.com"):
    """Create a user and return (user_id, access_token)."""
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


def _insert_ioc_hash(sha256: str, description: str = "test hash", severity: str = "high"):
    """Insert an IocHash record for testing."""
    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            h = IocHash(
                sha256=sha256,
                description=description,
                severity=severity,
                source="test",
                reported_at="2026-01-01",
            )
            session.add(h)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


def _insert_ioc_domain(domain: str, description: str = "test domain", severity: str = "medium"):
    """Insert an IocDomain record for testing."""
    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            d = IocDomain(
                domain=domain,
                description=description,
                severity=severity,
                source="test",
                reported_at="2026-02-01",
            )
            session.add(d)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


def _insert_yara_rule(name: str, content: str = "rule test { condition: true }"):
    """Insert a YaraRule record for testing."""
    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            r = YaraRule(
                name=name,
                content=content,
                source="test",
            )
            session.add(r)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


# --- Tests ---


def test_ioc_unauthenticated(client):
    """GET /v1/ioc without Bearer token returns 401 (SYNC-08)."""
    resp = client.get("/v1/ioc")
    assert resp.status_code in (401, 403)


def test_yara_unauthenticated(client):
    """GET /v1/yara without Bearer token returns 401 (SYNC-08)."""
    resp = client.get("/v1/yara")
    assert resp.status_code in (401, 403)


def test_ioc_empty(client):
    """Authenticated GET /v1/ioc on empty DB returns empty envelope (D-05)."""
    _, token = _create_user_with_jwt()
    resp = client.get(
        "/v1/ioc",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["updated_at"] is None
    assert data["count"] == 0
    assert data["hashes"] == []
    assert data["domains"] == []


def test_yara_empty(client):
    """Authenticated GET /v1/yara on empty DB returns empty envelope (D-05)."""
    _, token = _create_user_with_jwt()
    resp = client.get(
        "/v1/yara",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["updated_at"] is None
    assert data["count"] == 0
    assert data["rules"] == []


def test_ioc_with_data(client):
    """GET /v1/ioc returns IOC hashes and domains in correct envelope (SYNC-05, D-04)."""
    _, token = _create_user_with_jwt()
    _insert_ioc_hash("a" * 64, description="malicious hash", severity="critical")
    _insert_ioc_domain("evil.example.com", description="C2 domain", severity="high")

    resp = client.get(
        "/v1/ioc",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    assert len(data["hashes"]) == 1
    assert len(data["domains"]) == 1
    assert data["hashes"][0]["sha256"] == "a" * 64
    assert data["hashes"][0]["severity"] == "critical"
    assert data["domains"][0]["domain"] == "evil.example.com"
    assert data["updated_at"] is not None


def test_yara_with_data(client):
    """GET /v1/yara returns YARA rules in correct envelope (SYNC-06, D-04)."""
    _, token = _create_user_with_jwt()
    _insert_yara_rule("test_rule", "rule test_rule { condition: true }")

    resp = client.get(
        "/v1/yara",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert len(data["rules"]) == 1
    assert data["rules"][0]["name"] == "test_rule"
    assert data["rules"][0]["content"] == "rule test_rule { condition: true }"
    assert data["rules"][0]["source"] == "test"
    assert data["updated_at"] is not None


def test_ioc_etag_304(client):
    """First GET returns 200 with ETag; second GET with matching ETag returns 304 (SYNC-04, D-06)."""
    _, token = _create_user_with_jwt()
    headers = {"Authorization": f"Bearer {token}"}

    # First request -- get the ETag
    resp1 = client.get("/v1/ioc", headers=headers)
    assert resp1.status_code == 200
    etag = resp1.headers.get("etag")
    assert etag is not None

    # Second request with If-None-Match
    resp2 = client.get(
        "/v1/ioc",
        headers={**headers, "If-None-Match": etag},
    )
    assert resp2.status_code == 304


def test_yara_etag_304(client):
    """ETag conditional fetch for /v1/yara returns 304 (SYNC-04, D-06)."""
    _, token = _create_user_with_jwt()
    headers = {"Authorization": f"Bearer {token}"}

    resp1 = client.get("/v1/yara", headers=headers)
    assert resp1.status_code == 200
    etag = resp1.headers.get("etag")
    assert etag is not None

    resp2 = client.get(
        "/v1/yara",
        headers={**headers, "If-None-Match": etag},
    )
    assert resp2.status_code == 304


def test_ioc_etag_mismatch(client):
    """GET with wrong ETag returns 200 with full body."""
    _, token = _create_user_with_jwt()
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get(
        "/v1/ioc",
        headers={**headers, "If-None-Match": '"wrong-etag-value"'},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data


def test_ioc_cache_control(client):
    """Response includes Cache-Control: private, max-age=300 (D-07)."""
    _, token = _create_user_with_jwt()
    resp = client.get(
        "/v1/ioc",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    cc = resp.headers.get("cache-control")
    assert cc == "private, max-age=300"
