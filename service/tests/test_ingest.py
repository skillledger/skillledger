"""Tests for the admin threat-library ingestion endpoint (POST /v1/admin/threat-library/ingest).

Covers: admin auth enforcement, hash/domain/rule upsert, idempotency,
field updates on upsert, severity validation, and empty payloads.
"""

import asyncio
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
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402

ADMIN_HEADERS = {"Authorization": "Bearer test-admin-key-12345"}
INGEST_URL = "/v1/admin/threat-library/ingest"


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
    with patch("skillledger_service.main.seed_threat_data", new_callable=AsyncMock):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _make_user_token(email: str = "ingest-test@example.com") -> str:
    """Create a user in DB and return a JWT."""
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

    return create_access_token(user_id, email, os.environ["SKILLLEDGER_JWT_SECRET"])


# --- Tests ---


def test_ingest_requires_admin(client):
    """POST without auth returns 401/403; POST with user JWT returns 403."""
    # No auth at all
    resp = client.post(INGEST_URL, json={"hashes": [], "domains": [], "rules": []})
    assert resp.status_code in (401, 403)

    # User JWT (not admin key)
    user_token = _make_user_token()
    resp = client.post(
        INGEST_URL,
        json={"hashes": [], "domains": [], "rules": []},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403


def test_ingest_hashes(client):
    """Admin can ingest IOC hashes; they appear via GET /v1/ioc."""
    payload = {
        "hashes": [
            {
                "sha256": "a" * 64,
                "description": "test malicious hash",
                "severity": "critical",
                "source": "community",
                "reported_at": "2026-01-01",
            }
        ],
        "domains": [],
        "rules": [],
    }
    resp = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["hashes_upserted"] == 1
    assert data["domains_upserted"] == 0
    assert data["rules_upserted"] == 0

    # Verify via GET /v1/ioc (requires user JWT)
    user_token = _make_user_token()
    ioc_resp = client.get("/v1/ioc", headers={"Authorization": f"Bearer {user_token}"})
    assert ioc_resp.status_code == 200
    ioc_data = ioc_resp.json()
    assert len(ioc_data["hashes"]) == 1
    assert ioc_data["hashes"][0]["sha256"] == "a" * 64


def test_ingest_domains(client):
    """Admin can ingest IOC domains; they appear via GET /v1/ioc."""
    payload = {
        "hashes": [],
        "domains": [
            {
                "domain": "evil.example.com",
                "description": "C2 domain",
                "severity": "high",
                "source": "community",
                "reported_at": "2026-01-01",
            }
        ],
        "rules": [],
    }
    resp = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["domains_upserted"] == 1

    user_token = _make_user_token("domain-test@example.com")
    ioc_resp = client.get("/v1/ioc", headers={"Authorization": f"Bearer {user_token}"})
    assert ioc_resp.status_code == 200
    assert len(ioc_resp.json()["domains"]) == 1
    assert ioc_resp.json()["domains"][0]["domain"] == "evil.example.com"


def test_ingest_rules(client):
    """Admin can ingest YARA rules; they appear via GET /v1/yara."""
    payload = {
        "hashes": [],
        "domains": [],
        "rules": [
            {
                "name": "test_rule",
                "content": "rule test_rule { condition: true }",
                "source": "community",
            }
        ],
    }
    resp = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rules_upserted"] == 1

    user_token = _make_user_token("yara-test@example.com")
    yara_resp = client.get("/v1/yara", headers={"Authorization": f"Bearer {user_token}"})
    assert yara_resp.status_code == 200
    assert len(yara_resp.json()["rules"]) == 1
    assert yara_resp.json()["rules"][0]["name"] == "test_rule"


def test_ingest_idempotent(client):
    """Ingesting the same hash twice does not create duplicates."""
    payload = {
        "hashes": [
            {
                "sha256": "b" * 64,
                "description": "first insert",
                "severity": "medium",
                "source": "community",
            }
        ],
    }

    # First ingest
    resp1 = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp1.status_code == 200
    assert resp1.json()["hashes_upserted"] == 1

    # Second ingest (same sha256)
    resp2 = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp2.status_code == 200
    assert resp2.json()["hashes_upserted"] == 1

    # Verify only 1 hash exists
    user_token = _make_user_token("idempotent-test@example.com")
    ioc_resp = client.get("/v1/ioc", headers={"Authorization": f"Bearer {user_token}"})
    assert ioc_resp.status_code == 200
    assert len(ioc_resp.json()["hashes"]) == 1


def test_ingest_upsert_updates_fields(client):
    """Upserting an existing hash updates its description and severity."""
    original = {
        "hashes": [
            {
                "sha256": "c" * 64,
                "description": "original description",
                "severity": "low",
                "source": "community",
            }
        ],
    }
    updated = {
        "hashes": [
            {
                "sha256": "c" * 64,
                "description": "updated description",
                "severity": "critical",
                "source": "community-v2",
            }
        ],
    }

    client.post(INGEST_URL, json=original, headers=ADMIN_HEADERS)
    client.post(INGEST_URL, json=updated, headers=ADMIN_HEADERS)

    user_token = _make_user_token("upsert-test@example.com")
    ioc_resp = client.get("/v1/ioc", headers={"Authorization": f"Bearer {user_token}"})
    assert ioc_resp.status_code == 200
    h = ioc_resp.json()["hashes"][0]
    assert h["description"] == "updated description"
    assert h["severity"] == "critical"
    assert h["source"] == "community-v2"


def test_ingest_invalid_severity(client):
    """Invalid severity value returns 422."""
    payload = {
        "hashes": [
            {
                "sha256": "d" * 64,
                "description": "test",
                "severity": "unknown",
                "source": "community",
            }
        ],
    }
    resp = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp.status_code == 422
    assert "unknown" in resp.json()["detail"].lower()

    # Also test for domains
    payload2 = {
        "domains": [
            {
                "domain": "bad.example.com",
                "description": "test",
                "severity": "foo",
                "source": "community",
            }
        ],
    }
    resp2 = client.post(INGEST_URL, json=payload2, headers=ADMIN_HEADERS)
    assert resp2.status_code == 422


def test_ingest_empty_payload(client):
    """Empty arrays return 200 with all counts 0."""
    payload = {"hashes": [], "domains": [], "rules": []}
    resp = client.post(INGEST_URL, json=payload, headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["hashes_upserted"] == 0
    assert data["domains_upserted"] == 0
    assert data["rules_upserted"] == 0
