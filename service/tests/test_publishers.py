import asyncio
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SKILLLEDGER_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SKILLLEDGER_LOG_URL", "http://fake-log:2025")
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-bootstrap-key")

from skillledger_service.db import get_engine, get_settings  # noqa: E402
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402


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


# Read admin key from cached settings to handle test ordering (lru_cache on get_settings)
ADMIN_HEADERS = {"Authorization": f"Bearer {get_settings().admin_api_key}"}


def test_create_publisher(client):
    response = client.post(
        "/publishers",
        json={"name": "my-publisher", "contact_email": "dev@example.com"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "my-publisher"
    assert data["contact_email"] == "dev@example.com"
    assert data["active"] is True
    assert "id" in data


def test_create_publisher_duplicate(client):
    client.post(
        "/publishers",
        json={"name": "dup-publisher"},
        headers=ADMIN_HEADERS,
    )
    response = client.post(
        "/publishers",
        json={"name": "dup-publisher"},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 409


def test_create_publisher_requires_auth(client):
    response = client.post("/publishers", json={"name": "unauthorized"})
    # HTTPBearer returns 401 or 403 when no credentials header is present
    assert response.status_code in (401, 403)


def test_list_publishers(client):
    client.post("/publishers", json={"name": "pub-a"}, headers=ADMIN_HEADERS)
    client.post("/publishers", json={"name": "pub-b"}, headers=ADMIN_HEADERS)
    response = client.get("/publishers", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    names = [p["name"] for p in data]
    assert "pub-a" in names
    assert "pub-b" in names


def test_create_api_key(client):
    # Create publisher first
    pub_resp = client.post(
        "/publishers", json={"name": "key-publisher"}, headers=ADMIN_HEADERS
    )
    pub_id = pub_resp.json()["id"]

    # Create key
    key_resp = client.post(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    assert "raw_key" in key_data
    assert len(key_data["raw_key"]) == 64
    assert key_data["key_prefix"] == key_data["raw_key"][:8]
    assert key_data["publisher_name"] == "key-publisher"


def test_list_keys(client):
    pub_resp = client.post(
        "/publishers", json={"name": "list-keys-pub"}, headers=ADMIN_HEADERS
    )
    pub_id = pub_resp.json()["id"]
    client.post(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)
    client.post(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)

    list_resp = client.get(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert len(keys) == 2
    # Raw key must NOT be in list response
    for k in keys:
        assert "raw_key" not in k
        assert "key_prefix" in k


def test_revoke_key(client):
    pub_resp = client.post(
        "/publishers", json={"name": "revoke-pub"}, headers=ADMIN_HEADERS
    )
    pub_id = pub_resp.json()["id"]
    client.post(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)

    # Get key ID from list
    list_resp = client.get(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)
    key_id = list_resp.json()[0]["id"]

    # Revoke
    del_resp = client.delete(f"/publishers/{pub_id}/keys/{key_id}", headers=ADMIN_HEADERS)
    assert del_resp.status_code == 204

    # Verify revoked
    list_resp2 = client.get(f"/publishers/{pub_id}/keys", headers=ADMIN_HEADERS)
    assert list_resp2.json()[0]["revoked"] is True


def test_publisher_not_found_for_key(client):
    response = client.post("/publishers/9999/keys", headers=ADMIN_HEADERS)
    assert response.status_code == 404
