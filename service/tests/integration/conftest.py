"""Shared fixtures for integration tests (UAT dashboard scenarios).

Sets up in-memory SQLite, resets DB between tests, and provides
helpers to create users with JWT tokens and EE-licensed apps.
"""

import asyncio
import datetime
import hashlib
import os

import pytest

# Environment must be set before importing any service modules
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_LOG_URL"] = "http://fake-log:2025"
os.environ.setdefault("SKILLLEDGER_ADMIN_API_KEY", "test-admin-key-integration")
os.environ.setdefault("SKILLLEDGER_RESEND_API_KEY", "re_test_fake")
os.environ.setdefault("SKILLLEDGER_JWT_SECRET", "test-secret-for-integration")
os.environ.setdefault("SKILLLEDGER_DEBUG", "true")

from fastapi.testclient import TestClient  # noqa: E402

from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.organization import OrgMembership, OrgRole  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402

# EE license setup
_LICENSE_KEY = "test-license-key-integration"
_LICENSE_HASH = hashlib.sha256(_LICENSE_KEY.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _reset_db():
    """Drop and recreate all tables between tests."""
    async def _reset():
        async with get_engine().begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_reset())
    loop.close()
    yield


def _make_ee_app():
    """Create app with EE license enabled."""
    os.environ["SKILLLEDGER_EE_LICENSE_KEY"] = _LICENSE_KEY
    os.environ["SKILLLEDGER_EE_LICENSE_HASH"] = _LICENSE_HASH
    get_settings.cache_clear()
    return create_app()


def _make_app():
    """Create app without EE license."""
    os.environ.pop("SKILLLEDGER_EE_LICENSE_KEY", None)
    os.environ.pop("SKILLLEDGER_EE_LICENSE_HASH", None)
    get_settings.cache_clear()
    return create_app()


@pytest.fixture
def client():
    """TestClient without EE features."""
    app = _make_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def ee_client():
    """TestClient with EE features enabled."""
    app = _make_ee_app()
    with TestClient(app) as c:
        yield c


def create_test_user(email: str) -> dict:
    """Create a user in the DB and return id, email, and auth headers."""
    holder: dict = {}

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            user = User(
                email=email,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            holder["id"] = user.id
            holder["email"] = user.email

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()
    settings = get_settings()
    token = create_access_token(holder["id"], holder["email"], settings.jwt_secret)
    holder["token"] = token
    holder["headers"] = {"Authorization": f"Bearer {token}"}
    return holder


def create_org_via_api(client, headers, name="Test Org"):
    """Create an org via the EE API and return the response JSON."""
    resp = client.post("/ee/v1/orgs", json={"name": name}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def add_org_membership(org_id: int, user_id: int, role: OrgRole):
    """Directly insert an org membership record."""
    async def _insert():
        factory = get_async_session_factory()
        async with factory() as session:
            m = OrgMembership(user_id=user_id, org_id=org_id, role=role)
            session.add(m)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_insert())
    loop.close()
