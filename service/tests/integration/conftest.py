"""Integration test fixtures for SkillLedger service UAT scenarios.

Provides shared setup: in-memory SQLite, app client, user creation helpers,
and JWT generation utilities.
"""

import asyncio
import datetime
import os

import pytest

# Set env vars before any module imports
os.environ["SKILLLEDGER_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SKILLLEDGER_JWT_SECRET"] = "integration-test-secret-minimum-32-bytes-long!"
os.environ["SKILLLEDGER_ADMIN_API_KEY"] = "integration-test-admin-key"
os.environ["SKILLLEDGER_RESEND_API_KEY"] = "re_test_fake"
os.environ["SKILLLEDGER_DEBUG"] = "true"
os.environ["SKILLLEDGER_TEST_MODE"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from skillledger_service.auth import hash_api_key  # noqa: E402
from skillledger_service.db import (  # noqa: E402
    get_async_session_factory,
    get_engine,
    get_settings,
)
from skillledger_service.main import create_app  # noqa: E402
from skillledger_service.models import Base  # noqa: E402
from skillledger_service.models.user import User  # noqa: E402
from skillledger_service.user_auth import create_access_token  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear lru_cache singletons so env vars take effect."""
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_async_session_factory.cache_clear()
    yield
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_async_session_factory.cache_clear()


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
    """Create a test client for the FastAPI app."""
    app = create_app()
    with TestClient(app) as c:
        yield c


def create_test_user(email: str = "testuser@example.com") -> User:
    """Insert a User record into the DB and return it."""
    holder = {}

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

    # Return a simple object with id and email
    class UserInfo:
        def __init__(self, id, email):
            self.id = id
            self.email = email

    return UserInfo(holder["id"], holder["email"])


def get_valid_token(user_id: int, email: str) -> str:
    """Generate a valid JWT access token for the given user."""
    settings = get_settings()
    return create_access_token(user_id, email, settings.jwt_secret)
