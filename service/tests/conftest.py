"""Shared test fixtures for the SkillLedger service test suite.

Clears lru_cache on get_settings/get_engine/get_async_session_factory before
each test so environment variable overrides (e.g. SKILLLEDGER_JWT_SECRET) take
effect regardless of test ordering.
"""

import os

import pytest

# Set JWT secret before any module imports db.py / get_settings()
os.environ.setdefault("SKILLLEDGER_JWT_SECRET", "test-secret-for-ci")


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Clear all lru_cache'd singletons so env vars are re-read per test."""
    from skillledger_service.db import get_async_session_factory, get_engine, get_settings

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_async_session_factory.cache_clear()
    yield
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_async_session_factory.cache_clear()
