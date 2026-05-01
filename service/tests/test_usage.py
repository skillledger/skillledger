"""Tests for free-tier usage enforcement (BILL-01, BILL-07, D-02, D-03, D-06, D-10)."""

import asyncio
import datetime
import os
from unittest.mock import AsyncMock, MagicMock, patch

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
from skillledger_service.models.usage import Subscription, UsageRecord  # noqa: E402
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


def _do_publish_with_stripe_mock(client, headers, stripe_mock, entry=None, mock_text="42"):
    """Helper: publish with mocked httpx AND mocked stripe client."""
    if entry is None:
        entry = VALID_ENTRY
    mock_resp = _mock_publish_success(200, mock_text)
    with patch("skillledger_service.routers.log.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        with patch("skillledger_service.routers.log.get_stripe_client", return_value=stripe_mock):
            return client.post("/log/publish", json=entry, headers=headers)


def _seed_subscription(user_id, status="active", stripe_customer_id="cus_test123"):
    """Seed a Subscription record for a user."""

    async def _create():
        factory = get_async_session_factory()
        async with factory() as session:
            sub = Subscription(
                user_id=user_id,
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id="sub_test123",
                plan="pay_as_you_go",
                status=status,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(sub)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_create())
    loop.close()


def _seed_usage(user_id, count=50):
    """Seed a UsageRecord at the specified count."""

    async def _seed():
        factory = get_async_session_factory()
        async with factory() as session:
            now = datetime.datetime.now(datetime.timezone.utc)
            record = UsageRecord(
                user_id=user_id,
                operation="tlog_publish",
                month=now.strftime("%Y-%m"),
                count=count,
                created_at=now,
            )
            session.add(record)
            await session.commit()

    loop = asyncio.new_event_loop()
    loop.run_until_complete(_seed())
    loop.close()


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
    _seed_usage(user_id, count=50)

    # Mock Stripe checkout to avoid real API calls
    with patch("skillledger_service.usage.get_stripe_client") as mock_stripe:
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/test"
        mock_client.v1.checkout.sessions.create.return_value = mock_session
        mock_stripe.return_value = mock_client

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
    assert body["billing_status"] == "free"


# ---- New billing-related tests (BILL-02, BILL-03, BILL-06) ----


def test_paid_user_bypasses_limit(client, user_auth_headers):
    """BILL-02, D-11: Paid user with active subscription bypasses 50-publish limit."""
    headers, user_id = user_auth_headers

    # Seed usage at limit
    _seed_usage(user_id, count=50)

    # Seed active subscription
    _seed_subscription(user_id, status="active", stripe_customer_id="cus_test123")

    # Publish should succeed (not 429)
    mock_stripe = MagicMock()
    resp = _do_publish_with_stripe_mock(client, headers, mock_stripe)
    assert resp.status_code == 200, f"Paid user should bypass limit: {resp.text}"


def test_meter_event_on_publish(client, user_auth_headers):
    """BILL-02, D-10: Paid user publish sends Stripe meter event."""
    headers, user_id = user_auth_headers

    # Seed active subscription
    _seed_subscription(user_id, status="active", stripe_customer_id="cus_paid_test")

    # Create mock stripe client
    mock_stripe = MagicMock()

    resp = _do_publish_with_stripe_mock(client, headers, mock_stripe)
    assert resp.status_code == 200

    # Verify meter event was created
    mock_stripe.v1.billing.meter_events.create.assert_called_once()
    call_kwargs = mock_stripe.v1.billing.meter_events.create.call_args
    params = call_kwargs[1]["params"] if "params" in call_kwargs[1] else call_kwargs[0][0]
    if isinstance(params, dict):
        assert params["payload"]["value"] == "1"
        assert params["payload"]["stripe_customer_id"] == "cus_paid_test"


def test_meter_event_failure_does_not_block_publish(client, user_auth_headers):
    """D-10 anti-pattern: Meter event failure should not block publish."""
    headers, user_id = user_auth_headers

    # Seed active subscription
    _seed_subscription(user_id, status="active", stripe_customer_id="cus_fail_test")

    # Create mock stripe client that raises on meter event
    mock_stripe = MagicMock()
    mock_stripe.v1.billing.meter_events.create.side_effect = Exception("Stripe API error")

    resp = _do_publish_with_stripe_mock(client, headers, mock_stripe)
    assert resp.status_code == 200, "Publish should succeed despite meter event failure"


def test_free_user_no_meter_event(client, user_auth_headers):
    """Free user publishes should not trigger Stripe meter events."""
    headers, _ = user_auth_headers

    with patch("skillledger_service.routers.log.get_stripe_client") as mock_get_stripe:
        resp = _do_publish(client, headers)
        assert resp.status_code == 200
        # get_stripe_client should not be called for free users
        mock_get_stripe.assert_not_called()


def test_usage_endpoint_billing_status_free(client, user_auth_headers):
    """BILL-06: Usage endpoint returns billing_status='free' for users without subscription."""
    headers, _ = user_auth_headers

    resp = client.get("/v1/usage", headers=headers)
    assert resp.status_code == 200

    body = resp.json()
    assert body["billing_status"] == "free"
    assert body["limit"] == 50


def test_usage_endpoint_billing_status_active(client, user_auth_headers):
    """BILL-06: Usage endpoint returns billing_status='active' and limit=null for paid users."""
    headers, user_id = user_auth_headers

    # Seed active subscription
    _seed_subscription(user_id, status="active")

    resp = client.get("/v1/usage", headers=headers)
    assert resp.status_code == 200

    body = resp.json()
    assert body["billing_status"] == "active"
    assert body["limit"] is None


def test_429_includes_upgrade_command(client, user_auth_headers):
    """BILL-03: 429 response includes 'skillledger billing upgrade' command."""
    headers, user_id = user_auth_headers
    _seed_usage(user_id, count=50)

    # Mock Stripe to avoid real calls
    with patch("skillledger_service.usage.get_stripe_client") as mock_stripe:
        mock_client = MagicMock()
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/test"
        mock_client.v1.checkout.sessions.create.return_value = mock_session
        mock_stripe.return_value = mock_client

        resp = _do_publish(client, headers)

    assert resp.status_code == 429
    detail = resp.json()["detail"]
    assert "skillledger billing upgrade" in detail.get("upgrade_command", "")


def test_paid_user_no_rate_limit_headers(client, user_auth_headers):
    """Paid users should not receive X-RateLimit-* headers."""
    headers, user_id = user_auth_headers

    # Seed active subscription
    _seed_subscription(user_id, status="active", stripe_customer_id="cus_headers_test")

    mock_stripe = MagicMock()
    resp = _do_publish_with_stripe_mock(client, headers, mock_stripe)
    assert resp.status_code == 200

    # Paid users should NOT have rate limit headers
    assert "x-ratelimit-limit" not in resp.headers
    assert "x-ratelimit-remaining" not in resp.headers
