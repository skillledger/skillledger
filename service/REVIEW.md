# SkillLedger Service: Code Review Report

**Reviewed:** 2026-05-07
**Depth:** deep
**Files Reviewed:** 44 Python files across `service/src/` and `service/tests/`
**Reviewer:** Claude (adversarial review)

---

## Strengths

- **Auth key storage** is properly SHA-256 hashed (`auth.py:16-18`), raw keys never persisted.
- **Admin key comparison** uses `hmac.compare_digest` (`auth.py:60`) -- constant-time as required.
- **OTP brute-force protection** with attempt counting and rate limiting (`auth_router.py:99, 154`).
- **Refresh token rotation** is correctly implemented -- old token deleted before new one issued (`auth_router.py:237`).
- **Webhook signature verification** uses `stripe.Webhook.construct_event` on raw body bytes (`webhooks.py:34-38`).
- **Webhook idempotency** via `stripe_events` table dedup (`webhooks.py:47-52`).
- **SAML SSRF prevention** -- uses `parse()` not `parse_remote()` (`saml.py:143-145`).
- **JIT provisioning blocks owner auto-assignment** (`saml.py:209`).
- **Parameterized queries throughout** -- SQLAlchemy ORM prevents SQL injection.
- **Pydantic v2 input validation** with Field constraints (sha256 pattern, length limits).
- **Test coverage** is solid for core flows: auth, publish, lookup, webhook, ingest.

---

## Critical Issues

### CR-01: JWT Accepts Empty Secret -- Authentication Bypass

**File:** `config.py:25`, `user_auth.py:54-56`, `main.py:30-33`

**Issue:** `jwt_secret` defaults to `""` (empty string). The main.py lifespan only *logs a warning* when it's empty and debug is off (line 30-33), but does not prevent the app from starting. An empty string is a valid HMAC key -- anyone can forge JWTs signed with `""` as the secret. The `decode_token` function at `user_auth.py:56` will happily validate tokens signed with `""`.

This means in production, if `SKILLLEDGER_JWT_SECRET` is not set, every JWT endpoint is trivially bypassable: an attacker generates `jwt.encode(payload, "", algorithm="HS256")` and has full user access.

**Classification:** BLOCKER

**Fix:** Fail-closed at startup. In the lifespan function, raise if jwt_secret is empty in non-debug mode:
```python
if not settings.jwt_secret and not settings.debug:
    raise RuntimeError(
        "SKILLLEDGER_JWT_SECRET must be set in production. "
        "Set SKILLLEDGER_DEBUG=true for development."
    )
```

### CR-02: CORS Middleware Never Applied -- cors_origins Config is Dead Code

**File:** `config.py:29`, `main.py:45-76`

**Issue:** `Settings.cors_origins` is defined (`["https://log.skillledger.dev"]`) but `CORSMiddleware` is never added to the FastAPI app in `create_app()`. The dashboard at `dashboard.skillledger.dev` will fail on all fetch requests due to missing CORS headers, OR (worse) the default behavior allows no CORS, which may push developers to disable CORS entirely as a workaround.

**Classification:** BLOCKER

**Fix:** Add CORS middleware in `create_app()`:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### CR-03: OTP Verification Uses Non-Constant-Time Comparison

**File:** `auth_router.py:161-163`

**Issue:** OTP hash comparison uses `code_hash != otp.otp_hash` (line 163), which is a standard string comparison and susceptible to timing attacks. While the OTP is only 6 digits (1M combinations) making timing attacks less practical, the CLAUDE.md security conventions state constant-time comparison for all secrets, and combined with no per-IP rate limiting (only per-email), this is exploitable at scale.

**Classification:** BLOCKER

**Fix:**
```python
import hmac
if not hmac.compare_digest(code_hash, otp.otp_hash):
```

### CR-04: Webhook Idempotency Check Has TOCTOU Race Condition

**File:** `webhooks.py:47-67`

**Issue:** The idempotency check (SELECT at line 47) and INSERT (line 56-62) are not atomic. Two concurrent webhook deliveries of the same event can both pass the SELECT check before either inserts, causing duplicate processing. The `stripe_event_id` unique constraint will cause one to fail with an unhandled IntegrityError, crashing that request with a 500.

**Classification:** BLOCKER

**Fix:** Use `SELECT ... FOR UPDATE` or wrap in try/except for IntegrityError:
```python
try:
    session.add(stripe_event)
    await session.flush()  # Trigger unique constraint check
except IntegrityError:
    await session.rollback()
    return {"status": "ok"}  # Already processed
```

---

## Warnings

### WR-01: Database Session Not Yielded as Context Manager in Webhook Handler

**File:** `webhooks.py:44-68`

**Issue:** The webhook handler creates its own session (`async with factory() as session`) instead of using the `get_session` dependency. This bypasses any session middleware or cleanup logic. More critically, if `_handle_event` raises an exception after the StripeEvent record is added (line 62) but before commit (line 67), the exception propagates without rollback, and the `async with` may or may not rollback depending on SQLAlchemy version behavior.

**Classification:** WARNING

**Fix:** Add explicit rollback in exception handling, or use `try/except/rollback` pattern inside the `async with`.

### WR-02: `resend.api_key` Set as Module-Level Global -- Thread Safety Issue

**File:** `email.py:9`, `ee/routers/orgs.py:255`

**Issue:** `resend.api_key = api_key` mutates a module-level global. If the service runs with multiple workers or concurrent async tasks, this is a shared mutable state issue. Additionally, `orgs.py:255` sets it again before sending invite emails. In concurrent requests, one coroutine's `resend.api_key` assignment could be overwritten by another.

**Classification:** WARNING

**Fix:** Use Resend's client API if available, or ensure the API key is set once at startup rather than per-call.

### WR-03: `_resolve_database_url()` Called at Class Definition Time

**File:** `config.py:6-15, 21`

**Issue:** `database_url: str = _resolve_database_url()` is evaluated when the `Settings` class is *defined* (module import time), not when `Settings()` is instantiated. This means:
1. Environment variables set after import but before instantiation are ignored
2. The `SKILLLEDGER_DATABASE_URL` env var from the pydantic-settings `env_prefix` mechanism is bypassed for this field
3. Test fixtures that set env vars after import don't affect this default

The `lru_cache` on `get_settings()` partially masks this in practice, but it's architecturally wrong.

**Classification:** WARNING

**Fix:** Use a `model_validator` or `@field_validator` to resolve the URL at instantiation time, or use pydantic-settings' native env var resolution.

### WR-04: `get_session` Generator Missing Rollback on Exception

**File:** `db.py:25-28`

**Issue:** The `get_session` dependency yields a session but has no `try/finally` to ensure rollback on unhandled exceptions. If an endpoint raises after modifying the session but before committing, the session may be returned to the pool in a dirty state.

```python
async def get_session():
    factory = get_async_session_factory()
    async with factory() as session:
        yield session  # No try/finally/rollback
```

**Classification:** WARNING

**Fix:**
```python
async def get_session():
    factory = get_async_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
```

### WR-05: Publish Endpoint Double-Commits with No Atomicity Guarantee

**File:** `routers/log.py:103-123`

**Issue:** The publish endpoint commits the log entry record (line 105), then commits usage increment separately (line 123). If the process crashes between these two commits, the log entry is recorded but usage is not counted. Over time this creates billing leakage. Both operations should be in a single transaction.

**Classification:** WARNING

### WR-06: `increment_usage` Has Race Condition Under Concurrent Access

**File:** `usage.py:45-78`

**Issue:** `increment_usage` does SELECT then UPDATE without `FOR UPDATE` or an atomic upsert. Two concurrent requests for the same user+month+operation will both read the same count, both increment to the same value, and one increment is lost. This means free-tier users can exceed their 50-publish limit.

**Classification:** WARNING

**Fix:** Add `.with_for_update()` to the select, or use a database-level atomic increment:
```python
stmt = select(UsageRecord).where(...).with_for_update()
```

### WR-07: Stripe Meter Event Uses Synchronous API Call in Async Context

**File:** `routers/log.py:138-154`

**Issue:** `stripe_client.v1.billing.meter_events.create()` at line 140 is a synchronous Stripe SDK call inside an async endpoint. This blocks the event loop for the duration of the HTTP call to Stripe, degrading throughput for all concurrent requests.

**Classification:** WARNING

**Fix:** Run in a thread via `asyncio.to_thread()` or use the async Stripe client.

### WR-08: `saml_config.py` Uses PostgreSQL-Specific JSON Column Type

**File:** `models/saml_config.py:6`

**Issue:** `from sqlalchemy.dialects.postgresql import JSON` -- this import uses the PostgreSQL-specific JSON type. Other models use `sqlalchemy.JSON` (generic). While this works because SQLAlchemy falls back to the generic type on non-PostgreSQL databases, it's inconsistent and will break if PostgreSQL-specific JSON operators (e.g., `@>`, `->>`) are used in queries against this column.

**Classification:** WARNING

**Fix:** Use `from sqlalchemy import JSON` for consistency with other models.

### WR-09: Lookup Endpoint Unauthenticated -- Potential Information Leakage

**File:** `routers/log.py:167-191`

**Issue:** The `/log/lookup/{artifact_id}` endpoint has no authentication requirement. Anyone can enumerate artifact IDs and discover publisher names, content addresses, and publication timestamps. While transparency logs are generally public, this should be a conscious design decision documented in the security model, not an accidental omission.

**Classification:** WARNING

### WR-10: ETag Uses MD5 for Policy Content Hash

**File:** `ee/routers/policy.py:137`

**Issue:** `hashlib.md5(policy.rego.encode()).hexdigest()` -- MD5 is used for the ETag. While ETags don't require cryptographic strength, the threat library endpoint uses SHA-256 for the same purpose (`threat_library.py:61`). Inconsistency signals carelessness. The `threat_library.py` approach is correct.

**Classification:** WARNING

**Fix:** Use `hashlib.sha256` for consistency.

---

## Info

### IN-01: `secrets` Import Unused in `publisher.py`

**File:** `models/publisher.py:2`

**Issue:** `import secrets` is imported but never used in the file.

**Classification:** INFO (unused import)

### IN-02: `_next_month_reset` and `check_tlog_limit` Internal Names Exported

**File:** `usage.py:81`, imported in `routers/log.py:18-22` and `routers/usage_router.py:16`

**Issue:** `_next_month_reset` has a leading underscore indicating it's private, but it's imported and used by two other modules. Either rename it to remove the underscore (making it part of the public API), or provide a proper public wrapper.

**Classification:** INFO

### IN-03: Hardcoded URLs in Billing Router

**File:** `routers/billing.py:69-70, 98`

**Issue:** `https://skillledger.dev/billing/success`, `https://skillledger.dev/billing/cancel`, and `https://skillledger.dev` are hardcoded. The dashboard URL is configurable via `settings.dashboard_url` and `settings.service_url`, but billing uses neither.

**Classification:** INFO

**Fix:** Use `settings.dashboard_url` or `settings.service_url` for consistency.

### IN-04: Event Loop Created per Test Fixture -- Deprecation Risk

**File:** Multiple test files (e.g., `test_auth.py:27-29`, `test_log.py:37-39`)

**Issue:** Tests create `asyncio.new_event_loop()` manually to run async setup code. This pattern is deprecated in newer pytest-asyncio versions and creates overhead. Consider using `pytest-asyncio` fixtures with `@pytest.fixture` async support.

**Classification:** INFO

### IN-05: Missing Input Validation on `ProfileRequest.capabilities`

**File:** `ee/routers/profiles.py:40`

**Issue:** `capabilities: list` accepts any list content with no validation -- could contain arbitrary nested objects of unlimited depth. Consider adding `max_length` or a more specific type.

**Classification:** INFO

### IN-06: `EventItem.details` Has Mutable Default Argument

**File:** `ee/routers/events.py:47`

**Issue:** `details: dict = {}` uses a mutable default. While Pydantic handles this correctly (creates a new dict per instance), it's a bad pattern that could be confusing. Use `Field(default_factory=dict)` for clarity.

**Classification:** INFO

---

## Assessment

| Category | Score (1-10) | Notes |
|----------|:----:|-------|
| **Overall Quality** | 7 | Well-structured FastAPI app with clean separation. Async patterns are mostly correct. Models are well-defined. |
| **Security Posture** | 5 | The empty JWT secret default is a serious production risk. OTP timing attack surface exists. CORS is configured but never applied. Webhook race condition exists. Core API key auth is solid. |
| **Test Coverage** | 7 | Good coverage of happy paths and key error cases (auth, webhooks, ingest, publishers). Missing: usage limit tests, billing endpoint tests with real flow, SAML endpoint tests in the main test suite, concurrent access tests. |

### Summary

The codebase demonstrates strong fundamentals -- proper use of SQLAlchemy async sessions, Pydantic v2 validation, Sigstore-compatible auth patterns, and solid webhook handling. However, **four issues must be resolved before shipping**: the empty JWT secret that enables auth bypass in production (CR-01), the CORS middleware that's configured but never applied (CR-02), the non-constant-time OTP comparison (CR-03), and the webhook idempotency race condition (CR-04). The session management and usage tracking race conditions (WR-04, WR-06) should also be addressed to prevent data integrity issues under load.
