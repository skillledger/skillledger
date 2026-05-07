# SkillLedger Service: Alembic Migrations & App Factory Review

**Reviewed:** 2026-05-07
**Scope:** `service/alembic/` (env.py, 8 migrations), `service/src/skillledger_service/main.py`, `alembic.ini`, `config.py`, `db.py`

---

## Strengths

- **Migration reversibility (all 8 files):** Every migration has a correct `downgrade()` that reverses tables in dependency-safe order (child tables dropped before parents).
- **Migration 006 downgrade (lines 94-103):** Properly drops added columns and indexes in reverse order.
- **env.py:16-20:** Database URL override from env var with automatic `postgresql://` to `postgresql+asyncpg://` rewriting is clean.
- **main.py:23-42:** Proper use of `asynccontextmanager` lifespan with engine disposal on shutdown.
- **Migration 004:25-27:** Good use of composite unique constraint + explicit index on `usage_records`.
- **Migration 006:62-64, 87-91:** Composite indexes on high-cardinality query paths (org_events, org_profiles).
- **Migration 005:100:** Downgrade correctly drops the `orgrole` enum type after dropping dependent tables.

---

## Issues

### Critical

#### CR-01: JWT secret silently falls back to insecure default in production

**File:** `service/src/skillledger_service/main.py:30-33`

**Issue:** When `jwt_secret` is empty and `debug` is false, the code only logs a warning but continues startup. Looking at `config.py:25`, `jwt_secret` defaults to empty string `""`. Any downstream JWT signing/verification using this empty string means tokens are trivially forgeable in production -- an attacker can sign any JWT payload with `""` as the HMAC key.

**Why it matters:** Authentication bypass. The entire auth layer (user login, API key issuance, session management) is compromised if JWT tokens can be forged.

**Fix:** Fail-closed -- refuse to start in non-debug mode without a JWT secret:
```python
if not settings.jwt_secret and not settings.debug:
    raise RuntimeError(
        "SKILLLEDGER_JWT_SECRET must be set in production. "
        "Refusing to start with insecure default."
    )
```

#### CR-02: `database_url` default computed at class definition time, not instantiation

**File:** `service/src/skillledger_service/config.py:21`

**Issue:** `database_url: str = _resolve_database_url()` calls the function when the module is imported (class body parse time), not when `Settings()` is instantiated. This means:
1. The env var is read once at import time and baked into the class default.
2. Pydantic-settings' env var reading (via `env_prefix = "SKILLLEDGER_"`) would look for `SKILLLEDGER_DATABASE_URL` and override the default -- but only if the env var is set at instantiation time. If it was set at import time but changed later (e.g., in tests), the default is stale.
3. More critically: `_resolve_database_url()` also checks `DATABASE_URL` (line 12), but pydantic-settings only checks `SKILLLEDGER_DATABASE_URL`. So the `DATABASE_URL` fallback only works through the default value hack, and it is evaluated once at import time.

Combined with `@lru_cache` on `get_settings()` in `db.py:8-10`, the settings are completely frozen after first import. Tests that set env vars after import will operate against the wrong database.

**Why it matters:** In testing, this causes silent connection to wrong databases. In production with Render (which provides `DATABASE_URL`), if the module is imported before Render injects the env var (e.g., during container build), the SQLite fallback is baked in permanently.

**Fix:** Use pydantic-settings' native env var reading with a validator:
```python
class Settings(BaseSettings):
    database_url: str = "sqlite+aiosqlite:///./skillledger.db"

    @field_validator("database_url", mode="before")
    @classmethod
    def rewrite_pg_url(cls, v: str) -> str:
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    model_config = {
        "env_prefix": "SKILLLEDGER_",
        # Allow DATABASE_URL as alias
    }
```

### Important (WARNING)

#### WR-01: No CORS middleware configured despite `cors_origins` setting

**File:** `service/src/skillledger_service/main.py:45-73`

**Issue:** `config.py:29` defines `cors_origins = ["https://log.skillledger.dev"]` but `create_app()` never adds `CORSMiddleware`. The dashboard at `dashboard.skillledger.dev` will be blocked by browser CORS policy on every API call.

**Why it matters:** The dashboard frontend is non-functional from a browser. This is a runtime bug, not a style issue.

**Fix:**
```python
from fastapi.middleware.cors import CORSMiddleware

def create_app() -> FastAPI:
    app = FastAPI(...)
    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

#### WR-02: `alembic.ini` hardcodes SQLite URL -- silent mis-targeting in production

**File:** `service/alembic.ini:3`

**Issue:** `sqlalchemy.url = sqlite+aiosqlite:///./skillledger.db` is the fallback. `env.py:22-26` logs a warning when no env var is set but does not fail. If an operator runs `alembic upgrade head` in production without `SKILLLEDGER_DATABASE_URL`, they silently migrate a local SQLite file and believe the migration succeeded.

**Why it matters:** Silent data loss risk. Production PostgreSQL stays un-migrated while the operator believes migrations ran successfully.

**Fix:** Fail-closed in env.py for non-dev contexts:
```python
else:
    if os.environ.get("SKILLLEDGER_ENV", "dev") != "dev":
        raise RuntimeError("SKILLLEDGER_DATABASE_URL must be set in non-dev environments")
```

#### WR-03: Missing indexes on 6+ foreign key columns

**Files:**
- `002_add_users.py:25` -- `refresh_tokens.user_id`
- `002_add_users.py:33` -- `user_api_keys.user_id`
- `005_add_org_tables.py:36` -- `org_memberships.user_id`
- `005_add_org_tables.py:40` -- `org_memberships.org_id`
- `006_add_org_events_profiles.py:49` -- `org_events.user_id`
- `006_add_org_events_profiles.py:77` -- `org_profiles.user_id`

**Issue:** PostgreSQL does NOT auto-create indexes on FK columns. Queries like "list all refresh tokens for user X" or "find memberships for org Y" will full-table-scan.

**Why it matters:** Tables like `org_events` grow indefinitely. Without an index on `user_id`, per-user queries degrade to timeouts as the table grows. This is a correctness issue (queries will time out and fail), not just performance.

**Fix:** Add indexes in a new migration 009.

#### WR-04: `saml_configs.created_at` is nullable -- inconsistent with all other tables

**File:** `service/alembic/versions/008_add_saml_configs.py:28-30`

**Issue:** Every other table defines `created_at` as `nullable=False`. Migration 008 sets `nullable=True`. This allows NULL `created_at` values, breaking audit queries that assume non-null timestamps.

**Fix:**
```python
sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
          server_default=sa.text("now()")),
```

#### WR-05: Module-level `create_app()` call defeats factory pattern

**File:** `service/src/skillledger_service/main.py:76`

**Issue:** `app = create_app()` executes at import time. This triggers `get_settings()`, license validation, and router registration on every `import main`. Combined with `@lru_cache` on `get_settings()`, this freezes configuration at first import.

**Why it matters:** Tests that mock settings or env vars after importing `main` will operate against the frozen initial configuration. Uvicorn supports factory mode (`--factory`) which avoids this.

**Fix:** Guard with `if __name__` or switch to factory mode:
```python
# For uvicorn: uvicorn skillledger_service.main:create_app --factory
# Remove: app = create_app()
```

#### WR-06: Seed operation failure crashes the entire service

**File:** `service/src/skillledger_service/main.py:39-40`

**Issue:** `seed_threat_data(session)` is awaited without try/except. If seeding fails (corrupt bundled data, constraint violation on re-seed, network error for live data), the application fails to start entirely.

**Why it matters:** A failure in a non-critical subsystem (threat library seeding) should not prevent the core service (log publish/verify, auth, billing) from operating.

**Fix:**
```python
try:
    async with get_async_session_factory()() as session:
        await seed_threat_data(session)
except Exception:
    logger.exception("Threat data seeding failed -- continuing startup")
```

#### WR-07: `org_invites.token` appears to store plaintext tokens

**File:** `service/alembic/versions/005_add_org_tables.py:63`

**Issue:** Column is `token` (not `token_hash`). The project convention established in `api_keys.key_hash` (001:28), `refresh_tokens.token_hash` (002:27), and `user_api_keys.key_hash` (002:34) is to store hashed secrets. If invite tokens are stored in plaintext, a database read (SQL injection, backup leak, admin access) allows accepting any pending invitation.

**Why it matters:** Invite tokens grant organization membership, which in an enterprise context means access to org policies, events, and potentially SAML SSO configuration.

**Fix:** Rename to `token_hash`, store SHA-256 hash of the invite token, and send the plaintext token only via email.

### Minor

#### MN-01: No `ON DELETE CASCADE` on any foreign key across all 8 migrations

**Files:** All migrations with FK references (001, 002, 004, 005, 006, 008)

**Issue:** No FK specifies `ondelete` behavior. Deleting a user leaves orphaned rows in 8+ dependent tables. Attempting to delete a user or org will raise `IntegrityError`.

**Why it matters:** Makes user/org deletion impossible without manual cleanup. May be intentional (soft-delete pattern), but should be documented as a conscious decision.

#### MN-02: `org_policies` created as empty shell in 005, then immediately extended in 006

**File:** `005_add_org_tables.py:69-79` and `006_add_org_events_profiles.py:17-36`

**Issue:** Migration 005 creates `org_policies` with only `id`, `org_id`, and `created_at`. The very next migration (006) adds the actual functional columns. These were clearly developed together.

#### MN-03: No `server_default` on `created_at` columns for most tables

**Files:** Migrations 001-006 (e.g., `001:21`, `002:20`, `003:24`)

**Issue:** Most `created_at` columns are `nullable=False` with no `server_default`. This means the application code MUST always provide a value. If any code path creates a row without explicitly setting `created_at`, it will fail with a NOT NULL violation rather than defaulting to `now()`.

---

## Score: 5/10

The migration structure is mechanically sound -- all 8 migrations are reversible, the chain is correctly ordered, and the enum lifecycle (create/drop in 005) is handled properly. However:

- **CR-01** (JWT empty secret in production) is a textbook authentication bypass that should block shipping.
- **CR-02** (import-time config evaluation) is a latent bug that will cause test failures and could cause production misrouting if container build order varies.
- **WR-01** (missing CORS middleware) makes the dashboard non-functional.
- **WR-03** (6 missing FK indexes) will cause query timeouts at scale.
- **WR-07** (plaintext invite tokens) violates the project's own security conventions.

The app factory pattern is partially defeated by the module-level `create_app()` call (WR-05), and the lifespan handler has no resilience to seeding failures (WR-06).
