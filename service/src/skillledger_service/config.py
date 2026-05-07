import os

from pydantic_settings import BaseSettings


def _resolve_database_url() -> str:
    """Build async database URL from available env vars.

    Priority: SKILLLEDGER_DATABASE_URL > DATABASE_URL (Render provides this).
    Automatically swaps postgresql:// prefix to postgresql+asyncpg://.
    """
    url = os.environ.get("SKILLLEDGER_DATABASE_URL") or os.environ.get("DATABASE_URL", "")
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url or "sqlite+aiosqlite:///./skillledger.db"


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    database_url: str = _resolve_database_url()
    log_url: str = "http://localhost:2025"
    api_key_hash_algorithm: str = "sha256"
    admin_api_key: str = ""
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    resend_api_key: str = ""
    otp_from_email: str = "SkillLedger <noreply@skillledger.dev>"
    cors_origins: list[str] = ["https://log.skillledger.dev"]
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_id: str = ""
    stripe_seat_price_id: str = ""
    stripe_meter_event_name: str = "tlog_publish"
    service_url: str = "https://log.skillledger.dev"
    dashboard_url: str = "https://dashboard.skillledger.dev"
    ee_license_key: str = ""
    ee_license_hash: str = ""
    saml_sp_entity_id: str = ""
    model_config = {"env_prefix": "SKILLLEDGER_"}
