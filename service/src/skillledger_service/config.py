import os

from pydantic import model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    database_url: str = ""
    log_url: str = "http://localhost:2025"
    api_key_hash_algorithm: str = "sha256"
    admin_api_key: str = ""
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    resend_api_key: str = ""
    otp_from_email: str = "SkillLedger <noreply@skillledger.in>"
    cors_origins: list[str] = ["https://api.skillledger.in"]
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_id: str = ""
    stripe_seat_price_id: str = ""
    stripe_meter_event_name: str = "tlog_publish"
    service_url: str = "https://api.skillledger.in"
    dashboard_url: str = "https://app.skillledger.in"
    ee_license_key: str = ""
    ee_license_hash: str = ""
    saml_sp_entity_id: str = ""
    model_config = {"env_prefix": "SKILLLEDGER_"}

    @model_validator(mode="after")
    def resolve_db_url(self) -> "Settings":
        """Build async database URL from available env vars.

        Priority: SKILLLEDGER_DATABASE_URL > DATABASE_URL (Render provides this).
        Automatically swaps postgresql:// prefix to postgresql+asyncpg://.
        """
        if not self.database_url:
            url = os.environ.get("DATABASE_URL", "")
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            self.database_url = url or "sqlite+aiosqlite:///./skillledger.db"
        elif self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            )
        return self
