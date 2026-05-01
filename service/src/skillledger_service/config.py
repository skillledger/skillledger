from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    database_url: str = "sqlite+aiosqlite:///./skillledger.db"
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
    stripe_meter_event_name: str = "tlog_publish"
    service_url: str = "https://log.skillledger.dev"
    model_config = {"env_prefix": "SKILLLEDGER_"}
