from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    database_url: str = "sqlite+aiosqlite:///./skillledger.db"
    log_url: str = "http://localhost:2025"
    api_key_hash_algorithm: str = "sha256"
    admin_api_key: str = ""
    cors_origins: list[str] = ["https://log.skillledger.dev"]
    model_config = {"env_prefix": "SKILLLEDGER_"}
