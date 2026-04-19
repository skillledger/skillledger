from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    database_url: str = "sqlite+aiosqlite:///./skillledger.db"
    log_url: str = "http://localhost:2025"
    model_config = {"env_prefix": "SKILLLEDGER_"}
