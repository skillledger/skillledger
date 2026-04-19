from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    service_name: str = "skillledger-service"
    model_config = {"env_prefix": "SKILLLEDGER_"}
