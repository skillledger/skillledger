from fastapi import FastAPI

from skillledger_service.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(title="SkillLedger Service", version="0.1.0")
    app.include_router(health_router)
    return app


app = create_app()
