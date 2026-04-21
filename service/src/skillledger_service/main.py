import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from skillledger_service.db import get_engine, get_settings
from skillledger_service.health import router as health_router
from skillledger_service.models import Base
from skillledger_service.routers.log import router as log_router
from skillledger_service.routers.publishers import router as publishers_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if not settings.admin_api_key:
        logger.warning(
            "SKILLLEDGER_ADMIN_API_KEY is not set. Admin endpoints will be inaccessible."
        )
    eng = get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await eng.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="SkillLedger Service", version="0.1.0", lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(log_router)
    app.include_router(publishers_router)
    return app


app = create_app()
