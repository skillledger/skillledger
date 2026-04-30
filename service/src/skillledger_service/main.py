import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from skillledger_service.db import get_async_session_factory, get_engine, get_settings
from skillledger_service.seed import seed_threat_data
from skillledger_service.health import router as health_router
from skillledger_service.models import Base
from skillledger_service.routers.log import router as log_router
from skillledger_service.routers.auth_router import router as auth_router
from skillledger_service.routers.publishers import router as publishers_router
from skillledger_service.routers.ingest import router as ingest_router
from skillledger_service.routers.threat_library import router as threat_library_router
from skillledger_service.routers.usage_router import router as usage_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if not settings.admin_api_key:
        logger.warning(
            "SKILLLEDGER_ADMIN_API_KEY is not set. Admin endpoints will be inaccessible."
        )
    if not settings.jwt_secret and not settings.debug:
        logger.warning(
            "SKILLLEDGER_JWT_SECRET is not set. JWT auth will use an insecure default."
        )
    eng = get_engine()
    if settings.debug:
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    # Auto-seed threat library data from bundled CLI files (D-02: zero-touch deployment)
    async with get_async_session_factory()() as session:
        await seed_threat_data(session)
    yield
    await eng.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="SkillLedger Service", version="0.1.0", lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(log_router)
    app.include_router(publishers_router)
    app.include_router(auth_router)
    app.include_router(threat_library_router)
    app.include_router(ingest_router)
    app.include_router(usage_router)
    return app


app = create_app()
