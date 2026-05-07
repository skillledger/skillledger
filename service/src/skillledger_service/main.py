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
from skillledger_service.routers.billing import router as billing_router
from skillledger_service.routers.me import router as me_router
from skillledger_service.routers.webhooks import router as webhooks_router

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
        raise RuntimeError(
            "SKILLLEDGER_JWT_SECRET must be set in production. "
            "Set SKILLLEDGER_DEBUG=true for development."
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
    app.include_router(billing_router)
    app.include_router(me_router)
    app.include_router(webhooks_router)

    # Conditionally load enterprise edition routers
    settings = get_settings()
    if settings.ee_license_key:
        from skillledger_service.ee.license import validate_license_key

        if validate_license_key(settings.ee_license_key, settings.ee_license_hash):
            from skillledger_service.ee import load_ee_routers

            load_ee_routers(app)
            logger.info("Enterprise features enabled")
        else:
            logger.warning(
                "SKILLLEDGER_EE_LICENSE_KEY is set but invalid -- ee/ routes NOT loaded"
            )

    return app


app = create_app()
