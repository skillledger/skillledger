from contextlib import asynccontextmanager

from fastapi import FastAPI

from skillledger_service.db import engine
from skillledger_service.health import router as health_router
from skillledger_service.models import Base
from skillledger_service.routers.log import router as log_router
from skillledger_service.routers.publishers import router as publishers_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="SkillLedger Service", version="0.1.0", lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(log_router)
    app.include_router(publishers_router)
    return app


app = create_app()
