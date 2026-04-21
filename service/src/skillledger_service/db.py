from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from skillledger_service.config import Settings


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_engine():
    settings = get_settings()
    return create_async_engine(settings.database_url, echo=settings.debug)


@lru_cache
def get_async_session_factory():
    return async_sessionmaker(get_engine(), class_=AsyncSession, expire_on_commit=False)



async def get_session():
    factory = get_async_session_factory()
    async with factory() as session:
        yield session
