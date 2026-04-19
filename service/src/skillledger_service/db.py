from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from skillledger_service.config import Settings

settings = Settings()

engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session():
    async with async_session() as session:
        yield session
