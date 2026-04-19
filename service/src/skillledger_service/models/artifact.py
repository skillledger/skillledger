import datetime

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LogEntryRecord(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    artifact_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_address: Mapped[str] = mapped_column(String(255), nullable=False)
    log_index: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    publisher: Mapped[str] = mapped_column(String(255), nullable=False)
    published_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
