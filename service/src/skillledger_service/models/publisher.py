import datetime
import secrets

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from skillledger_service.models.artifact import Base


class Publisher(Base):
    __tablename__ = "publishers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    contact_email: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="publisher")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    publisher_id: Mapped[int] = mapped_column(ForeignKey("publishers.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    publisher: Mapped["Publisher"] = relationship(back_populates="api_keys")
