"""OrgPolicy, OrgEvent, and OrgProfile models for Phase 25.

OrgPolicy extends the org_policies table (created in migration 005) with
rego content storage.  OrgEvent and OrgProfile are new tables for violation
event ingestion and auto-profile data respectively.
"""

import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from skillledger_service.models.artifact import Base

__all__ = ["OrgPolicy", "OrgEvent", "OrgProfile"]


class OrgPolicy(Base):
    __tablename__ = "org_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    rego: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compiled_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class OrgEvent(Base):
    __tablename__ = "org_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(100), nullable=False)
    skill_id: Mapped[str] = mapped_column(String(500), nullable=False)
    rule: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    event_timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )


class OrgProfile(Base):
    __tablename__ = "org_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    skill_id: Mapped[str] = mapped_column(String(500), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(100), nullable=False)
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False)
    detected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
