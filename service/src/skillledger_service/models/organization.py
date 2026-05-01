import datetime
import enum
import re
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from skillledger_service.models.artifact import Base


class OrgRole(str, enum.Enum):
    owner = "owner"
    admin = "admin"
    member = "member"
    viewer = "viewer"


ROLE_HIERARCHY: dict[OrgRole, int] = {
    OrgRole.viewer: 0,
    OrgRole.member: 1,
    OrgRole.admin: 2,
    OrgRole.owner: 3,
}


def slugify(name: str) -> str:
    """Convert a name to a URL-safe slug."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower().strip()).strip("-")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    license_key_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    memberships: Mapped[list["OrgMembership"]] = relationship(
        back_populates="organization"
    )
    invites: Mapped[list["OrgInvite"]] = relationship(back_populates="organization")


class OrgMembership(Base):
    __tablename__ = "org_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    role: Mapped[OrgRole] = mapped_column(
        Enum(OrgRole, name="orgrole", create_constraint=True), nullable=False
    )
    joined_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    organization: Mapped["Organization"] = relationship(back_populates="memberships")


class OrgInvite(Base):
    __tablename__ = "org_invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[OrgRole] = mapped_column(
        Enum(OrgRole, name="orgrole", create_constraint=True, create_type=False),
        nullable=False,
    )
    invited_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    organization: Mapped["Organization"] = relationship(back_populates="invites")


class Seat(Base):
    __tablename__ = "seats"
    __table_args__ = (
        UniqueConstraint("org_id", name="uq_seats_org_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, unique=True
    )
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    seat_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    out_of_sync: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
