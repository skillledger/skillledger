import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import Mapped, mapped_column

from skillledger_service.models.artifact import Base


class SamlConfig(Base):
    __tablename__ = "saml_configs"
    __table_args__ = (
        UniqueConstraint("org_id", name="uq_saml_configs_org_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, unique=True
    )
    entity_id: Mapped[str] = mapped_column(String(512), nullable=False)
    sso_url: Mapped[str] = mapped_column(String(512), nullable=False)
    slo_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    x509_cert: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_xml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attribute_mapping: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
    )
    updated_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
