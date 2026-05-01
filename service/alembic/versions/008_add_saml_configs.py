"""Add saml_configs table for per-org SAML SSO configuration

Revision ID: 008
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saml_configs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.String(512), nullable=False),
        sa.Column("sso_url", sa.String(512), nullable=False),
        sa.Column("slo_url", sa.String(512), nullable=True),
        sa.Column("x509_cert", sa.Text(), nullable=False),
        sa.Column("metadata_xml", sa.Text(), nullable=True),
        sa.Column("attribute_mapping", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", name="uq_saml_configs_org_id"),
    )


def downgrade() -> None:
    op.drop_table("saml_configs")
