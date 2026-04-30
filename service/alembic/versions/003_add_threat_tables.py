"""Add ioc_hashes, ioc_domains, yara_rules tables

Revision ID: 003
Create Date: 2026-04-30
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ioc_hashes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("sha256", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("severity", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("source", sa.String(255), nullable=False, server_default=""),
        sa.Column("reported_at", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "ioc_domains",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("description", sa.String(512), nullable=False, server_default=""),
        sa.Column("severity", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("source", sa.String(255), nullable=False, server_default=""),
        sa.Column("reported_at", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "yara_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("yara_rules")
    op.drop_table("ioc_domains")
    op.drop_table("ioc_hashes")
