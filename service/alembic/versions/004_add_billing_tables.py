"""Add usage_records, subscriptions, stripe_events tables

Revision ID: 004
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "usage_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("operation", sa.String(64), nullable=False),
        sa.Column("month", sa.String(7), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "operation", "month", name="uq_usage_user_op_month"),
    )
    op.create_index("ix_usage_records_user_id", "usage_records", ["user_id"])

    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("stripe_customer_id", sa.String(255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True, unique=True),
        sa.Column("plan", sa.String(64), nullable=False, server_default="free"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_subscriptions_user_id", "subscriptions", ["user_id"])

    op.create_table(
        "stripe_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("stripe_event_id", sa.String(255), unique=True, nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("stripe_events")
    op.drop_table("subscriptions")
    op.drop_table("usage_records")
