"""Add seat billing columns to seats table

Revision ID: 007
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "seats",
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True),
    )
    op.add_column(
        "seats",
        sa.Column("stripe_customer_id", sa.String(255), nullable=True),
    )
    op.add_column(
        "seats",
        sa.Column(
            "seat_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "seats",
        sa.Column(
            "out_of_sync",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "seats",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_unique_constraint("uq_seats_org_id", "seats", ["org_id"])


def downgrade() -> None:
    op.drop_constraint("uq_seats_org_id", "seats", type_="unique")
    op.drop_column("seats", "updated_at")
    op.drop_column("seats", "out_of_sync")
    op.drop_column("seats", "seat_count")
    op.drop_column("seats", "stripe_customer_id")
    op.drop_column("seats", "stripe_subscription_id")
