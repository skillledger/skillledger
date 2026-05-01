"""Add org_events, org_profiles tables and extend org_policies with rego columns

Revision ID: 006
Create Date: 2026-05-01
"""
from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extend org_policies with rego-related columns
    op.add_column(
        "org_policies", sa.Column("rego", sa.Text(), nullable=True)
    )
    op.add_column(
        "org_policies",
        sa.Column("compiled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "org_policies",
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
    )
    op.add_column(
        "org_policies",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Create org_events table
    op.create_table(
        "org_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("ecosystem", sa.String(100), nullable=False),
        sa.Column("skill_id", sa.String(500), nullable=False),
        sa.Column("rule", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column(
            "event_timestamp", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_org_events_org_created", "org_events", ["org_id", "created_at"]
    )

    # Create org_profiles table
    op.create_table(
        "org_profiles",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("skill_id", sa.String(500), nullable=False),
        sa.Column("ecosystem", sa.String(100), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column(
            "detected_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_org_profiles_org_skill",
        "org_profiles",
        ["org_id", "skill_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_org_profiles_org_skill", table_name="org_profiles")
    op.drop_table("org_profiles")
    op.drop_index("ix_org_events_org_created", table_name="org_events")
    op.drop_table("org_events")

    op.drop_column("org_policies", "updated_at")
    op.drop_column("org_policies", "created_by")
    op.drop_column("org_policies", "compiled_at")
    op.drop_column("org_policies", "rego")
