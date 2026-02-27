"""add sla policy proposals table

Revision ID: 20260226_0006
Revises: 20260226_0005
Create Date: 2026-02-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0006"
down_revision = "20260226_0005"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "sla_policy_proposals"):
        op.create_table(
            "sla_policy_proposals",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=True),
            sa.Column("policy_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("simulation_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("requested_by", sa.String(length=80), nullable=False),
            sa.Column("decided_by", sa.String(length=80), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "sla_policy_proposals", "ix_sla_policy_proposals_status_created_at"):
        op.create_index(
            "ix_sla_policy_proposals_status_created_at",
            "sla_policy_proposals",
            ["status", "created_at"],
            unique=False,
        )
    if not _index_exists(inspector, "sla_policy_proposals", "ix_sla_policy_proposals_site"):
        op.create_index(
            "ix_sla_policy_proposals_site",
            "sla_policy_proposals",
            ["site"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

