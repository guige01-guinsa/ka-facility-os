"""add sla policy revision history table

Revision ID: 20260226_0007
Revises: 20260226_0006
Create Date: 2026-02-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0007"
down_revision = "20260226_0006"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "sla_policy_revisions"):
        op.create_table(
            "sla_policy_revisions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=True),
            sa.Column("policy_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("source_action", sa.String(length=40), nullable=False, server_default=sa.text("'manual_update'")),
            sa.Column("actor_username", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "sla_policy_revisions", "ix_sla_policy_revisions_site_created_at"):
        op.create_index(
            "ix_sla_policy_revisions_site_created_at",
            "sla_policy_revisions",
            ["site", "created_at"],
            unique=False,
        )
    if not _index_exists(inspector, "sla_policy_revisions", "ix_sla_policy_revisions_source_action"):
        op.create_index(
            "ix_sla_policy_revisions_source_action",
            "sla_policy_revisions",
            ["source_action"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

