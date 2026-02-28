"""add workflow locks table for role workflow lock process

Revision ID: 20260228_0008
Revises: 20260226_0007
Create Date: 2026-02-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260228_0008"
down_revision = "20260226_0007"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "workflow_locks"):
        op.create_table(
            "workflow_locks",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("workflow_key", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'draft'")),
            sa.Column("content_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("requested_ticket", sa.String(length=120), nullable=True),
            sa.Column("last_comment", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("lock_reason", sa.Text(), nullable=True),
            sa.Column("unlock_reason", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("reviewed_by", sa.String(length=80), nullable=True),
            sa.Column("approved_by", sa.String(length=80), nullable=True),
            sa.Column("locked_by", sa.String(length=80), nullable=True),
            sa.Column("unlocked_by", sa.String(length=80), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("unlocked_at", sa.DateTime(timezone=True), nullable=True),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "workflow_locks", "ix_workflow_locks_site_status_created_at"):
        op.create_index(
            "ix_workflow_locks_site_status_created_at",
            "workflow_locks",
            ["site", "status", "created_at"],
            unique=False,
        )
    if not _index_exists(inspector, "workflow_locks", "ix_workflow_locks_workflow_key"):
        op.create_index(
            "ix_workflow_locks_workflow_key",
            "workflow_locks",
            ["workflow_key"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

