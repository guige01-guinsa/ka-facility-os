"""add adoption w02 completion state table

Revision ID: 20260228_0011
Revises: 20260228_0010
Create Date: 2026-02-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260228_0011"
down_revision = "20260228_0010"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "adoption_w02_site_runs"):
        op.create_table(
            "adoption_w02_site_runs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False, unique=True),
            sa.Column("status", sa.String(length=40), nullable=False, server_default=sa.text("'active'")),
            sa.Column("completion_note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("force_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("completed_by", sa.String(length=80), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("readiness_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "adoption_w02_site_runs", "ix_w02_site_runs_status"):
        op.create_index(
            "ix_w02_site_runs_status",
            "adoption_w02_site_runs",
            ["status"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w02_site_runs", "ux_w02_site_runs_site"):
        op.create_index(
            "ux_w02_site_runs_site",
            "adoption_w02_site_runs",
            ["site"],
            unique=True,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

