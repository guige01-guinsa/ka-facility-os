"""add alert deliveries history table

Revision ID: 20260226_0005
Revises: 20260226_0004
Create Date: 2026-02-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0005"
down_revision = "20260226_0004"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "alert_deliveries"):
        op.create_table(
            "alert_deliveries",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("event_type", sa.String(length=80), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'success'")),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("payload_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
            sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "alert_deliveries", "ix_alert_deliveries_status_last_attempt_at"):
        op.create_index(
            "ix_alert_deliveries_status_last_attempt_at",
            "alert_deliveries",
            ["status", "last_attempt_at"],
            unique=False,
        )
    if not _index_exists(inspector, "alert_deliveries", "ix_alert_deliveries_event_type"):
        op.create_index(
            "ix_alert_deliveries_event_type",
            "alert_deliveries",
            ["event_type"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

