"""add api latency status/error columns

Revision ID: 20260303_0023
Revises: 20260303_0022
Create Date: 2026-03-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260303_0023"
down_revision = "20260303_0022"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {str(col.get("name") or "") for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not _has_table(inspector, "api_latency_samples"):
        return

    columns = _column_names(inspector, "api_latency_samples")
    if "status_code" not in columns:
        op.add_column("api_latency_samples", sa.Column("status_code", sa.Integer(), nullable=True))
    if "is_error" not in columns:
        op.add_column(
            "api_latency_samples",
            sa.Column("is_error", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass
