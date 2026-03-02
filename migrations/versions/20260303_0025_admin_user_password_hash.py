"""add admin user password hash columns

Revision ID: 20260303_0025
Revises: 20260303_0024
Create Date: 2026-03-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260303_0025"
down_revision = "20260303_0024"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {str(col.get("name") or "") for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not _has_table(inspector, "admin_users"):
        return

    columns = _column_names(inspector, "admin_users")
    if "password_hash" not in columns:
        op.add_column("admin_users", sa.Column("password_hash", sa.String(length=255), nullable=True))
    if "password_updated_at" not in columns:
        op.add_column("admin_users", sa.Column("password_updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Forward-only safety migration.
    pass
