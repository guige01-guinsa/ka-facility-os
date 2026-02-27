"""add site scopes to admin users and tokens

Revision ID: 20260226_0003
Revises: 20260226_0002
Create Date: 2026-02-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0003"
down_revision = "20260226_0002"
branch_labels = None
depends_on = None


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    admin_user_columns = _column_names(inspector, "admin_users")
    if "site_scope" not in admin_user_columns:
        op.add_column(
            "admin_users",
            sa.Column("site_scope", sa.Text(), nullable=False, server_default=sa.text("'*'")),
        )
        bind.execute(sa.text("UPDATE admin_users SET site_scope='*' WHERE site_scope IS NULL OR TRIM(site_scope)=''"))

    inspector = sa.inspect(bind)
    admin_token_columns = _column_names(inspector, "admin_tokens")
    if "site_scope" not in admin_token_columns:
        op.add_column(
            "admin_tokens",
            sa.Column("site_scope", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

