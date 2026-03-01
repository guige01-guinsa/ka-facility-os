"""add api latency samples table for persistence

Revision ID: 20260303_0022
Revises: 20260303_0021
Create Date: 2026-03-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260303_0022"
down_revision = "20260303_0021"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "api_latency_samples"):
        op.create_table(
            "api_latency_samples",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("endpoint_key", sa.String(length=220), nullable=False),
            sa.Column("method", sa.String(length=10), nullable=False),
            sa.Column("path", sa.String(length=240), nullable=False),
            sa.Column("duration_ms", sa.Float(), nullable=False),
            sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "api_latency_samples", "ix_api_latency_endpoint_sampled_at"):
        op.create_index(
            "ix_api_latency_endpoint_sampled_at",
            "api_latency_samples",
            ["endpoint_key", "sampled_at"],
            unique=False,
        )
    if not _index_exists(inspector, "api_latency_samples", "ix_api_latency_sampled_at"):
        op.create_index(
            "ix_api_latency_sampled_at",
            "api_latency_samples",
            ["sampled_at"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass
