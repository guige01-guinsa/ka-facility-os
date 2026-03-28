"""add team ops module tables

Revision ID: 20260329_0037
Revises: 20260322_0036
Create Date: 2026-03-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260329_0037"
down_revision = "20260322_0036"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "team_ops_logs"):
        op.create_table(
            "team_ops_logs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reporter", sa.String(length=120), nullable=False),
            sa.Column("category", sa.String(length=40), nullable=False, server_default="general"),
            sa.Column("location", sa.String(length=160), nullable=False),
            sa.Column("issue", sa.Text(), nullable=False, server_default=""),
            sa.Column("action_taken", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="in_progress"),
            sa.Column("priority", sa.String(length=20), nullable=False, server_default="medium"),
            sa.Column("photo_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("linked_work_order_id", sa.Integer(), nullable=True),
            sa.Column("linked_complaint_id", sa.Integer(), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "team_ops_facilities"):
        op.create_table(
            "team_ops_facilities",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("facility_type", sa.String(length=120), nullable=False),
            sa.Column("location", sa.String(length=160), nullable=False),
            sa.Column("detail", sa.String(length=200), nullable=False, server_default=""),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "team_ops_inventory_items"):
        op.create_table(
            "team_ops_inventory_items",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("item_kind", sa.String(length=40), nullable=False, server_default="material"),
            sa.Column("item_name", sa.String(length=160), nullable=False),
            sa.Column("stock_quantity", sa.Float(), nullable=False, server_default="0"),
            sa.Column("unit", sa.String(length=40), nullable=False, server_default="개"),
            sa.Column("storage_place", sa.String(length=160), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="normal"),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    for table_name, index_name, columns in [
        ("team_ops_logs", "ix_team_ops_logs_site_recorded_at", ["site", "recorded_at"]),
        ("team_ops_logs", "ix_team_ops_logs_site_status", ["site", "status"]),
        ("team_ops_facilities", "ix_team_ops_facilities_site_active", ["site", "is_active"]),
        ("team_ops_inventory_items", "ix_team_ops_inventory_site_status", ["site", "status"]),
    ]:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table_name, index_name in [
        ("team_ops_inventory_items", "ix_team_ops_inventory_site_status"),
        ("team_ops_facilities", "ix_team_ops_facilities_site_active"),
        ("team_ops_logs", "ix_team_ops_logs_site_status"),
        ("team_ops_logs", "ix_team_ops_logs_site_recorded_at"),
    ]:
        if _has_table(inspector, table_name) and _index_exists(inspector, table_name, index_name):
            op.drop_index(index_name, table_name=table_name)

    inspector = sa.inspect(bind)
    for table_name in ["team_ops_inventory_items", "team_ops_facilities", "team_ops_logs"]:
        if _has_table(inspector, table_name):
            op.drop_table(table_name)
