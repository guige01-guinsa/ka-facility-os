"""add ops checklist master tables

Revision ID: 20260314_0032
Revises: 20260314_0031
Create Date: 2026-03-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0032"
down_revision = "20260314_0031"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "ops_checklist_sets"):
        op.create_table(
            "ops_checklist_sets",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("set_id", sa.String(length=80), nullable=False),
            sa.Column("label", sa.String(length=200), nullable=False),
            sa.Column("task_type", sa.String(length=80), nullable=False),
            sa.Column("source", sa.String(length=40), nullable=False, server_default="catalog"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("set_id", name="uq_ops_checklist_sets_set_id"),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "ops_checklist_sets", "ix_ops_checklist_sets_set_id"):
        op.create_index("ix_ops_checklist_sets_set_id", "ops_checklist_sets", ["set_id"], unique=False)

    if not _has_table(inspector, "ops_checklist_set_items"):
        op.create_table(
            "ops_checklist_set_items",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("set_id", sa.String(length=80), nullable=False),
            sa.Column("seq", sa.Integer(), nullable=False),
            sa.Column("item_text", sa.String(length=200), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "ops_checklist_set_items", "ix_ops_checklist_set_items_set_id"):
        op.create_index("ix_ops_checklist_set_items_set_id", "ops_checklist_set_items", ["set_id"], unique=False)
    if not _index_exists(inspector, "ops_checklist_set_items", "ix_ops_checklist_set_items_set_seq"):
        op.create_index(
            "ix_ops_checklist_set_items_set_seq",
            "ops_checklist_set_items",
            ["set_id", "seq"],
            unique=False,
        )
    if not _index_exists(inspector, "ops_checklist_set_items", "ix_ops_checklist_set_items_set_item_text"):
        op.create_index(
            "ix_ops_checklist_set_items_set_item_text",
            "ops_checklist_set_items",
            ["set_id", "item_text"],
            unique=False,
        )
