"""add official document management tables

Revision ID: 20260312_0028
Revises: 20260312_0027
Create Date: 2026-03-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260312_0028"
down_revision = "20260312_0027"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "official_documents"):
        op.create_table(
            "official_documents",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("organization", sa.String(length=120), nullable=False),
            sa.Column("document_number", sa.String(length=80), nullable=True),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("document_type", sa.String(length=40), nullable=False, server_default=sa.text("'general'")),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'received'")),
            sa.Column("priority", sa.String(length=20), nullable=False, server_default=sa.text("'medium'")),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("required_action", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("summary", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("linked_inspection_id", sa.Integer(), nullable=True),
            sa.Column("linked_work_order_id", sa.Integer(), nullable=True),
            sa.Column("closed_report_title", sa.String(length=200), nullable=True),
            sa.Column("closure_summary", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("closure_result", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    indexes = [
        ("official_documents", "ix_official_documents_site_received_at", ["site", "received_at"]),
        ("official_documents", "ix_official_documents_status_due_at", ["status", "due_at"]),
        ("official_documents", "ix_official_documents_organization", ["organization"]),
        ("official_documents", "ix_official_documents_closed_at", ["closed_at"]),
        ("official_documents", "ix_official_documents_linked_inspection", ["linked_inspection_id"]),
        ("official_documents", "ix_official_documents_linked_work_order", ["linked_work_order_id"]),
    ]
    for table_name, index_name, columns in indexes:
        if not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    # Forward-only safety migration.
    pass
