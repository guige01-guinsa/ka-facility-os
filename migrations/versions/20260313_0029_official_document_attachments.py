"""extend official document management with attachments and registry numbers

Revision ID: 20260313_0029
Revises: 20260312_0028
Create Date: 2026-03-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260313_0029"
down_revision = "20260312_0028"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _has_column(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    return any(column.get("name") == column_name for column in inspector.get_columns(table_name))


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "official_documents"):
        if not _has_column(inspector, "official_documents", "organization_code"):
            op.add_column("official_documents", sa.Column("organization_code", sa.String(length=40), nullable=True))
        if not _has_column(inspector, "official_documents", "registry_number"):
            op.add_column("official_documents", sa.Column("registry_number", sa.String(length=80), nullable=True))

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "official_document_attachments"):
        op.create_table(
            "official_document_attachments",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("document_id", sa.Integer(), nullable=False),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("file_name", sa.String(length=255), nullable=False),
            sa.Column("content_type", sa.String(length=120), nullable=False, server_default=sa.text("'application/octet-stream'")),
            sa.Column("file_size", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("storage_backend", sa.String(length=20), nullable=False, server_default=sa.text("'db'")),
            sa.Column("storage_key", sa.String(length=255), nullable=True),
            sa.Column("file_bytes", sa.LargeBinary(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("malware_scan_status", sa.String(length=20), nullable=False, server_default=sa.text("'unknown'")),
            sa.Column("malware_scan_engine", sa.String(length=80), nullable=True),
            sa.Column("malware_scanned_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("uploaded_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    indexes = [
        ("official_documents", "ix_official_documents_registry_number", ["registry_number"]),
        ("official_documents", "ix_official_documents_org_code_site_received", ["organization_code", "site", "received_at"]),
        ("official_document_attachments", "ix_official_document_attachments_document_id", ["document_id"]),
        ("official_document_attachments", "ix_official_document_attachments_site_uploaded_at", ["site", "uploaded_at"]),
    ]
    for table_name, index_name, columns in indexes:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    # Forward-only safety migration.
    pass
