"""add inspection evidence files table

Revision ID: 20260304_0026
Revises: 20260303_0025
Create Date: 2026-03-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260304_0026"
down_revision = "20260303_0025"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "inspection_evidence_files"):
        op.create_table(
            "inspection_evidence_files",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("inspection_id", sa.Integer(), nullable=False),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("file_name", sa.String(length=255), nullable=False),
            sa.Column(
                "content_type",
                sa.String(length=120),
                nullable=False,
                server_default=sa.text("'application/octet-stream'"),
            ),
            sa.Column("file_size", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("file_bytes", sa.LargeBinary(), nullable=False),
            sa.Column("storage_backend", sa.String(length=20), nullable=False, server_default=sa.text("'db'")),
            sa.Column("storage_key", sa.String(length=400), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column(
                "malware_scan_status",
                sa.String(length=20),
                nullable=False,
                server_default=sa.text("'unknown'"),
            ),
            sa.Column("malware_scan_engine", sa.String(length=80), nullable=True),
            sa.Column("malware_scanned_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("uploaded_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "inspection_evidence_files", "ix_inspection_evidence_inspection_uploaded_at"):
        op.create_index(
            "ix_inspection_evidence_inspection_uploaded_at",
            "inspection_evidence_files",
            ["inspection_id", "uploaded_at"],
            unique=False,
        )
    if not _index_exists(inspector, "inspection_evidence_files", "ix_inspection_evidence_site_uploaded_at"):
        op.create_index(
            "ix_inspection_evidence_site_uploaded_at",
            "inspection_evidence_files",
            ["site", "uploaded_at"],
            unique=False,
        )
    if not _index_exists(inspector, "inspection_evidence_files", "ix_inspection_evidence_sha256"):
        op.create_index(
            "ix_inspection_evidence_sha256",
            "inspection_evidence_files",
            ["sha256"],
            unique=False,
        )
    if not _index_exists(inspector, "inspection_evidence_files", "ix_inspection_evidence_storage_key"):
        op.create_index(
            "ix_inspection_evidence_storage_key",
            "inspection_evidence_files",
            ["storage_key"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

