"""security hardening columns for audit integrity and evidence storage

Revision ID: 20260228_0010
Revises: 20260228_0009
Create Date: 2026-02-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260228_0010"
down_revision = "20260228_0009"
branch_labels = None
depends_on = None


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table_name)}


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    audit_cols = _column_names(inspector, "admin_audit_logs")
    if "prev_hash" not in audit_cols:
        op.add_column(
            "admin_audit_logs",
            sa.Column("prev_hash", sa.String(length=64), nullable=True),
        )
    if "entry_hash" not in audit_cols:
        op.add_column(
            "admin_audit_logs",
            sa.Column("entry_hash", sa.String(length=64), nullable=True),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "admin_audit_logs", "ix_admin_audit_entry_hash"):
        op.create_index(
            "ix_admin_audit_entry_hash",
            "admin_audit_logs",
            ["entry_hash"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    evidence_cols = _column_names(inspector, "adoption_w02_evidence_files")
    if "storage_backend" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column("storage_backend", sa.String(length=20), nullable=False, server_default=sa.text("'db'")),
        )
    if "storage_key" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column("storage_key", sa.String(length=400), nullable=True),
        )
    if "sha256" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column("sha256", sa.String(length=64), nullable=True),
        )
    if "malware_scan_status" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column(
                "malware_scan_status",
                sa.String(length=20),
                nullable=False,
                server_default=sa.text("'unknown'"),
            ),
        )
    if "malware_scan_engine" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column("malware_scan_engine", sa.String(length=80), nullable=True),
        )
    if "malware_scanned_at" not in evidence_cols:
        op.add_column(
            "adoption_w02_evidence_files",
            sa.Column("malware_scanned_at", sa.DateTime(timezone=True), nullable=True),
        )

    bind.execute(
        sa.text(
            "UPDATE adoption_w02_evidence_files "
            "SET storage_backend='db' "
            "WHERE storage_backend IS NULL OR TRIM(storage_backend)=''"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE adoption_w02_evidence_files "
            "SET malware_scan_status='legacy' "
            "WHERE malware_scan_status IS NULL OR TRIM(malware_scan_status)=''"
        )
    )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "adoption_w02_evidence_files", "ix_w02_evidence_sha256"):
        op.create_index(
            "ix_w02_evidence_sha256",
            "adoption_w02_evidence_files",
            ["sha256"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w02_evidence_files", "ix_w02_evidence_storage_key"):
        op.create_index(
            "ix_w02_evidence_storage_key",
            "adoption_w02_evidence_files",
            ["storage_key"],
            unique=False,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

