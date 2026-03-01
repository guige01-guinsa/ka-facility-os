"""add adoption w09 execution tracker tables

Revision ID: 20260301_0015
Revises: 20260301_0014
Create Date: 2026-03-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260301_0015"
down_revision = "20260301_0014"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "adoption_w09_tracker_items"):
        op.create_table(
            "adoption_w09_tracker_items",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("item_type", sa.String(length=40), nullable=False),
            sa.Column("item_key", sa.String(length=120), nullable=False),
            sa.Column("item_name", sa.String(length=200), nullable=False),
            sa.Column("assignee", sa.String(length=120), nullable=True),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("completion_checked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("completion_note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("evidence_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "adoption_w09_tracker_items", "ix_w09_tracker_site_status"):
        op.create_index(
            "ix_w09_tracker_site_status",
            "adoption_w09_tracker_items",
            ["site", "status"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w09_tracker_items", "ux_w09_tracker_site_type_key"):
        op.create_index(
            "ux_w09_tracker_site_type_key",
            "adoption_w09_tracker_items",
            ["site", "item_type", "item_key"],
            unique=True,
        )
    if not _index_exists(inspector, "adoption_w09_tracker_items", "ix_w09_tracker_assignee"):
        op.create_index(
            "ix_w09_tracker_assignee",
            "adoption_w09_tracker_items",
            ["assignee"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "adoption_w09_evidence_files"):
        op.create_table(
            "adoption_w09_evidence_files",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("tracker_item_id", sa.Integer(), nullable=False),
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
    if not _index_exists(inspector, "adoption_w09_evidence_files", "ix_w09_evidence_tracker_uploaded_at"):
        op.create_index(
            "ix_w09_evidence_tracker_uploaded_at",
            "adoption_w09_evidence_files",
            ["tracker_item_id", "uploaded_at"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w09_evidence_files", "ix_w09_evidence_site_uploaded_at"):
        op.create_index(
            "ix_w09_evidence_site_uploaded_at",
            "adoption_w09_evidence_files",
            ["site", "uploaded_at"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w09_evidence_files", "ix_w09_evidence_sha256"):
        op.create_index(
            "ix_w09_evidence_sha256",
            "adoption_w09_evidence_files",
            ["sha256"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w09_evidence_files", "ix_w09_evidence_storage_key"):
        op.create_index(
            "ix_w09_evidence_storage_key",
            "adoption_w09_evidence_files",
            ["storage_key"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "adoption_w09_site_runs"):
        op.create_table(
            "adoption_w09_site_runs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False, unique=True),
            sa.Column("status", sa.String(length=40), nullable=False, server_default=sa.text("'active'")),
            sa.Column("completion_note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("force_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("completed_by", sa.String(length=80), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("readiness_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "adoption_w09_site_runs", "ix_w09_site_runs_status"):
        op.create_index(
            "ix_w09_site_runs_status",
            "adoption_w09_site_runs",
            ["status"],
            unique=False,
        )
    if not _index_exists(inspector, "adoption_w09_site_runs", "ux_w09_site_runs_site"):
        op.create_index(
            "ux_w09_site_runs_site",
            "adoption_w09_site_runs",
            ["site"],
            unique=True,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

