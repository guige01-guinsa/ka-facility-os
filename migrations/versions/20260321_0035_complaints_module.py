"""add complaints module tables

Revision ID: 20260321_0035
Revises: 20260314_0034
Create Date: 2026-03-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260321_0035"
down_revision = "20260314_0034"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "complaint_cases"):
        op.create_table(
            "complaint_cases",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("case_key", sa.String(length=160), nullable=False, unique=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("building", sa.String(length=120), nullable=False),
            sa.Column("unit_number", sa.String(length=40), nullable=False),
            sa.Column("resident_name", sa.String(length=120), nullable=True),
            sa.Column("contact_phone", sa.String(length=40), nullable=True),
            sa.Column("complaint_type", sa.String(length=80), nullable=False, server_default="other_finish_issue"),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="received"),
            sa.Column("priority", sa.String(length=20), nullable=False, server_default="medium"),
            sa.Column("source_channel", sa.String(length=40), nullable=False, server_default="manual"),
            sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("scheduled_visit_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resident_confirmed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("recurrence_flag", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("recurrence_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("assignee", sa.String(length=80), nullable=True),
            sa.Column("linked_work_order_id", sa.Integer(), nullable=True),
            sa.Column("import_batch_id", sa.String(length=80), nullable=True),
            sa.Column("source_workbook", sa.String(length=255), nullable=True),
            sa.Column("source_sheet", sa.String(length=120), nullable=True),
            sa.Column("source_row_number", sa.Integer(), nullable=True),
            sa.Column("source_row_hash", sa.String(length=64), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "complaint_events"):
        op.create_table(
            "complaint_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("complaint_id", sa.Integer(), nullable=False),
            sa.Column("event_type", sa.String(length=40), nullable=False, server_default="note"),
            sa.Column("from_status", sa.String(length=30), nullable=True),
            sa.Column("to_status", sa.String(length=30), nullable=True),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("detail_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("actor_username", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "complaint_attachments"):
        op.create_table(
            "complaint_attachments",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("complaint_id", sa.Integer(), nullable=False),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("attachment_kind", sa.String(length=20), nullable=False, server_default="intake"),
            sa.Column("file_name", sa.String(length=255), nullable=False),
            sa.Column("content_type", sa.String(length=120), nullable=False, server_default="application/octet-stream"),
            sa.Column("file_size", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("storage_backend", sa.String(length=20), nullable=False, server_default="db"),
            sa.Column("storage_key", sa.String(length=400), nullable=True),
            sa.Column("file_bytes", sa.LargeBinary(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("malware_scan_status", sa.String(length=20), nullable=False, server_default="unknown"),
            sa.Column("malware_scan_engine", sa.String(length=80), nullable=True),
            sa.Column("malware_scanned_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("uploaded_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "complaint_messages"):
        op.create_table(
            "complaint_messages",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("complaint_id", sa.Integer(), nullable=False),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("delivery_kind", sa.String(length=20), nullable=False, server_default="sms"),
            sa.Column("template_key", sa.String(length=80), nullable=True),
            sa.Column("recipient", sa.String(length=40), nullable=False),
            sa.Column("body", sa.Text(), nullable=False, server_default=""),
            sa.Column("provider_name", sa.String(length=80), nullable=False, server_default="stub"),
            sa.Column("provider_message_id", sa.String(length=120), nullable=True),
            sa.Column("delivery_status", sa.String(length=20), nullable=False, server_default="queued"),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("sent_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "complaint_cost_items"):
        op.create_table(
            "complaint_cost_items",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("complaint_id", sa.Integer(), nullable=False),
            sa.Column("cost_category", sa.String(length=40), nullable=False, server_default="other"),
            sa.Column("item_name", sa.String(length=120), nullable=False),
            sa.Column("quantity", sa.Float(), nullable=False, server_default="1"),
            sa.Column("unit_price", sa.Float(), nullable=False, server_default="0"),
            sa.Column("material_cost", sa.Float(), nullable=False, server_default="0"),
            sa.Column("labor_cost", sa.Float(), nullable=False, server_default="0"),
            sa.Column("vendor_cost", sa.Float(), nullable=False, server_default="0"),
            sa.Column("total_cost", sa.Float(), nullable=False, server_default="0"),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("approved_by", sa.String(length=80), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    index_specs = [
        ("complaint_cases", "ix_complaint_cases_site", ["site"]),
        ("complaint_cases", "ix_complaint_cases_status", ["status"]),
        ("complaint_cases", "ix_complaint_cases_household", ["site", "building", "unit_number"]),
        ("complaint_cases", "ix_complaint_cases_reported_at", ["reported_at"]),
        ("complaint_events", "ix_complaint_events_case", ["complaint_id", "created_at"]),
        ("complaint_attachments", "ix_complaint_attachments_case", ["complaint_id", "uploaded_at"]),
        ("complaint_messages", "ix_complaint_messages_case", ["complaint_id", "created_at"]),
        ("complaint_cost_items", "ix_complaint_cost_items_case", ["complaint_id", "created_at"]),
    ]
    for table_name, index_name, columns in index_specs:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table_name, index_name in [
        ("complaint_cost_items", "ix_complaint_cost_items_case"),
        ("complaint_messages", "ix_complaint_messages_case"),
        ("complaint_attachments", "ix_complaint_attachments_case"),
        ("complaint_events", "ix_complaint_events_case"),
        ("complaint_cases", "ix_complaint_cases_reported_at"),
        ("complaint_cases", "ix_complaint_cases_household"),
        ("complaint_cases", "ix_complaint_cases_status"),
        ("complaint_cases", "ix_complaint_cases_site"),
    ]:
        if _has_table(inspector, table_name) and _index_exists(inspector, table_name, index_name):
            op.drop_index(index_name, table_name=table_name)

    inspector = sa.inspect(bind)
    for table_name in [
        "complaint_cost_items",
        "complaint_messages",
        "complaint_attachments",
        "complaint_events",
        "complaint_cases",
    ]:
        if _has_table(inspector, table_name):
            op.drop_table(table_name)
            inspector = sa.inspect(bind)
