"""Complaint table definitions split out from app.database."""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, LargeBinary, MetaData, String, Table, Text


def register_complaint_tables(metadata: MetaData) -> dict[str, Table]:
    complaint_cases = Table(
        "complaint_cases",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("case_key", String(160), nullable=False, unique=True),
        Column("site", String(120), nullable=False),
        Column("building", String(120), nullable=False),
        Column("unit_number", String(40), nullable=False),
        Column("resident_name", String(120), nullable=True),
        Column("contact_phone", String(40), nullable=True),
        Column("complaint_type", String(80), nullable=False, default="other_finish_issue"),
        Column("title", String(200), nullable=False),
        Column("description", Text, nullable=False, default=""),
        Column("status", String(30), nullable=False, default="received"),
        Column("priority", String(20), nullable=False, default="medium"),
        Column("source_channel", String(40), nullable=False, default="manual"),
        Column("reported_at", DateTime(timezone=True), nullable=False),
        Column("scheduled_visit_at", DateTime(timezone=True), nullable=True),
        Column("resolved_at", DateTime(timezone=True), nullable=True),
        Column("resident_confirmed_at", DateTime(timezone=True), nullable=True),
        Column("closed_at", DateTime(timezone=True), nullable=True),
        Column("recurrence_flag", Boolean, nullable=False, default=False),
        Column("recurrence_count", Integer, nullable=False, default=0),
        Column("assignee", String(80), nullable=True),
        Column("linked_work_order_id", Integer, nullable=True),
        Column("import_batch_id", String(80), nullable=True),
        Column("source_workbook", String(255), nullable=True),
        Column("source_sheet", String(120), nullable=True),
        Column("source_row_number", Integer, nullable=True),
        Column("source_row_hash", String(64), nullable=True),
        Column("created_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    complaint_events = Table(
        "complaint_events",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("complaint_id", Integer, nullable=False),
        Column("event_type", String(40), nullable=False, default="note"),
        Column("from_status", String(30), nullable=True),
        Column("to_status", String(30), nullable=True),
        Column("note", Text, nullable=False, default=""),
        Column("detail_json", Text, nullable=False, default="{}"),
        Column("actor_username", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
    )

    complaint_attachments = Table(
        "complaint_attachments",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("complaint_id", Integer, nullable=False),
        Column("site", String(120), nullable=False),
        Column("attachment_kind", String(20), nullable=False, default="intake"),
        Column("file_name", String(255), nullable=False),
        Column("content_type", String(120), nullable=False, default="application/octet-stream"),
        Column("file_size", Integer, nullable=False, default=0),
        Column("storage_backend", String(20), nullable=False, default="db"),
        Column("storage_key", String(400), nullable=True),
        Column("file_bytes", LargeBinary, nullable=False, default=b""),
        Column("sha256", String(64), nullable=False),
        Column("malware_scan_status", String(20), nullable=False, default="unknown"),
        Column("malware_scan_engine", String(80), nullable=True),
        Column("malware_scanned_at", DateTime(timezone=True), nullable=True),
        Column("note", Text, nullable=False, default=""),
        Column("uploaded_by", String(80), nullable=False, default="system"),
        Column("uploaded_at", DateTime(timezone=True), nullable=False),
    )

    complaint_messages = Table(
        "complaint_messages",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("complaint_id", Integer, nullable=False),
        Column("site", String(120), nullable=False),
        Column("delivery_kind", String(20), nullable=False, default="sms"),
        Column("template_key", String(80), nullable=True),
        Column("recipient", String(40), nullable=False),
        Column("body", Text, nullable=False, default=""),
        Column("provider_name", String(80), nullable=False, default="stub"),
        Column("provider_message_id", String(120), nullable=True),
        Column("delivery_status", String(20), nullable=False, default="queued"),
        Column("error", Text, nullable=True),
        Column("sent_by", String(80), nullable=False, default="system"),
        Column("sent_at", DateTime(timezone=True), nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False),
    )

    complaint_cost_items = Table(
        "complaint_cost_items",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("complaint_id", Integer, nullable=False),
        Column("cost_category", String(40), nullable=False, default="other"),
        Column("item_name", String(120), nullable=False),
        Column("quantity", Float, nullable=False, default=1.0),
        Column("unit_price", Float, nullable=False, default=0.0),
        Column("material_cost", Float, nullable=False, default=0.0),
        Column("labor_cost", Float, nullable=False, default=0.0),
        Column("vendor_cost", Float, nullable=False, default=0.0),
        Column("total_cost", Float, nullable=False, default=0.0),
        Column("note", Text, nullable=False, default=""),
        Column("approved_by", String(80), nullable=True),
        Column("approved_at", DateTime(timezone=True), nullable=True),
        Column("created_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    complaint_report_cover_defaults = Table(
        "complaint_report_cover_defaults",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("scope_type", String(20), nullable=False, default="site"),
        Column("site", String(120), nullable=True),
        Column("company_name", String(120), nullable=True),
        Column("contractor_name", String(120), nullable=True),
        Column("submission_phrase", Text, nullable=True),
        Column("logo_file_name", String(200), nullable=True),
        Column("logo_content_type", String(120), nullable=True),
        Column("logo_bytes", LargeBinary, nullable=False, default=b""),
        Column("updated_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    return {
        "complaint_cases": complaint_cases,
        "complaint_events": complaint_events,
        "complaint_attachments": complaint_attachments,
        "complaint_messages": complaint_messages,
        "complaint_cost_items": complaint_cost_items,
        "complaint_report_cover_defaults": complaint_report_cover_defaults,
    }
