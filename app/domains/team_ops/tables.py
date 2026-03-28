"""Team operations module table definitions."""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, Text


def register_team_ops_tables(metadata: MetaData) -> dict[str, Table]:
    team_ops_logs = Table(
        "team_ops_logs",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("site", String(120), nullable=False),
        Column("recorded_at", DateTime(timezone=True), nullable=False),
        Column("reporter", String(120), nullable=False),
        Column("category", String(40), nullable=False, default="general"),
        Column("location", String(160), nullable=False),
        Column("issue", Text, nullable=False, default=""),
        Column("action_taken", Text, nullable=False, default=""),
        Column("status", String(20), nullable=False, default="in_progress"),
        Column("priority", String(20), nullable=False, default="medium"),
        Column("photo_count", Integer, nullable=False, default=0),
        Column("linked_work_order_id", Integer, nullable=True),
        Column("linked_complaint_id", Integer, nullable=True),
        Column("created_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    team_ops_facilities = Table(
        "team_ops_facilities",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("site", String(120), nullable=False),
        Column("facility_type", String(120), nullable=False),
        Column("location", String(160), nullable=False),
        Column("detail", String(200), nullable=False, default=""),
        Column("note", Text, nullable=False, default=""),
        Column("is_active", Boolean, nullable=False, default=True),
        Column("last_checked_at", DateTime(timezone=True), nullable=True),
        Column("created_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    team_ops_inventory_items = Table(
        "team_ops_inventory_items",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("site", String(120), nullable=False),
        Column("item_kind", String(40), nullable=False, default="material"),
        Column("item_name", String(160), nullable=False),
        Column("stock_quantity", Float, nullable=False, default=0.0),
        Column("unit", String(40), nullable=False, default="개"),
        Column("storage_place", String(160), nullable=False, default=""),
        Column("status", String(20), nullable=False, default="normal"),
        Column("note", Text, nullable=False, default=""),
        Column("updated_by", String(80), nullable=False, default="system"),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )

    return {
        "team_ops_logs": team_ops_logs,
        "team_ops_facilities": team_ops_facilities,
        "team_ops_inventory_items": team_ops_inventory_items,
    }
