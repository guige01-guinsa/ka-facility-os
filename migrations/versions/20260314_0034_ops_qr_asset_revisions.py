"""add ops qr asset revision history

Revision ID: 20260314_0034
Revises: 20260314_0033
Create Date: 2026-03-14
"""

from __future__ import annotations

from datetime import datetime, timezone
import json

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0034"
down_revision = "20260314_0033"
branch_labels = None
depends_on = None


OPS_QR_PLACEHOLDER_VALUES = {"설비", "위치", "점검항목"}


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _build_quality_flags(row: dict[str, object]) -> list[str]:
    flags: list[str] = []
    equipment = str(row.get("equipment") or "").strip()
    location = str(row.get("location") or "").strip()
    default_item = str(row.get("default_item") or "").strip()
    checklist_set_id = str(row.get("checklist_set_id") or "").strip()
    if equipment in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_equipment")
    if location in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_location")
    if default_item in OPS_QR_PLACEHOLDER_VALUES:
        flags.append("placeholder_default_item")
    if default_item and not checklist_set_id:
        flags.append("unknown_default_item")
    return flags


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "ops_qr_asset_revisions"):
        op.create_table(
            "ops_qr_asset_revisions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("qr_asset_id", sa.Integer(), nullable=True),
            sa.Column("qr_id", sa.String(length=80), nullable=False),
            sa.Column("change_source", sa.String(length=40), nullable=False, server_default="qr_asset_api"),
            sa.Column("change_action", sa.String(length=20), nullable=False, server_default="updated"),
            sa.Column("change_note", sa.Text(), nullable=False, server_default=""),
            sa.Column("before_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("after_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("quality_flags_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_qr_asset_revisions"):
        if not _index_exists(inspector, "ops_qr_asset_revisions", "ix_ops_qr_asset_revisions_qr_id"):
            op.create_index(
                "ix_ops_qr_asset_revisions_qr_id",
                "ops_qr_asset_revisions",
                ["qr_id"],
                unique=False,
            )
        if not _index_exists(inspector, "ops_qr_asset_revisions", "ix_ops_qr_asset_revisions_created_at"):
            op.create_index(
                "ix_ops_qr_asset_revisions_created_at",
                "ops_qr_asset_revisions",
                ["created_at"],
                unique=False,
            )

    inspector = sa.inspect(bind)
    if not (_has_table(inspector, "ops_qr_asset_revisions") and _has_table(inspector, "ops_qr_assets")):
        return

    revision_table = sa.table(
        "ops_qr_asset_revisions",
        sa.column("id", sa.Integer),
        sa.column("qr_asset_id", sa.Integer),
        sa.column("qr_id", sa.String),
        sa.column("change_source", sa.String),
        sa.column("change_action", sa.String),
        sa.column("change_note", sa.Text),
        sa.column("before_json", sa.Text),
        sa.column("after_json", sa.Text),
        sa.column("quality_flags_json", sa.Text),
        sa.column("created_by", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    qr_table = sa.table(
        "ops_qr_assets",
        sa.column("id", sa.Integer),
        sa.column("qr_id", sa.String),
        sa.column("equipment_id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("default_item", sa.String),
        sa.column("checklist_set_id", sa.String),
        sa.column("lifecycle_state", sa.String),
    )
    existing_count = int(
        bind.execute(sa.select(sa.func.count()).select_from(revision_table)).scalar_one()
    )
    if existing_count > 0:
        return

    rows = bind.execute(
        sa.select(
            qr_table.c.id,
            qr_table.c.qr_id,
            qr_table.c.equipment_id,
            qr_table.c.equipment_snapshot,
            qr_table.c.equipment_location_snapshot,
            qr_table.c.default_item,
            qr_table.c.checklist_set_id,
            qr_table.c.lifecycle_state,
        )
    ).mappings().all()
    if not rows:
        return

    created_at = datetime.now(timezone.utc)
    baseline_rows: list[dict[str, object]] = []
    for row in rows:
        qr_id = str(row.get("qr_id") or "").strip()
        if not qr_id:
            continue
        after_row = {
            "qr_asset_id": int(row["id"]),
            "qr_id": qr_id,
            "equipment_id": int(row["equipment_id"]) if row.get("equipment_id") is not None else None,
            "equipment": str(row.get("equipment_snapshot") or "").strip(),
            "location": str(row.get("equipment_location_snapshot") or "").strip(),
            "default_item": str(row.get("default_item") or "").strip(),
            "checklist_set_id": str(row.get("checklist_set_id") or "").strip() or None,
            "lifecycle_state": str(row.get("lifecycle_state") or "active").strip() or "active",
        }
        baseline_rows.append(
            {
                "qr_asset_id": int(row["id"]),
                "qr_id": qr_id,
                "change_source": "migration_backfill",
                "change_action": "baseline",
                "change_note": "baseline qr asset snapshot",
                "before_json": "{}",
                "after_json": json.dumps(after_row, ensure_ascii=False, default=str),
                "quality_flags_json": json.dumps(_build_quality_flags(after_row), ensure_ascii=False, default=str),
                "created_by": "migration:20260314_0034",
                "created_at": created_at,
            }
        )
    if baseline_rows:
        bind.execute(revision_table.insert(), baseline_rows)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "ops_qr_asset_revisions"):
        for index_name in [
            "ix_ops_qr_asset_revisions_created_at",
            "ix_ops_qr_asset_revisions_qr_id",
        ]:
            if _index_exists(inspector, "ops_qr_asset_revisions", index_name):
                op.drop_index(index_name, table_name="ops_qr_asset_revisions")
        op.drop_table("ops_qr_asset_revisions")
