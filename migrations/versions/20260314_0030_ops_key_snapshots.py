"""persist ops key snapshots on inspections and work orders

Revision ID: 20260314_0030
Revises: 20260313_0029
Create Date: 2026-03-14
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0030"
down_revision = "20260313_0029"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _has_column(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    return any(column.get("name") == column_name for column in inspector.get_columns(table_name))


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _normalize_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _parse_ops_meta(note_text: object) -> dict[str, str | None]:
    text = str(note_text or "")
    if "[OPS_CHECKLIST_V1]" not in text and "[OPS_ELECTRICAL_V1]" not in text:
        return {
            "equipment_snapshot": None,
            "equipment_location_snapshot": None,
            "qr_id": None,
            "checklist_set_id": None,
            "checklist_version": None,
        }

    meta: dict[str, object] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("meta="):
            continue
        try:
            parsed = json.loads(line[5:].strip())
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            meta = parsed
        break

    if meta is None:
        return {
            "equipment_snapshot": None,
            "equipment_location_snapshot": None,
            "qr_id": None,
            "checklist_set_id": None,
            "checklist_version": None,
        }

    return {
        "equipment_snapshot": _normalize_text(meta.get("equipment")),
        "equipment_location_snapshot": _normalize_text(meta.get("equipment_location")),
        "qr_id": _normalize_text(meta.get("qr_id")),
        "checklist_set_id": _normalize_text(meta.get("checklist_set_id")),
        "checklist_version": _normalize_text(meta.get("checklist_data_version") or meta.get("checklist_version")),
    }


def _backfill_inspection_snapshots(bind: sa.Connection) -> None:
    inspections_table = sa.table(
        "inspections",
        sa.column("id", sa.Integer),
        sa.column("location", sa.String),
        sa.column("notes", sa.Text),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("qr_id", sa.String),
        sa.column("checklist_set_id", sa.String),
        sa.column("checklist_version", sa.String),
    )
    rows = bind.execute(
        sa.select(
            inspections_table.c.id,
            inspections_table.c.location,
            inspections_table.c.notes,
            inspections_table.c.equipment_snapshot,
            inspections_table.c.equipment_location_snapshot,
            inspections_table.c.qr_id,
            inspections_table.c.checklist_set_id,
            inspections_table.c.checklist_version,
        )
    ).mappings().all()
    for row in rows:
        parsed = _parse_ops_meta(row.get("notes"))
        values: dict[str, object] = {}
        equipment_snapshot = _normalize_text(row.get("equipment_snapshot")) or parsed["equipment_snapshot"]
        equipment_location_snapshot = _normalize_text(row.get("equipment_location_snapshot")) or parsed["equipment_location_snapshot"]
        if equipment_snapshot and not equipment_location_snapshot:
            equipment_location_snapshot = _normalize_text(row.get("location"))
        qr_id = _normalize_text(row.get("qr_id")) or parsed["qr_id"]
        checklist_set_id = _normalize_text(row.get("checklist_set_id")) or parsed["checklist_set_id"]
        checklist_version = _normalize_text(row.get("checklist_version")) or parsed["checklist_version"]

        if equipment_snapshot != _normalize_text(row.get("equipment_snapshot")):
            values["equipment_snapshot"] = equipment_snapshot
        if equipment_location_snapshot != _normalize_text(row.get("equipment_location_snapshot")):
            values["equipment_location_snapshot"] = equipment_location_snapshot
        if qr_id != _normalize_text(row.get("qr_id")):
            values["qr_id"] = qr_id
        if checklist_set_id != _normalize_text(row.get("checklist_set_id")):
            values["checklist_set_id"] = checklist_set_id
        if checklist_version != _normalize_text(row.get("checklist_version")):
            values["checklist_version"] = checklist_version

        if values:
            bind.execute(
                inspections_table.update()
                .where(inspections_table.c.id == int(row["id"]))
                .values(**values)
            )


def _backfill_work_order_snapshots(bind: sa.Connection) -> None:
    work_orders_table = sa.table(
        "work_orders",
        sa.column("id", sa.Integer),
        sa.column("inspection_id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("qr_id", sa.String),
        sa.column("checklist_set_id", sa.String),
    )
    inspections_table = sa.table(
        "inspections",
        sa.column("id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("qr_id", sa.String),
        sa.column("checklist_set_id", sa.String),
    )
    rows = bind.execute(
        sa.select(
            work_orders_table.c.id,
            work_orders_table.c.inspection_id,
            work_orders_table.c.equipment_snapshot,
            work_orders_table.c.equipment_location_snapshot,
            work_orders_table.c.qr_id,
            work_orders_table.c.checklist_set_id,
            inspections_table.c.equipment_snapshot.label("inspection_equipment_snapshot"),
            inspections_table.c.equipment_location_snapshot.label("inspection_equipment_location_snapshot"),
            inspections_table.c.qr_id.label("inspection_qr_id"),
            inspections_table.c.checklist_set_id.label("inspection_checklist_set_id"),
        )
        .select_from(
            work_orders_table.outerjoin(
                inspections_table,
                inspections_table.c.id == work_orders_table.c.inspection_id,
            )
        )
    ).mappings().all()
    for row in rows:
        if row.get("inspection_id") is None:
            continue
        values: dict[str, object] = {}
        equipment_snapshot = _normalize_text(row.get("equipment_snapshot")) or _normalize_text(row.get("inspection_equipment_snapshot"))
        equipment_location_snapshot = _normalize_text(row.get("equipment_location_snapshot")) or _normalize_text(row.get("inspection_equipment_location_snapshot"))
        qr_id = _normalize_text(row.get("qr_id")) or _normalize_text(row.get("inspection_qr_id"))
        checklist_set_id = _normalize_text(row.get("checklist_set_id")) or _normalize_text(row.get("inspection_checklist_set_id"))

        if equipment_snapshot != _normalize_text(row.get("equipment_snapshot")):
            values["equipment_snapshot"] = equipment_snapshot
        if equipment_location_snapshot != _normalize_text(row.get("equipment_location_snapshot")):
            values["equipment_location_snapshot"] = equipment_location_snapshot
        if qr_id != _normalize_text(row.get("qr_id")):
            values["qr_id"] = qr_id
        if checklist_set_id != _normalize_text(row.get("checklist_set_id")):
            values["checklist_set_id"] = checklist_set_id

        if values:
            bind.execute(
                work_orders_table.update()
                .where(work_orders_table.c.id == int(row["id"]))
                .values(**values)
            )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "inspections"):
        if not _has_column(inspector, "inspections", "equipment_snapshot"):
            op.add_column("inspections", sa.Column("equipment_snapshot", sa.String(length=200), nullable=True))
        if not _has_column(inspector, "inspections", "equipment_location_snapshot"):
            op.add_column("inspections", sa.Column("equipment_location_snapshot", sa.String(length=120), nullable=True))
        if not _has_column(inspector, "inspections", "qr_id"):
            op.add_column("inspections", sa.Column("qr_id", sa.String(length=80), nullable=True))
        if not _has_column(inspector, "inspections", "checklist_set_id"):
            op.add_column("inspections", sa.Column("checklist_set_id", sa.String(length=80), nullable=True))
        if not _has_column(inspector, "inspections", "checklist_version"):
            op.add_column("inspections", sa.Column("checklist_version", sa.String(length=80), nullable=True))

    inspector = sa.inspect(bind)
    if _has_table(inspector, "work_orders"):
        if not _has_column(inspector, "work_orders", "equipment_snapshot"):
            op.add_column("work_orders", sa.Column("equipment_snapshot", sa.String(length=200), nullable=True))
        if not _has_column(inspector, "work_orders", "equipment_location_snapshot"):
            op.add_column("work_orders", sa.Column("equipment_location_snapshot", sa.String(length=120), nullable=True))
        if not _has_column(inspector, "work_orders", "qr_id"):
            op.add_column("work_orders", sa.Column("qr_id", sa.String(length=80), nullable=True))
        if not _has_column(inspector, "work_orders", "checklist_set_id"):
            op.add_column("work_orders", sa.Column("checklist_set_id", sa.String(length=80), nullable=True))

    _backfill_inspection_snapshots(bind)
    _backfill_work_order_snapshots(bind)

    inspector = sa.inspect(bind)
    indexes = [
        ("inspections", "ix_inspections_site_qr_id", ["site", "qr_id"]),
        ("inspections", "ix_inspections_site_checklist_set_id", ["site", "checklist_set_id"]),
        ("work_orders", "ix_work_orders_site_qr_id", ["site", "qr_id"]),
    ]
    for table_name, index_name, columns in indexes:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    # Forward-only safety migration.
    pass
