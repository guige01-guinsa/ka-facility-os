"""add ops equipment/qr asset masters and relational ids

Revision ID: 20260314_0031
Revises: 20260314_0030
Create Date: 2026-03-14
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0031"
down_revision = "20260314_0030"
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


def _normalize_equipment_key(equipment_name: object, location_name: object) -> str | None:
    equipment = _normalize_text(equipment_name)
    location = _normalize_text(location_name)
    if equipment is None:
        return None
    return f"{equipment.lower()}::{(location or '').lower()}"


def _load_existing_equipment_cache(bind: sa.Connection) -> dict[str, int]:
    equipment_table = sa.table(
        "ops_equipment_assets",
        sa.column("id", sa.Integer),
        sa.column("equipment_key", sa.String),
    )
    rows = bind.execute(
        sa.select(
            equipment_table.c.id,
            equipment_table.c.equipment_key,
        )
    ).mappings().all()
    cache: dict[str, int] = {}
    for row in rows:
        key = _normalize_text(row.get("equipment_key"))
        if key is None:
            continue
        cache[key] = int(row["id"])
    return cache


def _load_existing_qr_cache(bind: sa.Connection) -> dict[str, int]:
    qr_table = sa.table(
        "ops_qr_assets",
        sa.column("id", sa.Integer),
        sa.column("qr_id", sa.String),
    )
    rows = bind.execute(
        sa.select(
            qr_table.c.id,
            qr_table.c.qr_id,
        )
    ).mappings().all()
    cache: dict[str, int] = {}
    for row in rows:
        qr_id = _normalize_text(row.get("qr_id"))
        if qr_id is None:
            continue
        cache[qr_id] = int(row["id"])
    return cache


def _ensure_equipment_master(
    bind: sa.Connection,
    *,
    equipment_cache: dict[str, int],
    equipment_name: object,
    location_name: object,
    source: str,
) -> int | None:
    equipment_key = _normalize_equipment_key(equipment_name, location_name)
    if equipment_key is None:
        return None
    cached = equipment_cache.get(equipment_key)
    if cached is not None:
        return cached

    equipment_table = sa.table(
        "ops_equipment_assets",
        sa.column("id", sa.Integer),
        sa.column("equipment_key", sa.String),
        sa.column("equipment_name", sa.String),
        sa.column("location_name", sa.String),
        sa.column("source", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    now = datetime.now(timezone.utc)
    result = bind.execute(
        equipment_table.insert().values(
            equipment_key=equipment_key,
            equipment_name=_normalize_text(equipment_name),
            location_name=_normalize_text(location_name),
            source=source,
            created_at=now,
            updated_at=now,
        )
    )
    inserted_pk = result.inserted_primary_key[0] if result.inserted_primary_key else None
    if inserted_pk is None:
        inserted_row = bind.execute(
            sa.select(equipment_table.c.id).where(equipment_table.c.equipment_key == equipment_key).limit(1)
        ).first()
        if inserted_row is None:
            return None
        inserted_pk = inserted_row[0]
    equipment_id = int(inserted_pk)
    equipment_cache[equipment_key] = equipment_id
    return equipment_id


def _ensure_qr_master(
    bind: sa.Connection,
    *,
    qr_cache: dict[str, int],
    qr_id: object,
    equipment_id: int | None,
    equipment_snapshot: object,
    equipment_location_snapshot: object,
    checklist_set_id: object,
    source: str,
) -> int | None:
    normalized_qr_id = _normalize_text(qr_id)
    if normalized_qr_id is None:
        return None
    qr_table = sa.table(
        "ops_qr_assets",
        sa.column("id", sa.Integer),
        sa.column("qr_id", sa.String),
        sa.column("equipment_id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("default_item", sa.String),
        sa.column("checklist_set_id", sa.String),
        sa.column("source", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    existing_id = qr_cache.get(normalized_qr_id)
    now = datetime.now(timezone.utc)
    values = {
        "equipment_id": equipment_id,
        "equipment_snapshot": _normalize_text(equipment_snapshot),
        "equipment_location_snapshot": _normalize_text(equipment_location_snapshot),
        "checklist_set_id": _normalize_text(checklist_set_id),
        "source": source,
        "updated_at": now,
    }
    if existing_id is None:
        result = bind.execute(
            qr_table.insert().values(
                qr_id=normalized_qr_id,
                default_item=None,
                created_at=now,
                **values,
            )
        )
        inserted_pk = result.inserted_primary_key[0] if result.inserted_primary_key else None
        if inserted_pk is None:
            inserted_row = bind.execute(
                sa.select(qr_table.c.id).where(qr_table.c.qr_id == normalized_qr_id).limit(1)
            ).first()
            if inserted_row is None:
                return None
            inserted_pk = inserted_row[0]
        qr_asset_id = int(inserted_pk)
        qr_cache[normalized_qr_id] = qr_asset_id
        return qr_asset_id

    current = bind.execute(
        sa.select(
            qr_table.c.id,
            qr_table.c.equipment_id,
            qr_table.c.equipment_snapshot,
            qr_table.c.equipment_location_snapshot,
            qr_table.c.checklist_set_id,
        ).where(qr_table.c.id == existing_id)
    ).mappings().first()
    if current is None:
        qr_cache.pop(normalized_qr_id, None)
        return _ensure_qr_master(
            bind,
            qr_cache=qr_cache,
            qr_id=normalized_qr_id,
            equipment_id=equipment_id,
            equipment_snapshot=equipment_snapshot,
            equipment_location_snapshot=equipment_location_snapshot,
            checklist_set_id=checklist_set_id,
            source=source,
        )

    updates: dict[str, object] = {}
    if current.get("equipment_id") is None and equipment_id is not None:
        updates["equipment_id"] = equipment_id
    if _normalize_text(current.get("equipment_snapshot")) is None and values["equipment_snapshot"] is not None:
        updates["equipment_snapshot"] = values["equipment_snapshot"]
    if (
        _normalize_text(current.get("equipment_location_snapshot")) is None
        and values["equipment_location_snapshot"] is not None
    ):
        updates["equipment_location_snapshot"] = values["equipment_location_snapshot"]
    if _normalize_text(current.get("checklist_set_id")) is None and values["checklist_set_id"] is not None:
        updates["checklist_set_id"] = values["checklist_set_id"]
    if updates:
        updates["source"] = source
        updates["updated_at"] = now
        bind.execute(
            qr_table.update()
            .where(qr_table.c.id == existing_id)
            .values(**updates)
        )
    return existing_id


def _backfill_relational_ids(bind: sa.Connection) -> None:
    inspector = sa.inspect(bind)
    equipment_cache = _load_existing_equipment_cache(bind)
    qr_cache = _load_existing_qr_cache(bind)

    inspections_table = sa.table(
        "inspections",
        sa.column("id", sa.Integer),
        sa.column("equipment_id", sa.Integer),
        sa.column("qr_asset_id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("qr_id", sa.String),
        sa.column("checklist_set_id", sa.String),
    )
    work_orders_table = sa.table(
        "work_orders",
        sa.column("id", sa.Integer),
        sa.column("equipment_id", sa.Integer),
        sa.column("qr_asset_id", sa.Integer),
        sa.column("equipment_snapshot", sa.String),
        sa.column("equipment_location_snapshot", sa.String),
        sa.column("qr_id", sa.String),
        sa.column("checklist_set_id", sa.String),
    )

    if _has_table(inspector, "inspections"):
        rows = bind.execute(
            sa.select(
                inspections_table.c.id,
                inspections_table.c.equipment_id,
                inspections_table.c.qr_asset_id,
                inspections_table.c.equipment_snapshot,
                inspections_table.c.equipment_location_snapshot,
                inspections_table.c.qr_id,
                inspections_table.c.checklist_set_id,
            )
        ).mappings().all()
        for row in rows:
            equipment_id = row.get("equipment_id")
            if equipment_id is None:
                equipment_id = _ensure_equipment_master(
                    bind,
                    equipment_cache=equipment_cache,
                    equipment_name=row.get("equipment_snapshot"),
                    location_name=row.get("equipment_location_snapshot"),
                    source="migration_backfill",
                )
            qr_asset_id = row.get("qr_asset_id")
            if qr_asset_id is None:
                qr_asset_id = _ensure_qr_master(
                    bind,
                    qr_cache=qr_cache,
                    qr_id=row.get("qr_id"),
                    equipment_id=equipment_id,
                    equipment_snapshot=row.get("equipment_snapshot"),
                    equipment_location_snapshot=row.get("equipment_location_snapshot"),
                    checklist_set_id=row.get("checklist_set_id"),
                    source="migration_backfill",
                )
            updates: dict[str, object] = {}
            if row.get("equipment_id") is None and equipment_id is not None:
                updates["equipment_id"] = equipment_id
            if row.get("qr_asset_id") is None and qr_asset_id is not None:
                updates["qr_asset_id"] = qr_asset_id
            if updates:
                bind.execute(
                    inspections_table.update()
                    .where(inspections_table.c.id == int(row["id"]))
                    .values(**updates)
                )

    if _has_table(inspector, "work_orders"):
        rows = bind.execute(
            sa.select(
                work_orders_table.c.id,
                work_orders_table.c.equipment_id,
                work_orders_table.c.qr_asset_id,
                work_orders_table.c.equipment_snapshot,
                work_orders_table.c.equipment_location_snapshot,
                work_orders_table.c.qr_id,
                work_orders_table.c.checklist_set_id,
            )
        ).mappings().all()
        for row in rows:
            equipment_id = row.get("equipment_id")
            if equipment_id is None:
                equipment_id = _ensure_equipment_master(
                    bind,
                    equipment_cache=equipment_cache,
                    equipment_name=row.get("equipment_snapshot"),
                    location_name=row.get("equipment_location_snapshot"),
                    source="migration_backfill",
                )
            qr_asset_id = row.get("qr_asset_id")
            if qr_asset_id is None:
                qr_asset_id = _ensure_qr_master(
                    bind,
                    qr_cache=qr_cache,
                    qr_id=row.get("qr_id"),
                    equipment_id=equipment_id,
                    equipment_snapshot=row.get("equipment_snapshot"),
                    equipment_location_snapshot=row.get("equipment_location_snapshot"),
                    checklist_set_id=row.get("checklist_set_id"),
                    source="migration_backfill",
                )
            updates: dict[str, object] = {}
            if row.get("equipment_id") is None and equipment_id is not None:
                updates["equipment_id"] = equipment_id
            if row.get("qr_asset_id") is None and qr_asset_id is not None:
                updates["qr_asset_id"] = qr_asset_id
            if updates:
                bind.execute(
                    work_orders_table.update()
                    .where(work_orders_table.c.id == int(row["id"]))
                    .values(**updates)
                )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "ops_equipment_assets"):
        op.create_table(
            "ops_equipment_assets",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("equipment_key", sa.String(length=400), nullable=False),
            sa.Column("equipment_name", sa.String(length=200), nullable=False),
            sa.Column("location_name", sa.String(length=120), nullable=True),
            sa.Column("source", sa.String(length=40), nullable=False, server_default="catalog"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("equipment_key", name="uq_ops_equipment_assets_equipment_key"),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "ops_qr_assets"):
        op.create_table(
            "ops_qr_assets",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("qr_id", sa.String(length=80), nullable=False),
            sa.Column("equipment_id", sa.Integer(), nullable=True),
            sa.Column("equipment_snapshot", sa.String(length=200), nullable=True),
            sa.Column("equipment_location_snapshot", sa.String(length=120), nullable=True),
            sa.Column("default_item", sa.String(length=200), nullable=True),
            sa.Column("checklist_set_id", sa.String(length=80), nullable=True),
            sa.Column("source", sa.String(length=40), nullable=False, server_default="catalog"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("qr_id", name="uq_ops_qr_assets_qr_id"),
        )

    inspector = sa.inspect(bind)
    if _has_table(inspector, "inspections"):
        if not _has_column(inspector, "inspections", "equipment_id"):
            op.add_column("inspections", sa.Column("equipment_id", sa.Integer(), nullable=True))
        if not _has_column(inspector, "inspections", "qr_asset_id"):
            op.add_column("inspections", sa.Column("qr_asset_id", sa.Integer(), nullable=True))

    inspector = sa.inspect(bind)
    if _has_table(inspector, "work_orders"):
        if not _has_column(inspector, "work_orders", "equipment_id"):
            op.add_column("work_orders", sa.Column("equipment_id", sa.Integer(), nullable=True))
        if not _has_column(inspector, "work_orders", "qr_asset_id"):
            op.add_column("work_orders", sa.Column("qr_asset_id", sa.Integer(), nullable=True))

    _backfill_relational_ids(bind)

    inspector = sa.inspect(bind)
    indexes = [
        ("inspections", "ix_inspections_site_equipment_id", ["site", "equipment_id"]),
        ("inspections", "ix_inspections_site_qr_asset_id", ["site", "qr_asset_id"]),
        ("work_orders", "ix_work_orders_site_equipment_id", ["site", "equipment_id"]),
        ("work_orders", "ix_work_orders_site_qr_asset_id", ["site", "qr_asset_id"]),
        ("ops_qr_assets", "ix_ops_qr_assets_equipment_id", ["equipment_id"]),
    ]
    for table_name, index_name, columns in indexes:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    # Forward-only safety migration.
    pass
