"""add ops master lifecycle states and checklist revision workflow

Revision ID: 20260314_0033
Revises: 20260314_0032
Create Date: 2026-03-14
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0033"
down_revision = "20260314_0032"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _has_column(inspector: sa.Inspector, table_name: str, column_name: str) -> bool:
    return any(column.get("name") == column_name for column in inspector.get_columns(table_name))


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _normalize_lifecycle_state(value: object) -> str:
    normalized = str(value or "").strip().lower() or "active"
    if normalized not in {"active", "retired", "replaced"}:
        return "active"
    return normalized


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "ops_checklist_sets"):
        if not _has_column(inspector, "ops_checklist_sets", "version_no"):
            op.add_column(
                "ops_checklist_sets",
                sa.Column("version_no", sa.Integer(), nullable=False, server_default="1"),
            )
        if not _has_column(inspector, "ops_checklist_sets", "lifecycle_state"):
            op.add_column(
                "ops_checklist_sets",
                sa.Column("lifecycle_state", sa.String(length=20), nullable=False, server_default="active"),
            )

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_equipment_assets") and not _has_column(inspector, "ops_equipment_assets", "lifecycle_state"):
        op.add_column(
            "ops_equipment_assets",
            sa.Column("lifecycle_state", sa.String(length=20), nullable=False, server_default="active"),
        )

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_qr_assets") and not _has_column(inspector, "ops_qr_assets", "lifecycle_state"):
        op.add_column(
            "ops_qr_assets",
            sa.Column("lifecycle_state", sa.String(length=20), nullable=False, server_default="active"),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "ops_checklist_set_revisions"):
        op.create_table(
            "ops_checklist_set_revisions",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("set_id", sa.String(length=80), nullable=False),
            sa.Column("base_version_no", sa.Integer(), nullable=True),
            sa.Column("proposed_version_no", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("label", sa.String(length=200), nullable=False),
            sa.Column("task_type", sa.String(length=80), nullable=False),
            sa.Column("lifecycle_state", sa.String(length=20), nullable=False, server_default="active"),
            sa.Column("items_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="draft"),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("submitted_by", sa.String(length=80), nullable=True),
            sa.Column("decided_by", sa.String(length=80), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        )

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_checklist_set_revisions"):
        if not _index_exists(inspector, "ops_checklist_set_revisions", "ix_ops_checklist_set_revisions_set_id"):
            op.create_index(
                "ix_ops_checklist_set_revisions_set_id",
                "ops_checklist_set_revisions",
                ["set_id"],
                unique=False,
            )
        if not _index_exists(inspector, "ops_checklist_set_revisions", "ix_ops_checklist_set_revisions_status"):
            op.create_index(
                "ix_ops_checklist_set_revisions_status",
                "ops_checklist_set_revisions",
                ["status"],
                unique=False,
            )

    now = datetime.now(timezone.utc)
    checklist_table = sa.table(
        "ops_checklist_sets",
        sa.column("id", sa.Integer),
        sa.column("version_no", sa.Integer),
        sa.column("lifecycle_state", sa.String),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    equipment_table = sa.table(
        "ops_equipment_assets",
        sa.column("id", sa.Integer),
        sa.column("lifecycle_state", sa.String),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    qr_table = sa.table(
        "ops_qr_assets",
        sa.column("id", sa.Integer),
        sa.column("lifecycle_state", sa.String),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )

    if _has_table(sa.inspect(bind), "ops_checklist_sets"):
        rows = bind.execute(
            sa.select(
                checklist_table.c.id,
                checklist_table.c.version_no,
                checklist_table.c.lifecycle_state,
            )
        ).mappings().all()
        for row in rows:
            updates: dict[str, object] = {}
            version_no = row.get("version_no")
            if version_no is None or int(version_no or 0) <= 0:
                updates["version_no"] = 1
            lifecycle_state = _normalize_lifecycle_state(row.get("lifecycle_state"))
            if str(row.get("lifecycle_state") or "").strip().lower() != lifecycle_state:
                updates["lifecycle_state"] = lifecycle_state
            if updates:
                updates["updated_at"] = now
                bind.execute(
                    checklist_table.update()
                    .where(checklist_table.c.id == int(row["id"]))
                    .values(**updates)
                )

    if _has_table(sa.inspect(bind), "ops_equipment_assets"):
        rows = bind.execute(
            sa.select(
                equipment_table.c.id,
                equipment_table.c.lifecycle_state,
            )
        ).mappings().all()
        for row in rows:
            lifecycle_state = _normalize_lifecycle_state(row.get("lifecycle_state"))
            if str(row.get("lifecycle_state") or "").strip().lower() == lifecycle_state:
                continue
            bind.execute(
                equipment_table.update()
                .where(equipment_table.c.id == int(row["id"]))
                .values(
                    lifecycle_state=lifecycle_state,
                    updated_at=now,
                )
            )

    if _has_table(sa.inspect(bind), "ops_qr_assets"):
        rows = bind.execute(
            sa.select(
                qr_table.c.id,
                qr_table.c.lifecycle_state,
            )
        ).mappings().all()
        for row in rows:
            lifecycle_state = _normalize_lifecycle_state(row.get("lifecycle_state"))
            if str(row.get("lifecycle_state") or "").strip().lower() == lifecycle_state:
                continue
            bind.execute(
                qr_table.update()
                .where(qr_table.c.id == int(row["id"]))
                .values(
                    lifecycle_state=lifecycle_state,
                    updated_at=now,
                )
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_table(inspector, "ops_checklist_set_revisions"):
        for index_name in [
            "ix_ops_checklist_set_revisions_status",
            "ix_ops_checklist_set_revisions_set_id",
        ]:
            if _index_exists(inspector, "ops_checklist_set_revisions", index_name):
                op.drop_index(index_name, table_name="ops_checklist_set_revisions")
        op.drop_table("ops_checklist_set_revisions")

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_qr_assets") and _has_column(inspector, "ops_qr_assets", "lifecycle_state"):
        op.drop_column("ops_qr_assets", "lifecycle_state")

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_equipment_assets") and _has_column(inspector, "ops_equipment_assets", "lifecycle_state"):
        op.drop_column("ops_equipment_assets", "lifecycle_state")

    inspector = sa.inspect(bind)
    if _has_table(inspector, "ops_checklist_sets"):
        if _has_column(inspector, "ops_checklist_sets", "lifecycle_state"):
            op.drop_column("ops_checklist_sets", "lifecycle_state")
        inspector = sa.inspect(bind)
        if _has_column(inspector, "ops_checklist_sets", "version_no"):
            op.drop_column("ops_checklist_sets", "version_no")
