from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config


def _alembic_config(database_url: str) -> Config:
    project_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(project_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(project_root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def test_migration_0031_backfills_ops_asset_masters(tmp_path) -> None:
    db_path = tmp_path / "migration_ops_asset_masters.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    cfg = _alembic_config(database_url)

    command.upgrade(cfg, "20260314_0030")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO inspections (
                site, location, cycle, inspector, inspected_at,
                equipment_snapshot, equipment_location_snapshot,
                qr_id, checklist_set_id, checklist_version,
                transformer_kva, voltage_r, voltage_s, voltage_t,
                current_r, current_s, current_t,
                winding_temp_c, grounding_ohm, insulation_mohm,
                notes, risk_level, risk_flags, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "MASTER-SITE",
                "B1 수변전실",
                "monthly",
                "migration_test",
                "2026-03-14T00:00:00+00:00",
                "변압기 1호기",
                "B1 수변전실",
                "QR-002",
                "electrical_60",
                "tests-fixture",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "[OPS_CHECKLIST_V1]",
                "warning",
                "ops_check_abnormal",
                "2026-03-14T00:00:00+00:00",
            ),
        )
        inspection_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO work_orders (
                title, description, site, location, priority, status,
                assignee, reporter, inspection_id,
                equipment_snapshot, equipment_location_snapshot, qr_id, checklist_set_id,
                due_at, acknowledged_at, completed_at, resolution_notes,
                is_escalated, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy work order",
                "created before ops asset masters",
                "MASTER-SITE",
                "B1 수변전실",
                "high",
                "open",
                None,
                "migration_test",
                inspection_id,
                "변압기 1호기",
                "B1 수변전실",
                "QR-002",
                "electrical_60",
                "2026-03-15T00:00:00+00:00",
                None,
                None,
                "",
                0,
                "2026-03-14T00:00:00+00:00",
                "2026-03-14T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    command.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    try:
        inspection_row = conn.execute(
            """
            SELECT equipment_id, qr_asset_id
            FROM inspections
            WHERE id = ?
            """,
            (inspection_id,),
        ).fetchone()
        assert inspection_row is not None
        equipment_id, qr_asset_id = inspection_row
        assert int(equipment_id) > 0
        assert int(qr_asset_id) > 0

        work_order_row = conn.execute(
            """
            SELECT equipment_id, qr_asset_id
            FROM work_orders
            WHERE inspection_id = ?
            """,
            (inspection_id,),
        ).fetchone()
        assert work_order_row == inspection_row

        equipment_row = conn.execute(
            """
            SELECT equipment_key, equipment_name, location_name
            FROM ops_equipment_assets
            WHERE id = ?
            """,
            (equipment_id,),
        ).fetchone()
        assert equipment_row == ("변압기 1호기::b1 수변전실", "변압기 1호기", "B1 수변전실")

        qr_row = conn.execute(
            """
            SELECT qr_id, equipment_id, equipment_snapshot, equipment_location_snapshot, checklist_set_id
            FROM ops_qr_assets
            WHERE id = ?
            """,
            (qr_asset_id,),
        ).fetchone()
        assert qr_row == ("QR-002", equipment_id, "변압기 1호기", "B1 수변전실", "electrical_60")
    finally:
        conn.close()
