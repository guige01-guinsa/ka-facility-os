from __future__ import annotations

import json
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


def _build_ops_notes() -> str:
    meta = {
        "task_type": "전기점검",
        "equipment": "변압기 1호기",
        "equipment_location": "B1 수변전실",
        "qr_id": "QR-002",
        "checklist_set_id": "electrical_60",
        "checklist_data_version": "tests-fixture",
        "summary": {"total": 1, "normal": 0, "abnormal": 1, "na": 0},
        "abnormal_action": "재점검",
    }
    checklist = [{"group": "변압기", "item": "변압기 외관 점검", "result": "abnormal", "action": ""}]
    return "\n".join(
        [
            "[OPS_CHECKLIST_V1]",
            "meta=" + json.dumps(meta, ensure_ascii=False),
            "checklist=" + json.dumps(checklist, ensure_ascii=False),
        ]
    )


def test_migration_0030_backfills_ops_key_snapshots(tmp_path) -> None:
    db_path = tmp_path / "migration_ops_keys.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    cfg = _alembic_config(database_url)

    command.upgrade(cfg, "20260313_0029")

    conn = sqlite3.connect(db_path)
    try:
        notes = _build_ops_notes()
        conn.execute(
            """
            INSERT INTO inspections (
                site, location, cycle, inspector, inspected_at,
                transformer_kva, voltage_r, voltage_s, voltage_t,
                current_r, current_s, current_t,
                winding_temp_c, grounding_ohm, insulation_mohm,
                notes, risk_level, risk_flags, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "MIGRATION-SITE",
                "B1 수변전실",
                "monthly",
                "migration_test",
                "2026-03-14T00:00:00+00:00",
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
                notes,
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
                assignee, reporter, inspection_id, due_at,
                acknowledged_at, completed_at, resolution_notes,
                is_escalated, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy work order",
                "created before ops key snapshots",
                "MIGRATION-SITE",
                "B1 수변전실",
                "high",
                "open",
                None,
                "migration_test",
                inspection_id,
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
            SELECT equipment_snapshot, equipment_location_snapshot, qr_id, checklist_set_id, checklist_version
            FROM inspections
            WHERE id = ?
            """,
            (inspection_id,),
        ).fetchone()
        assert inspection_row == ("변압기 1호기", "B1 수변전실", "QR-002", "electrical_60", "tests-fixture")

        work_order_row = conn.execute(
            """
            SELECT equipment_snapshot, equipment_location_snapshot, qr_id, checklist_set_id
            FROM work_orders
            WHERE inspection_id = ?
            """,
            (inspection_id,),
        ).fetchone()
        assert work_order_row == ("변압기 1호기", "B1 수변전실", "QR-002", "electrical_60")
    finally:
        conn.close()
