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


def test_migration_0033_adds_ops_master_lifecycle_and_revision_tables(tmp_path) -> None:
    db_path = tmp_path / "migration_ops_master_lifecycle.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    cfg = _alembic_config(database_url)

    command.upgrade(cfg, "20260314_0032")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO ops_checklist_sets (
                set_id, label, task_type, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "migration_lifecycle_ops",
                "마이그레이션 점검",
                "전기점검",
                "migration-seed",
                "2026-03-14T00:00:00+00:00",
                "2026-03-14T00:00:00+00:00",
            ),
        )
        conn.execute(
            """
            INSERT INTO ops_checklist_set_items (
                set_id, seq, item_text, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "migration_lifecycle_ops",
                1,
                "외관 상태 확인",
                "2026-03-14T00:00:00+00:00",
                "2026-03-14T00:00:00+00:00",
            ),
        )
        conn.execute(
            """
            INSERT INTO ops_equipment_assets (
                equipment_key, equipment_name, location_name, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "migration pump::b1",
                "Migration Pump",
                "B1",
                "migration-seed",
                "2026-03-14T00:00:00+00:00",
                "2026-03-14T00:00:00+00:00",
            ),
        )
        equipment_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.execute(
            """
            INSERT INTO ops_qr_assets (
                qr_id, equipment_id, equipment_snapshot, equipment_location_snapshot,
                default_item, checklist_set_id, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "QR-MIGRATION-001",
                equipment_id,
                "Migration Pump",
                "B1",
                "외관 상태 확인",
                "migration_lifecycle_ops",
                "migration-seed",
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
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "ops_checklist_set_revisions" in tables

        checklist_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_checklist_sets)").fetchall()
        }
        assert {"version_no", "lifecycle_state"} <= checklist_columns

        equipment_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_equipment_assets)").fetchall()
        }
        assert "lifecycle_state" in equipment_columns

        qr_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_qr_assets)").fetchall()
        }
        assert "lifecycle_state" in qr_columns

        checklist_row = conn.execute(
            """
            SELECT version_no, lifecycle_state
            FROM ops_checklist_sets
            WHERE set_id = ?
            """,
            ("migration_lifecycle_ops",),
        ).fetchone()
        assert checklist_row == (1, "active")

        equipment_row = conn.execute(
            """
            SELECT lifecycle_state
            FROM ops_equipment_assets
            WHERE id = ?
            """,
            (equipment_id,),
        ).fetchone()
        assert equipment_row == ("active",)

        qr_row = conn.execute(
            """
            SELECT lifecycle_state
            FROM ops_qr_assets
            WHERE qr_id = ?
            """,
            ("QR-MIGRATION-001",),
        ).fetchone()
        assert qr_row == ("active",)
    finally:
        conn.close()
