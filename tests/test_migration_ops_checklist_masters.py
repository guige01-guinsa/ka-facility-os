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


def test_migration_0032_creates_ops_checklist_master_tables(tmp_path) -> None:
    db_path = tmp_path / "migration_ops_checklist_masters.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    cfg = _alembic_config(database_url)

    command.upgrade(cfg, "20260314_0031")
    command.upgrade(cfg, "head")

    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "ops_checklist_sets" in tables
        assert "ops_checklist_set_items" in tables

        checklist_set_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_checklist_sets)").fetchall()
        }
        assert {"id", "set_id", "label", "task_type", "source", "created_at", "updated_at"} <= checklist_set_columns

        checklist_item_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_checklist_set_items)").fetchall()
        }
        assert {"id", "set_id", "seq", "item_text", "created_at", "updated_at"} <= checklist_item_columns
    finally:
        conn.close()
