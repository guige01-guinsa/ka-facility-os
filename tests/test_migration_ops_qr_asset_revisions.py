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


def test_migration_0034_adds_ops_qr_asset_revisions_and_backfills(tmp_path) -> None:
    db_path = tmp_path / "migration_ops_qr_asset_revisions.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    cfg = _alembic_config(database_url)

    command.upgrade(cfg, "20260314_0033")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO ops_qr_assets (
                qr_id, equipment_snapshot, equipment_location_snapshot,
                default_item, checklist_set_id, lifecycle_state, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "QR-MIGRATION-REV-001",
                "Migration Pump",
                "B1",
                "외관 상태 확인",
                "migration_set",
                "active",
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
        assert "ops_qr_asset_revisions" in tables

        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(ops_qr_asset_revisions)").fetchall()
        }
        assert {
            "qr_asset_id",
            "qr_id",
            "change_source",
            "change_action",
            "before_json",
            "after_json",
            "quality_flags_json",
            "created_by",
            "created_at",
        } <= columns

        row = conn.execute(
            """
            SELECT qr_id, change_source, change_action, created_by, before_json, after_json
            FROM ops_qr_asset_revisions
            WHERE qr_id = ?
            """,
            ("QR-MIGRATION-REV-001",),
        ).fetchone()
        assert row is not None
        assert row[0] == "QR-MIGRATION-REV-001"
        assert row[1] == "migration_backfill"
        assert row[2] == "baseline"
        assert row[3] == "migration:20260314_0034"
        assert row[4] == "{}"
        assert "Migration Pump" in row[5]
    finally:
        conn.close()
