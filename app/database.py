import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DB_PATH = Path(os.getenv("DB_PATH", "data/facility.db"))


def ensure_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inspections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                location TEXT NOT NULL,
                cycle TEXT NOT NULL,
                inspector TEXT NOT NULL,
                inspected_at TEXT NOT NULL,
                transformer_kva REAL,
                voltage_r REAL,
                voltage_s REAL,
                voltage_t REAL,
                current_r REAL,
                current_s REAL,
                current_t REAL,
                winding_temp_c REAL,
                grounding_ohm REAL,
                insulation_mohm REAL,
                notes TEXT NOT NULL DEFAULT '',
                risk_level TEXT NOT NULL,
                risk_flags TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
