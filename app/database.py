import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Column, DateTime, Float, Integer, MetaData, String, Table, Text, create_engine
from sqlalchemy.engine import Connection, make_url

DEFAULT_SQLITE_URL = "sqlite:///data/facility.db"


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL))
IS_SQLITE = DATABASE_URL.startswith("sqlite")

connect_args = {"check_same_thread": False} if IS_SQLITE else {}
engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    connect_args=connect_args,
)

metadata = MetaData()
inspections = Table(
    "inspections",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("site", String(120), nullable=False),
    Column("location", String(120), nullable=False),
    Column("cycle", String(40), nullable=False),
    Column("inspector", String(80), nullable=False),
    Column("inspected_at", DateTime(timezone=True), nullable=False),
    Column("transformer_kva", Float, nullable=True),
    Column("voltage_r", Float, nullable=True),
    Column("voltage_s", Float, nullable=True),
    Column("voltage_t", Float, nullable=True),
    Column("current_r", Float, nullable=True),
    Column("current_s", Float, nullable=True),
    Column("current_t", Float, nullable=True),
    Column("winding_temp_c", Float, nullable=True),
    Column("grounding_ohm", Float, nullable=True),
    Column("insulation_mohm", Float, nullable=True),
    Column("notes", Text, nullable=False, default=""),
    Column("risk_level", String(20), nullable=False),
    Column("risk_flags", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


def _ensure_sqlite_parent_dir() -> None:
    if not IS_SQLITE:
        return

    db_path = make_url(DATABASE_URL).database
    if not db_path or db_path == ":memory:":
        return
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)


def ensure_database() -> None:
    _ensure_sqlite_parent_dir()
    metadata.create_all(engine)


@contextmanager
def get_conn() -> Iterator[Connection]:
    with engine.begin() as conn:
        yield conn
