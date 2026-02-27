import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from alembic import command
from alembic.config import Config
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, Text, create_engine
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

work_orders = Table(
    "work_orders",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String(200), nullable=False),
    Column("description", Text, nullable=False, default=""),
    Column("site", String(120), nullable=False),
    Column("location", String(120), nullable=False),
    Column("priority", String(20), nullable=False, default="medium"),
    Column("status", String(20), nullable=False, default="open"),
    Column("assignee", String(80), nullable=True),
    Column("reporter", String(80), nullable=True),
    Column("inspection_id", Integer, nullable=True),
    Column("due_at", DateTime(timezone=True), nullable=True),
    Column("acknowledged_at", DateTime(timezone=True), nullable=True),
    Column("completed_at", DateTime(timezone=True), nullable=True),
    Column("resolution_notes", Text, nullable=False, default=""),
    Column("is_escalated", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

work_order_events = Table(
    "work_order_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("work_order_id", Integer, nullable=False),
    Column("event_type", String(40), nullable=False),
    Column("actor_username", String(80), nullable=False, default="system"),
    Column("from_status", String(20), nullable=True),
    Column("to_status", String(20), nullable=True),
    Column("note", Text, nullable=False, default=""),
    Column("detail_json", Text, nullable=False, default="{}"),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

admin_users = Table(
    "admin_users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(80), nullable=False, unique=True),
    Column("display_name", String(120), nullable=False, default=""),
    Column("role", String(20), nullable=False, default="operator"),
    Column("permissions", Text, nullable=False, default=""),
    Column("site_scope", Text, nullable=False, default="*"),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

admin_tokens = Table(
    "admin_tokens",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False),
    Column("label", String(120), nullable=False, default=""),
    Column("token_hash", String(128), nullable=False, unique=True),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("site_scope", Text, nullable=True),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("last_used_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

admin_audit_logs = Table(
    "admin_audit_logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("actor_user_id", Integer, nullable=True),
    Column("actor_username", String(80), nullable=False),
    Column("action", String(80), nullable=False),
    Column("resource_type", String(80), nullable=False),
    Column("resource_id", String(120), nullable=False),
    Column("status", String(20), nullable=False, default="success"),
    Column("detail_json", Text, nullable=False, default="{}"),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

sla_policies = Table(
    "sla_policies",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("policy_key", String(80), nullable=False, unique=True),
    Column("policy_json", Text, nullable=False, default="{}"),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

job_runs = Table(
    "job_runs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("job_name", String(80), nullable=False),
    Column("trigger", String(40), nullable=False, default="manual"),
    Column("status", String(20), nullable=False, default="success"),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False),
    Column("detail_json", Text, nullable=False, default="{}"),
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
    project_root = Path(__file__).resolve().parent.parent
    alembic_ini = project_root / "alembic.ini"
    alembic_dir = project_root / "migrations"

    cfg = Config(str(alembic_ini))
    cfg.set_main_option("script_location", str(alembic_dir))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(cfg, "head")


@contextmanager
def get_conn() -> Iterator[Connection]:
    with engine.begin() as conn:
        yield conn
