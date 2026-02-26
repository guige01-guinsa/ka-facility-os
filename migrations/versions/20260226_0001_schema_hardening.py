"""schema hardening with constraints and indexes

Revision ID: 20260226_0001
Revises:
Create Date: 2026-02-26
"""

from __future__ import annotations

from typing import Iterable

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0001"
down_revision = None
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _column_names(inspector: sa.Inspector, table_name: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table_name)}


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _unique_exists(inspector: sa.Inspector, table_name: str, columns: Iterable[str]) -> bool:
    target = set(columns)
    return any(set(unique.get("column_names") or []) == target for unique in inspector.get_unique_constraints(table_name))


def _fk_exists(
    inspector: sa.Inspector,
    table_name: str,
    constrained_columns: Iterable[str],
    referred_table: str,
) -> bool:
    target_cols = list(constrained_columns)
    for fk in inspector.get_foreign_keys(table_name):
        if fk.get("referred_table") != referred_table:
            continue
        if list(fk.get("constrained_columns") or []) == target_cols:
            return True
    return False


def _ensure_column(table_name: str, column: sa.Column) -> None:
    inspector = sa.inspect(op.get_bind())
    if column.name in _column_names(inspector, table_name):
        return
    op.add_column(table_name, column)


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "inspections"):
        op.create_table(
            "inspections",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("location", sa.String(length=120), nullable=False),
            sa.Column("cycle", sa.String(length=40), nullable=False),
            sa.Column("inspector", sa.String(length=80), nullable=False),
            sa.Column("inspected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("transformer_kva", sa.Float(), nullable=True),
            sa.Column("voltage_r", sa.Float(), nullable=True),
            sa.Column("voltage_s", sa.Float(), nullable=True),
            sa.Column("voltage_t", sa.Float(), nullable=True),
            sa.Column("current_r", sa.Float(), nullable=True),
            sa.Column("current_s", sa.Float(), nullable=True),
            sa.Column("current_t", sa.Float(), nullable=True),
            sa.Column("winding_temp_c", sa.Float(), nullable=True),
            sa.Column("grounding_ohm", sa.Float(), nullable=True),
            sa.Column("insulation_mohm", sa.Float(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("risk_level", sa.String(length=20), nullable=False),
            sa.Column("risk_flags", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "admin_users"):
        op.create_table(
            "admin_users",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("username", sa.String(length=80), nullable=False),
            sa.Column("display_name", sa.String(length=120), nullable=False, server_default=sa.text("''")),
            sa.Column("role", sa.String(length=20), nullable=False, server_default=sa.text("'operator'")),
            sa.Column("permissions", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "work_orders"):
        fk_args = []
        if _has_table(inspector, "inspections"):
            fk_args = [sa.ForeignKeyConstraint(["inspection_id"], ["inspections.id"], name="fk_work_orders_inspection_id")]
        op.create_table(
            "work_orders",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("location", sa.String(length=120), nullable=False),
            sa.Column("priority", sa.String(length=20), nullable=False, server_default=sa.text("'medium'")),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'open'")),
            sa.Column("assignee", sa.String(length=80), nullable=True),
            sa.Column("reporter", sa.String(length=80), nullable=True),
            sa.Column("inspection_id", sa.Integer(), nullable=True),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolution_notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("is_escalated", sa.Boolean(), nullable=False, server_default=sa.text("0")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            *fk_args,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "admin_tokens"):
        fk_args = []
        if _has_table(inspector, "admin_users"):
            fk_args = [sa.ForeignKeyConstraint(["user_id"], ["admin_users.id"], name="fk_admin_tokens_user_id")]
        op.create_table(
            "admin_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("label", sa.String(length=120), nullable=False, server_default=sa.text("''")),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            *fk_args,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "admin_audit_logs"):
        fk_args = []
        if _has_table(inspector, "admin_users"):
            fk_args = [sa.ForeignKeyConstraint(["actor_user_id"], ["admin_users.id"], name="fk_admin_audit_logs_actor_user_id")]
        op.create_table(
            "admin_audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_username", sa.String(length=80), nullable=False),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("resource_type", sa.String(length=80), nullable=False),
            sa.Column("resource_id", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'success'")),
            sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            *fk_args,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "job_runs"):
        op.create_table(
            "job_runs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("job_name", sa.String(length=80), nullable=False),
            sa.Column("trigger", sa.String(length=40), nullable=False, server_default=sa.text("'manual'")),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'success'")),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        )

    # Missing-column safety for older databases.
    _ensure_column("work_orders", sa.Column("is_escalated", sa.Boolean(), nullable=False, server_default=sa.text("0")))
    _ensure_column("admin_users", sa.Column("display_name", sa.String(length=120), nullable=False, server_default=sa.text("''")))
    _ensure_column("admin_users", sa.Column("role", sa.String(length=20), nullable=False, server_default=sa.text("'operator'")))
    _ensure_column("admin_users", sa.Column("permissions", sa.Text(), nullable=False, server_default=sa.text("''")))
    _ensure_column("admin_users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")))
    _ensure_column("admin_users", sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
    _ensure_column("admin_users", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    _ensure_column("admin_tokens", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")))
    _ensure_column("admin_tokens", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    _ensure_column("admin_tokens", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))
    _ensure_column("admin_audit_logs", sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'success'")))
    _ensure_column("admin_audit_logs", sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")))
    _ensure_column("job_runs", sa.Column("trigger", sa.String(length=40), nullable=False, server_default=sa.text("'manual'")))
    _ensure_column("job_runs", sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'success'")))
    _ensure_column("job_runs", sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")))

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "inspections", "ix_inspections_site_inspected_at"):
        op.create_index("ix_inspections_site_inspected_at", "inspections", ["site", "inspected_at"], unique=False)
    if not _index_exists(inspector, "work_orders", "ix_work_orders_site_status"):
        op.create_index("ix_work_orders_site_status", "work_orders", ["site", "status"], unique=False)
    if not _index_exists(inspector, "work_orders", "ix_work_orders_due_at"):
        op.create_index("ix_work_orders_due_at", "work_orders", ["due_at"], unique=False)
    if not _index_exists(inspector, "work_orders", "ix_work_orders_is_escalated"):
        op.create_index("ix_work_orders_is_escalated", "work_orders", ["is_escalated"], unique=False)
    if not _index_exists(inspector, "admin_tokens", "ix_admin_tokens_user_id_is_active"):
        op.create_index("ix_admin_tokens_user_id_is_active", "admin_tokens", ["user_id", "is_active"], unique=False)
    if not _index_exists(inspector, "admin_audit_logs", "ix_admin_audit_logs_created_at"):
        op.create_index("ix_admin_audit_logs_created_at", "admin_audit_logs", ["created_at"], unique=False)
    if not _index_exists(inspector, "admin_audit_logs", "ix_admin_audit_logs_action"):
        op.create_index("ix_admin_audit_logs_action", "admin_audit_logs", ["action"], unique=False)
    if not _index_exists(inspector, "admin_audit_logs", "ix_admin_audit_logs_actor_username"):
        op.create_index("ix_admin_audit_logs_actor_username", "admin_audit_logs", ["actor_username"], unique=False)
    if not _index_exists(inspector, "job_runs", "ix_job_runs_job_name_finished_at"):
        op.create_index("ix_job_runs_job_name_finished_at", "job_runs", ["job_name", "finished_at"], unique=False)

    if dialect != "sqlite":
        inspector = sa.inspect(bind)
        if not _unique_exists(inspector, "admin_users", ["username"]):
            op.create_unique_constraint("uq_admin_users_username", "admin_users", ["username"])
        if not _unique_exists(inspector, "admin_tokens", ["token_hash"]):
            op.create_unique_constraint("uq_admin_tokens_token_hash", "admin_tokens", ["token_hash"])

        inspector = sa.inspect(bind)
        if _has_table(inspector, "inspections") and not _fk_exists(
            inspector, "work_orders", ["inspection_id"], "inspections"
        ):
            op.create_foreign_key(
                "fk_work_orders_inspection_id",
                "work_orders",
                "inspections",
                ["inspection_id"],
                ["id"],
                ondelete="SET NULL",
            )

        inspector = sa.inspect(bind)
        if _has_table(inspector, "admin_users") and not _fk_exists(
            inspector, "admin_tokens", ["user_id"], "admin_users"
        ):
            op.create_foreign_key(
                "fk_admin_tokens_user_id",
                "admin_tokens",
                "admin_users",
                ["user_id"],
                ["id"],
                ondelete="CASCADE",
            )

        inspector = sa.inspect(bind)
        if _has_table(inspector, "admin_users") and not _fk_exists(
            inspector, "admin_audit_logs", ["actor_user_id"], "admin_users"
        ):
            op.create_foreign_key(
                "fk_admin_audit_logs_actor_user_id",
                "admin_audit_logs",
                "admin_users",
                ["actor_user_id"],
                ["id"],
                ondelete="SET NULL",
            )


def downgrade() -> None:
    # Forward-only safety migration.
    pass
