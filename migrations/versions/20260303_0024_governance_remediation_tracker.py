"""add governance remediation tracker tables

Revision ID: 20260303_0024
Revises: 20260303_0023
Create Date: 2026-03-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260303_0024"
down_revision = "20260303_0023"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "ops_governance_remediation_tracker_items"):
        op.create_table(
            "ops_governance_remediation_tracker_items",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("item_id", sa.String(length=40), nullable=False),
            sa.Column("rule_id", sa.String(length=120), nullable=False),
            sa.Column("rule_status", sa.String(length=20), nullable=False, server_default=sa.text("'warning'")),
            sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("9")),
            sa.Column("owner_role", sa.String(length=120), nullable=False),
            sa.Column("sla_hours", sa.Integer(), nullable=False, server_default=sa.text("24")),
            sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("action", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("reason", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("gate_generated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("source_decision", sa.String(length=20), nullable=False, server_default=sa.text("'no_go'")),
            sa.Column("assignee", sa.String(length=120), nullable=True),
            sa.Column("status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("completion_checked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("completion_note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(
        inspector,
        "ops_governance_remediation_tracker_items",
        "ux_ops_governance_remediation_tracker_rule",
    ):
        op.create_index(
            "ux_ops_governance_remediation_tracker_rule",
            "ops_governance_remediation_tracker_items",
            ["rule_id"],
            unique=True,
        )
    if not _index_exists(
        inspector,
        "ops_governance_remediation_tracker_items",
        "ix_ops_governance_remediation_tracker_status",
    ):
        op.create_index(
            "ix_ops_governance_remediation_tracker_status",
            "ops_governance_remediation_tracker_items",
            ["status", "is_active"],
            unique=False,
        )
    if not _index_exists(
        inspector,
        "ops_governance_remediation_tracker_items",
        "ix_ops_governance_remediation_tracker_due",
    ):
        op.create_index(
            "ix_ops_governance_remediation_tracker_due",
            "ops_governance_remediation_tracker_items",
            ["due_at", "priority"],
            unique=False,
        )
    if not _index_exists(
        inspector,
        "ops_governance_remediation_tracker_items",
        "ix_ops_governance_remediation_tracker_assignee",
    ):
        op.create_index(
            "ix_ops_governance_remediation_tracker_assignee",
            "ops_governance_remediation_tracker_items",
            ["assignee"],
            unique=False,
        )

    inspector = sa.inspect(bind)
    if not _has_table(inspector, "ops_governance_remediation_tracker_runs"):
        op.create_table(
            "ops_governance_remediation_tracker_runs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("scope", sa.String(length=40), nullable=False, unique=True, server_default=sa.text("'global'")),
            sa.Column("status", sa.String(length=40), nullable=False, server_default=sa.text("'active'")),
            sa.Column("completion_note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("force_used", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("completed_by", sa.String(length=80), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("readiness_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(
        inspector,
        "ops_governance_remediation_tracker_runs",
        "ux_ops_governance_remediation_tracker_runs_scope",
    ):
        op.create_index(
            "ux_ops_governance_remediation_tracker_runs_scope",
            "ops_governance_remediation_tracker_runs",
            ["scope"],
            unique=True,
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

