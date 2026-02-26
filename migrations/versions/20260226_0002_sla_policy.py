"""add sla policy table

Revision ID: 20260226_0002
Revises: 20260226_0001
Create Date: 2026-02-26
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0002"
down_revision = "20260226_0001"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _unique_exists(inspector: sa.Inspector, table_name: str, columns: list[str]) -> bool:
    target = set(columns)
    return any(set(unique.get("column_names") or []) == target for unique in inspector.get_unique_constraints(table_name))


def _default_policy_json() -> str:
    return json.dumps(
        {
            "default_due_hours": {
                "low": 72,
                "medium": 24,
                "high": 8,
                "critical": 2,
            },
            "escalation_grace_minutes": 0,
        }
    )


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "sla_policies"):
        op.create_table(
            "sla_policies",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("policy_key", sa.String(length=80), nullable=False),
            sa.Column("policy_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "sla_policies", "ix_sla_policies_policy_key"):
        op.create_index("ix_sla_policies_policy_key", "sla_policies", ["policy_key"], unique=False)

    if dialect != "sqlite":
        inspector = sa.inspect(bind)
        if not _unique_exists(inspector, "sla_policies", ["policy_key"]):
            op.create_unique_constraint("uq_sla_policies_policy_key", "sla_policies", ["policy_key"])

    now = datetime.now(timezone.utc)
    existing = bind.execute(
        sa.text("SELECT id FROM sla_policies WHERE policy_key = :policy_key LIMIT 1"),
        {"policy_key": "default"},
    ).fetchone()
    if existing is None:
        bind.execute(
            sa.text(
                "INSERT INTO sla_policies (policy_key, policy_json, updated_at) "
                "VALUES (:policy_key, :policy_json, :updated_at)"
            ),
            {
                "policy_key": "default",
                "policy_json": _default_policy_json(),
                "updated_at": now,
            },
        )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

