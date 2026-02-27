"""add work order events timeline table

Revision ID: 20260226_0004
Revises: 20260226_0003
Create Date: 2026-02-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260226_0004"
down_revision = "20260226_0003"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _fk_exists(
    inspector: sa.Inspector,
    table_name: str,
    constrained_columns: list[str],
    referred_table: str,
) -> bool:
    for fk in inspector.get_foreign_keys(table_name):
        if fk.get("referred_table") != referred_table:
            continue
        if list(fk.get("constrained_columns") or []) == constrained_columns:
            return True
    return False


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "work_order_events"):
        fk_args = []
        if _has_table(inspector, "work_orders"):
            fk_args = [
                sa.ForeignKeyConstraint(
                    ["work_order_id"],
                    ["work_orders.id"],
                    name="fk_work_order_events_work_order_id",
                )
            ]

        op.create_table(
            "work_order_events",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("work_order_id", sa.Integer(), nullable=False),
            sa.Column("event_type", sa.String(length=40), nullable=False),
            sa.Column("actor_username", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("from_status", sa.String(length=20), nullable=True),
            sa.Column("to_status", sa.String(length=20), nullable=True),
            sa.Column("note", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("detail_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            *fk_args,
        )

    inspector = sa.inspect(bind)
    if not _index_exists(inspector, "work_order_events", "ix_work_order_events_work_order_id_created_at"):
        op.create_index(
            "ix_work_order_events_work_order_id_created_at",
            "work_order_events",
            ["work_order_id", "created_at"],
            unique=False,
        )

    if dialect != "sqlite":
        inspector = sa.inspect(bind)
        if _has_table(inspector, "work_orders") and not _fk_exists(
            inspector, "work_order_events", ["work_order_id"], "work_orders"
        ):
            op.create_foreign_key(
                "fk_work_order_events_work_order_id",
                "work_order_events",
                "work_orders",
                ["work_order_id"],
                ["id"],
                ondelete="CASCADE",
            )


def downgrade() -> None:
    # Forward-only safety migration.
    pass

