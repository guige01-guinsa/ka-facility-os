"""add utility billing tables

Revision ID: 20260312_0027
Revises: 20260304_0026
Create Date: 2026-03-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260312_0027"
down_revision = "20260304_0026"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "utility_billing_units"):
        op.create_table(
            "utility_billing_units",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("building", sa.String(length=120), nullable=False),
            sa.Column("unit_number", sa.String(length=40), nullable=False),
            sa.Column("occupant_name", sa.String(length=120), nullable=True),
            sa.Column("area_sqm", sa.Float(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "utility_rate_policies"):
        op.create_table(
            "utility_rate_policies",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("utility_type", sa.String(length=20), nullable=False),
            sa.Column("effective_month", sa.String(length=7), nullable=False),
            sa.Column("basic_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("unit_rate", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("sewage_rate_per_unit", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("service_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("vat_rate", sa.Float(), nullable=False, server_default=sa.text("0.1")),
            sa.Column("tiers_json", sa.Text(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "utility_meter_readings"):
        op.create_table(
            "utility_meter_readings",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("building", sa.String(length=120), nullable=False),
            sa.Column("unit_number", sa.String(length=40), nullable=False),
            sa.Column("utility_type", sa.String(length=20), nullable=False),
            sa.Column("reading_month", sa.String(length=7), nullable=False),
            sa.Column("previous_reading", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("current_reading", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("usage", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("reader_name", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("reading_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "utility_common_charges"):
        op.create_table(
            "utility_common_charges",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("billing_month", sa.String(length=7), nullable=False),
            sa.Column("utility_type", sa.String(length=20), nullable=False),
            sa.Column("charge_category", sa.String(length=40), nullable=False),
            sa.Column("amount", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "utility_billing_runs"):
        op.create_table(
            "utility_billing_runs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("billing_month", sa.String(length=7), nullable=False),
            sa.Column("utility_type", sa.String(length=20), nullable=False),
            sa.Column("policy_id", sa.Integer(), nullable=False),
            sa.Column("statement_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("total_usage", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("total_amount", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("created_by", sa.String(length=80), nullable=False, server_default=sa.text("'system'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(inspector, "utility_billing_statements"):
        op.create_table(
            "utility_billing_statements",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("run_id", sa.Integer(), nullable=False),
            sa.Column("site", sa.String(length=120), nullable=False),
            sa.Column("building", sa.String(length=120), nullable=False),
            sa.Column("unit_number", sa.String(length=40), nullable=False),
            sa.Column("utility_type", sa.String(length=20), nullable=False),
            sa.Column("billing_month", sa.String(length=7), nullable=False),
            sa.Column("policy_id", sa.Integer(), nullable=False),
            sa.Column("reading_id", sa.Integer(), nullable=False),
            sa.Column("previous_reading", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("current_reading", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("usage", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("basic_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("usage_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("common_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("sewage_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("service_fee", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("vat_amount", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("total_amount", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("breakdown_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    indexes = [
        ("utility_billing_units", "ix_utility_units_site_building_unit", ["site", "building", "unit_number"]),
        ("utility_rate_policies", "ix_utility_rate_policies_site_type_month", ["site", "utility_type", "effective_month"]),
        ("utility_meter_readings", "ix_utility_readings_site_month", ["site", "reading_month"]),
        ("utility_meter_readings", "uq_utility_readings_site_building_unit_type_month", ["site", "building", "unit_number", "utility_type", "reading_month"]),
        ("utility_common_charges", "ix_utility_common_charges_site_month_type", ["site", "billing_month", "utility_type"]),
        ("utility_billing_runs", "ix_utility_runs_site_month_type", ["site", "billing_month", "utility_type"]),
        ("utility_billing_statements", "ix_utility_statements_site_month_type", ["site", "billing_month", "utility_type"]),
        ("utility_billing_statements", "ix_utility_statements_run_id", ["run_id"]),
        ("utility_billing_statements", "uq_utility_statements_site_building_unit_type_month", ["site", "building", "unit_number", "utility_type", "billing_month"]),
    ]
    for table_name, index_name, columns in indexes:
        if not _index_exists(inspector, table_name, index_name):
            op.create_index(
                index_name,
                table_name,
                columns,
                unique=index_name.startswith("uq_"),
            )


def downgrade() -> None:
    # Forward-only safety migration.
    pass
