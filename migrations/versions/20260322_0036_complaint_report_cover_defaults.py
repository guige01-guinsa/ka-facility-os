"""add complaint report cover defaults

Revision ID: 20260322_0036
Revises: 20260321_0035
Create Date: 2026-03-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260322_0036"
down_revision = "20260321_0035"
branch_labels = None
depends_on = None


def _has_table(inspector: sa.Inspector, table_name: str) -> bool:
    return table_name in inspector.get_table_names()


def _index_exists(inspector: sa.Inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "complaint_report_cover_defaults"):
        op.create_table(
            "complaint_report_cover_defaults",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("scope_type", sa.String(length=20), nullable=False, server_default="site"),
            sa.Column("site", sa.String(length=120), nullable=True),
            sa.Column("company_name", sa.String(length=120), nullable=True),
            sa.Column("contractor_name", sa.String(length=120), nullable=True),
            sa.Column("submission_phrase", sa.Text(), nullable=True),
            sa.Column("logo_file_name", sa.String(length=200), nullable=True),
            sa.Column("logo_content_type", sa.String(length=120), nullable=True),
            sa.Column("logo_bytes", sa.LargeBinary(), nullable=False),
            sa.Column("updated_by", sa.String(length=80), nullable=False, server_default="system"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    inspector = sa.inspect(bind)
    for table_name, index_name, columns, unique in [
        ("complaint_report_cover_defaults", "ix_complaint_report_cover_defaults_scope", ["scope_type", "site"], True),
        ("complaint_report_cover_defaults", "ix_complaint_report_cover_defaults_site", ["site"], False),
    ]:
        if _has_table(inspector, table_name) and not _index_exists(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns, unique=unique)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for table_name, index_name in [
        ("complaint_report_cover_defaults", "ix_complaint_report_cover_defaults_site"),
        ("complaint_report_cover_defaults", "ix_complaint_report_cover_defaults_scope"),
    ]:
        if _has_table(inspector, table_name) and _index_exists(inspector, table_name, index_name):
            op.drop_index(index_name, table_name=table_name)

    inspector = sa.inspect(bind)
    if _has_table(inspector, "complaint_report_cover_defaults"):
        op.drop_table("complaint_report_cover_defaults")
