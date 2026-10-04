"""Phase 4F: Custom Dashboard Widget Builder

Revision ID: 4f1dashboards
Revises: 4e1casemgmt
Create Date: 2026-10-04 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '4f1dashboards'
down_revision: Union[str, Sequence[str], None] = '4e1casemgmt'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create dashboards table
    if "dashboards" not in existing_tables:
        op.create_table(
            "dashboards",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.String(length=512), nullable=True),
            sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("visibility", sa.String(length=32), nullable=False, server_default="PRIVATE"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_dashboards_owner_id", "dashboards", ["owner_id"])
        op.create_index("ix_dashboards_visibility", "dashboards", ["visibility"])
        op.create_index("ix_dashboards_is_default", "dashboards", ["is_default"])

    # 2. Create dashboard_widgets table
    if "dashboard_widgets" not in existing_tables:
        op.create_table(
            "dashboard_widgets",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("dashboard_id", sa.String(length=36), sa.ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False),
            sa.Column("title", sa.String(length=128), nullable=False),
            sa.Column("description", sa.String(length=256), nullable=True),
            sa.Column("widget_type", sa.String(length=64), nullable=False),
            sa.Column("data_source", sa.String(length=64), nullable=False),
            sa.Column("metric", sa.String(length=64), nullable=False),
            sa.Column("time_range", sa.String(length=32), nullable=False, server_default="24h"),
            sa.Column("filters", sa.JSON(), nullable=True),
            sa.Column("display_options", sa.JSON(), nullable=True),
            sa.Column("position_x", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("position_y", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("width", sa.Integer(), nullable=False, server_default="6"),
            sa.Column("height", sa.Integer(), nullable=False, server_default="4"),
            sa.Column("refresh_interval_seconds", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_dashboard_widgets_dashboard_id", "dashboard_widgets", ["dashboard_id"])
        op.create_index("ix_dashboard_widgets_widget_type", "dashboard_widgets", ["widget_type"])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "dashboard_widgets" in existing_tables:
        op.drop_table("dashboard_widgets")
    if "dashboards" in existing_tables:
        op.drop_table("dashboards")
