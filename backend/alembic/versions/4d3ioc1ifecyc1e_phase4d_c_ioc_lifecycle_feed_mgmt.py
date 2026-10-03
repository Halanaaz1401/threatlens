"""Phase 4D-C: IOC Lifecycle, TTL Expiration, and Feed Management

Revision ID: 4d3ioc1ifecyc1e
Revises: 4d2detect1onru1es
Create Date: 2026-10-03 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '4d3ioc1ifecyc1e'
down_revision: Union[str, Sequence[str], None] = '4d2detect1onru1es'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Alter indicators table
    if "indicators" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("indicators")}
        with op.batch_alter_table("indicators") as batch_op:
            if "expires_at" not in existing_cols:
                batch_op.add_column(sa.Column("expires_at", sa.DateTime(), nullable=True))
                batch_op.create_index("ix_indicators_expires_at", ["expires_at"])
            if "ttl_days" not in existing_cols:
                batch_op.add_column(sa.Column("ttl_days", sa.Integer(), nullable=True, server_default="30"))
            if "analyst_notes" not in existing_cols:
                batch_op.add_column(sa.Column("analyst_notes", sa.Text(), nullable=True))
            if "revoked_reason" not in existing_cols:
                batch_op.add_column(sa.Column("revoked_reason", sa.String(length=255), nullable=True))

    # 2. Alter feeds table
    if "feeds" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("feeds")}
        with op.batch_alter_table("feeds") as batch_op:
            if "display_name" not in existing_cols:
                batch_op.add_column(sa.Column("display_name", sa.String(length=100), nullable=True))
            if "provider" not in existing_cols:
                batch_op.add_column(sa.Column("provider", sa.String(length=100), nullable=True))
            if "feed_type" not in existing_cols:
                batch_op.add_column(sa.Column("feed_type", sa.String(length=50), nullable=True))
            if "endpoint_url" not in existing_cols:
                batch_op.add_column(sa.Column("endpoint_url", sa.String(length=500), nullable=True))
            if "description" not in existing_cols:
                batch_op.add_column(sa.Column("description", sa.Text(), nullable=True))
            if "status" not in existing_cols:
                batch_op.add_column(sa.Column("status", sa.String(length=50), nullable=False, server_default="active"))
            if "last_successful_fetch_at" not in existing_cols:
                batch_op.add_column(sa.Column("last_successful_fetch_at", sa.DateTime(), nullable=True))
            if "last_attempted_fetch_at" not in existing_cols:
                batch_op.add_column(sa.Column("last_attempted_fetch_at", sa.DateTime(), nullable=True))
            if "error_message" not in existing_cols:
                batch_op.add_column(sa.Column("error_message", sa.Text(), nullable=True))
            if "total_indicators_ingested" not in existing_cols:
                batch_op.add_column(sa.Column("total_indicators_ingested", sa.Integer(), nullable=False, server_default="0"))
            if "last_ingested_count" not in existing_cols:
                batch_op.add_column(sa.Column("last_ingested_count", sa.Integer(), nullable=False, server_default="0"))
            if "updated_at" not in existing_cols:
                batch_op.add_column(sa.Column("updated_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "feeds" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("feeds")}
        with op.batch_alter_table("feeds") as batch_op:
            for col in [
                "updated_at",
                "last_ingested_count",
                "total_indicators_ingested",
                "error_message",
                "last_attempted_fetch_at",
                "last_successful_fetch_at",
                "status",
                "description",
                "endpoint_url",
                "feed_type",
                "provider",
                "display_name"
            ]:
                if col in existing_cols:
                    batch_op.drop_column(col)

    if "indicators" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("indicators")}
        with op.batch_alter_table("indicators") as batch_op:
            if "expires_at" in existing_cols:
                try:
                    batch_op.drop_index("ix_indicators_expires_at")
                except Exception:
                    pass
            for col in ["revoked_reason", "analyst_notes", "ttl_days", "expires_at"]:
                if col in existing_cols:
                    batch_op.drop_column(col)
