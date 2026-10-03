"""Phase 4D-D: SIEM/EDR Inbound Integrations and TAXII 2.1 Feed Support

Revision ID: 4d4integrat10ns
Revises: 4d3ioc1ifecyc1e
Create Date: 2026-10-03 21:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '4d4integrat10ns'
down_revision: Union[str, Sequence[str], None] = '4d3ioc1ifecyc1e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Alter feeds table to support TAXII 2.1
    if "feeds" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("feeds")}
        with op.batch_alter_table("feeds") as batch_op:
            if "taxii_api_root" not in existing_cols:
                batch_op.add_column(sa.Column("taxii_api_root", sa.String(length=255), nullable=True))
            if "taxii_collection_id" not in existing_cols:
                batch_op.add_column(sa.Column("taxii_collection_id", sa.String(length=100), nullable=True))
            if "taxii_version" not in existing_cols:
                batch_op.add_column(sa.Column("taxii_version", sa.String(length=20), nullable=True, server_default="2.1"))
            if "last_added_after" not in existing_cols:
                batch_op.add_column(sa.Column("last_added_after", sa.String(length=50), nullable=True))
            if "taxii_username" not in existing_cols:
                batch_op.add_column(sa.Column("taxii_username", sa.String(length=100), nullable=True))
            if "taxii_password_hash" not in existing_cols:
                batch_op.add_column(sa.Column("taxii_password_hash", sa.String(length=255), nullable=True))

    # 2. Alter security_events table for SIEM/EDR Webhook telemetry
    if "security_events" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("security_events")}
        with op.batch_alter_table("security_events") as batch_op:
            if "provider" not in existing_cols:
                batch_op.add_column(sa.Column("provider", sa.String(length=50), nullable=True))
                batch_op.create_index("ix_security_events_provider", ["provider"])
            if "external_event_id" not in existing_cols:
                batch_op.add_column(sa.Column("external_event_id", sa.String(length=100), nullable=True))
                batch_op.create_index("ix_security_events_external_event_id", ["external_event_id"])
            if "dedup_key" not in existing_cols:
                batch_op.add_column(sa.Column("dedup_key", sa.String(length=150), nullable=True))
                batch_op.create_index("ix_security_events_dedup_key", ["dedup_key"], unique=True)
            if "url" not in existing_cols:
                batch_op.add_column(sa.Column("url", sa.String(length=500), nullable=True))
            if "hostname" not in existing_cols:
                batch_op.add_column(sa.Column("hostname", sa.String(length=100), nullable=True))
            if "username" not in existing_cols:
                batch_op.add_column(sa.Column("username", sa.String(length=100), nullable=True))
            if "severity" not in existing_cols:
                batch_op.add_column(sa.Column("severity", sa.String(length=50), nullable=False, server_default="MEDIUM"))
            if "description" not in existing_cols:
                batch_op.add_column(sa.Column("description", sa.Text(), nullable=True))
            if "mitre_technique" not in existing_cols:
                batch_op.add_column(sa.Column("mitre_technique", sa.String(length=50), nullable=True))
            if "status" not in existing_cols:
                batch_op.add_column(sa.Column("status", sa.String(length=50), nullable=False, server_default="INGESTED"))
            if "created_alert_id" not in existing_cols:
                batch_op.add_column(sa.Column("created_alert_id", sa.String(length=36), nullable=True))
            if "created_indicator_id" not in existing_cols:
                batch_op.add_column(sa.Column("created_indicator_id", sa.String(length=36), nullable=True))

    # 3. Create webhook_configs table
    if "webhook_configs" not in existing_tables:
        op.create_table(
            "webhook_configs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("provider", sa.String(length=50), unique=True, nullable=False),
            sa.Column("display_name", sa.String(length=100), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default="1"),
            sa.Column("secret_token", sa.String(length=255), nullable=True),
            sa.Column("hmac_secret", sa.String(length=255), nullable=True),
            sa.Column("total_events_received", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_received_at", sa.DateTime(), nullable=True),
            sa.Column("last_status", sa.String(length=50), nullable=False, server_default="idle"),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_webhook_configs_provider", "webhook_configs", ["provider"])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "webhook_configs" in existing_tables:
        op.drop_table("webhook_configs")

    if "security_events" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("security_events")}
        with op.batch_alter_table("security_events") as batch_op:
            for col in ["created_indicator_id", "created_alert_id", "status", "mitre_technique",
                        "description", "severity", "username", "hostname", "url", "dedup_key",
                        "external_event_id", "provider"]:
                if col in existing_cols:
                    batch_op.drop_column(col)

    if "feeds" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("feeds")}
        with op.batch_alter_table("feeds") as batch_op:
            for col in ["taxii_password_hash", "taxii_username", "last_added_after",
                        "taxii_version", "taxii_collection_id", "taxii_api_root"]:
                if col in existing_cols:
                    batch_op.drop_column(col)
