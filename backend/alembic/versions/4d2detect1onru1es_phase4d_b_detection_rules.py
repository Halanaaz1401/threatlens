"""Phase 4D-B: Configurable Detection Rule Engine and Alert Routing

Revision ID: 4d2detect1onru1es
Revises: 4d1re1at1onsh1p
Create Date: 2026-10-02 21:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.reflection import Inspector

revision: str = '4d2detect1onru1es'
down_revision: Union[str, Sequence[str], None] = '4d1re1at1onsh1p'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    dialect = conn.dialect.name
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    id_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)
    fk_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)

    # 1. Create detection_rules table
    if "detection_rules" not in existing_tables:
        op.create_table(
            "detection_rules",
            sa.Column("id", id_col_type, primary_key=True, nullable=False),
            sa.Column("rule_code", sa.String(length=50), nullable=True, unique=True),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=50), nullable=False, server_default="HIGH"),
            sa.Column("priority", sa.SmallInteger(), nullable=False, server_default="50"),
            sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("conditions", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("logic_operator", sa.String(length=10), nullable=False, server_default="AND"),
            sa.Column("match_scope", sa.String(length=50), nullable=False, server_default="indicator"),
            sa.Column("routing_target", sa.String(length=100), nullable=False, server_default="SOC_TIER_2"),
            sa.Column("routing_channel", sa.String(length=100), nullable=False, server_default="internal"),
            sa.Column("dedup_window_minutes", sa.Integer(), nullable=False, server_default="60"),
            sa.Column("actions", sa.Text(), nullable=True, server_default='["create_alert"]'),
            sa.Column("total_matches", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_matched_at", sa.DateTime(), nullable=True),
            sa.Column("created_by", sa.String(length=100), nullable=False, server_default="system"),
            sa.Column("version", sa.SmallInteger(), nullable=False, server_default="1"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
        try:
            op.create_index("ix_detection_rules_rule_code", "detection_rules", ["rule_code"])
            op.create_index("ix_detection_rules_name", "detection_rules", ["name"])
            op.create_index("ix_detection_rules_severity", "detection_rules", ["severity"])
            op.create_index("ix_detection_rules_is_enabled", "detection_rules", ["is_enabled"])
        except Exception:
            pass

    # 2. Add rule_id and routed_to to alerts table if not existing
    if "alerts" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("alerts")}
        if "rule_id" not in existing_cols:
            try:
                op.add_column("alerts", sa.Column("rule_id", fk_col_type, sa.ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True))
                op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
            except Exception:
                pass
        if "routed_to" not in existing_cols:
            try:
                op.add_column("alerts", sa.Column("routed_to", sa.String(length=100), nullable=True, server_default="SOC_TIER_2"))
            except Exception:
                pass


def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "alerts" in existing_tables:
        existing_cols = {c["name"] for c in inspector.get_columns("alerts")}
        if "routed_to" in existing_cols:
            try:
                op.drop_column("alerts", "routed_to")
            except Exception:
                pass
        if "rule_id" in existing_cols:
            try:
                op.drop_index("ix_alerts_rule_id", table_name="alerts")
                op.drop_column("alerts", "rule_id")
            except Exception:
                pass

    if "detection_rules" in existing_tables:
        try:
            op.drop_index("ix_detection_rules_is_enabled", table_name="detection_rules")
            op.drop_index("ix_detection_rules_severity", table_name="detection_rules")
            op.drop_index("ix_detection_rules_name", table_name="detection_rules")
            op.drop_index("ix_detection_rules_rule_code", table_name="detection_rules")
        except Exception:
            pass
        op.drop_table("detection_rules")
