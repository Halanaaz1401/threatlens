"""Phase 4A: Advanced Threat Correlation and Incidents Engine

Revision ID: 4a1c0rre1at1
Revises: 3f89a12c4b5e
Create Date: 2026-10-01 18:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.dialects import postgresql

revision: str = '4a1c0rre1at1'
down_revision: Union[str, Sequence[str], None] = '3f89a12c4b5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())
    dialect = conn.dialect.name

    # 1. Update incidents table
    if "incidents" in existing_tables:
        if dialect == "postgresql":
            op.execute("ALTER TABLE incidents ALTER COLUMN status TYPE VARCHAR(50) USING status::text;")
            op.execute("ALTER TABLE incidents ALTER COLUMN severity TYPE VARCHAR(50) USING severity::text;")

        existing_cols = {col["name"] for col in inspector.get_columns("incidents")}
        
        if "incident_code" not in existing_cols:
            op.add_column("incidents", sa.Column("incident_code", sa.String(length=50), nullable=True))
            try:
                op.create_index("ix_incidents_incident_code", "incidents", ["incident_code"], unique=True)
            except Exception:
                pass

        if "correlation_score" not in existing_cols:
            op.add_column("incidents", sa.Column("correlation_score", sa.Integer(), server_default="0", nullable=False))

        if "primary_indicator" not in existing_cols:
            op.add_column("incidents", sa.Column("primary_indicator", sa.String(length=500), nullable=True))

        if "primary_source" not in existing_cols:
            op.add_column("incidents", sa.Column("primary_source", sa.String(length=100), nullable=True))

        if "mitre_techniques" not in existing_cols:
            op.add_column("incidents", sa.Column("mitre_techniques", sa.Text(), nullable=True))

        if "affected_host" not in existing_cols:
            op.add_column("incidents", sa.Column("affected_host", sa.String(length=100), nullable=True))

        if "first_seen" not in existing_cols:
            op.add_column("incidents", sa.Column("first_seen", sa.DateTime(), server_default=sa.func.now(), nullable=False))

        if "last_seen" not in existing_cols:
            op.add_column("incidents", sa.Column("last_seen", sa.DateTime(), server_default=sa.func.now(), nullable=False))

    # 2. Update alerts table to link to incidents
    if "alerts" in existing_tables:
        existing_cols = {col["name"] for col in inspector.get_columns("alerts")}
        
        if "incident_id" not in existing_cols:
            col_type = postgresql.UUID(as_uuid=True) if dialect == "postgresql" else sa.String(length=36)
            op.add_column("alerts", sa.Column("incident_id", col_type, nullable=True))
            try:
                op.create_foreign_key(
                    "fk_alerts_incident_id",
                    "alerts",
                    "incidents",
                    ["incident_id"],
                    ["id"],
                    ondelete="SET NULL"
                )
            except Exception:
                pass
            try:
                op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])
            except Exception:
                pass

def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "alerts" in existing_tables:
        existing_cols = {col["name"] for col in inspector.get_columns("alerts")}
        if "incident_id" in existing_cols:
            try:
                op.drop_constraint("fk_alerts_incident_id", "alerts", type_="foreignkey")
            except Exception:
                pass
            try:
                op.drop_index("ix_alerts_incident_id", table_name="alerts")
            except Exception:
                pass
            op.drop_column("alerts", "incident_id")

    if "incidents" in existing_tables:
        existing_cols = {col["name"] for col in inspector.get_columns("incidents")}
        for col_name in [
            "last_seen",
            "first_seen",
            "affected_host",
            "mitre_techniques",
            "primary_source",
            "primary_indicator",
            "correlation_score",
            "incident_code"
        ]:
            if col_name in existing_cols:
                if col_name == "incident_code":
                    try:
                        op.drop_index("ix_incidents_incident_code", table_name="incidents")
                    except Exception:
                        pass
                op.drop_column("incidents", col_name)
