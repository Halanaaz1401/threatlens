"""Phase 2: Complete persistent schema and audit log immutability

Revision ID: 3f89a12c4b5e
Revises: 2de275776032
Create Date: 2026-09-26 21:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '3f89a12c4b5e'
down_revision: Union[str, Sequence[str], None] = '2de275776032'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create alerts table if not exists
    if "alerts" not in existing_tables:
        op.create_table(
            'alerts',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('alert_code', sa.String(length=50), nullable=True),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('description', sa.String(length=1000), nullable=True),
            sa.Column('severity', sa.String(length=50), server_default="HIGH", nullable=False),
            sa.Column('severity_score', sa.SmallInteger(), server_default="70"),
            sa.Column('status', sa.String(length=50), server_default="new", nullable=False),
            sa.Column('indicator_id', sa.String(length=36), nullable=True),
            sa.Column('indicator_value', sa.String(length=500), nullable=True),
            sa.Column('rule_name', sa.String(length=100), server_default="DEFAULT_SEVERITY_THRESHOLD", nullable=False),
            sa.Column('assignee', sa.String(length=100), server_default="Priya Nair", nullable=True),
            sa.Column('source', sa.String(length=100), server_default="ThreatLens Stream"),
            sa.Column('mitre_technique', sa.String(length=50), server_default="T1071"),
            sa.Column('internal_sightings_count', sa.SmallInteger(), server_default="1"),
            sa.Column('internal_host', sa.String(length=100), server_default="host-wkstn-04.corp.local"),
            sa.Column('context', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )

    # 2. Create incidents table if not exists
    if "incidents" not in existing_tables:
        op.create_table(
            'incidents',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('severity', sa.String(length=50), server_default="HIGH", nullable=False),
            sa.Column('status', sa.String(length=50), server_default="OPEN", nullable=False),
            sa.Column('assignee', sa.String(length=100), nullable=True),
            sa.Column('indicator_id', sa.String(length=36), nullable=True),
            sa.Column('matched_ioc_value', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
        )

    # 3. Create incident_timeline table if not exists
    if "incident_timeline" not in existing_tables:
        op.create_table(
            'incident_timeline',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('incident_id', sa.String(length=36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column('action', sa.String(length=255), nullable=False),
            sa.Column('details', sa.Text(), nullable=True),
            sa.Column('actor', sa.String(length=100), server_default="System", nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )

    # 4. Create security_events table if not exists
    if "security_events" not in existing_tables:
        op.create_table(
            'security_events',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('source_ip', sa.String(length=50), nullable=True),
            sa.Column('destination_ip', sa.String(length=50), nullable=True),
            sa.Column('domain', sa.String(length=255), nullable=True),
            sa.Column('file_hash', sa.String(length=128), nullable=True),
            sa.Column('event_type', sa.String(length=50), server_default="NETWORK_TRAFFIC", nullable=False),
            sa.Column('raw_log', sa.Text(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=False),
        )

    # 5. Create indicator_sources table if not exists
    if "indicator_sources" not in existing_tables:
        op.create_table(
            'indicator_sources',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('indicator_id', sa.String(length=36), sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
            sa.Column('source_name', sa.String(length=100), nullable=False),
            sa.Column('confidence', sa.SmallInteger(), server_default="50"),
            sa.Column('reported_at', sa.DateTime(), nullable=True),
        )

    # 6. Apply database-level audit immutability trigger
    dialect = conn.dialect.name
    if dialect == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'AuditLog records are append-only and cannot be updated or deleted.';
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
            CREATE TRIGGER trg_audit_log_immutable
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW
            EXECUTE FUNCTION prevent_audit_log_modification();
        """)
    elif dialect == "sqlite":
        op.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
            END;
        """)
        op.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
            END;
        """)

def downgrade() -> None:
    conn = op.get_bind()
    dialect = conn.dialect.name

    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;")
        op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_modification();")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update;")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete;")

    op.drop_table('indicator_sources')
    op.drop_table('security_events')
    op.drop_table('incident_timeline')
    op.drop_table('incidents')
    op.drop_table('alerts')
