"""Phase 4B: Threat Intelligence Enrichment Engine

Revision ID: 4b2enr1chment
Revises: 4a1c0rre1at1
Create Date: 2026-10-01 19:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.reflection import Inspector

revision: str = '4b2enr1chment'
down_revision: Union[str, Sequence[str], None] = '4a1c0rre1at1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    dialect = conn.dialect.name
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    id_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)
    fk_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)

    if "indicator_enrichments" not in existing_tables:
        op.create_table(
            "indicator_enrichments",
            sa.Column("id", id_col_type, primary_key=True, nullable=False),
            sa.Column("indicator_id", fk_col_type, sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.String(length=50), nullable=False),
            sa.Column("queried_value", sa.String(length=500), nullable=False),
            sa.Column("indicator_type", sa.String(length=50), nullable=False),
            sa.Column("verdict", sa.String(length=50), nullable=False, server_default="unknown"),
            sa.Column("confidence", sa.SmallInteger(), nullable=True, server_default="0"),
            sa.Column("malicious_count", sa.Integer(), nullable=True, server_default="0"),
            sa.Column("suspicious_count", sa.Integer(), nullable=True, server_default="0"),
            sa.Column("reputation", sa.Integer(), nullable=True),
            sa.Column("categories", sa.Text(), nullable=True),
            sa.Column("tags", sa.Text(), nullable=True),
            sa.Column("malware_families", sa.Text(), nullable=True),
            sa.Column("threat_actors", sa.Text(), nullable=True),
            sa.Column("country", sa.String(length=10), nullable=True),
            sa.Column("asn", sa.String(length=100), nullable=True),
            sa.Column("network", sa.String(length=100), nullable=True),
            sa.Column("external_references", sa.Text(), nullable=True),
            sa.Column("raw_metadata", sa.Text(), nullable=True),
            sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("fetched_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("indicator_id", "provider", name="uq_indicator_provider_enrichment"),
        )
        try:
            op.create_index("ix_indicator_enrichments_indicator_id", "indicator_enrichments", ["indicator_id"])
            op.create_index("ix_indicator_enrichments_provider", "indicator_enrichments", ["provider"])
            op.create_index("ix_indicator_enrichments_verdict", "indicator_enrichments", ["verdict"])
            op.create_index("ix_indicator_enrichments_fetched_at", "indicator_enrichments", ["fetched_at"])
            op.create_index("ix_indicator_enrichments_expires_at", "indicator_enrichments", ["expires_at"])
        except Exception:
            pass

def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "indicator_enrichments" in existing_tables:
        op.drop_table("indicator_enrichments")
