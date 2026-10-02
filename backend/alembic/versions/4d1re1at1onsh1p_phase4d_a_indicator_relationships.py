"""Phase 4D-A: Threat Hunting Indicator Relationships

Revision ID: 4d1re1at1onsh1p
Revises: 4b2enr1chment
Create Date: 2026-10-02 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.reflection import Inspector

revision: str = '4d1re1at1onsh1p'
down_revision: Union[str, Sequence[str], None] = '4b2enr1chment'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    dialect = conn.dialect.name
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    id_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)
    fk_col_type = postgresql.UUID(as_uuid=False) if dialect == "postgresql" else sa.String(length=36)

    if "indicator_relationships" not in existing_tables:
        op.create_table(
            "indicator_relationships",
            sa.Column("id", id_col_type, primary_key=True, nullable=False),
            sa.Column("source_indicator_id", fk_col_type, sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
            sa.Column("target_indicator_id", fk_col_type, sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
            sa.Column("relationship_type", sa.String(length=50), nullable=False),
            sa.Column("confidence", sa.SmallInteger(), nullable=False, server_default="50"),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("source", sa.String(length=100), nullable=False, server_default="manual"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("source_indicator_id", "target_indicator_id", "relationship_type", name="uq_indicator_relationship"),
            sa.CheckConstraint("source_indicator_id != target_indicator_id", name="ck_no_self_relationship"),
        )
        try:
            op.create_index("ix_indicator_relationships_source_indicator_id", "indicator_relationships", ["source_indicator_id"])
            op.create_index("ix_indicator_relationships_target_indicator_id", "indicator_relationships", ["target_indicator_id"])
            op.create_index("ix_indicator_relationships_relationship_type", "indicator_relationships", ["relationship_type"])
        except Exception:
            pass


def downgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if "indicator_relationships" in existing_tables:
        try:
            op.drop_index("ix_indicator_relationships_relationship_type", table_name="indicator_relationships")
            op.drop_index("ix_indicator_relationships_target_indicator_id", table_name="indicator_relationships")
            op.drop_index("ix_indicator_relationships_source_indicator_id", table_name="indicator_relationships")
        except Exception:
            pass
        op.drop_table("indicator_relationships")
