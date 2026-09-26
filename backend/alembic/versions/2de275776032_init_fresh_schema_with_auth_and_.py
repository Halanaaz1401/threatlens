"""Init fresh schema with auth and indicators

Revision ID: 2de275776032
Revises: 
Create Date: 2026-08-11 17:51:34.038691

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '2de275776032'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    if 'audit_log' not in existing_tables:
        op.create_table('audit_log',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('user_id', sa.String(length=36), nullable=True),
            sa.Column('action', sa.String(), nullable=False),
            sa.Column('details', sa.Text(), nullable=True),
            sa.Column('ip_address', sa.String(), nullable=True),
            sa.Column('timestamp', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )

    if 'feeds' not in existing_tables:
        op.create_table('feeds',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('enabled', sa.Boolean(), nullable=True),
            sa.Column('poll_interval_seconds', sa.Integer(), nullable=True),
            sa.Column('last_polled_at', sa.DateTime(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('name')
        )

    if 'indicators' not in existing_tables:
        op.create_table('indicators',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('value', sa.String(), nullable=False),
            sa.Column('type', sa.String(length=50), nullable=False),
            sa.Column('status', sa.String(length=50), nullable=True),
            sa.Column('severity', sa.String(), nullable=True),
            sa.Column('threat_actor', sa.String(), nullable=True),
            sa.Column('tags', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        try:
            op.create_index(op.f('ix_indicators_status'), 'indicators', ['status'], unique=False)
            op.create_index(op.f('ix_indicators_type'), 'indicators', ['type'], unique=False)
            op.create_index(op.f('ix_indicators_value'), 'indicators', ['value'], unique=True)
        except Exception:
            pass

    if 'users' not in existing_tables:
        op.create_table('users',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('email', sa.String(), nullable=False),
            sa.Column('hashed_password', sa.String(), nullable=False),
            sa.Column('full_name', sa.String(), nullable=False),
            sa.Column('role', sa.String(length=50), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        try:
            op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
        except Exception:
            pass

def downgrade() -> None:
    try:
        op.drop_index(op.f('ix_users_email'), table_name='users')
    except Exception:
        pass
    op.drop_table('users')
    try:
        op.drop_index(op.f('ix_indicators_value'), table_name='indicators')
        op.drop_index(op.f('ix_indicators_type'), table_name='indicators')
        op.drop_index(op.f('ix_indicators_status'), table_name='indicators')
    except Exception:
        pass
    op.drop_table('indicators')
    op.drop_table('feeds')
    op.drop_table('audit_log')
