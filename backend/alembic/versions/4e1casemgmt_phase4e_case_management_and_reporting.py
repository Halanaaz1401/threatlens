"""Phase 4E: Forensic Case Management and Executive Reporting

Revision ID: 4e1casemgmt
Revises: 4d4integrat10ns
Create Date: 2026-10-04 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

revision: str = '4e1casemgmt'
down_revision: Union[str, Sequence[str], None] = '4d4integrat10ns'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create cases table
    if "cases" not in existing_tables:
        op.create_table(
            "cases",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_number", sa.String(length=50), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=50), nullable=False, server_default="MEDIUM"),
            sa.Column("priority", sa.String(length=50), nullable=False, server_default="P2"),
            sa.Column("status", sa.String(length=50), nullable=False, server_default="OPEN"),
            sa.Column("owner", sa.String(length=100), nullable=True),
            sa.Column("assignee", sa.String(length=100), nullable=True),
            sa.Column("source", sa.String(length=100), nullable=False, server_default="Manual"),
            sa.Column("tags", sa.JSON(), nullable=True),
            sa.Column("created_by", sa.String(length=100), nullable=True),
            sa.Column("closed_by", sa.String(length=100), nullable=True),
            sa.Column("closed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_cases_case_number", "cases", ["case_number"], unique=True)
        op.create_index("ix_cases_status", "cases", ["status"])
        op.create_index("ix_cases_severity", "cases", ["severity"])
        op.create_index("ix_cases_priority", "cases", ["priority"])
        op.create_index("ix_cases_created_at", "cases", ["created_at"])

    # 2. Create case_incidents table
    if "case_incidents" not in existing_tables:
        op.create_table(
            "case_incidents",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("linked_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("linked_by", sa.String(length=100), nullable=True),
            sa.UniqueConstraint("case_id", "incident_id", name="uq_case_incident"),
        )
        op.create_index("ix_case_incidents_case_id", "case_incidents", ["case_id"])
        op.create_index("ix_case_incidents_incident_id", "case_incidents", ["incident_id"])

    # 3. Create case_alerts table
    if "case_alerts" not in existing_tables:
        op.create_table(
            "case_alerts",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("alert_id", sa.String(length=36), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("linked_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("linked_by", sa.String(length=100), nullable=True),
            sa.UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),
        )
        op.create_index("ix_case_alerts_case_id", "case_alerts", ["case_id"])
        op.create_index("ix_case_alerts_alert_id", "case_alerts", ["alert_id"])

    # 4. Create case_indicators table
    if "case_indicators" not in existing_tables:
        op.create_table(
            "case_indicators",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("indicator_id", sa.String(length=36), sa.ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False),
            sa.Column("linked_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("linked_by", sa.String(length=100), nullable=True),
            sa.UniqueConstraint("case_id", "indicator_id", name="uq_case_indicator"),
        )
        op.create_index("ix_case_indicators_case_id", "case_indicators", ["case_id"])
        op.create_index("ix_case_indicators_indicator_id", "case_indicators", ["indicator_id"])

    # 5. Create case_evidence table
    if "case_evidence" not in existing_tables:
        op.create_table(
            "case_evidence",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("evidence_type", sa.String(length=100), nullable=False, server_default="INDICATOR"),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("source_entity", sa.String(length=100), nullable=True),
            sa.Column("source_provider", sa.String(length=100), nullable=True),
            sa.Column("reference_hash", sa.String(length=128), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
            sa.Column("data", sa.JSON(), nullable=True),
            sa.Column("observed_at", sa.DateTime(), nullable=True),
            sa.Column("collected_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("collected_by", sa.String(length=100), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_case_evidence_case_id", "case_evidence", ["case_id"])

    # 6. Create case_notes table
    if "case_notes" not in existing_tables:
        op.create_table(
            "case_notes",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("author", sa.String(length=100), nullable=False),
            sa.Column("author_id", sa.String(length=36), nullable=True),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"])
        op.create_index("ix_case_notes_created_at", "case_notes", ["created_at"])

    # 7. Create case_timeline table
    if "case_timeline" not in existing_tables:
        op.create_table(
            "case_timeline",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("case_id", sa.String(length=36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
            sa.Column("event_type", sa.String(length=100), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("details", sa.Text(), nullable=True),
            sa.Column("actor", sa.String(length=100), nullable=False, server_default="System"),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_case_timeline_case_id", "case_timeline", ["case_id"])
        op.create_index("ix_case_timeline_created_at", "case_timeline", ["created_at"])

    # 8. Create reports table
    if "reports" not in existing_tables:
        op.create_table(
            "reports",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("report_code", sa.String(length=50), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("report_type", sa.String(length=50), nullable=False, server_default="EXECUTIVE_SECURITY_SUMMARY"),
            sa.Column("time_range", sa.String(length=20), nullable=False, server_default="30d"),
            sa.Column("status", sa.String(length=50), nullable=False, server_default="COMPLETED"),
            sa.Column("file_path", sa.String(length=500), nullable=True),
            sa.Column("file_name", sa.String(length=255), nullable=False),
            sa.Column("file_size_bytes", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("content_hash", sa.String(length=64), nullable=True),
            sa.Column("created_by", sa.String(length=100), nullable=False),
            sa.Column("created_by_role", sa.String(length=50), nullable=True),
            sa.Column("generation_duration_ms", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("parameters", sa.JSON(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_reports_report_code", "reports", ["report_code"], unique=True)
        op.create_index("ix_reports_report_type", "reports", ["report_type"])
        op.create_index("ix_reports_status", "reports", ["status"])
        op.create_index("ix_reports_created_at", "reports", ["created_at"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("case_timeline")
    op.drop_table("case_notes")
    op.drop_table("case_evidence")
    op.drop_table("case_indicators")
    op.drop_table("case_alerts")
    op.drop_table("case_incidents")
    op.drop_table("cases")
