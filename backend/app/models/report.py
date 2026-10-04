import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text
from app.db.base import Base
from app.models.indicator import SafeJSONOrList

class ReportType(str, enum.Enum):
    EXECUTIVE_SECURITY_SUMMARY = "EXECUTIVE_SECURITY_SUMMARY"
    INCIDENT_FORENSIC_SUMMARY = "INCIDENT_FORENSIC_SUMMARY"
    THREAT_LANDSCAPE_REPORT = "THREAT_LANDSCAPE_REPORT"

class ReportStatus(str, enum.Enum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Report(Base):
    __tablename__ = "reports"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_code = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), default=ReportType.EXECUTIVE_SECURITY_SUMMARY.value, nullable=False, index=True)
    time_range = Column(String(20), default="30d", nullable=False)
    status = Column(String(50), default=ReportStatus.COMPLETED.value, nullable=False, index=True)
    
    file_path = Column(String(500), nullable=True)
    file_name = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, default=0, nullable=False)
    content_hash = Column(String(64), nullable=True)  # SHA-256 fingerprint

    created_by = Column(String(100), nullable=False)
    created_by_role = Column(String(50), nullable=True)
    generation_duration_ms = Column(Integer, default=0, nullable=False)
    parameters = Column(SafeJSONOrList, default=dict, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

__all__ = [
    "Report",
    "ReportType",
    "ReportStatus"
]
