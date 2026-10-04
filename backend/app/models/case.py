import uuid
import enum
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.indicator import SafeJSONOrList

class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class CaseSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class CasePriority(str, enum.Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

VALID_CASE_STATUS_TRANSITIONS: Dict[str, List[str]] = {
    CaseStatus.OPEN.value: [
        CaseStatus.IN_PROGRESS.value,
        CaseStatus.CONTAINED.value,
        CaseStatus.RESOLVED.value,
        CaseStatus.CLOSED.value,
    ],
    CaseStatus.IN_PROGRESS.value: [
        CaseStatus.CONTAINED.value,
        CaseStatus.RESOLVED.value,
        CaseStatus.CLOSED.value,
        CaseStatus.OPEN.value,
    ],
    CaseStatus.CONTAINED.value: [
        CaseStatus.IN_PROGRESS.value,
        CaseStatus.RESOLVED.value,
        CaseStatus.CLOSED.value,
    ],
    CaseStatus.RESOLVED.value: [
        CaseStatus.CLOSED.value,
        CaseStatus.OPEN.value,
        CaseStatus.IN_PROGRESS.value,
    ],
    CaseStatus.CLOSED.value: [
        CaseStatus.OPEN.value,
    ],
}

def is_valid_case_status_transition(current_status: str, new_status: str) -> bool:
    curr = current_status.upper() if current_status else CaseStatus.OPEN.value
    nxt = new_status.upper() if new_status else ""
    if curr == nxt:
        return True
    allowed = VALID_CASE_STATUS_TRANSITIONS.get(curr, [])
    return nxt in allowed

class Case(Base):
    __tablename__ = "cases"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="MEDIUM", nullable=False, index=True)
    priority = Column(String(50), default="P2", nullable=False, index=True)
    status = Column(String(50), default="OPEN", nullable=False, index=True)
    owner = Column(String(100), nullable=True)
    assignee = Column(String(100), nullable=True)
    source = Column(String(100), default="Manual", nullable=False)
    tags = Column(SafeJSONOrList, default=list, nullable=True)

    created_by = Column(String(100), nullable=True)
    closed_by = Column(String(100), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    case_incidents = relationship("CaseIncident", back_populates="case", cascade="all, delete-orphan", order_by="CaseIncident.linked_at.desc()")
    case_alerts = relationship("CaseAlert", back_populates="case", cascade="all, delete-orphan", order_by="CaseAlert.linked_at.desc()")
    case_indicators = relationship("CaseIndicator", back_populates="case", cascade="all, delete-orphan", order_by="CaseIndicator.linked_at.desc()")
    evidence = relationship("CaseEvidence", back_populates="case", cascade="all, delete-orphan", order_by="CaseEvidence.created_at.desc()")
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at.asc()")
    timeline = relationship("CaseTimeline", back_populates="case", cascade="all, delete-orphan", order_by="CaseTimeline.created_at.asc()")

class CaseIncident(Base):
    __tablename__ = "case_incidents"
    __table_args__ = (
        UniqueConstraint("case_id", "incident_id", name="uq_case_incident"),
        {"extend_existing": True}
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    linked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    linked_by = Column(String(100), nullable=True)

    case = relationship("Case", back_populates="case_incidents")
    incident = relationship("Incident")

class CaseAlert(Base):
    __tablename__ = "case_alerts"
    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),
        {"extend_existing": True}
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    linked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    linked_by = Column(String(100), nullable=True)

    case = relationship("Case", back_populates="case_alerts")
    alert = relationship("Alert")

class CaseIndicator(Base):
    __tablename__ = "case_indicators"
    __table_args__ = (
        UniqueConstraint("case_id", "indicator_id", name="uq_case_indicator"),
        {"extend_existing": True}
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    linked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    linked_by = Column(String(100), nullable=True)

    case = relationship("Case", back_populates="case_indicators")
    indicator = relationship("Indicator")

class CaseEvidence(Base):
    __tablename__ = "case_evidence"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(100), default="INDICATOR", nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_entity = Column(String(100), nullable=True)
    source_provider = Column(String(100), nullable=True)
    reference_hash = Column(String(128), nullable=True)
    confidence = Column(Integer, default=80, nullable=False)
    data = Column(SafeJSONOrList, default=dict, nullable=True)
    observed_at = Column(DateTime, nullable=True)
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    collected_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="evidence")

class CaseNote(Base):
    __tablename__ = "case_notes"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    author_id = Column(String(36), nullable=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = relationship("Case", back_populates="notes")

class CaseTimeline(Base):
    __tablename__ = "case_timeline"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    actor = Column(String(100), default="System", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    case = relationship("Case", back_populates="timeline")

__all__ = [
    "Case",
    "CaseStatus",
    "CaseSeverity",
    "CasePriority",
    "CaseIncident",
    "CaseAlert",
    "CaseIndicator",
    "CaseEvidence",
    "CaseNote",
    "CaseTimeline",
    "VALID_CASE_STATUS_TRANSITIONS",
    "is_valid_case_status_transition"
]
