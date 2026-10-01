import uuid
import enum
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.indicator import SafeJSONOrList

class IncidentSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    INVESTIGATING = "INVESTIGATING"  # backward compatible alias for IN_PROGRESS
    CONTAINED = "CONTAINED"          # backward compatible alias
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

# Server-side validated state transitions (Step 6)
VALID_STATUS_TRANSITIONS: Dict[str, List[str]] = {
    IncidentStatus.OPEN.value: [
        IncidentStatus.ACKNOWLEDGED.value,
        IncidentStatus.IN_PROGRESS.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    ],
    IncidentStatus.ACKNOWLEDGED.value: [
        IncidentStatus.IN_PROGRESS.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    ],
    IncidentStatus.IN_PROGRESS.value: [
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.ACKNOWLEDGED.value,
        IncidentStatus.CONTAINED.value,
    ],
    IncidentStatus.INVESTIGATING.value: [
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.ACKNOWLEDGED.value,
        IncidentStatus.CONTAINED.value,
    ],
    IncidentStatus.CONTAINED.value: [
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
        IncidentStatus.IN_PROGRESS.value,
    ],
    IncidentStatus.RESOLVED.value: [
        IncidentStatus.CLOSED.value,
        IncidentStatus.OPEN.value,  # Allowed: Reopening an incident
    ],
    IncidentStatus.CLOSED.value: [
        IncidentStatus.OPEN.value,  # Allowed: Reopening a closed incident
    ],
}

def is_valid_status_transition(current_status: str, new_status: str) -> bool:
    curr = current_status.upper() if current_status else IncidentStatus.OPEN.value
    nxt = new_status.upper() if new_status else ""
    if curr == nxt:
        return True
    allowed = VALID_STATUS_TRANSITIONS.get(curr, [])
    return nxt in allowed

class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    domain = Column(String(255), nullable=True)
    file_hash = Column(String(128), nullable=True)
    event_type = Column(String(50), default="NETWORK_TRAFFIC", nullable=False)
    raw_log = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_code = Column(String(50), nullable=True, unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="HIGH", nullable=False, index=True)
    status = Column(String(50), default="OPEN", nullable=False, index=True)
    correlation_score = Column(Integer, default=0, nullable=False)
    assignee = Column(String(100), nullable=True)
    
    # Associated indicator & telemetry references
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True)
    matched_ioc_value = Column(String(255), nullable=True)
    primary_indicator = Column(String(500), nullable=True)
    primary_source = Column(String(100), nullable=True)
    mitre_techniques = Column(SafeJSONOrList, default=list, nullable=True)
    affected_host = Column(String(100), nullable=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    timeline = relationship(
        "IncidentTimeline",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimeline.created_at.asc()"
    )
    alerts = relationship(
        "Alert",
        back_populates="incident",
        foreign_keys="[Alert.incident_id]",
        order_by="Alert.created_at.desc()"
    )

class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    action = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    actor = Column(String(100), default="System", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    incident = relationship("Incident", back_populates="timeline")