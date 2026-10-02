import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, SmallInteger, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base

class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_code = Column(String(50), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(String(1000), nullable=True)
    severity = Column(String(50), default="HIGH", nullable=False, index=True)
    severity_score = Column(SmallInteger, default=70)
    status = Column(String(50), default="new", nullable=False, index=True)
    
    # Associated indicator and incident links
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True)
    indicator_value = Column(String(500), nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Context, matched rule name, assignee, telemetry
    rule_name = Column(String(100), default="DEFAULT_SEVERITY_THRESHOLD", nullable=False)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    routed_to = Column(String(100), nullable=True, default="SOC_TIER_2")
    assignee = Column(String(100), nullable=True, default="Priya Nair")
    source = Column(String(100), default="ThreatLens Stream")
    mitre_technique = Column(String(50), default="T1071")
    internal_sightings_count = Column(SmallInteger, default=1)
    internal_host = Column(String(100), nullable=True, default=None)
    context = Column(JSON, default=dict, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    indicator = relationship("Indicator", back_populates="alerts", foreign_keys=[indicator_id], lazy="joined")
    incident = relationship("Incident", back_populates="alerts", foreign_keys=[incident_id])
    detection_rule = relationship("DetectionRule", back_populates="alerts", foreign_keys=[rule_id])