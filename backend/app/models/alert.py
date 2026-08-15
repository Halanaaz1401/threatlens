import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
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

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(String(1000), nullable=True)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.HIGH, nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, nullable=False)
    
    # Associated indicator (optional link)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True)
    
    # Context, matched rule name, and metadata
    rule_name = Column(String(100), default="DEFAULT_SEVERITY_THRESHOLD", nullable=False)
    assignee = Column(String(100), nullable=True)
    context = Column(JSON, default=dict, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    indicator = relationship("Indicator", lazy="joined")