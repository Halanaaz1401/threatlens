import uuid
from datetime import datetime
from sqlalchemy import Column, String, SmallInteger, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    value = Column(Text, nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)
    severity_score = Column(SmallInteger, default=0, index=True)
    confidence = Column(SmallInteger, default=50)
    tlp = Column(String(20), default="amber")
    status = Column(String(50), default="active", index=True)
    tags = Column(String(255), nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    sources = relationship("IndicatorSource", back_populates="indicator", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="indicator")

class IndicatorSource(Base):
    __tablename__ = "indicator_sources"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    source_name = Column(String(100), nullable=False)
    confidence = Column(SmallInteger, default=50)
    reported_at = Column(DateTime, default=datetime.utcnow)

    indicator = relationship("Indicator", back_populates="sources")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_code = Column(String(50), unique=True, index=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), default="High", index=True)
    status = Column(String(50), default="New", index=True)
    assignee = Column(String(100), default="Priya Nair")
    created_at = Column(DateTime, default=datetime.utcnow)

    indicator = relationship("Indicator", back_populates="alerts")

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    target_resource = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
