import uuid
import enum
import json
from datetime import datetime
from sqlalchemy import Column, String, SmallInteger, Integer, DateTime, ForeignKey, Text
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import relationship
from app.db.base import Base

class SafeJSONOrList(TypeDecorator):
    """Safely decodes JSON arrays or comma-separated tag strings in SQLite/PostgreSQL."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return "[]"
        if isinstance(value, list):
            return json.dumps(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            val = value.strip()
            if val.startswith("[") and val.endswith("]"):
                try:
                    return json.loads(val)
                except Exception:
                    pass
            # Handle comma-separated legacy strings
            return [t.strip() for t in val.split(",") if t.strip()]
        return [str(value)]

class SafeJSONOrDict(TypeDecorator):
    """Safely decodes JSON objects or key-value dicts in SQLite/PostgreSQL."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return "{}"
        if isinstance(value, dict):
            return json.dumps(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            val = value.strip()
            if val.startswith("{") and val.endswith("}"):
                try:
                    return json.loads(val)
                except Exception:
                    pass
            return {"raw": val}
        return {}

class IndicatorType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"

class ThreatSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IndicatorStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    WHITELISTED = "whitelisted"
    UNDER_REVIEW = "under_review"
    REVOKED = "revoked"

class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    value = Column(String(500), nullable=False, unique=True, index=True)
    type = Column(String(50), nullable=False, index=True)
    severity_score = Column(SmallInteger, default=0, index=True)
    threat_score = Column(SmallInteger, default=0)
    severity = Column(String(20), default="MEDIUM", index=True)
    confidence = Column(SmallInteger, default=50)
    source = Column(String(100), default="manual")
    sightings = Column(Integer, default=1)
    tlp = Column(String(20), default="amber")
    status = Column(String(50), default="active", index=True)
    tags = Column(SafeJSONOrList, default=list, nullable=True)
    context = Column(SafeJSONOrDict, default=dict, nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sources = relationship("IndicatorSource", back_populates="indicator", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="indicator", foreign_keys="[Alert.indicator_id]")

class IndicatorSource(Base):
    __tablename__ = "indicator_sources"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    source_name = Column(String(100), nullable=False)
    confidence = Column(SmallInteger, default=50)
    reported_at = Column(DateTime, default=datetime.utcnow)

    indicator = relationship("Indicator", back_populates="sources")

# Re-export Alert and AuditLog for backward compatibility with legacy router imports
from app.models.alert import Alert
from app.models.audit import AuditLog

__all__ = [
    "IndicatorType",
    "ThreatSeverity",
    "IndicatorStatus",
    "Indicator",
    "IndicatorSource",
    "Alert",
    "AuditLog"
]
