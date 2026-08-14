import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from app.db.base import Base

class IndicatorType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"

class ThreatSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IndicatorStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    value = Column(String, unique=True, index=True, nullable=False)
    type = Column(Enum(IndicatorType), nullable=False)
    source = Column(String, nullable=False)
    confidence = Column(Integer, default=50)
    threat_score = Column(Integer, default=50)
    severity = Column(Enum(ThreatSeverity), default=ThreatSeverity.MEDIUM)
    status = Column(Enum(IndicatorStatus), default=IndicatorStatus.ACTIVE)
    tags = Column(ARRAY(String), default=[])
    context = Column(JSON, default={})
    sightings = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))