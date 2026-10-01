import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    SmallInteger,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.indicator import SafeJSONOrList, SafeJSONOrDict

GUID = String(36).with_variant(PGUUID(as_uuid=False), "postgresql")

class IndicatorEnrichment(Base):
    __tablename__ = "indicator_enrichments"
    __table_args__ = (
        UniqueConstraint("indicator_id", "provider", name="uq_indicator_provider_enrichment"),
        {"extend_existing": True},
    )

    id = Column(GUID, primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_id = Column(GUID, ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False, index=True)
    queried_value = Column(String(500), nullable=False)
    indicator_type = Column(String(50), nullable=False)
    verdict = Column(String(50), nullable=False, default="unknown", index=True)
    confidence = Column(SmallInteger, default=0)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    reputation = Column(Integer, nullable=True)
    categories = Column(SafeJSONOrList, default=list, nullable=True)
    tags = Column(SafeJSONOrList, default=list, nullable=True)
    malware_families = Column(SafeJSONOrList, default=list, nullable=True)
    threat_actors = Column(SafeJSONOrList, default=list, nullable=True)
    country = Column(String(10), nullable=True)
    asn = Column(String(100), nullable=True)
    network = Column(String(100), nullable=True)
    external_references = Column(SafeJSONOrList, default=list, nullable=True)
    raw_metadata = Column(SafeJSONOrDict, default=dict, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    fetched_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    indicator = relationship("Indicator", back_populates="enrichments")
