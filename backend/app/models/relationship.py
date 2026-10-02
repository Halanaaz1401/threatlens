import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, SmallInteger, DateTime, ForeignKey, Text, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import relationship
from app.db.base import Base

class RelationshipType(str, enum.Enum):
    RESOLVES_TO = "resolves-to"
    COMMUNICATES_WITH = "communicates-with"
    REDIRECTS_TO = "redirects-to"
    HOSTED_ON = "hosted-on"
    RELATED_TO = "related-to"
    DOWNLOADED_FROM = "downloaded-from"

class IndicatorRelationship(Base):
    __tablename__ = "indicator_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_indicator_id",
            "target_indicator_id",
            "relationship_type",
            name="uq_indicator_relationship"
        ),
        CheckConstraint(
            "source_indicator_id != target_indicator_id",
            name="ck_no_self_relationship"
        ),
        {"extend_existing": True},
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_indicator_id = Column(
        String(36),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    target_indicator_id = Column(
        String(36),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    relationship_type = Column(String(50), nullable=False, index=True)
    confidence = Column(SmallInteger, default=70)
    evidence = Column(Text, nullable=True)
    source = Column(String(100), default="automated")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships to Indicator
    source_indicator = relationship(
        "Indicator",
        foreign_keys=[source_indicator_id],
        back_populates="outgoing_relationships"
    )
    target_indicator = relationship(
        "Indicator",
        foreign_keys=[target_indicator_id],
        back_populates="incoming_relationships"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "source_indicator_id": self.source_indicator_id,
            "target_indicator_id": self.target_indicator_id,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

__all__ = ["RelationshipType", "IndicatorRelationship"]
