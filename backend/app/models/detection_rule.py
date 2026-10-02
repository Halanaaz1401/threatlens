import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, SmallInteger, Integer, Boolean, DateTime, Text
from sqlalchemy.orm import relationship
from app.db.base import Base
from app.models.indicator import SafeJSONOrList, SafeJSONOrDict

class RuleSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RuleRoutingQueue(str, enum.Enum):
    SOC_TIER_1 = "SOC_TIER_1"
    SOC_TIER_2 = "SOC_TIER_2"
    IR_LEAD = "IR_LEAD"
    THREAT_HUNTING = "THREAT_HUNTING"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    CISO_ESCALATION = "CISO_ESCALATION"

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_code = Column(String(50), nullable=True, unique=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default=RuleSeverity.HIGH.value, nullable=False, index=True)
    priority = Column(SmallInteger, default=50, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    
    # Declarative rule conditions DSL: list of {"field": ..., "operator": ..., "value": ...}
    conditions = Column(SafeJSONOrList, default=list, nullable=False)
    logic_operator = Column(String(10), default="AND", nullable=False)  # "AND" or "OR"
    match_scope = Column(String(50), default="indicator", nullable=False)  # "indicator", "enrichment", "all"
    
    # Alert routing specifications
    routing_target = Column(String(100), default=RuleRoutingQueue.SOC_TIER_2.value, nullable=False)
    routing_channel = Column(String(100), default="internal", nullable=False)  # "internal", "email_notification", "webhook"
    
    # Deterministic alert deduplication window (in minutes)
    dedup_window_minutes = Column(Integer, default=60, nullable=False)
    
    # Rule actions e.g. ["create_alert", "escalate_severity", "tag_indicator"]
    actions = Column(SafeJSONOrList, default=lambda: ["create_alert"], nullable=True)
    
    # Operational telemetry
    total_matches = Column(Integer, default=0, nullable=False)
    last_matched_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), default="system", nullable=False)
    version = Column(SmallInteger, default=1, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    alerts = relationship("Alert", back_populates="detection_rule", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "rule_code": self.rule_code,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "priority": self.priority,
            "is_enabled": self.is_enabled,
            "conditions": self.conditions,
            "logic_operator": self.logic_operator,
            "match_scope": self.match_scope,
            "routing_target": self.routing_target,
            "routing_channel": self.routing_channel,
            "dedup_window_minutes": self.dedup_window_minutes,
            "actions": self.actions,
            "total_matches": self.total_matches,
            "last_matched_at": self.last_matched_at.isoformat() if self.last_matched_at else None,
            "created_by": self.created_by,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

__all__ = ["DetectionRule", "RuleSeverity", "RuleRoutingQueue"]
