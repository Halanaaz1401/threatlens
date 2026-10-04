import uuid
import enum
from datetime import datetime
from typing import List, Dict, Optional, Any
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, CheckConstraint
from sqlalchemy.orm import relationship

from app.db.base import Base
from app.models.indicator import SafeJSONOrList

class DashboardVisibility(str, enum.Enum):
    PRIVATE = "PRIVATE"
    SHARED = "SHARED"

class WidgetType(str, enum.Enum):
    KPI = "KPI"
    TIME_SERIES = "TIME_SERIES"
    BAR_CHART = "BAR_CHART"
    LINE_CHART = "LINE_CHART"
    SEVERITY_DISTRIBUTION = "SEVERITY_DISTRIBUTION"
    INCIDENT_TREND = "INCIDENT_TREND"
    ALERT_TREND = "ALERT_TREND"
    IOC_TYPE_DISTRIBUTION = "IOC_TYPE_DISTRIBUTION"
    THREAT_INTEL_SOURCES = "THREAT_INTEL_SOURCES"
    MITRE_ATTACK = "MITRE_ATTACK"
    GEOGRAPHIC_DISTRIBUTION = "GEOGRAPHIC_DISTRIBUTION"
    DETECTION_RULE_ACTIVITY = "DETECTION_RULE_ACTIVITY"
    CASE_STATUS_DISTRIBUTION = "CASE_STATUS_DISTRIBUTION"
    CASE_SEVERITY_DISTRIBUTION = "CASE_SEVERITY_DISTRIBUTION"
    TOP_INDICATORS = "TOP_INDICATORS"
    RECENT_CRITICAL_INCIDENTS = "RECENT_CRITICAL_INCIDENTS"
    RECENT_CRITICAL_ALERTS = "RECENT_CRITICAL_ALERTS"
    ENRICHMENT_STATISTICS = "ENRICHMENT_STATISTICS"

class WidgetDataSource(str, enum.Enum):
    ANALYTICS = "ANALYTICS"
    INCIDENTS = "INCIDENTS"
    ALERTS = "ALERTS"
    INDICATORS = "INDICATORS"
    CASES = "CASES"
    DETECTION_RULES = "DETECTION_RULES"
    ENRICHMENT = "ENRICHMENT"

class WidgetMetric(str, enum.Enum):
    RISK_SCORE = "RISK_SCORE"
    MTTD = "MTTD"
    MTTR = "MTTR"
    TOTAL_INDICATORS = "TOTAL_INDICATORS"
    ACTIVE_ALERTS = "ACTIVE_ALERTS"
    ACTIVE_INCIDENTS = "ACTIVE_INCIDENTS"
    ACTIVE_SEV1_INCIDENTS = "ACTIVE_SEV1_INCIDENTS"
    ENRICHMENT_COVERAGE = "ENRICHMENT_COVERAGE"
    INGESTION_VELOCITY = "INGESTION_VELOCITY"
    SEVERITY_BREAKDOWN = "SEVERITY_BREAKDOWN"
    TYPE_BREAKDOWN = "TYPE_BREAKDOWN"
    SOURCE_BREAKDOWN = "SOURCE_BREAKDOWN"
    MITRE_FREQUENCY = "MITRE_FREQUENCY"
    GEOGRAPHIC_ORIGIN = "GEOGRAPHIC_ORIGIN"
    RULE_MATCHES = "RULE_MATCHES"
    CASE_STATUS_BREAKDOWN = "CASE_STATUS_BREAKDOWN"
    CASE_SEVERITY_BREAKDOWN = "CASE_SEVERITY_BREAKDOWN"
    TOP_IOC_LIST = "TOP_IOC_LIST"
    RECENT_INCIDENT_LIST = "RECENT_INCIDENT_LIST"
    RECENT_ALERT_LIST = "RECENT_ALERT_LIST"

class Dashboard(Base):
    __tablename__ = "dashboards"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)
    description = Column(String(512), nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    is_default = Column(Boolean, default=False, nullable=False)
    visibility = Column(String(32), default=DashboardVisibility.PRIVATE.value, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = relationship("User", foreign_keys=[owner_id])
    widgets = relationship(
        "DashboardWidget",
        back_populates="dashboard",
        cascade="all, delete-orphan",
        order_by="DashboardWidget.position_y, DashboardWidget.position_x"
    )

    __table_args__ = (
        CheckConstraint("visibility IN ('PRIVATE', 'SHARED')", name="ck_dashboards_visibility_valid"),
    )

    def to_dict(self, include_widgets: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "is_default": self.is_default,
            "visibility": self.visibility,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "widget_count": len(self.widgets) if self.widgets is not None else 0,
        }
        if include_widgets and self.widgets is not None:
            data["widgets"] = [w.to_dict() for w in self.widgets]
        return data


class DashboardWidget(Base):
    __tablename__ = "dashboard_widgets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dashboard_id = Column(String(36), ForeignKey("dashboards.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(128), nullable=False)
    description = Column(String(256), nullable=True)
    widget_type = Column(String(64), nullable=False)
    data_source = Column(String(64), nullable=False)
    metric = Column(String(64), nullable=False)
    time_range = Column(String(32), default="24h", nullable=False)
    filters = Column(SafeJSONOrList, default=dict)
    display_options = Column(SafeJSONOrList, default=dict)
    position_x = Column(Integer, default=0, nullable=False)
    position_y = Column(Integer, default=0, nullable=False)
    width = Column(Integer, default=6, nullable=False)
    height = Column(Integer, default=4, nullable=False)
    refresh_interval_seconds = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    dashboard = relationship("Dashboard", back_populates="widgets")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "dashboard_id": self.dashboard_id,
            "title": self.title,
            "description": self.description,
            "widget_type": self.widget_type,
            "data_source": self.data_source,
            "metric": self.metric,
            "time_range": self.time_range,
            "filters": self.filters or {},
            "display_options": self.display_options or {},
            "position_x": self.position_x,
            "position_y": self.position_y,
            "width": self.width,
            "height": self.height,
            "refresh_interval_seconds": self.refresh_interval_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
