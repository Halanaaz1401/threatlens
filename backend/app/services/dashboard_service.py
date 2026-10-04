"""
ThreatLens - Phase 4F Custom Dashboard and Widget Service
Provides database-backed CRUD, layout persistence, and real telemetry resolution
for user dashboards and modular security widgets.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, and_

from app.models.dashboard import (
    Dashboard,
    DashboardWidget,
    DashboardVisibility,
    WidgetType,
    WidgetDataSource,
    WidgetMetric,
)
from app.models.indicator import Indicator
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.case import Case, CaseStatus, CaseSeverity
from app.models.detection_rule import DetectionRule
from app.models.enrichment import IndicatorEnrichment
from app.models.audit import AuditLog
from app.services import analytics_service
from app.core.redis import publish_dashboard_event

MAX_WIDGETS_PER_DASHBOARD = 24
MIN_REFRESH_INTERVAL_SECONDS = 30
MAX_REFRESH_INTERVAL_SECONDS = 3600

# Predefined safe widget catalog
WIDGET_CATALOG: List[Dict[str, Any]] = [
    {
        "widget_type": WidgetType.KPI.value,
        "title": "Security Metric KPI",
        "description": "Single-metric key performance indicator with baseline trend",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [
            WidgetMetric.RISK_SCORE.value,
            WidgetMetric.TOTAL_INDICATORS.value,
            WidgetMetric.ACTIVE_ALERTS.value,
            WidgetMetric.ACTIVE_INCIDENTS.value,
            WidgetMetric.ACTIVE_SEV1_INCIDENTS.value,
            WidgetMetric.MTTD.value,
            WidgetMetric.MTTR.value,
            WidgetMetric.ENRICHMENT_COVERAGE.value,
        ],
        "default_width": 3,
        "default_height": 3,
        "category": "KPI",
    },
    {
        "widget_type": WidgetType.TIME_SERIES.value,
        "title": "Threat Ingestion Velocity",
        "description": "Continuous, zero-filled time-series threat ingestion volume",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [WidgetMetric.INGESTION_VELOCITY.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Trend",
    },
    {
        "widget_type": WidgetType.LINE_CHART.value,
        "title": "Threat Volume Over Time",
        "description": "Multi-interval line chart of total versus high-severity IOC ingests",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [WidgetMetric.INGESTION_VELOCITY.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Trend",
    },
    {
        "widget_type": WidgetType.BAR_CHART.value,
        "title": "Threat Category Breakdown",
        "description": "Ranked bar chart comparing counts across types or sources",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [WidgetMetric.TYPE_BREAKDOWN.value, WidgetMetric.SOURCE_BREAKDOWN.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Comparison",
    },
    {
        "widget_type": WidgetType.SEVERITY_DISTRIBUTION.value,
        "title": "Global Threat Severity Donut",
        "description": "Severity breakdown across indicators, alerts, and incidents",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [WidgetMetric.SEVERITY_BREAKDOWN.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Distribution",
    },
    {
        "widget_type": WidgetType.INCIDENT_TREND.value,
        "title": "Incident Lifecycle & Resolution",
        "description": "Correlated security incidents grouped by status and severity",
        "data_source": WidgetDataSource.INCIDENTS.value,
        "allowed_metrics": [WidgetMetric.ACTIVE_INCIDENTS.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Incidents",
    },
    {
        "widget_type": WidgetType.ALERT_TREND.value,
        "title": "Alert Volume & Status",
        "description": "Active alerts grouped by triage status and severity level",
        "data_source": WidgetDataSource.ALERTS.value,
        "allowed_metrics": [WidgetMetric.ACTIVE_ALERTS.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Alerts",
    },
    {
        "widget_type": WidgetType.IOC_TYPE_DISTRIBUTION.value,
        "title": "Indicator Type Breakdown",
        "description": "Distribution across IPv4, IPv6, Domain, URL, Hash, and CVE",
        "data_source": WidgetDataSource.INDICATORS.value,
        "allowed_metrics": [WidgetMetric.TYPE_BREAKDOWN.value],
        "default_width": 4,
        "default_height": 4,
        "category": "Distribution",
    },
    {
        "widget_type": WidgetType.THREAT_INTEL_SOURCES.value,
        "title": "Threat Intelligence Sources",
        "description": "Ingestion volume grouped by public and commercial feed source",
        "data_source": WidgetDataSource.INDICATORS.value,
        "allowed_metrics": [WidgetMetric.SOURCE_BREAKDOWN.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Feeds",
    },
    {
        "widget_type": WidgetType.MITRE_ATTACK.value,
        "title": "MITRE ATT&CK Matrix Activity",
        "description": "Observed adversary techniques mapped to tactics from real IOCs",
        "data_source": WidgetDataSource.ANALYTICS.value,
        "allowed_metrics": [WidgetMetric.MITRE_FREQUENCY.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Threat Intel",
    },
    {
        "widget_type": WidgetType.GEOGRAPHIC_DISTRIBUTION.value,
        "title": "Geographic Threat Origins",
        "description": "Top source countries derived from verified threat enrichments",
        "data_source": WidgetDataSource.ENRICHMENT.value,
        "allowed_metrics": [WidgetMetric.GEOGRAPHIC_ORIGIN.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Geography",
    },
    {
        "widget_type": WidgetType.DETECTION_RULE_ACTIVITY.value,
        "title": "Detection Rule Activity",
        "description": "Active detection rules, match volume, and queue routing stats",
        "data_source": WidgetDataSource.DETECTION_RULES.value,
        "allowed_metrics": [WidgetMetric.RULE_MATCHES.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Detection",
    },
    {
        "widget_type": WidgetType.CASE_STATUS_DISTRIBUTION.value,
        "title": "Forensic Case Status Breakdown",
        "description": "Distribution of forensic cases across OPEN, IN_PROGRESS, CONTAINED, CLOSED",
        "data_source": WidgetDataSource.CASES.value,
        "allowed_metrics": [WidgetMetric.CASE_STATUS_BREAKDOWN.value],
        "default_width": 4,
        "default_height": 4,
        "category": "Cases",
    },
    {
        "widget_type": WidgetType.CASE_SEVERITY_DISTRIBUTION.value,
        "title": "Forensic Case Severity Breakdown",
        "description": "Active forensic cases grouped by severity (Critical, High, Medium, Low)",
        "data_source": WidgetDataSource.CASES.value,
        "allowed_metrics": [WidgetMetric.CASE_SEVERITY_BREAKDOWN.value],
        "default_width": 4,
        "default_height": 4,
        "category": "Cases",
    },
    {
        "widget_type": WidgetType.TOP_INDICATORS.value,
        "title": "Top Threat Indicators",
        "description": "Highest risk active threat indicators with severity scores and types",
        "data_source": WidgetDataSource.INDICATORS.value,
        "allowed_metrics": [WidgetMetric.TOP_IOC_LIST.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Threat Intel",
    },
    {
        "widget_type": WidgetType.RECENT_CRITICAL_INCIDENTS.value,
        "title": "Recent Critical Incidents",
        "description": "High-severity correlated incidents requiring immediate triage",
        "data_source": WidgetDataSource.INCIDENTS.value,
        "allowed_metrics": [WidgetMetric.RECENT_INCIDENT_LIST.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Incidents",
    },
    {
        "widget_type": WidgetType.RECENT_CRITICAL_ALERTS.value,
        "title": "Recent Critical Alerts",
        "description": "Latest high-priority security alerts with source and routed analyst team",
        "data_source": WidgetDataSource.ALERTS.value,
        "allowed_metrics": [WidgetMetric.RECENT_ALERT_LIST.value],
        "default_width": 6,
        "default_height": 4,
        "category": "Alerts",
    },
    {
        "widget_type": WidgetType.ENRICHMENT_STATISTICS.value,
        "title": "Enrichment Engine Performance",
        "description": "Enrichment coverage ratio and provider query breakdown",
        "data_source": WidgetDataSource.ENRICHMENT.value,
        "allowed_metrics": [WidgetMetric.ENRICHMENT_COVERAGE.value],
        "default_width": 4,
        "default_height": 4,
        "category": "Enrichment",
    },
]

def get_widget_catalog() -> List[Dict[str, Any]]:
    """Return the predefined safe widget catalog."""
    return WIDGET_CATALOG

def _validate_widget_config(widget_type: str, data_source: str, metric: str, refresh_interval: int = 0):
    """Enforce strict catalog validation against client-provided widget definitions."""
    matching_catalog = next((c for c in WIDGET_CATALOG if c["widget_type"] == widget_type), None)
    if not matching_catalog:
        valid_types = [c["widget_type"] for c in WIDGET_CATALOG]
        raise ValueError(f"Invalid widget_type '{widget_type}'. Allowed types: {valid_types}")

    if matching_catalog["data_source"] != data_source:
        raise ValueError(f"Invalid data_source '{data_source}' for widget_type '{widget_type}'. Expected '{matching_catalog['data_source']}'")

    if metric not in matching_catalog["allowed_metrics"]:
        raise ValueError(f"Invalid metric '{metric}' for widget_type '{widget_type}'. Allowed metrics: {matching_catalog['allowed_metrics']}")

    if refresh_interval != 0 and (refresh_interval < MIN_REFRESH_INTERVAL_SECONDS or refresh_interval > MAX_REFRESH_INTERVAL_SECONDS):
        raise ValueError(f"Refresh interval must be 0 (manual) or between {MIN_REFRESH_INTERVAL_SECONDS} and {MAX_REFRESH_INTERVAL_SECONDS} seconds")

def _log_audit(db: Session, user_id: str, action: str, details: Dict[str, Any]):
    """Record state change in canonical audit log."""
    try:
        audit_entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            created_at=datetime.now(timezone.utc)
        )
        db.add(audit_entry)
        db.flush()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Dashboard CRUD Operations
# ---------------------------------------------------------------------------

def list_dashboards(
    db: Session,
    user_id: str,
    user_role: str,
    limit: int = 50,
    offset: int = 0
) -> Tuple[List[Dashboard], int]:
    """
    List dashboards accessible to current user.
    Admins see all; analysts/viewers see dashboards they own or that are SHARED.
    """
    query = db.query(Dashboard)
    if user_role.lower() != "admin":
        query = query.filter(
            or_(
                Dashboard.owner_id == user_id,
                Dashboard.visibility == DashboardVisibility.SHARED.value
            )
        )
    total = query.count()
    dashboards = query.order_by(desc(Dashboard.is_default), desc(Dashboard.updated_at)).offset(offset).limit(limit).all()
    return dashboards, total

def get_dashboard(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str
) -> Optional[Dashboard]:
    """Retrieve single dashboard and verify access rights."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        return None

    # Check IDOR / visibility access
    if user_role.lower() != "admin":
        if dashboard.owner_id != user_id and dashboard.visibility != DashboardVisibility.SHARED.value:
            raise PermissionError("Access denied: dashboard is private and owned by another user")

    return dashboard

def create_dashboard(
    db: Session,
    user_id: str,
    name: str,
    description: Optional[str] = None,
    is_default: bool = False,
    visibility: str = DashboardVisibility.PRIVATE.value,
) -> Dashboard:
    """Create a new custom dashboard."""
    if visibility not in [DashboardVisibility.PRIVATE.value, DashboardVisibility.SHARED.value]:
        raise ValueError(f"Invalid visibility '{visibility}'. Allowed: ['PRIVATE', 'SHARED']")

    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Dashboard name cannot be empty")
    if len(clean_name) > 128:
        raise ValueError("Dashboard name must be 128 characters or fewer")

    # If is_default, unset other defaults for this user
    if is_default:
        db.query(Dashboard).filter(Dashboard.owner_id == user_id, Dashboard.is_default == True).update({"is_default": False})

    dashboard = Dashboard(
        id=str(uuid.uuid4()),
        name=clean_name,
        description=description.strip() if description else None,
        owner_id=user_id,
        is_default=is_default,
        visibility=visibility,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(dashboard)
    db.commit()
    db.refresh(dashboard)

    _log_audit(db, user_id, "DASHBOARD_CREATED", {"dashboard_id": dashboard.id, "name": dashboard.name})
    publish_dashboard_event("DASHBOARD_CREATED", {"dashboard_id": dashboard.id, "name": dashboard.name, "owner_id": user_id})

    return dashboard

def update_dashboard(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    is_default: Optional[bool] = None,
    visibility: Optional[str] = None,
) -> Dashboard:
    """Update dashboard metadata with IDOR/permission checks."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only owner or administrator can modify dashboard settings")

    if name is not None:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Dashboard name cannot be empty")
        if len(clean_name) > 128:
            raise ValueError("Dashboard name must be 128 characters or fewer")
        dashboard.name = clean_name

    if description is not None:
        dashboard.description = description.strip() if description else None

    if visibility is not None:
        if visibility not in [DashboardVisibility.PRIVATE.value, DashboardVisibility.SHARED.value]:
            raise ValueError(f"Invalid visibility '{visibility}'")
        dashboard.visibility = visibility

    if is_default is not None:
        if is_default:
            db.query(Dashboard).filter(Dashboard.owner_id == user_id, Dashboard.is_default == True).update({"is_default": False})
        dashboard.is_default = is_default

    dashboard.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(dashboard)

    _log_audit(db, user_id, "DASHBOARD_UPDATED", {"dashboard_id": dashboard.id, "name": dashboard.name})
    publish_dashboard_event("DASHBOARD_UPDATED", {"dashboard_id": dashboard.id, "name": dashboard.name})

    return dashboard

def delete_dashboard(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str
) -> bool:
    """Delete dashboard with IDOR/permission checks."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only owner or administrator can delete dashboard")

    db.delete(dashboard)
    db.commit()

    _log_audit(db, user_id, "DASHBOARD_DELETED", {"dashboard_id": dashboard_id, "name": dashboard.name})
    publish_dashboard_event("DASHBOARD_DELETED", {"dashboard_id": dashboard_id})

    return True

def duplicate_dashboard(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str,
    new_name: Optional[str] = None
) -> Dashboard:
    """Clone an existing dashboard and all its widgets for the current user."""
    source = get_dashboard(db, dashboard_id, user_id, user_role)
    if not source:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    clone_name = (new_name or f"{source.name} (Copy)").strip()
    new_dashboard = Dashboard(
        id=str(uuid.uuid4()),
        name=clone_name,
        description=source.description,
        owner_id=user_id,
        is_default=False,
        visibility=DashboardVisibility.PRIVATE.value,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(new_dashboard)
    db.flush()

    for w in source.widgets:
        new_widget = DashboardWidget(
            id=str(uuid.uuid4()),
            dashboard_id=new_dashboard.id,
            title=w.title,
            description=w.description,
            widget_type=w.widget_type,
            data_source=w.data_source,
            metric=w.metric,
            time_range=w.time_range,
            filters=w.filters,
            display_options=w.display_options,
            position_x=w.position_x,
            position_y=w.position_y,
            width=w.width,
            height=w.height,
            refresh_interval_seconds=w.refresh_interval_seconds,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(new_widget)

    db.commit()
    db.refresh(new_dashboard)

    _log_audit(db, user_id, "DASHBOARD_DUPLICATED", {"source_id": dashboard_id, "new_dashboard_id": new_dashboard.id})
    return new_dashboard

# ---------------------------------------------------------------------------
# Widget CRUD Operations
# ---------------------------------------------------------------------------

def add_widget(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str,
    widget_data: Dict[str, Any]
) -> DashboardWidget:
    """Add a validated widget from the catalog to a dashboard."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only dashboard owner or administrator can add widgets")

    current_widget_count = db.query(func.count(DashboardWidget.id)).filter(DashboardWidget.dashboard_id == dashboard_id).scalar() or 0
    if current_widget_count >= MAX_WIDGETS_PER_DASHBOARD:
        raise ValueError(f"Dashboard widget capacity exceeded (maximum {MAX_WIDGETS_PER_DASHBOARD} widgets)")

    widget_type = widget_data.get("widget_type")
    data_source = widget_data.get("data_source")
    metric = widget_data.get("metric")
    time_range = widget_data.get("time_range", "24h")
    refresh_interval = widget_data.get("refresh_interval_seconds", 0)

    _validate_widget_config(widget_type, data_source, metric, refresh_interval)

    if time_range not in ["24h", "7d", "30d", "90d"]:
        raise ValueError(f"Invalid time_range '{time_range}'. Allowed values: ['24h', '7d', '30d', '90d']")

    title = (widget_data.get("title") or "New Widget").strip()
    if len(title) > 128:
        raise ValueError("Widget title must be 128 characters or fewer")

    # Position defaults to bottom of grid
    max_y = db.query(func.max(DashboardWidget.position_y + DashboardWidget.height)).filter(DashboardWidget.dashboard_id == dashboard_id).scalar() or 0

    widget = DashboardWidget(
        id=str(uuid.uuid4()),
        dashboard_id=dashboard_id,
        title=title,
        description=widget_data.get("description"),
        widget_type=widget_type,
        data_source=data_source,
        metric=metric,
        time_range=time_range,
        filters=widget_data.get("filters", {}),
        display_options=widget_data.get("display_options", {}),
        position_x=widget_data.get("position_x", 0),
        position_y=widget_data.get("position_y", max_y),
        width=max(1, min(12, int(widget_data.get("width", 6)))),
        height=max(1, min(12, int(widget_data.get("height", 4)))),
        refresh_interval_seconds=refresh_interval,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    db.add(widget)
    dashboard.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(widget)

    _log_audit(db, user_id, "WIDGET_CREATED", {"dashboard_id": dashboard_id, "widget_id": widget.id, "type": widget.widget_type})
    publish_dashboard_event("WIDGET_CREATED", {"dashboard_id": dashboard_id, "widget_id": widget.id})

    return widget

def update_widget(
    db: Session,
    dashboard_id: str,
    widget_id: str,
    user_id: str,
    user_role: str,
    widget_data: Dict[str, Any]
) -> DashboardWidget:
    """Update widget configuration or layout dimensions."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only dashboard owner or administrator can modify widgets")

    widget = db.query(DashboardWidget).filter(
        DashboardWidget.id == widget_id,
        DashboardWidget.dashboard_id == dashboard_id
    ).first()
    if not widget:
        raise KeyError(f"Widget {widget_id} not found on dashboard {dashboard_id}")

    # Validate if changing configuration
    new_type = widget_data.get("widget_type", widget.widget_type)
    new_source = widget_data.get("data_source", widget.data_source)
    new_metric = widget_data.get("metric", widget.metric)
    new_refresh = widget_data.get("refresh_interval_seconds", widget.refresh_interval_seconds)

    if "widget_type" in widget_data or "data_source" in widget_data or "metric" in widget_data or "refresh_interval_seconds" in widget_data:
        _validate_widget_config(new_type, new_source, new_metric, new_refresh)
        widget.widget_type = new_type
        widget.data_source = new_source
        widget.metric = new_metric
        widget.refresh_interval_seconds = new_refresh

    if "title" in widget_data and widget_data["title"]:
        clean_title = widget_data["title"].strip()
        if len(clean_title) > 128:
            raise ValueError("Widget title must be 128 characters or fewer")
        widget.title = clean_title

    if "description" in widget_data:
        widget.description = widget_data["description"]

    if "time_range" in widget_data:
        tr = widget_data["time_range"]
        if tr not in ["24h", "7d", "30d", "90d"]:
            raise ValueError(f"Invalid time_range '{tr}'")
        widget.time_range = tr

    if "filters" in widget_data:
        widget.filters = widget_data["filters"]

    if "display_options" in widget_data:
        widget.display_options = widget_data["display_options"]

    if "position_x" in widget_data:
        widget.position_x = max(0, min(11, int(widget_data["position_x"])))
    if "position_y" in widget_data:
        widget.position_y = max(0, int(widget_data["position_y"]))
    if "width" in widget_data:
        widget.width = max(1, min(12, int(widget_data["width"])))
    if "height" in widget_data:
        widget.height = max(1, min(12, int(widget_data["height"])))

    widget.updated_at = datetime.now(timezone.utc)
    dashboard.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(widget)

    _log_audit(db, user_id, "WIDGET_UPDATED", {"dashboard_id": dashboard_id, "widget_id": widget.id})
    publish_dashboard_event("WIDGET_UPDATED", {"dashboard_id": dashboard_id, "widget_id": widget.id})

    return widget

def delete_widget(
    db: Session,
    dashboard_id: str,
    widget_id: str,
    user_id: str,
    user_role: str
) -> bool:
    """Remove a widget from a dashboard."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only dashboard owner or administrator can delete widgets")

    widget = db.query(DashboardWidget).filter(
        DashboardWidget.id == widget_id,
        DashboardWidget.dashboard_id == dashboard_id
    ).first()
    if not widget:
        raise KeyError(f"Widget {widget_id} not found on dashboard {dashboard_id}")

    db.delete(widget)
    dashboard.updated_at = datetime.now(timezone.utc)
    db.commit()

    _log_audit(db, user_id, "WIDGET_DELETED", {"dashboard_id": dashboard_id, "widget_id": widget_id})
    publish_dashboard_event("WIDGET_DELETED", {"dashboard_id": dashboard_id, "widget_id": widget_id})

    return True

def update_dashboard_layout(
    db: Session,
    dashboard_id: str,
    user_id: str,
    user_role: str,
    layout_items: List[Dict[str, Any]]
) -> List[DashboardWidget]:
    """Batch persist widget coordinates and sizes for a dashboard."""
    dashboard = db.query(Dashboard).filter(Dashboard.id == dashboard_id).first()
    if not dashboard:
        raise KeyError(f"Dashboard {dashboard_id} not found")

    if user_role.lower() != "admin" and dashboard.owner_id != user_id:
        raise PermissionError("Access denied: only dashboard owner or administrator can modify layout")

    widgets_by_id = {w.id: w for w in dashboard.widgets}
    for item in layout_items:
        w_id = item.get("id")
        if w_id in widgets_by_id:
            w = widgets_by_id[w_id]
            if "position_x" in item:
                w.position_x = max(0, min(11, int(item["position_x"])))
            if "position_y" in item:
                w.position_y = max(0, int(item["position_y"]))
            if "width" in item:
                w.width = max(1, min(12, int(item["width"])))
            if "height" in item:
                w.height = max(1, min(12, int(item["height"])))
            w.updated_at = datetime.now(timezone.utc)

    dashboard.updated_at = datetime.now(timezone.utc)
    db.commit()

    _log_audit(db, user_id, "LAYOUT_UPDATED", {"dashboard_id": dashboard_id, "widgets_count": len(layout_items)})
    publish_dashboard_event("LAYOUT_UPDATED", {"dashboard_id": dashboard_id})

    return dashboard.widgets

# ---------------------------------------------------------------------------
# Real Telemetry Resolution Engine
# ---------------------------------------------------------------------------

def resolve_widget_data(
    db: Session,
    widget: DashboardWidget,
    time_range_override: Optional[str] = None
) -> Dict[str, Any]:
    """
    Resolve live data for a widget by querying authoritative database tables
    and Phase 4C analytics services. Zero synthetic or fake numbers.
    """
    time_range = time_range_override or widget.time_range or "24h"
    w_type = widget.widget_type
    metric = widget.metric

    # 1. KPI Widgets
    if w_type == WidgetType.KPI.value:
        kpis = analytics_service.get_executive_kpis(db, time_range)
        if metric == WidgetMetric.RISK_SCORE.value:
            return {
                "value": kpis["enterprise_risk_score"]["score"],
                "unit": "/100",
                "label": "Enterprise Risk Score",
                "level": kpis["enterprise_risk_score"]["level"],
                "basis": kpis["enterprise_risk_score"]["calculation_basis"]
            }
        elif metric == WidgetMetric.TOTAL_INDICATORS.value:
            return {
                "value": kpis["indicators"]["total"],
                "recent": kpis["indicators"]["recent_ingested"],
                "unit": "IOCs",
                "label": "Total Threat Indicators",
                "basis": "Authoritative database indicators"
            }
        elif metric == WidgetMetric.ACTIVE_ALERTS.value:
            return {
                "value": kpis["alerts"]["active_total"],
                "sev1": kpis["alerts"]["active_sev1"],
                "unit": "Alerts",
                "label": "Active Security Alerts",
                "basis": "Unclosed alerts requiring triage"
            }
        elif metric == WidgetMetric.ACTIVE_INCIDENTS.value:
            return {
                "value": kpis["active_sev1_incidents"]["total_open_incidents"],
                "sev1": kpis["active_sev1_incidents"]["count"],
                "unit": "Incidents",
                "label": "Open Correlated Incidents",
                "basis": "Active incidents undergoing investigation"
            }
        elif metric == WidgetMetric.ACTIVE_SEV1_INCIDENTS.value:
            return {
                "value": kpis["active_sev1_incidents"]["count"],
                "unit": "SEV-1",
                "label": "Critical SEV-1 Incidents",
                "basis": "Incidents flagged as CRITICAL severity"
            }
        elif metric == WidgetMetric.MTTD.value:
            return {
                "value": kpis["mttd"]["value_minutes"],
                "formatted": kpis["mttd"]["formatted"],
                "unit": "mins",
                "label": "Mean Time to Detect (MTTD)",
                "basis": kpis["mttd"]["calculation_basis"]
            }
        elif metric == WidgetMetric.MTTR.value:
            return {
                "value": kpis["mttr"]["value_minutes"],
                "formatted": kpis["mttr"]["formatted"],
                "unit": "mins",
                "label": "Mean Time to Respond (MTTR)",
                "basis": kpis["mttr"]["calculation_basis"]
            }
        elif metric == WidgetMetric.ENRICHMENT_COVERAGE.value:
            return {
                "value": kpis["enrichment_coverage"]["percentage"],
                "unit": "%",
                "label": "Threat Intel Coverage",
                "basis": f"{kpis['enrichment_coverage']['enriched_indicators']} of {kpis['enrichment_coverage']['total_indicators']} enriched"
            }
        else:
            return {"value": 0, "label": metric}

    # 2. Time-Series & Line Charts
    elif w_type in [WidgetType.TIME_SERIES.value, WidgetType.LINE_CHART.value]:
        trends = analytics_service.get_threat_trends(db, time_range)
        return {
            "series": trends["series"],
            "interval": trends["interval"],
            "total_ingests": trends["total_ingests"],
            "total_high_severity": trends["total_high_severity"]
        }

    # 3. Bar Charts
    elif w_type == WidgetType.BAR_CHART.value:
        if metric == WidgetMetric.SOURCE_BREAKDOWN.value:
            srcs = analytics_service.get_source_analytics(db)
            return {"items": srcs["sources"][:10], "total": srcs["total_indicators"]}
        else:
            types_data = analytics_service.get_indicator_type_distribution(db)
            return {"items": types_data["items"][:10], "total": types_data["total"]}

    # 4. Severity Distribution
    elif w_type == WidgetType.SEVERITY_DISTRIBUTION.value:
        dist = analytics_service.get_severity_distribution(db)
        return {
            "chart_data": dist["chart_data"],
            "indicators": dist["indicators"],
            "alerts": dist["alerts"],
            "incidents": dist["incidents"]
        }

    # 5. Incident Trend
    elif w_type == WidgetType.INCIDENT_TREND.value:
        return analytics_service.get_incident_analytics(db)

    # 6. Alert Trend
    elif w_type == WidgetType.ALERT_TREND.value:
        rows = db.query(
            func.coalesce(Alert.status, "NEW").label("st"),
            func.count(Alert.id).label("cnt")
        ).group_by("st").all()
        by_status = {st.upper(): cnt for st, cnt in rows}
        
        sev_rows = db.query(
            func.coalesce(Alert.severity, "HIGH").label("sv"),
            func.count(Alert.id).label("cnt")
        ).group_by("sv").all()
        by_severity = {sv.upper(): cnt for sv, cnt in sev_rows}

        total = sum(by_status.values())
        return {"total_alerts": total, "by_status": by_status, "by_severity": by_severity}

    # 7. IOC Type Distribution
    elif w_type == WidgetType.IOC_TYPE_DISTRIBUTION.value:
        return analytics_service.get_indicator_type_distribution(db)

    # 8. Threat Intel Sources
    elif w_type == WidgetType.THREAT_INTEL_SOURCES.value:
        return analytics_service.get_source_analytics(db)

    # 9. MITRE ATT&CK
    elif w_type == WidgetType.MITRE_ATTACK.value:
        return analytics_service.get_mitre_analytics(db, limit=10)

    # 10. Geographic Distribution
    elif w_type == WidgetType.GEOGRAPHIC_DISTRIBUTION.value:
        return analytics_service.get_geographic_analytics(db, limit=10)

    # 11. Detection Rule Activity
    elif w_type == WidgetType.DETECTION_RULE_ACTIVITY.value:
        total_rules = db.query(func.count(DetectionRule.id)).scalar() or 0
        active_rules = db.query(func.count(DetectionRule.id)).filter(DetectionRule.is_active == True).scalar() or 0
        total_matches = db.query(func.sum(DetectionRule.match_count)).scalar() or 0
        rules = db.query(DetectionRule).order_by(desc(DetectionRule.match_count)).limit(5).all()
        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "total_matches": total_matches,
            "top_rules": [
                {"name": r.name, "severity": r.severity, "matches": r.match_count, "queue": r.routing_queue}
                for r in rules
            ]
        }

    # 12. Case Status Distribution
    elif w_type == WidgetType.CASE_STATUS_DISTRIBUTION.value:
        rows = db.query(
            func.coalesce(Case.status, "OPEN").label("st"),
            func.count(Case.id).label("cnt")
        ).group_by("st").all()
        by_status = {st.upper(): cnt for st, cnt in rows}
        return {"total_cases": sum(by_status.values()), "by_status": by_status}

    # 13. Case Severity Distribution
    elif w_type == WidgetType.CASE_SEVERITY_DISTRIBUTION.value:
        rows = db.query(
            func.coalesce(Case.severity, "MEDIUM").label("sv"),
            func.count(Case.id).label("cnt")
        ).group_by("sv").all()
        by_severity = {sv.upper(): cnt for sv, cnt in rows}
        return {"total_cases": sum(by_severity.values()), "by_severity": by_severity}

    # 14. Top Threat Indicators
    elif w_type == WidgetType.TOP_INDICATORS.value:
        iocs = db.query(Indicator).order_by(desc(Indicator.severity_score), desc(Indicator.created_at)).limit(6).all()
        return {
            "indicators": [
                {
                    "id": ind.id,
                    "value": ind.value,
                    "type": ind.type,
                    "severity": ind.severity or "UNKNOWN",
                    "severity_score": ind.severity_score or 0,
                    "confidence": ind.confidence or 0,
                    "source": ind.source or "unknown",
                }
                for ind in iocs
            ]
        }

    # 15. Recent Critical Incidents
    elif w_type == WidgetType.RECENT_CRITICAL_INCIDENTS.value:
        incidents = db.query(Incident).filter(
            or_(Incident.severity == "CRITICAL", Incident.severity == "HIGH")
        ).order_by(desc(Incident.created_at)).limit(5).all()
        return {
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "correlation_score": inc.correlation_score,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                }
                for inc in incidents
            ]
        }

    # 16. Recent Critical Alerts
    elif w_type == WidgetType.RECENT_CRITICAL_ALERTS.value:
        alerts = db.query(Alert).filter(
            or_(Alert.severity == "CRITICAL", Alert.severity == "HIGH")
        ).order_by(desc(Alert.created_at)).limit(5).all()
        return {
            "alerts": [
                {
                    "id": al.id,
                    "title": al.title,
                    "severity": al.severity,
                    "status": al.status,
                    "routed_to": al.routed_to,
                    "created_at": al.created_at.isoformat() if al.created_at else None,
                }
                for al in alerts
            ]
        }

    # 17. Enrichment Statistics
    elif w_type == WidgetType.ENRICHMENT_STATISTICS.value:
        kpis = analytics_service.get_executive_kpis(db, time_range)
        provider_rows = db.query(
            func.coalesce(IndicatorEnrichment.provider, "unknown").label("prv"),
            func.count(IndicatorEnrichment.id).label("cnt")
        ).group_by("prv").all()
        providers = {p: c for p, c in provider_rows}
        return {
            "coverage_percentage": kpis["enrichment_coverage"]["percentage"],
            "total_indicators": kpis["enrichment_coverage"]["total_indicators"],
            "enriched_indicators": kpis["enrichment_coverage"]["enriched_indicators"],
            "by_provider": providers
        }

    return {"error": "Unsupported widget resolution", "widget_type": w_type}
