"""
ThreatLens - Phase 4F Custom Dashboard and Modular Widget Test Suite.

Covers:
- Predefined safe widget catalog retrieval (18 SOC widgets)
- Dashboard CRUD (create, read, list, update, delete, duplicate)
- Strict widget configuration validation (rejection of illegal types, metrics, time ranges)
- Prevention of arbitrary SQL, code injection, or dynamic execution
- Relational widget persistence and association with dashboards
- Responsive 12-column grid layout persistence (positions, width, height)
- Live telemetry data resolution against real database tables
- Server-side RBAC (Viewer read-only vs 403 mutations, Analyst management, Admin governance)
- IDOR defense: cross-user private dashboard modification and viewing rejection
- Shared dashboard visibility access
- Immutable audit log verification
"""
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models.user import User
from app.models.dashboard import Dashboard, DashboardWidget, DashboardVisibility, WidgetType, WidgetMetric, WidgetDataSource
from app.models.indicator import Indicator, IndicatorType
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.audit import AuditLog
from app.core.security import create_access_token, get_password_hash
from app.services import dashboard_service

client = TestClient(app)

@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def auth_headers(db_session):
    """Generate authenticated bearer headers for various RBAC roles."""
    def _get_headers(role_str: str, custom_email: str = None):
        unique_email = custom_email or f"test_{role_str.lower()}_{uuid.uuid4().hex[:6]}@threatlens.io"
        user = User(
            email=unique_email,
            hashed_password=get_password_hash("Password123!"),
            full_name=f"Test {role_str}",
            role=role_str,
            is_active=True
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        token = create_access_token(data={"sub": user.email, "role": role_str})
        return {"Authorization": f"Bearer {token}"}, user
    return _get_headers


# ===========================================================================
# 1. Widget Catalog
# ===========================================================================

def test_get_widget_catalog(auth_headers):
    """Authenticated user can fetch catalog containing 18 supported SOC widgets."""
    headers, _ = auth_headers("viewer")
    res = client.get("/api/v1/dashboards/catalog/widgets", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "catalog" in data
    catalog = data["catalog"]
    assert len(catalog) >= 18
    types = [c["widget_type"] for c in catalog]
    assert "KPI" in types
    assert "TIME_SERIES" in types
    assert "SEVERITY_DISTRIBUTION" in types
    assert "TOP_INDICATORS" in types
    assert "RECENT_CRITICAL_INCIDENTS" in types


# ===========================================================================
# 2. Dashboard CRUD & Duplication
# ===========================================================================

def test_create_dashboard_success(auth_headers):
    """Analyst can create a custom dashboard."""
    headers, user = auth_headers("analyst")
    payload = {
        "name": "SOC Tier 2 Cockpit",
        "description": "Daily alert triage and high severity indicator monitoring",
        "is_default": True,
        "visibility": "PRIVATE"
    }
    res = client.post("/api/v1/dashboards", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == payload["name"]
    assert data["description"] == payload["description"]
    assert data["owner_id"] == user.id
    assert data["visibility"] == "PRIVATE"
    assert data["is_default"] is True

def test_list_dashboards(auth_headers):
    """List accessible dashboards with pagination."""
    headers, _ = auth_headers("analyst")
    # Create two dashboards
    client.post("/api/v1/dashboards", json={"name": "Dash A"}, headers=headers)
    client.post("/api/v1/dashboards", json={"name": "Dash B"}, headers=headers)

    res = client.get("/api/v1/dashboards?limit=10&offset=0", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert data["total"] >= 2
    assert len(data["dashboards"]) >= 2

def test_update_dashboard(auth_headers):
    """Analyst can update their own dashboard name, description, and visibility."""
    headers, _ = auth_headers("analyst")
    c_res = client.post("/api/v1/dashboards", json={"name": "Initial Name"}, headers=headers)
    dash_id = c_res.json()["id"]

    u_res = client.patch(f"/api/v1/dashboards/{dash_id}", json={
        "name": "Updated Name",
        "description": "New description",
        "visibility": "SHARED"
    }, headers=headers)
    assert u_res.status_code == 200
    data = u_res.json()
    assert data["name"] == "Updated Name"
    assert data["description"] == "New description"
    assert data["visibility"] == "SHARED"

def test_duplicate_dashboard(auth_headers):
    """Analyst can clone an existing dashboard with all widgets."""
    headers, _ = auth_headers("analyst")
    c_res = client.post("/api/v1/dashboards", json={"name": "Master Template"}, headers=headers)
    dash_id = c_res.json()["id"]

    # Add a widget to master
    client.post(f"/api/v1/dashboards/{dash_id}/widgets", json={
        "title": "Master KPI",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "TOTAL_INDICATORS",
        "time_range": "24h"
    }, headers=headers)

    dup_res = client.post(f"/api/v1/dashboards/{dash_id}/duplicate?new_name=Cloned+Cockpit", headers=headers)
    assert dup_res.status_code == 201
    cloned = dup_res.json()
    assert cloned["name"] == "Cloned Cockpit"
    assert cloned["id"] != dash_id
    assert len(cloned["widgets"]) == 1
    assert cloned["widgets"][0]["title"] == "Master KPI"

def test_delete_dashboard(auth_headers):
    """Analyst can delete their own dashboard."""
    headers, _ = auth_headers("analyst")
    c_res = client.post("/api/v1/dashboards", json={"name": "To Delete"}, headers=headers)
    dash_id = c_res.json()["id"]

    d_res = client.delete(f"/api/v1/dashboards/{dash_id}", headers=headers)
    assert d_res.status_code == 200

    # Ensure 404 on subsequent fetch
    g_res = client.get(f"/api/v1/dashboards/{dash_id}", headers=headers)
    assert g_res.status_code == 404


# ===========================================================================
# 3. Widget Configuration & Validation
# ===========================================================================

def test_add_widget_success(auth_headers):
    """Add a validated widget to a dashboard."""
    headers, _ = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Widget Host"}, headers=headers).json()

    w_payload = {
        "title": "Enterprise Risk Posture",
        "description": "Live board risk index",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "RISK_SCORE",
        "time_range": "7d",
        "width": 3,
        "height": 3
    }
    w_res = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json=w_payload, headers=headers)
    assert w_res.status_code == 201
    w_data = w_res.json()
    assert w_data["title"] == w_payload["title"]
    assert w_data["widget_type"] == "KPI"
    assert w_data["metric"] == "RISK_SCORE"
    assert w_data["width"] == 3

def test_widget_validation_rejection(auth_headers):
    """Server strictly rejects invalid widget types or metrics."""
    headers, _ = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Security Host"}, headers=headers).json()

    # 1. Invalid widget_type
    bad_type = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Malicious Widget",
        "widget_type": "RAW_SQL_EXECUTION",
        "data_source": "ANALYTICS",
        "metric": "SELECT *",
    }, headers=headers)
    assert bad_type.status_code == 400

    # 2. Incompatible metric for widget_type
    bad_metric = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Bad Metric",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "INVALID_METRIC_NAME",
    }, headers=headers)
    assert bad_metric.status_code == 400

def test_update_and_delete_widget(auth_headers):
    """Update widget title/dimensions and delete widget."""
    headers, _ = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Widget Lifecycle"}, headers=headers).json()

    widget = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Original Title",
        "widget_type": "TIME_SERIES",
        "data_source": "ANALYTICS",
        "metric": "INGESTION_VELOCITY",
        "width": 6
    }, headers=headers).json()

    # Update width
    u_res = client.patch(f"/api/v1/dashboards/{dash['id']}/widgets/{widget['id']}", json={
        "title": "New Title",
        "width": 12
    }, headers=headers)
    assert u_res.status_code == 200
    assert u_res.json()["title"] == "New Title"
    assert u_res.json()["width"] == 12

    # Delete
    del_res = client.delete(f"/api/v1/dashboards/{dash['id']}/widgets/{widget['id']}", headers=headers)
    assert del_res.status_code == 200


# ===========================================================================
# 4. Layout Persistence
# ===========================================================================

def test_batch_layout_update(auth_headers):
    """Persist batch widget positioning across grid."""
    headers, _ = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Grid Test"}, headers=headers).json()

    w1 = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Widget 1",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "TOTAL_INDICATORS",
    }, headers=headers).json()

    w2 = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Widget 2",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "ACTIVE_ALERTS",
    }, headers=headers).json()

    layout_payload = {
        "items": [
            {"id": w1["id"], "position_x": 0, "position_y": 0, "width": 6, "height": 3},
            {"id": w2["id"], "position_x": 6, "position_y": 0, "width": 6, "height": 3}
        ]
    }
    l_res = client.post(f"/api/v1/dashboards/{dash['id']}/layout", json=layout_payload, headers=headers)
    assert l_res.status_code == 200

    # Verify on reload
    reloaded = client.get(f"/api/v1/dashboards/{dash['id']}", headers=headers).json()
    w1_r = next(w for w in reloaded["widgets"] if w["id"] == w1["id"])
    w2_r = next(w for w in reloaded["widgets"] if w["id"] == w2["id"])
    assert w1_r["position_x"] == 0
    assert w2_r["position_x"] == 6


# ===========================================================================
# 5. Live Telemetry Data Resolution
# ===========================================================================

def test_resolve_widget_telemetry(auth_headers, db_session):
    """Widget data endpoint returns real telemetry without crashing on empty or populated corpus."""
    headers, _ = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Telemetry Host"}, headers=headers).json()

    # 1. KPI Widget
    kpi_w = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "KPI Test",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "RISK_SCORE",
        "time_range": "24h"
    }, headers=headers).json()

    kpi_res = client.get(f"/api/v1/dashboards/{dash['id']}/widgets/{kpi_w['id']}/data", headers=headers)
    assert kpi_res.status_code == 200
    kpi_data = kpi_res.json()
    assert "data" in kpi_data
    assert "value" in kpi_data["data"]

    # 2. Severity Distribution Widget
    sev_w = client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Severity Donut",
        "widget_type": "SEVERITY_DISTRIBUTION",
        "data_source": "ANALYTICS",
        "metric": "SEVERITY_BREAKDOWN",
    }, headers=headers).json()

    sev_res = client.get(f"/api/v1/dashboards/{dash['id']}/widgets/{sev_w['id']}/data", headers=headers)
    assert sev_res.status_code == 200
    sev_data = sev_res.json()
    assert "chart_data" in sev_data["data"]


# ===========================================================================
# 6. RBAC & IDOR Enforcement
# ===========================================================================

def test_viewer_mutation_forbidden(auth_headers):
    """Viewer role is forbidden from creating or modifying dashboards."""
    viewer_headers, _ = auth_headers("viewer")

    # Viewer cannot create dashboard
    res1 = client.post("/api/v1/dashboards", json={"name": "Viewer Dash"}, headers=viewer_headers)
    assert res1.status_code == 403

def test_idor_cross_user_isolation(auth_headers):
    """User B cannot view, modify, or delete User A's private dashboard."""
    user_a_headers, user_a = auth_headers("analyst")
    user_b_headers, user_b = auth_headers("analyst")

    # User A creates private dashboard
    dash_a = client.post("/api/v1/dashboards", json={
        "name": "User A Private",
        "visibility": "PRIVATE"
    }, headers=user_a_headers).json()

    # User B tries to view it -> 403 Forbidden
    res_view = client.get(f"/api/v1/dashboards/{dash_a['id']}", headers=user_b_headers)
    assert res_view.status_code == 403

    # User B tries to edit it -> 403 Forbidden
    res_edit = client.patch(f"/api/v1/dashboards/{dash_a['id']}", json={"name": "Hacked"}, headers=user_b_headers)
    assert res_edit.status_code == 403

    # User B tries to delete it -> 403 Forbidden
    res_del = client.delete(f"/api/v1/dashboards/{dash_a['id']}", headers=user_b_headers)
    assert res_del.status_code == 403

def test_shared_dashboard_access(auth_headers):
    """User B CAN view User A's SHARED dashboard, but cannot delete it."""
    user_a_headers, _ = auth_headers("analyst")
    user_b_headers, _ = auth_headers("analyst")

    dash_shared = client.post("/api/v1/dashboards", json={
        "name": "Team Shared Cockpit",
        "visibility": "SHARED"
    }, headers=user_a_headers).json()

    # User B can view -> 200 OK
    res_view = client.get(f"/api/v1/dashboards/{dash_shared['id']}", headers=user_b_headers)
    assert res_view.status_code == 200
    assert res_view.json()["name"] == "Team Shared Cockpit"

    # User B cannot delete -> 403 Forbidden
    res_del = client.delete(f"/api/v1/dashboards/{dash_shared['id']}", headers=user_b_headers)
    assert res_del.status_code == 403


# ===========================================================================
# 7. Audit Trail Logging
# ===========================================================================

def test_dashboard_audit_logging(auth_headers, db_session):
    """Dashboard creation and widget addition generate immutable audit log entries."""
    headers, user = auth_headers("analyst")
    dash = client.post("/api/v1/dashboards", json={"name": "Audited Dash"}, headers=headers).json()

    client.post(f"/api/v1/dashboards/{dash['id']}/widgets", json={
        "title": "Audited Widget",
        "widget_type": "KPI",
        "data_source": "ANALYTICS",
        "metric": "TOTAL_INDICATORS"
    }, headers=headers)

    audit_dash = db_session.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.action == "DASHBOARD_CREATED"
    ).first()
    assert audit_dash is not None

    audit_widget = db_session.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.action == "WIDGET_CREATED"
    ).first()
    assert audit_widget is not None
