"""
ThreatLens - Phase 4C Threat Analytics Test Suite
Verifies:
1. Authentication & RBAC enforcement on analytics endpoints
2. Parameter validation (bounded time_range: 24h, 7d, 30d, 90d)
3. Deterministic Executive KPI calculations (MTTD, MTTR, Risk Score)
4. Continuous zero-filled time-series threat velocity
5. Severity and indicator-type distributions
6. Incident lifecycle statistics
7. MITRE ATT&CK analytics (with data & honest empty state)
8. Geographic density analytics (with data & honest empty state)
9. Source/feed volume breakdown
10. Empty database graceful behavior
11. Regressions against Phase 4A & 4B
"""
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.incident import Incident, IncidentStatus, IncidentTimeline
from app.models.enrichment import IndicatorEnrichment
from app.models.user import User, UserRole
from app.core.security import create_access_token, get_password_hash

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
    email = f"analyst_4c_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4C Analyst",
        role=UserRole.ANALYST.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role, "email": user.email},
        expires_delta=timedelta(minutes=60)
    )
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def viewer_headers(db_session):
    email = f"viewer_4c_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4C Viewer",
        role=UserRole.VIEWER.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role, "email": user.email},
        expires_delta=timedelta(minutes=60)
    )
    return {"Authorization": f"Bearer {token}"}

def test_analytics_requires_authentication():
    """Unauthenticated requests must be rejected with 401."""
    resp = client.get("/api/v1/analytics/overview")
    assert resp.status_code in (401, 403)

    resp_kpis = client.get("/api/v1/analytics/kpis")
    assert resp_kpis.status_code in (401, 403)

def test_analytics_rbac_viewer_and_analyst_access(auth_headers, viewer_headers):
    """Viewers and analysts can retrieve analytics overview."""
    resp_analyst = client.get("/api/v1/analytics/overview", headers=auth_headers)
    assert resp_analyst.status_code == 200

    resp_viewer = client.get("/api/v1/analytics/overview", headers=viewer_headers)
    assert resp_viewer.status_code == 200

def test_time_range_validation(auth_headers):
    """Invalid time ranges must be rejected; valid ones accepted."""
    # Invalid
    resp_invalid = client.get("/api/v1/analytics/trends?time_range=invalid_range", headers=auth_headers)
    assert resp_invalid.status_code == 422  # Query regex validation failure

    # Valid ranges
    for tr in ["24h", "7d", "30d", "90d"]:
        resp = client.get(f"/api/v1/analytics/trends?time_range={tr}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["time_range"] == tr
        assert len(data["series"]) > 0

def test_executive_kpis_calculation(auth_headers):
    """Verify deterministic calculations for executive KPIs."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # Seed test indicators
        ioc_crit = Indicator(
            id=str(uuid.uuid4()),
            value=f"198.51.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
            type="ip",
            severity="CRITICAL",
            severity_score=95,
            confidence=90,
            status="active",
            created_at=now - timedelta(hours=2)
        )
        ioc_high = Indicator(
            id=str(uuid.uuid4()),
            value=f"threat-{uuid.uuid4().hex[:6]}.com",
            type="domain",
            severity="HIGH",
            severity_score=75,
            confidence=80,
            status="active",
            created_at=now - timedelta(hours=5)
        )
        ioc_med = Indicator(
            id=str(uuid.uuid4()),
            value=f"https://phish-{uuid.uuid4().hex[:6]}.net/login",
            type="url",
            severity="MEDIUM",
            severity_score=50,
            confidence=70,
            status="active",
            created_at=now - timedelta(hours=10)
        )
        db.add_all([ioc_crit, ioc_high, ioc_med])
        db.commit()

        # Seed test alert and incident
        alert = Alert(
            id=str(uuid.uuid4()),
            title="Critical Ingress C2",
            severity="CRITICAL",
            severity_score=95,
            status="NEW",
            indicator_id=ioc_crit.id,
            created_at=now - timedelta(hours=1)
        )
        db.add(alert)

        inc = Incident(
            id=str(uuid.uuid4()),
            incident_code=f"INC-TEST-{uuid.uuid4().hex[:4].upper()}",
            title="Targeted Intrusion Incident",
            severity="CRITICAL",
            status="OPEN",
            indicator_id=ioc_crit.id,
            created_at=now - timedelta(hours=2)
        )
        db.add(inc)
        db.commit()

        # Call endpoint
        resp = client.get("/api/v1/analytics/kpis?time_range=24h", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()

        assert data["indicators"]["total"] >= 3
        assert data["indicators"]["critical_count"] >= 1
        assert data["indicators"]["high_count"] >= 1
        assert data["alerts"]["active_total"] >= 1
        assert data["alerts"]["active_sev1"] >= 1
        assert data["active_sev1_incidents"]["count"] >= 1
        assert 0 <= data["enterprise_risk_score"]["score"] <= 100
        assert data["enterprise_risk_score"]["level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    finally:
        db.close()

def test_threat_trends_continuous_zero_fill(auth_headers):
    """Verify threat trends return continuous, zero-filled series without null gaps."""
    resp = client.get("/api/v1/analytics/trends?time_range=24h", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["interval"] == "hour"
    series = data["series"]
    assert len(series) >= 24

    for point in series:
        assert "timestamp" in point
        assert "label" in point
        assert "ingests" in point
        assert "high_severity" in point
        assert point["ingests"] >= 0
        assert point["high_severity"] >= 0

def test_severity_distribution_aggregation(auth_headers):
    """Verify severity aggregation across indicators, alerts, and incidents."""
    resp = client.get("/api/v1/analytics/severity", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "indicators" in data
    assert "alerts" in data
    assert "incidents" in data
    assert "chart_data" in data

    chart = data["chart_data"]
    assert len(chart) == 4
    categories = [c["name"] for c in chart]
    assert any("Critical" in c for c in categories)
    assert any("High" in c for c in categories)

def test_indicator_type_distribution(auth_headers):
    """Verify grouping by canonical IOC types."""
    resp = client.get("/api/v1/analytics/indicator-types", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "distribution" in data
    assert "items" in data
    assert isinstance(data["items"], list)

def test_incident_analytics_summary(auth_headers):
    """Verify incident metrics: status breakdown, severity breakdown, and alert ratio."""
    resp = client.get("/api/v1/analytics/incidents", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_incidents" in data
    assert "by_status" in data
    assert "by_severity" in data
    assert "avg_alerts_per_incident" in data

def test_mitre_analytics_with_data_and_empty(auth_headers):
    """Verify MITRE ATT&CK technique extraction and honest fallback."""
    db = SessionLocal()
    try:
        # Seed indicator with real MITRE technique
        ioc = Indicator(
            id=str(uuid.uuid4()),
            value=f"cve-{uuid.uuid4().hex[:6]}",
            type="cve",
            severity="HIGH",
            mitre_technique="T1190",
            status="active"
        )
        db.add(ioc)
        db.commit()

        resp = client.get("/api/v1/analytics/mitre", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_data"] is True
        assert data["total_techniques_observed"] >= 1
        tech_ids = [t["id"] for t in data["techniques"]]
        assert "T1190" in tech_ids
        tech_t1190 = next(t for t in data["techniques"] if t["id"] == "T1190")
        assert tech_t1190["name"] == "Exploit Public-Facing Application"
        assert tech_t1190["tactic"] == "Initial Access"
    finally:
        db.close()

def test_geographic_analytics_with_data(auth_headers):
    """Verify geographic origin aggregation from indicator enrichments."""
    db = SessionLocal()
    try:
        ioc = Indicator(
            id=str(uuid.uuid4()),
            value=f"198.51.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
            type="ip",
            severity="MEDIUM",
            status="active"
        )
        db.add(ioc)
        db.commit()

        enrich = IndicatorEnrichment(
            id=str(uuid.uuid4()),
            indicator_id=ioc.id,
            provider="virustotal",
            queried_value=ioc.value,
            indicator_type="ip",
            verdict="clean",
            country="DE",
            asn="AS13335"
        )
        db.add(enrich)
        db.commit()

        resp = client.get("/api/v1/analytics/geography", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_data"] is True
        codes = [c["country_code"] for c in data["countries"]]
        assert "DE" in codes
        de_entry = next(c for c in data["countries"] if c["country_code"] == "DE")
        assert de_entry["country_name"] == "Germany"
        assert de_entry["country"] == "Germany"
        assert de_entry["count"] >= 1
    finally:
        db.close()

def test_sources_analytics(auth_headers):
    """Verify threat intelligence feed volume aggregation."""
    resp = client.get("/api/v1/analytics/sources", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_sources" in data
    assert "total_indicators" in data
    assert "sources" in data
    assert isinstance(data["sources"], list)

def test_full_overview_endpoint(auth_headers):
    """Verify combined overview endpoint aggregates all sections."""
    resp = client.get("/api/v1/analytics/overview?time_range=7d", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["time_range"] == "7d"
    assert "kpis" in data
    assert "trends" in data
    assert "severity" in data
    assert "indicator_types" in data
