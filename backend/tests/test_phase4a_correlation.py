import pytest
import uuid
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentTimeline
from app.models.audit import AuditLog
from app.models.user import User, UserRole
from app.core.security import create_access_token, get_password_hash
from app.core.config import settings
from app.core.redis import redis_manager
from app.services.alert_service import evaluate_ioc_for_alerts
from app.services.correlation_service import (
    evaluate_correlation,
    correlate_alert_to_incident,
    derive_incident_severity,
    update_incident_status,
    update_incident_severity,
    WEIGHT_SAME_IOC,
    WEIGHT_SAME_HOST,
    WEIGHT_SAME_MITRE,
    WEIGHT_SAME_SOURCE,
    WEIGHT_TEMPORAL,
    CLUSTERING_THRESHOLD
)

client = TestClient(app)

@pytest.fixture
def db_session():
    """Provides an isolated database session per test."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def analyst_headers(db_session):
    """Generates an analyst-level user and bearer token."""
    email = f"analyst_p4a_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4A Analyst",
        role=UserRole.ANALYST.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email, "role": user.role, "user_id": str(user.id)})
    return {"Authorization": f"Bearer {token}", "token": token, "user": user}

@pytest.fixture
def viewer_headers(db_session):
    """Generates a viewer/read-only user and bearer token."""
    email = f"viewer_p4a_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4A Viewer",
        role=UserRole.VIEWER.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email, "role": user.role, "user_id": str(user.id)})
    return {"Authorization": f"Bearer {token}", "token": token, "user": user}


# -------------------------------------------------------------
# Test 1: Same IOC Correlates
# -------------------------------------------------------------
def test_same_ioc_correlates(db_session):
    now = datetime.utcnow()
    ioc_val = f"malware-c2-{uuid.uuid4().hex[:6]}.evil.com"
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Test Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        primary_indicator=ioc_val,
        primary_source="URLhaus",
        last_seen=now
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title=f"Alert on {ioc_val}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=ioc_val,
        source="URLhaus",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    assert score >= CLUSTERING_THRESHOLD
    assert any("same IOC" in f for f in factors)
    assert f"same IOC ({ioc_val})" in explanation


# -------------------------------------------------------------
# Test 2: Different IOC Does Not Incorrectly Correlate
# -------------------------------------------------------------
def test_different_ioc_does_not_incorrectly_correlate(db_session):
    now = datetime.utcnow()
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Test Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        primary_indicator="clean-host-alpha.corp.local",
        primary_source="SourceA",
        affected_host="wkstn-alpha",
        mitre_techniques=["T1059"],
        last_seen=now
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title="Completely unrelated alert",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value="completely-unrelated-threat.net",
        source="SourceB",
        internal_host="wkstn-beta",
        mitre_technique="T1071",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    # Only temporal proximity might match (15 pts), well below threshold (50)
    assert score < CLUSTERING_THRESHOLD


# -------------------------------------------------------------
# Test 3: Same Host Correlation
# -------------------------------------------------------------
def test_same_host_correlation(db_session):
    now = datetime.utcnow()
    host_target = "host-finance-srv-01.corp.local"
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Compromised Host Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        affected_host=host_target,
        mitre_techniques=["T1071"],
        last_seen=now
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title=f"Lateral Movement on {host_target}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        internal_host=host_target,
        mitre_technique="T1071",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    # Host (30) + MITRE (20) + Temporal (15) = 65 >= 50
    assert score >= CLUSTERING_THRESHOLD
    assert any("same affected host" in f for f in factors)


# -------------------------------------------------------------
# Test 4: Same MITRE Technique Correlation
# -------------------------------------------------------------
def test_same_mitre_technique_correlation(db_session):
    now = datetime.utcnow()
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="C2 Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        mitre_techniques=["T1071.001"],
        last_seen=now
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title="Web Protocol C2",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        mitre_technique="T1071.001",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    assert any("same MITRE technique" in f for f in factors)


# -------------------------------------------------------------
# Test 5: Temporal Correlation
# -------------------------------------------------------------
def test_temporal_correlation(db_session):
    now = datetime.utcnow()
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Temporal Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        primary_indicator="beacon.domain.com",
        last_seen=now - timedelta(minutes=3)  # within 15 min window
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title="Recent Beacon Alert",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value="beacon.domain.com",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    assert score >= CLUSTERING_THRESHOLD
    assert any("temporal proximity" in f for f in factors)


# -------------------------------------------------------------
# Test 6: Correlation Window Boundary
# -------------------------------------------------------------
def test_correlation_window_boundary(db_session):
    now = datetime.utcnow()
    # 25 minutes ago (outside the 15-minute default window)
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Old Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        primary_indicator="old-threat.com",
        last_seen=now - timedelta(minutes=25)
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title="New Alert on Same Old Indicator",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value="old-threat.com",
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    assert score == 0
    assert "Outside correlation time window" in explanation


# -------------------------------------------------------------
# Test 7: Correlation Score Calculation
# -------------------------------------------------------------
def test_correlation_score_calculation(db_session):
    now = datetime.utcnow()
    ioc = "score-test.evil.org"
    host = "srv-app-09"
    mitre = "T1071"
    source = "CISA-KEV"

    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Full Match Test",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value,
        primary_indicator=ioc,
        primary_source=source,
        affected_host=host,
        mitre_techniques=[mitre],
        last_seen=now - timedelta(minutes=1)
    )
    db_session.add(inc)
    db_session.commit()

    alert = Alert(
        title="Full Match Alert",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=ioc,
        source=source,
        internal_host=host,
        mitre_technique=mitre,
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    score, factors, explanation = evaluate_correlation(alert, inc, window_minutes=15)
    expected_min = WEIGHT_SAME_IOC + WEIGHT_SAME_HOST + WEIGHT_SAME_MITRE + WEIGHT_SAME_SOURCE + 5
    assert score >= expected_min
    assert len(factors) == 5  # IOC, host, MITRE, source, temporal


# -------------------------------------------------------------
# Test 8: New Incident Creation
# -------------------------------------------------------------
def test_new_incident_creation(db_session):
    unique_ioc = f"new-inc-{uuid.uuid4().hex[:8]}.org"
    alert = Alert(
        alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
        title=f"Threat Detected: {unique_ioc}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=unique_ioc,
        source="ThreatLens Stream",
        internal_host=f"wkstn-{uuid.uuid4().hex[:6]}",
        mitre_technique="T1071",
        created_at=datetime.utcnow()
    )
    db_session.add(alert)
    db_session.commit()

    incident = correlate_alert_to_incident(db_session, alert)
    assert incident is not None
    assert incident.id is not None
    assert incident.incident_code.startswith("INC-")
    assert alert.incident_id == incident.id
    assert incident.primary_indicator == unique_ioc
    assert incident.status == IncidentStatus.OPEN.value


# -------------------------------------------------------------
# Test 9: Existing Incident Reuse
# -------------------------------------------------------------
def test_existing_incident_reuse(db_session):
    now = datetime.utcnow()
    shared_ioc = f"shared-{uuid.uuid4().hex[:8]}.com"

    alert1 = Alert(
        alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
        title=f"Alert 1 on {shared_ioc}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=shared_ioc,
        source="FeedX",
        created_at=now
    )
    db_session.add(alert1)
    db_session.commit()

    inc1 = correlate_alert_to_incident(db_session, alert1)

    # Second alert arriving 2 minutes later
    alert2 = Alert(
        alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
        title=f"Alert 2 on {shared_ioc}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=shared_ioc,
        source="FeedX",
        created_at=now + timedelta(minutes=2)
    )
    db_session.add(alert2)
    db_session.commit()

    inc2 = correlate_alert_to_incident(db_session, alert2)

    assert inc1.id == inc2.id
    assert alert2.incident_id == inc1.id


# -------------------------------------------------------------
# Test 10: Multiple Alerts Attach to One Incident
# -------------------------------------------------------------
def test_multiple_alerts_attach_to_one_incident(db_session):
    now = datetime.utcnow()
    campaign_ioc = f"c2-cluster-{uuid.uuid4().hex[:6]}.ru"

    alerts = []
    for i in range(3):
        a = Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
            title=f"C2 Cluster Sighting #{i+1}",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.NEW.value,
            indicator_value=campaign_ioc,
            source="ThreatFeed",
            created_at=now + timedelta(minutes=i)
        )
        db_session.add(a)
        db_session.commit()
        alerts.append(a)

    incident = None
    for a in alerts:
        incident = correlate_alert_to_incident(db_session, a)

    db_session.refresh(incident)
    attached_count = db_session.query(Alert).filter(Alert.incident_id == incident.id).count()
    assert attached_count == 3


# -------------------------------------------------------------
# Test 11: Incident Severity Propagation (Deterministic Rules)
# -------------------------------------------------------------
def test_incident_severity_propagation(db_session):
    # Rule: 2 HIGH alerts escalate incident to CRITICAL
    alert1 = Alert(
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value="sev-test.com"
    )
    alert2 = Alert(
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value="sev-test.com"
    )
    sev = derive_incident_severity(IncidentSeverity.HIGH.value, [alert1, alert2])
    assert sev == IncidentSeverity.CRITICAL.value

    # Rule: Any CRITICAL alert elevates incident to CRITICAL
    alert_crit = Alert(
        severity=AlertSeverity.CRITICAL.value,
        status=AlertStatus.NEW.value,
        indicator_value="sev-crit.com"
    )
    sev_crit = derive_incident_severity(IncidentSeverity.MEDIUM.value, [alert_crit])
    assert sev_crit == IncidentSeverity.CRITICAL.value

    # Rule: Never downgrade automatically
    alert_low = Alert(
        severity=AlertSeverity.LOW.value,
        status=AlertStatus.NEW.value,
        indicator_value="sev-crit.com"
    )
    sev_no_downgrade = derive_incident_severity(IncidentSeverity.CRITICAL.value, [alert_low])
    assert sev_no_downgrade == IncidentSeverity.CRITICAL.value


# -------------------------------------------------------------
# Test 12: Incident Status Transitions
# -------------------------------------------------------------
def test_incident_status_transitions(db_session):
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Lifecycle Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value
    )
    db_session.add(inc)
    db_session.commit()

    # OPEN -> ACKNOWLEDGED
    update_incident_status(db_session, inc.id, IncidentStatus.ACKNOWLEDGED.value, actor="Analyst 1")
    db_session.refresh(inc)
    assert inc.status == IncidentStatus.ACKNOWLEDGED.value

    # ACKNOWLEDGED -> IN_PROGRESS
    update_incident_status(db_session, inc.id, IncidentStatus.IN_PROGRESS.value, actor="Analyst 1")
    db_session.refresh(inc)
    assert inc.status == IncidentStatus.IN_PROGRESS.value

    # IN_PROGRESS -> RESOLVED
    update_incident_status(db_session, inc.id, IncidentStatus.RESOLVED.value, actor="Analyst 1")
    db_session.refresh(inc)
    assert inc.status == IncidentStatus.RESOLVED.value

    # RESOLVED -> CLOSED
    update_incident_status(db_session, inc.id, IncidentStatus.CLOSED.value, actor="Lead Analyst")
    db_session.refresh(inc)
    assert inc.status == IncidentStatus.CLOSED.value


# -------------------------------------------------------------
# Test 13: Invalid Status Transition Rejected
# -------------------------------------------------------------
def test_invalid_status_transition_rejected(db_session):
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Invalid State Transition Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.CLOSED.value
    )
    db_session.add(inc)
    db_session.commit()

    # Cannot transition directly from CLOSED to IN_PROGRESS (must be OPEN first)
    with pytest.raises(ValueError) as exc:
        update_incident_status(db_session, inc.id, IncidentStatus.IN_PROGRESS.value, actor="Analyst")
    assert "Invalid status transition" in str(exc.value)


# -------------------------------------------------------------
# Test 14: Incident Timeline Contains Real Events
# -------------------------------------------------------------
def test_incident_timeline_contains_real_events(db_session):
    now = datetime.utcnow()
    ioc = f"timeline-{uuid.uuid4().hex[:6]}.com"
    alert = Alert(
        alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
        title=f"Alert on {ioc}",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_value=ioc,
        created_at=now
    )
    db_session.add(alert)
    db_session.commit()

    incident = correlate_alert_to_incident(db_session, alert)
    update_incident_status(db_session, incident.id, IncidentStatus.ACKNOWLEDGED.value, actor="SOC Lead", note="Investigating")

    timeline_entries = db_session.query(IncidentTimeline).filter(IncidentTimeline.incident_id == incident.id).all()
    actions = [t.action for t in timeline_entries]

    assert any("INCIDENT_CREATED" in a for a in actions)
    assert any("STATUS_CHANGED" in a for a in actions)
    assert all(t.created_at is not None for t in timeline_entries)


# -------------------------------------------------------------
# Test 15: Redis INCIDENT_CREATED Event
# -------------------------------------------------------------
def test_redis_incident_created_event(db_session):
    received_events = []

    def subscriber(channel, event_data):
        received_events.append(event_data)

    redis_manager.register_local_subscriber(subscriber)

    try:
        now = datetime.utcnow()
        ioc = f"redis-create-{uuid.uuid4().hex[:6]}.com"

        alert1 = Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
            title=f"Alert 1 for {ioc}",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.NEW.value,
            indicator_value=ioc,
            created_at=now
        )
        db_session.add(alert1)
        db_session.commit()
        inc = correlate_alert_to_incident(db_session, alert1)

        created_event = next((e for e in received_events if e.get("type") == "INCIDENT_CREATED"), None)
        assert created_event is not None
        assert created_event["data"]["incident_code"] == inc.incident_code
        assert created_event["data"]["severity"] == IncidentSeverity.HIGH.value
        assert "threatlens:events:incidents" in created_event["channel"]

    finally:
        redis_manager.unregister_local_subscriber(subscriber)


# -------------------------------------------------------------
# Test 16: Redis INCIDENT_UPDATED Event
# -------------------------------------------------------------
def test_redis_incident_updated_event(db_session):
    received_events = []

    def subscriber(channel, event_data):
        received_events.append(event_data)

    redis_manager.register_local_subscriber(subscriber)

    try:
        now = datetime.utcnow()
        ioc = f"redis-update-{uuid.uuid4().hex[:6]}.com"

        alert1 = Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
            title=f"Alert 1 for {ioc}",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.NEW.value,
            indicator_value=ioc,
            created_at=now
        )
        db_session.add(alert1)
        db_session.commit()
        inc = correlate_alert_to_incident(db_session, alert1)

        alert2 = Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
            title=f"Alert 2 for {ioc}",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.NEW.value,
            indicator_value=ioc,
            created_at=now + timedelta(minutes=1)
        )
        db_session.add(alert2)
        db_session.commit()
        correlate_alert_to_incident(db_session, alert2)

        updated_event = next((e for e in received_events if e.get("type") in ["INCIDENT_UPDATED", "INCIDENT_SEVERITY_CHANGED"]), None)
        assert updated_event is not None
        assert updated_event["data"]["incident_code"] == inc.incident_code

    finally:
        redis_manager.unregister_local_subscriber(subscriber)


# -------------------------------------------------------------
# Test 17: RBAC Enforcement on Incident Updates
# -------------------------------------------------------------
def test_rbac_enforcement_on_incidents(db_session, analyst_headers, viewer_headers):
    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="RBAC Test Incident",
        severity=IncidentSeverity.HIGH.value,
        status=IncidentStatus.OPEN.value
    )
    db_session.add(inc)
    db_session.commit()

    # Viewer cannot PATCH incident status (Analyst+ required) -> 403
    res_viewer = client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={"status": IncidentStatus.ACKNOWLEDGED.value},
        headers={"Authorization": viewer_headers["Authorization"]}
    )
    assert res_viewer.status_code == 403

    # Analyst can PATCH incident status -> 200
    res_analyst = client.patch(
        f"/api/v1/incidents/{inc.id}/status",
        json={"status": IncidentStatus.ACKNOWLEDGED.value},
        headers={"Authorization": analyst_headers["Authorization"]}
    )
    assert res_analyst.status_code == 200
    assert res_analyst.json()["status"] == IncidentStatus.ACKNOWLEDGED.value


# -------------------------------------------------------------
# Test 18: Unauthorized Incident Access Rejected
# -------------------------------------------------------------
def test_unauthorized_incident_access_rejected(db_session):
    res = client.get("/api/v1/incidents")
    assert res.status_code == 401

    res_single = client.get("/api/v1/incidents/some-id")
    assert res_single.status_code == 401


# -------------------------------------------------------------
# Test 19: No Duplicate Incidents Under Repeated Alert Ingestion
# -------------------------------------------------------------
def test_no_duplicate_incidents_under_repeated_alerts(db_session):
    now = datetime.utcnow()
    ioc = f"dedup-test-{uuid.uuid4().hex[:6]}.org"

    incidents_before = db_session.query(Incident).count()

    # Ingest 3 identical/correlated alerts
    for i in range(3):
        a = Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:6].upper()}",
            title=f"Burst Sighting {i}",
            severity=AlertSeverity.HIGH.value,
            status=AlertStatus.NEW.value,
            indicator_value=ioc,
            created_at=now + timedelta(seconds=i*10)
        )
        db_session.add(a)
        db_session.commit()
        correlate_alert_to_incident(db_session, a)

    incidents_after = db_session.query(Incident).count()
    # Exactly ONE new incident created for this cluster
    assert incidents_after == incidents_before + 1


# -------------------------------------------------------------
# Test 20: Full End-to-End Pipeline
# IOC -> ALERT -> CORRELATION -> INCIDENT -> DATABASE -> AUDIT -> REDIS
# -------------------------------------------------------------
def test_full_end_to_end_phase4a_pipeline(db_session, analyst_headers):
    received_events = []

    def subscriber(channel, event_data):
        received_events.append(event_data)

    redis_manager.register_local_subscriber(subscriber)

    try:
        ioc_val = f"e2e-c2-{uuid.uuid4().hex[:8]}.threatnet.io"

        # 1. Ingest IOC with high threat score
        indicator = Indicator(
            value=ioc_val,
            type=IndicatorType.DOMAIN.value,
            threat_score=88,
            severity=ThreatSeverity.CRITICAL.value,
            confidence=95,
            source="ThreatFeed-Live",
            status=IndicatorStatus.ACTIVE.value,
            mitre_technique="T1071"
        )
        db_session.add(indicator)
        db_session.commit()
        db_session.refresh(indicator)

        # 2. Trigger Alert Evaluation (which internally invokes Phase 4A Correlation Engine)
        alert = evaluate_ioc_for_alerts(db_session, indicator)
        assert alert is not None
        assert alert.incident_id is not None

        # 3. Verify Database Incident State
        incident = db_session.query(Incident).filter(Incident.id == alert.incident_id).first()
        assert incident is not None
        assert incident.primary_indicator == ioc_val
        assert incident.status == IncidentStatus.OPEN.value
        assert incident.severity == IncidentSeverity.CRITICAL.value

        # 4. Verify Database Timeline
        timeline = db_session.query(IncidentTimeline).filter(IncidentTimeline.incident_id == incident.id).all()
        assert len(timeline) >= 1
        assert timeline[0].action == "INCIDENT_CREATED"

        # 5. Verify Immutable Audit Log
        audit_entry = db_session.query(AuditLog).filter(
            AuditLog.target_resource == f"incident:{incident.id}"
        ).first()
        assert audit_entry is not None
        assert audit_entry.action == "INCIDENT_CREATED"

        # 6. Verify Redis Incident Event Received
        inc_event = next((e for e in received_events if e.get("type") == "INCIDENT_CREATED"), None)
        assert inc_event is not None
        assert inc_event["data"]["incident_id"] == str(incident.id)
        assert inc_event["data"]["primary_indicator"] == ioc_val

        # 7. Verify API Retrieval via Analyst Token
        res = client.get(f"/api/v1/incidents/{incident.id}", headers={"Authorization": analyst_headers["Authorization"]})
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == str(incident.id)
        assert data["incident_code"] == incident.incident_code
        assert data["alerts_count"] >= 1

    finally:
        redis_manager.unregister_local_subscriber(subscriber)
