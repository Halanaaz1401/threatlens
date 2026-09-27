import pytest
import uuid
import json
import asyncio
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus, IndicatorSource
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.audit import AuditLog
from app.models.user import User, UserRole
from app.core.security import create_access_token, get_password_hash
from app.core.config import settings
from app.core.redis import redis_manager
from app.core.websocket import ws_manager
from app.services.feed_service import _save_and_index_ioc
from app.services.alert_service import evaluate_ioc_for_alerts

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
def auth_headers(db_session):
    """Generates an authenticated user and bearer token."""
    email = f"telemetry_analyst_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Telemetry Test Analyst",
        role=UserRole.ANALYST.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email, "role": user.role, "user_id": str(user.id)})
    return {"Authorization": f"Bearer {token}", "token": token, "user": user}

# -------------------------------------------------------------
# Test 1: Ingestion Normalization, Persistence & Provenance
# -------------------------------------------------------------
def test_save_and_index_ioc_persistence_and_provenance(db_session):
    """
    Test 3B.1-3B.8: Normalized ingestion creates Indicator and IndicatorSource provenance.
    Subsequent sightings update sightings count and append to provenance without duplicating.
    """
    test_val = f"198.51.100.{uuid.uuid4().hex[:3]}"
    
    # First sighting
    res1 = _save_and_index_ioc(
        db=db_session,
        value=test_val,
        ioc_type=IndicatorType.IP,
        source="feodo_tracker",
        confidence=95,
        tags=["botnet", "c2"],
        mitre_technique="T1071.001"
    )
    assert res1 == "created"

    ioc = db_session.query(Indicator).filter(Indicator.value == test_val).first()
    assert ioc is not None
    assert ioc.sightings == 1
    assert ioc.threat_score >= 80
    assert ioc.severity in ["HIGH", "CRITICAL"]

    # Verify provenance row
    prov_rows = db_session.query(IndicatorSource).filter(IndicatorSource.indicator_id == ioc.id).all()
    assert len(prov_rows) == 1
    assert prov_rows[0].source_name == "feodo_tracker"
    assert prov_rows[0].confidence == 95

    # Second sighting from a different source
    res2 = _save_and_index_ioc(
        db=db_session,
        value=test_val,
        ioc_type=IndicatorType.IP,
        source="threatfox",
        confidence=85,
        tags=["botnet", "c2"]
    )
    assert res2 == "updated"

    db_session.refresh(ioc)
    assert ioc.sightings == 2

    # Verify second provenance sighting appended
    prov_rows_after = db_session.query(IndicatorSource).filter(IndicatorSource.indicator_id == ioc.id).all()
    assert len(prov_rows_after) == 2
    sources = {p.source_name for p in prov_rows_after}
    assert "feodo_tracker" in sources
    assert "threatfox" in sources

# -------------------------------------------------------------
# Test 2: Invalid Feed Record Resilience
# -------------------------------------------------------------
def test_invalid_feed_record_handling(db_session):
    """
    Test 3B.9-3B.11: Malformed or empty records are safely rejected without crashing ingestion.
    """
    assert _save_and_index_ioc(db_session, "", IndicatorType.IP, "test", 80) == "invalid"
    assert _save_and_index_ioc(db_session, "   ", IndicatorType.DOMAIN, "test", 80) == "invalid"
    assert _save_and_index_ioc(db_session, None, IndicatorType.URL, "test", 80) == "invalid"

# -------------------------------------------------------------
# Test 3: Alert Creation & Deduplication
# -------------------------------------------------------------
def test_alert_creation_and_deduplication(db_session):
    """
    Test 3C: Alert is generated for high-risk IOC, persisted in PostgreSQL,
    and deduplicated so re-evaluating the same IOC does not create spam alerts.
    """
    test_ip = f"203.0.113.{uuid.uuid4().hex[:3]}"
    ioc = Indicator(
        value=test_ip,
        type="ip",
        severity_score=95,
        threat_score=95,
        severity="CRITICAL",
        confidence=95,
        source="feodo_tracker",
        status="active"
    )
    db_session.add(ioc)
    db_session.commit()
    db_session.refresh(ioc)

    # First evaluation -> creates alert
    alert1 = evaluate_ioc_for_alerts(db_session, ioc)
    assert alert1 is not None
    assert alert1.indicator_value == test_ip
    assert alert1.severity == "CRITICAL"
    assert alert1.status.upper() == "NEW"
    assert alert1.alert_code.startswith("ALT-")

    # Verify Alert persisted in DB
    db_alert = db_session.query(Alert).filter(Alert.id == alert1.id).first()
    assert db_alert is not None
    assert db_alert.title == f"Threat Detected: {test_ip}"

    # Second evaluation on same IOC -> returns existing alert without duplicating
    alert2 = evaluate_ioc_for_alerts(db_session, ioc)
    assert alert2 is not None
    assert alert2.id == alert1.id

    # Count total alerts for this indicator
    total_alerts = db_session.query(Alert).filter(Alert.indicator_value == test_ip).count()
    assert total_alerts == 1

# -------------------------------------------------------------
# Test 4: Redis Event Publishing & Local Event Bus
# -------------------------------------------------------------
def test_redis_event_publishing_and_bus():
    """
    Test 3D: Events published to Redis channels are properly formatted
    and dispatched to registered subscriber callbacks.
    """
    received_events = []

    def mock_subscriber(channel: str, event_data: dict):
        received_events.append((channel, event_data))

    redis_manager.register_local_subscriber(mock_subscriber)
    try:
        test_payload = {
            "type": "NEW_ALERT",
            "event": "NEW_CRITICAL_ALERT",
            "data": {
                "id": str(uuid.uuid4()),
                "indicator": "198.51.100.99",
                "severity": "CRITICAL"
            }
        }
        res = redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, test_payload)
        assert res is True
        assert len(received_events) >= 1
        assert received_events[-1][0] == settings.REDIS_ALERT_CHANNEL
        assert received_events[-1][1]["type"] == "NEW_ALERT"
        assert received_events[-1][1]["data"]["indicator"] == "198.51.100.99"
    finally:
        redis_manager.unregister_local_subscriber(mock_subscriber)

# -------------------------------------------------------------
# Test 5: Redis Unavailable Resilience
# -------------------------------------------------------------
def test_redis_unavailable_resilience():
    """
    Test 3D.10: Safe execution when Redis is temporarily offline; does not raise unhandled exception.
    """
    res = redis_manager.publish_event("non_existent_channel", {"test": "data"})
    assert isinstance(res, bool)
    health = redis_manager.get_health()
    assert "status" in health

# -------------------------------------------------------------
# Test 6: WebSocket Authentication & Unauthorized Rejection
# -------------------------------------------------------------
def test_websocket_authentication_security(auth_headers):
    """
    Test 3E.1-3E.3: WebSocket endpoint rejects unauthenticated connections (code 1008)
    and allows valid authenticated bearer tokens.
    """
    # 1. Unauthenticated -> 1008 Policy Violation
    try:
        with client.websocket_connect("/api/v1/ws/alerts") as ws:
            pass
        pytest.fail("Unauthenticated WebSocket connection should be rejected")
    except Exception:
        pass  # Expected rejection

    # 2. Authenticated with valid token -> Accepted
    valid_token = auth_headers["token"]
    with client.websocket_connect(f"/api/v1/ws/alerts?token={valid_token}") as ws:
        assert ws is not None

# -------------------------------------------------------------
# Test 7: WebSocket Real Alert Event Delivery
# -------------------------------------------------------------
def test_websocket_real_alert_event_delivery(auth_headers):
    """
    Test 3E.5-3E.7: Authenticated WebSocket client receives real alert event dispatched via fan-out.
    """
    valid_token = auth_headers["token"]
    with client.websocket_connect(f"/api/v1/ws/alerts?token={valid_token}") as ws:
        # Fan out an alert event through ws_manager
        alert_event = {
            "type": "NEW_ALERT",
            "event": "NEW_CRITICAL_ALERT",
            "data": {
                "id": f"ALT-{uuid.uuid4().hex[:6]}",
                "title": "Threat Detected: 198.51.100.77",
                "severity": "CRITICAL",
                "status": "NEW",
                "indicator": "198.51.100.77",
                "type": "ip",
                "source": "ThreatFox",
                "threat_score": 92
            }
        }

        # Broadcast via WebSocket manager
        asyncio.run(ws_manager.broadcast_alert(alert_event))

        # Client receives message
        received = ws.receive_json()
        assert received["type"] == "NEW_ALERT"
        assert received["event"] == "NEW_CRITICAL_ALERT"
        assert received["data"]["indicator"] == "198.51.100.77"
        assert received["data"]["severity"] == "CRITICAL"

# -------------------------------------------------------------
# Test 8: End-to-End Pipeline (Ingestion -> Indicator -> Score -> Alert -> Redis -> WebSocket)
# -------------------------------------------------------------
def test_end_to_end_telemetry_pipeline(db_session, auth_headers):
    """
    Test 3H.13: Full end-to-end integration:
    Ingestion -> Indicator Persisted -> Sighting Scored -> Alert Generated ->
    PostgreSQL Record Created -> Redis Event Published -> WebSocket Client Receives Live Alert.
    """
    test_ioc_value = f"http://malware-drop-{uuid.uuid4().hex[:6]}.com/agent.exe"
    valid_token = auth_headers["token"]

    with client.websocket_connect(f"/api/v1/ws/alerts?token={valid_token}") as ws:
        # 1. Trigger ingestion of high-severity URL
        res = _save_and_index_ioc(
            db=db_session,
            value=test_ioc_value,
            ioc_type=IndicatorType.URL,
            source="urlhaus",
            confidence=95,
            tags=["malware", "stealer"],
            mitre_technique="T1566.002"
        )
        assert res == "created"

        # 2. Verify Indicator in DB
        db_ioc = db_session.query(Indicator).filter(Indicator.value == test_ioc_value).first()
        assert db_ioc is not None
        assert db_ioc.threat_score >= 80

        # 3. Verify Alert in DB
        db_alert = db_session.query(Alert).filter(Alert.indicator_value == test_ioc_value).first()
        assert db_alert is not None
        assert db_alert.severity in ["HIGH", "CRITICAL"]

        # 4. Verify WebSocket receives the real alert published by the pipeline
        received = ws.receive_json()
        assert received["type"] == "NEW_ALERT"
        assert received["data"]["indicator"] == test_ioc_value
        assert received["data"]["id"] == str(db_alert.id)
        assert received["data"]["source"] == "urlhaus"
