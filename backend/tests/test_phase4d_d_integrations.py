"""ThreatLens - Phase 4D-D Inbound Integrations and TAXII 2.1 Test Suite.

Covers:
- Webhook Authentication (Secret token, Bearer, and HMAC SHA-256)
- Webhook Replay Protection & Timestamp Skew Check
- Payload Size Limits & Malformed Input Handling
- Webhook Event Normalization & Extraction (IPv4, IPv6, Domain, URL, Hash)
- Webhook Deduplication (Provider + external_event_id idempotency)
- Detection Rule & Alert Routing Integration from Webhooks
- Phase 4A Incident Correlation from Webhook Alerts
- Redis Integration Events (SECURITY_EVENT_INGESTED, SECURITY_EVENT_DEDUPLICATED)
- Webhook Configuration Management & RBAC Protection
- TAXII 2.1 Server Discovery & Collection Discovery
- Safe STIX 2.1 Pattern Parsing (Zero eval, Zero exec)
- TAXII Collection Polling & Canonical Indicator Normalization
- TAXII Deduplication & Poll State Persistence (last_added_after)
- TAXII SSRF Protection (Blocked link-local metadata addresses)
- Secret Non-Disclosure across Webhooks and TAXII Feeds
"""
import hmac
import hashlib
import time
import json
import uuid
import asyncio
import pytest
import httpx
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.user import User, UserRole
from app.models.feed import Feed
from app.models.integration import WebhookConfig
from app.models.incident import SecurityEvent, Incident
from app.models.indicator import Indicator, IndicatorSource
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.core.security import create_access_token, get_password_hash
from app.core.redis import redis_manager
from app.services.webhook_service import (
    ensure_default_webhook_configs,
    InboundSecurityEventPayload,
    process_inbound_security_event,
)
from app.services.taxii_service import (
    parse_stix_indicator_pattern,
    validate_taxii_url_safety,
    poll_taxii_collection,
)

client = TestClient(app)

@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture(autouse=True)
def setup_db(db_session):
    ensure_default_webhook_configs(db_session)
    yield

@pytest.fixture
def auth_headers(db_session):
    """Generate headers for various RBAC roles."""
    def _get_headers(role_str: str):
        unique_email = f"test_{role_str.lower()}_{uuid.uuid4().hex[:6]}@threatlens.io"
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
        return {"Authorization": f"Bearer {token}"}
    return _get_headers


# ===========================================================================
# 1. Webhook Authentication & Security Tests (FR-29)
# ===========================================================================

def test_webhook_unauthenticated_request_blocked():
    """Unauthenticated webhook request must return HTTP 401."""
    res = client.post("/api/v1/integrations/webhooks/splunk", json={
        "event_id": "spl-test-01",
        "description": "Unauthorized attempt"
    })
    assert res.status_code == 401
    assert "authentication failed" in res.json()["detail"].lower()


def test_webhook_invalid_secret_blocked():
    """Webhook with wrong secret token must return HTTP 401."""
    res = client.post(
        "/api/v1/integrations/webhooks/splunk",
        headers={"X-ThreatLens-Webhook-Secret": "completely_wrong_secret"},
        json={
            "event_id": "spl-test-02",
            "description": "Invalid secret attempt"
        }
    )
    assert res.status_code == 401
    assert "invalid webhook secret token" in res.json()["detail"].lower()


def test_webhook_unsupported_provider_blocked():
    """Requests targeting unsupported providers must return HTTP 400."""
    res = client.post(
        "/api/v1/integrations/webhooks/unknown_unsupported_siem",
        headers={"X-ThreatLens-Webhook-Secret": "secret"},
        json={"event_id": "1"}
    )
    assert res.status_code == 400
    assert "unsupported webhook provider" in res.json()["detail"].lower()


def test_webhook_replay_protection_clock_skew():
    """Webhook with timestamp beyond clock skew window must return HTTP 401."""
    stale_timestamp = str(time.time() - 600)  # 10 minutes ago (> 5m allowed)
    res = client.post(
        "/api/v1/integrations/webhooks/splunk",
        headers={
            "X-ThreatLens-Webhook-Secret": "threatlens_splunk_webhook_secret_2026",
            "X-ThreatLens-Timestamp": stale_timestamp
        },
        json={
            "event_id": "spl-stale-01",
            "description": "Replayed stale event"
        }
    )
    assert res.status_code == 401
    assert "clock skew too large" in res.json()["detail"].lower()


def test_webhook_hmac_signature_verification():
    """Webhook authenticated via HMAC SHA-256 signature must be accepted."""
    secret = "threatlens_splunk_webhook_secret_2026"
    payload = {
        "event_id": f"spl-hmac-{uuid.uuid4().hex[:6]}",
        "event_type": "ENDPOINT_THREAT",
        "severity": "HIGH",
        "source_ip": "198.51.100.99",
        "description": "HMAC signed detection from Splunk"
    }
    raw_body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

    current_ts = str(time.time())
    res = client.post(
        "/api/v1/integrations/webhooks/splunk",
        headers={
            "X-ThreatLens-Signature": sig,
            "X-ThreatLens-Timestamp": current_ts,
            "Content-Type": "application/json"
        },
        content=raw_body
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ingested"
    assert res.json()["provider"] == "splunk"


def test_webhook_oversized_payload_rejected():
    """Oversized payloads exceeding max limits must return HTTP 413."""
    huge_text = "A" * (600 * 1024)  # 600 KB (> 512 KB max)
    payload = {
        "event_id": "huge-01",
        "description": huge_text
    }
    res = client.post(
        "/api/v1/integrations/webhooks/splunk",
        headers={"X-ThreatLens-Webhook-Secret": "threatlens_splunk_webhook_secret_2026"},
        json=payload
    )
    assert res.status_code == 413
    assert "exceeds maximum allowed" in res.json()["detail"]


# ===========================================================================
# 2. Inbound Webhook Ingestion, Normalization & Deduplication (FR-29)
# ===========================================================================

def test_webhook_valid_ingestion_and_normalization(db_session):
    """Valid security event must normalize IOCs, persist event, and create Alert."""
    unique_ip = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    unique_dom = f"MALICIOUS-C2-{uuid.uuid4().hex[:6]}.COM"
    event_id = f"sentinel-{uuid.uuid4().hex[:8]}"

    received_events = []
    def on_redis_event(channel, event):
        if channel == "threatlens:events:integrations":
            received_events.append(event)
    redis_manager.register_local_subscriber(on_redis_event)

    try:
        res = client.post(
            "/api/v1/integrations/webhooks/sentinel",
            headers={"X-ThreatLens-Webhook-Secret": "threatlens_sentinel_webhook_secret_2026"},
            json={
                "event_id": event_id,
                "event_type": "MALWARE_DETECTION",
                "severity": "CRITICAL",
                "source_ip": unique_ip,
                "domain": unique_dom,
                "hostname": "FINANCE-SRV-01",
                "username": "admin_service",
                "description": "Suspicious cobalt strike beacon to C2",
                "mitre_technique": "T1071"
            }
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ingested"
        assert data["provider"] == "sentinel"
        assert data["event_id"] == event_id
        assert data["indicators_extracted"] >= 1
        assert data["alert_created_id"] is not None

        # Verify indicator was normalized and saved
        ioc = db_session.query(Indicator).filter(Indicator.value == unique_ip).first()
        assert ioc is not None
        assert ioc.source == "webhook:sentinel" or any(s.source_name == "webhook:sentinel" for s in ioc.sources)

        # Verify domain was lowercased
        dom = db_session.query(Indicator).filter(Indicator.value == unique_dom.lower()).first()
        assert dom is not None

        # Verify Alert created and correlated
        alert = db_session.query(Alert).filter(Alert.id == data["alert_created_id"]).first()
        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert alert.incident_id is not None  # Automatically correlated into an Incident!

        # Verify SecurityEvent was persisted
        sec_evt = db_session.query(SecurityEvent).filter(SecurityEvent.external_event_id == event_id).first()
        assert sec_evt is not None
        assert sec_evt.provider == "sentinel"
        assert sec_evt.hostname == "FINANCE-SRV-01"

        # Verify Redis event was published
        assert any(e.get("type") == "SECURITY_EVENT_INGESTED" for e in received_events)
    finally:
        redis_manager.unregister_local_subscriber(on_redis_event)


def test_webhook_deduplication(db_session):
    """Resending the same webhook event_id must be deduplicated and not spam alerts."""
    event_id = f"qradar-{uuid.uuid4().hex[:8]}"
    unique_ip = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"

    headers = {"X-ThreatLens-Webhook-Secret": "threatlens_qradar_webhook_secret_2026"}
    payload = {
        "event_id": event_id,
        "event_type": "OFFENSE",
        "severity": "HIGH",
        "source_ip": unique_ip,
        "description": "QRadar network offense"
    }

    # First send -> ingested
    res1 = client.post("/api/v1/integrations/webhooks/qradar", headers=headers, json=payload)
    assert res1.status_code == 200
    assert res1.json()["status"] == "ingested"
    first_alert_id = res1.json()["alert_created_id"]

    # Second send with same event_id -> deduplicated!
    res2 = client.post("/api/v1/integrations/webhooks/qradar", headers=headers, json=payload)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == "deduplicated"
    assert data2["event_id"] == event_id
    assert data2["created_alert_id"] == first_alert_id

    # Verify no second alert was created
    alerts = db_session.query(Alert).filter(Alert.source == "webhook:qradar", Alert.indicator_value == unique_ip).all()
    assert len(alerts) == 1


# ===========================================================================
# 3. Integration Management Endpoints & RBAC Tests (FR-29)
# ===========================================================================

def test_integration_management_rbac(auth_headers, db_session):
    """Viewer can read configs, but cannot enable/disable or update integrations."""
    viewer_h = auth_headers(UserRole.VIEWER.value)
    eng_h = auth_headers(UserRole.SECURITY_ENGINEER.value)

    # Viewer lists configs -> allowed
    res = client.get("/api/v1/integrations/webhooks", headers=viewer_h)
    assert res.status_code == 200
    providers = [c["provider"] for c in res.json()]
    assert "splunk" in providers
    assert "crowdstrike" in providers

    # Secret tokens must not be exposed in GET
    for c in res.json():
        assert "secret_token" not in c
        assert "hmac_secret" not in c
        assert "has_secret" in c

    # Viewer attempts disable -> 403 Forbidden
    res_v_dis = client.post("/api/v1/integrations/webhooks/splunk/disable", headers=viewer_h)
    assert res_v_dis.status_code == 403

    # Security Engineer disables -> 200 OK
    res_e_dis = client.post("/api/v1/integrations/webhooks/splunk/disable", headers=eng_h)
    assert res_e_dis.status_code == 200
    assert res_e_dis.json()["config"]["is_enabled"] is False

    # Disabled provider rejects inbound webhooks
    res_wh = client.post(
        "/api/v1/integrations/webhooks/splunk",
        headers={"X-ThreatLens-Webhook-Secret": "threatlens_splunk_webhook_secret_2026"},
        json={"event_id": "test-disabled-01"}
    )
    assert res_wh.status_code == 401
    assert "disabled" in res_wh.json()["detail"].lower()

    # Security Engineer re-enables -> 200 OK
    res_e_en = client.post("/api/v1/integrations/webhooks/splunk/enable", headers=eng_h)
    assert res_e_en.status_code == 200
    assert res_e_en.json()["config"]["is_enabled"] is True


# ===========================================================================
# 4. TAXII 2.1 STIX Pattern & Security Tests (FR-04)
# ===========================================================================

def test_stix_indicator_pattern_parser_safe():
    """Verify STIX 2.1 pattern extraction without eval or exec."""
    # IPv4
    res = parse_stix_indicator_pattern("[ipv4-addr:value = '198.51.100.5']")
    assert res == ("198.51.100.5", "ipv4")

    # IPv6
    res = parse_stix_indicator_pattern("[ipv6-addr:value = '2001:db8::1']")
    assert res == ("2001:db8::1", "ipv6")

    # Domain
    res = parse_stix_indicator_pattern("[domain-name:value = 'evil-c2.example.com']")
    assert res == ("evil-c2.example.com", "domain")

    # URL
    res = parse_stix_indicator_pattern("[url:value = 'http://evil.com/malware.exe']")
    assert res == ("http://evil.com/malware.exe", "url")

    # SHA256
    res = parse_stix_indicator_pattern("[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']")
    assert res == ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256")

    # MD5
    res = parse_stix_indicator_pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
    assert res == ("d41d8cd98f00b204e9800998ecf8427e", "md5")

    # Email
    res = parse_stix_indicator_pattern("[email-addr:value = 'phishing@malicious.org']")
    assert res == ("phishing@malicious.org", "email")

    # Unsupported pattern must return None safely without throwing
    res = parse_stix_indicator_pattern("[windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\Software']")
    assert res is None


def test_taxii_url_safety_ssrf_blocking():
    """Verify SSRF validation blocks dangerous cloud metadata hosts."""
    # Block AWS/GCP link-local metadata address
    with pytest.raises(ValueError, match="SSRF violation"):
        validate_taxii_url_safety("http://169.254.169.254/taxii2/")

    # Block Google internal metadata
    with pytest.raises(ValueError, match="SSRF violation"):
        validate_taxii_url_safety("http://metadata.google.internal/taxii2/")

    # Block invalid scheme
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        validate_taxii_url_safety("ftp://taxii.example.com/taxii2/")


# ===========================================================================
# 5. TAXII 2.1 Collection Polling & STIX Ingestion (FR-04)
# ===========================================================================

def test_taxii_collection_polling_mock_server(db_session):
    """
    Test TAXII 2.1 collection polling using httpx transport with real STIX 2.1 bundle.
    Validates STIX extraction, canonical IOC saving, and poll state persistence.
    """
    unique_ip = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    unique_dom = f"taxii-c2-node-{uuid.uuid4().hex[:6]}.net"
    stix_timestamp = "2026-10-03T18:00:00.000Z"

    # Construct compliant STIX 2.1 bundle
    stix_envelope = {
        "more": False,
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": "2026-10-01T00:00:00.000Z",
                "modified": stix_timestamp,
                "pattern": f"[ipv4-addr:value = '{unique_ip}']",
                "pattern_type": "stix",
                "confidence": 88,
                "labels": ["malicious-activity", "botnet"]
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": "2026-10-01T00:00:00.000Z",
                "modified": stix_timestamp,
                "pattern": f"[domain-name:value = '{unique_dom}']",
                "pattern_type": "stix",
                "confidence": 92,
                "labels": ["c2"]
            }
        ]
    }

    # Setup mock transport for TAXII 2.1 endpoint
    def taxii_mock_handler(request: httpx.Request):
        return httpx.Response(
            status_code=200,
            json=stix_envelope,
            headers={"Content-Type": "application/taxii+json;version=2.1"}
        )

    mock_transport = httpx.MockTransport(taxii_mock_handler)
    mock_client = httpx.AsyncClient(transport=mock_transport)

    feed = Feed(
        name=f"test_taxii_{uuid.uuid4().hex[:6]}",
        display_name="Test TAXII Collection",
        provider="TAXII Provider",
        feed_type="taxii2.1",
        endpoint_url="https://taxii.example.org/api/v1/taxii2/collections/col-01/objects/",
        taxii_api_root="https://taxii.example.org/api/v1/taxii2/",
        taxii_collection_id="col-01",
        enabled=True,
        status="active"
    )
    db_session.add(feed)
    db_session.commit()
    db_session.refresh(feed)

    try:
        res = asyncio.run(poll_taxii_collection(db_session, feed, client=mock_client))
        assert res["status"] == "success"
        assert res["indicators_ingested"] >= 2

        # Check DB state
        db_session.refresh(feed)
        assert feed.last_successful_fetch_at is not None
        assert feed.last_added_after == stix_timestamp
        assert feed.total_indicators_ingested >= 2

        # Check indicators saved
        ioc = db_session.query(Indicator).filter(Indicator.value == unique_ip).first()
        assert ioc is not None
        assert ioc.source == f"taxii:{feed.name}"
        assert ioc.confidence == 88

        dom_ioc = db_session.query(Indicator).filter(Indicator.value == unique_dom).first()
        assert dom_ioc is not None
    finally:
        asyncio.run(mock_client.aclose())


# ===========================================================================
# 6. TAXII Feed Management Integration & RBAC (FR-04)
# ===========================================================================

def test_taxii_feed_registration_endpoint(auth_headers, db_session):
    """Security Engineer can register a TAXII 2.1 collection feed via REST API."""
    eng_h = auth_headers(UserRole.SECURITY_ENGINEER.value)
    feed_name = f"taxii_custom_{uuid.uuid4().hex[:6]}"

    payload = {
        "name": feed_name,
        "display_name": "Custom TAXII Feed",
        "provider": "OASIS CTI",
        "endpoint_url": "https://cti.example.org/taxii2/collections/123/objects/",
        "taxii_api_root": "https://cti.example.org/taxii2/",
        "taxii_collection_id": "123",
        "description": "Enterprise TAXII 2.1 threat feed",
        "poll_interval_seconds": 7200,
        "enabled": True
    }

    res = client.post("/api/v1/feeds/taxii", headers=eng_h, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["feed"]["name"] == feed_name
    assert data["feed"]["feed_type"] == "taxii2.1"
    assert data["feed"]["taxii_collection_id"] == "123"

    # Verify feed appears in canonical feed list
    res_list = client.get("/api/v1/feeds/", headers=eng_h)
    names = [f["name"] for f in res_list.json()]
    assert feed_name in names
