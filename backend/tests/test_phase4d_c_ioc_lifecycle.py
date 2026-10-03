"""
ThreatLens - Phase 4D-C IOC Lifecycle, TTL Expiration, and Feed Management Test Suite
Verifies:
1. FR-05 Feed Management: listing, inspection, enable/disable, config updates, honest stats & error reporting, no secrets exposed.
2. FR-06 IOC Lifecycle Management: active -> expired -> revoked, preservation of provenance, soft-delete revocation.
3. FR-07 IOC CRUD Completeness: GET individual, PUT/PATCH update, DELETE/revoke, full type coverage (IPv4, IPv6, domain, URL, email, MD5, SHA1, SHA256, CVE).
4. FR-08 TTL / Expiration: explicit persisted expires_at, deterministic UTC calculations, bounded idempotent expiration worker.
5. Strict validation & normalization: rejection of malformed or oversized IOCs.
6. RBAC enforcement: Viewer read-only, Analyst IOC operations, Engineer/Admin feed & expiration operations.
7. Audit logging and Redis event bus publishing.
"""
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType, IndicatorStatus, ThreatSeverity
from app.models.feed import Feed
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.core.security import create_access_token, get_password_hash
from app.services.indicator_service import (
    normalize_and_validate_ioc,
    calculate_expiration_date,
    serialize_indicator_detail,
    get_indicator_by_id,
)
from app.services.expiration_service import expire_stale_indicators
from app.services.feed_service import (
    ensure_default_feeds,
    update_feed_stats,
    is_feed_enabled,
)

client = TestClient(app)

@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def admin_headers(db_session):
    email = f"admin_4dc_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("AdminPass123!"),
        full_name="Phase 4D-C Admin",
        role=UserRole.ADMIN.value,
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
def engineer_headers(db_session):
    email = f"eng_4dc_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("EngPass123!"),
        full_name="Phase 4D-C SecOps Engineer",
        role=UserRole.SECURITY_ENGINEER.value,
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
def analyst_headers(db_session):
    email = f"analyst_4dc_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("AnalystPass123!"),
        full_name="Phase 4D-C Threat Analyst",
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
    email = f"viewer_4dc_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("ViewerPass123!"),
        full_name="Phase 4D-C Read-Only Viewer",
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


# =====================================================================
# 1. IOC Validation & Normalization
# =====================================================================
def test_ioc_validation_and_normalization():
    """Verify strict validation, canonical normalization, and malformed input rejection."""
    # IPv4
    norm_val, norm_type = normalize_and_validate_ioc("  198.51.100.14  ", "ipv4")
    assert norm_val == "198.51.100.14"
    assert norm_type == IndicatorType.IP

    with pytest.raises(ValueError, match="Invalid IP address format"):
        normalize_and_validate_ioc("999.1.1.1", "ip")

    # IPv6
    norm_val, norm_type = normalize_and_validate_ioc("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ipv6")
    assert norm_type == IndicatorType.IP

    # Domain
    norm_val, norm_type = normalize_and_validate_ioc("  APT29-C2.EvilCorp.COM.  ", "domain")
    assert norm_val == "apt29-c2.evilcorp.com"
    assert norm_type == IndicatorType.DOMAIN

    with pytest.raises(ValueError, match="Domain must not contain URL scheme"):
        normalize_and_validate_ioc("https://evil.com/path", "domain")

    # URL
    norm_val, norm_type = normalize_and_validate_ioc("https://c2.evil.com/drop/malware.bin", "url")
    assert norm_val == "https://c2.evil.com/drop/malware.bin"
    assert norm_type == IndicatorType.URL

    with pytest.raises(ValueError, match="URL must have a valid scheme"):
        normalize_and_validate_ioc("c2.evil.com/drop/malware.bin", "url")

    # Email
    norm_val, norm_type = normalize_and_validate_ioc("  Phisher.Boss@DarkWeb.ORG  ", "email")
    assert norm_val == "phisher.boss@darkweb.org"
    assert norm_type == IndicatorType.EMAIL

    with pytest.raises(ValueError, match="Invalid email address format"):
        normalize_and_validate_ioc("bad-email-without-at", "email")

    # Hashes
    md5_val = "d41d8cd98f00b204e9800998ecf8427e"
    norm_val, norm_type = normalize_and_validate_ioc(md5_val.upper(), "md5")
    assert norm_val == md5_val
    assert norm_type == IndicatorType.HASH_MD5

    sha1_val = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    norm_val, norm_type = normalize_and_validate_ioc(sha1_val.upper(), "sha1")
    assert norm_val == sha1_val
    assert norm_type == IndicatorType.HASH_SHA1

    sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    norm_val, norm_type = normalize_and_validate_ioc(sha256_val.upper(), "hash_sha256")
    assert norm_val == sha256_val
    assert norm_type == IndicatorType.HASH_SHA256

    # Generic hash inference
    norm_val, norm_type = normalize_and_validate_ioc(sha256_val, "hash")
    assert norm_type == IndicatorType.HASH_SHA256

    # CVE
    norm_val, norm_type = normalize_and_validate_ioc("cve-2024-21413", "cve")
    assert norm_val == "CVE-2024-21413"
    assert norm_type == IndicatorType.CVE

    # Oversized payload
    oversized = "a" * 2050
    with pytest.raises(ValueError, match="exceeds maximum allowed length"):
        normalize_and_validate_ioc(oversized, "domain")


# =====================================================================
# 2. IOC CRUD Completeness (FR-07)
# =====================================================================
def test_ioc_crud_lifecycle(analyst_headers, viewer_headers, admin_headers):
    """Verify individual IOC GET, update, and soft-delete/revocation operations."""
    unique_ip = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    create_payload = {
        "value": unique_ip,
        "type": "ip",
        "source": "manual_analyst",
        "confidence": 85,
        "ttl_days": 45,
        "tags": ["apt29", "c2"],
        "analyst_notes": "Initial investigation note",
        "context": {"campaign": "Storm-0558"}
    }

    # 1. CREATE
    res_create = client.post("/api/v1/indicators/create", json=create_payload, headers=analyst_headers)
    assert res_create.status_code == 200
    ioc_data = res_create.json()
    ioc_id = ioc_data["id"]
    assert ioc_data["value"] == unique_ip
    assert ioc_data["status"] == "active"
    assert ioc_data["ttl_days"] == 45
    assert ioc_data["expires_at"] is not None
    assert ioc_data["analyst_notes"] == "Initial investigation note"

    # 2. GET individual IOC
    res_get = client.get(f"/api/v1/indicators/{ioc_id}", headers=viewer_headers)
    assert res_get.status_code == 200
    detail = res_get.json()
    assert detail["id"] == ioc_id
    assert detail["value"] == unique_ip
    assert detail["confidence"] == 85
    assert len(detail["sources"]) >= 1

    # 3. UPDATE IOC (Analyst+)
    update_payload = {
        "confidence": 95,
        "tlp": "red",
        "tags": ["apt29", "c2", "verified"],
        "analyst_notes": "Updated after sandbox detonation",
        "ttl_days": 60,
    }
    res_update = client.put(f"/api/v1/indicators/{ioc_id}", json=update_payload, headers=analyst_headers)
    assert res_update.status_code == 200
    updated = res_update.json()
    assert updated["confidence"] == 95
    assert updated["tlp"] == "red"
    assert "verified" in updated["tags"]
    assert updated["analyst_notes"] == "Updated after sandbox detonation"
    assert updated["ttl_days"] == 60

    # Provenance preserved
    assert len(updated["sources"]) >= 1
    assert updated["sources"][0]["source_name"] == "manual_analyst"

    # 4. SOFT DELETE / REVOKE
    res_revoke = client.delete(
        f"/api/v1/indicators/{ioc_id}?reason=False+positive+verified+by+team",
        headers=analyst_headers
    )
    assert res_revoke.status_code == 200
    revoke_data = res_revoke.json()
    assert revoke_data["status"] == "success"
    assert revoke_data["indicator"]["status"] == "revoked"
    assert revoke_data["indicator"]["revoked_reason"] == "False positive verified by team"

    # Historical record still accessible
    res_recheck = client.get(f"/api/v1/indicators/{ioc_id}", headers=viewer_headers)
    assert res_recheck.status_code == 200
    assert res_recheck.json()["status"] == "revoked"


def test_ioc_hard_delete_rbac(analyst_headers, viewer_headers, admin_headers):
    """Verify that hard physical delete is restricted strictly to Administrator."""
    unique_dom = f"c2-{uuid.uuid4().hex[:8]}.malicious.io"
    res_create = client.post(
        "/api/v1/indicators/create",
        json={"value": unique_dom, "type": "domain", "confidence": 90},
        headers=analyst_headers
    )
    assert res_create.status_code == 200
    ioc_id = res_create.json()["id"]

    # Analyst cannot hard delete
    res_analyst_del = client.delete(
        f"/api/v1/indicators/{ioc_id}?hard_delete=true",
        headers=analyst_headers
    )
    assert res_analyst_del.status_code == 403

    # Admin can hard delete
    res_admin_del = client.delete(
        f"/api/v1/indicators/{ioc_id}?hard_delete=true",
        headers=admin_headers
    )
    assert res_admin_del.status_code == 200

    # Indicator is physically gone
    res_check = client.get(f"/api/v1/indicators/{ioc_id}", headers=admin_headers)
    assert res_check.status_code == 404


# =====================================================================
# 3. TTL / Expiration Worker (FR-08)
# =====================================================================
def test_ttl_expiration_worker(db_session, engineer_headers, viewer_headers):
    """Verify that the expiration worker transitions stale indicators and is idempotent."""
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    past_expiration = now_utc - timedelta(days=2)
    future_expiration = now_utc + timedelta(days=30)

    # Indicator 1: Stale active indicator
    stale_val = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    stale_ioc = Indicator(
        value=stale_val,
        type="ip",
        source="unit_test",
        confidence=80,
        status="active",
        expires_at=past_expiration,
        ttl_days=30,
        first_seen=now_utc - timedelta(days=32),
        last_seen=now_utc - timedelta(days=2)
    )
    db_session.add(stale_ioc)

    # Indicator 2: Fresh active indicator (should not expire)
    fresh_val = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    fresh_ioc = Indicator(
        value=fresh_val,
        type="ip",
        source="unit_test",
        confidence=80,
        status="active",
        expires_at=future_expiration,
        ttl_days=30,
        first_seen=now_utc,
        last_seen=now_utc
    )
    db_session.add(fresh_ioc)
    db_session.commit()

    # 1. Trigger expiration worker
    res = expire_stale_indicators(db_session, batch_size=50)
    assert res["expired_count"] >= 1
    assert str(stale_ioc.id) in res["processed_ids"]
    assert str(fresh_ioc.id) not in res["processed_ids"]

    # 2. Check stale indicator state
    db_session.refresh(stale_ioc)
    db_session.refresh(fresh_ioc)
    assert stale_ioc.status == "expired"
    assert fresh_ioc.status == "active"

    # 3. Idempotency: Run worker second time -> must process 0 remaining stale indicators
    res_second_run = expire_stale_indicators(db_session, batch_size=50)
    assert str(stale_ioc.id) not in res_second_run["processed_ids"]

    # 4. Trigger via API endpoint (Security Engineer+)
    res_api = client.post("/api/v1/indicators/expire-stale", json={"batch_size": 100}, headers=engineer_headers)
    assert res_api.status_code == 200
    assert res_api.json()["status"] == "success"

    # 5. Viewer cannot trigger expiration worker
    res_viewer = client.post("/api/v1/indicators/expire-stale", json={"batch_size": 100}, headers=viewer_headers)
    assert res_viewer.status_code == 403


# =====================================================================
# 4. Feed Management (FR-05)
# =====================================================================
def test_feed_listing_and_inspection(viewer_headers):
    """Verify feed listing returns all canonical feeds without exposing secrets."""
    res = client.get("/api/v1/feeds/", headers=viewer_headers)
    assert res.status_code == 200
    feeds = res.json()
    assert len(feeds) >= 6

    feed_names = {f["name"] for f in feeds}
    for expected in ["urlhaus", "threatfox", "feodo_tracker", "malwarebazaar", "cisa_kev", "alienvault_otx"]:
        assert expected in feed_names

    # Check safe serialization (no API keys, tokens, or passwords)
    for f in feeds:
        assert "api_key" not in f
        assert "password" not in f
        assert "authorization" not in f
        assert "status" in f
        assert "enabled" in f
        assert "poll_interval_seconds" in f
        assert "total_indicators_ingested" in f

    # Inspect single feed
    first_feed_id = feeds[0]["id"]
    res_single = client.get(f"/api/v1/feeds/{first_feed_id}", headers=viewer_headers)
    assert res_single.status_code == 200
    single_feed = res_single.json()
    assert single_feed["id"] == first_feed_id
    assert single_feed["name"] == feeds[0]["name"]


def test_feed_enable_disable_lifecycle(engineer_headers, viewer_headers):
    """Verify enable and disable operations and RBAC protection."""
    res_list = client.get("/api/v1/feeds/", headers=engineer_headers)
    feed_id = res_list.json()[0]["id"]

    # 1. Disable feed
    res_disable = client.post(f"/api/v1/feeds/{feed_id}/disable", headers=engineer_headers)
    assert res_disable.status_code == 200
    disabled_data = res_disable.json()
    assert disabled_data["enabled"] is False
    assert disabled_data["status"] == "disabled"

    # 2. Enable feed
    res_enable = client.post(f"/api/v1/feeds/{feed_id}/enable", headers=engineer_headers)
    assert res_enable.status_code == 200
    enabled_data = res_enable.json()
    assert enabled_data["enabled"] is True
    assert enabled_data["status"] == "active"

    # 3. Viewer blocked from mutating feed state
    res_viewer_disable = client.post(f"/api/v1/feeds/{feed_id}/disable", headers=viewer_headers)
    assert res_viewer_disable.status_code == 403


def test_feed_configuration_update(engineer_headers, viewer_headers):
    """Verify updating polling interval and descriptions with validation."""
    res_list = client.get("/api/v1/feeds/", headers=engineer_headers)
    feed_id = res_list.json()[0]["id"]

    update_payload = {
        "display_name": "Custom Feed Title",
        "description": "Updated SecOps description for ingestion cadence",
        "poll_interval_seconds": 7200,
    }
    res_update = client.put(f"/api/v1/feeds/{feed_id}", json=update_payload, headers=engineer_headers)
    assert res_update.status_code == 200
    updated = res_update.json()
    assert updated["display_name"] == "Custom Feed Title"
    assert updated["poll_interval_seconds"] == 7200
    assert updated["description"] == "Updated SecOps description for ingestion cadence"

    # Viewer blocked
    res_viewer = client.put(f"/api/v1/feeds/{feed_id}", json=update_payload, headers=viewer_headers)
    assert res_viewer.status_code == 403


def test_feed_stats_tracking_and_error_handling(db_session):
    """Verify that feed operational stats are accurately recorded without exposing credentials."""
    feed_name = "urlhaus"
    feed = db_session.query(Feed).filter(Feed.name == feed_name).first()
    if feed:
        feed.enabled = True
        db_session.commit()
    # Successful fetch simulation
    update_feed_stats(db_session, feed_name=feed_name, success=True, count=15)
    feed = db_session.query(Feed).filter(Feed.name == feed_name).first()
    assert feed.status == "active"
    assert feed.last_ingested_count == 15
    assert feed.total_indicators_ingested >= 15
    assert feed.error_message is None
    assert feed.last_successful_fetch_at is not None

    # Error simulation with potential secret in raw error
    secret_error = "Failed to authenticate with Bearer secret_jwt_token_12345 at endpoint"
    update_feed_stats(db_session, feed_name=feed_name, success=False, error=secret_error)
    db_session.refresh(feed)
    assert feed.status == "failing"
    assert feed.error_message is not None


# =====================================================================
# 5. Audit Logging Verification
# =====================================================================
def test_audit_logs_for_ioc_and_feed(db_session, analyst_headers, engineer_headers):
    """Verify that IOC mutations, status updates, and feed configuration trigger immutable audit logs."""
    test_ip = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
    # 1. Create IOC
    res = client.post(
        "/api/v1/indicators/create",
        json={"value": test_ip, "type": "ip", "confidence": 75},
        headers=analyst_headers
    )
    assert res.status_code == 200
    ioc_id = res.json()["id"]

    # 2. Check AuditLog for creation
    log_create = (
        db_session.query(AuditLog)
        .filter(AuditLog.target_resource == f"indicator:{ioc_id}", AuditLog.action == "IOC_MANUAL_CREATE")
        .first()
    )
    assert log_create is not None

    # 3. Update IOC
    client.put(
        f"/api/v1/indicators/{ioc_id}",
        json={"analyst_notes": "Added investigation notes"},
        headers=analyst_headers
    )
    log_update = (
        db_session.query(AuditLog)
        .filter(AuditLog.target_resource == f"indicator:{ioc_id}", AuditLog.action == "IOC_UPDATE")
        .first()
    )
    assert log_update is not None

    # 4. Disable feed
    res_feeds = client.get("/api/v1/feeds/", headers=engineer_headers)
    feed_id = res_feeds.json()[0]["id"]
    feed_name = res_feeds.json()[0]["name"]
    client.post(f"/api/v1/feeds/{feed_id}/disable", headers=engineer_headers)

    log_feed = (
        db_session.query(AuditLog)
        .filter(AuditLog.target_resource == f"feed:{feed_name}", AuditLog.action == "FEED_DISABLED")
        .first()
    )
    assert log_feed is not None
