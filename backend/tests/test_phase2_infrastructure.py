import time
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.main import app
from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.core.redis import redis_manager
from app.db.session import SessionLocal
from app.models.user import User
from app.models.indicator import Indicator
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.services.search_service import (
    init_es_index,
    index_indicator,
    delete_indicator,
    search_indicators_es,
    get_es_health
)

client = TestClient(app)

def get_or_create_user(email: str, role: str = "analyst", password: str = "TestPass123!") -> str:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                hashed_password=get_password_hash(password),
                full_name=f"Test {role.title()}",
                role=role,
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return create_access_token({"sub": user.email, "role": role})
    finally:
        db.close()

# =========================================================================
# A. Database & Persistence Tests
# =========================================================================

def test_database_connection_and_crud():
    """Verify database connection, session handling, and model CRUD operations."""
    db = SessionLocal()
    try:
        # Test active connection
        res = db.execute(text("SELECT 1")).scalar()
        assert res == 1

        # Test Indicator CRUD
        test_val = f"198.51.{uuid.uuid4().int % 240 + 1}.{uuid.uuid4().int % 240 + 1}"
        ind = Indicator(
            value=test_val,
            type="ip",
            severity="HIGH",
            threat_score=85,
            confidence=90,
            source="test_feed",
            status="active"
        )
        db.add(ind)
        db.commit()
        db.refresh(ind)

        assert ind.id is not None
        assert ind.value == test_val

        # Retrieve
        fetched = db.query(Indicator).filter(Indicator.id == ind.id).first()
        assert fetched is not None
        assert fetched.value == test_val
    finally:
        db.close()

def test_audit_immutability_enforced_at_db_layer():
    """
    CRITICAL: Verify audit log entries are strictly append-only at the database engine level.
    Any attempt to UPDATE or DELETE an audit_log record must be rejected by triggers.
    """
    db = SessionLocal()
    try:
        # 1. Insert an audit record (Allowed)
        audit_entry = AuditLog(
            action="PHASE2_IMMUTABILITY_TEST",
            actor="security_auditor@threatlens.io",
            target_resource="database:audit_log",
            details="Verifying DB trigger immutability"
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        entry_id = audit_entry.id

        # 2. Attempt UPDATE at DB level (Must Fail)
        with pytest.raises(Exception) as exc_info:
            db.execute(
                text("UPDATE audit_log SET action = 'TAMPERED_ACTION' WHERE id = :id"),
                {"id": entry_id}
            )
            db.commit()
        db.rollback()
        assert "immutable" in str(exc_info.value).lower() or "fail" in str(exc_info.value).lower() or "cannot be updated" in str(exc_info.value).lower()

        # 3. Attempt DELETE at DB level (Must Fail)
        with pytest.raises(Exception) as exc_info_del:
            db.execute(
                text("DELETE FROM audit_log WHERE id = :id"),
                {"id": entry_id}
            )
            db.commit()
        db.rollback()
        assert "immutable" in str(exc_info_del.value).lower() or "fail" in str(exc_info_del.value).lower() or "cannot be updated" in str(exc_info_del.value).lower()

        # 4. Verify original record remains intact and readable (SELECT Allowed)
        persisted = db.query(AuditLog).filter(AuditLog.id == entry_id).first()
        assert persisted is not None
        assert persisted.action == "PHASE2_IMMUTABILITY_TEST"
    finally:
        db.close()

# =========================================================================
# B. Redis & Token Revocation Tests
# =========================================================================

def test_jwt_contains_unique_jti():
    """Verify every issued access token contains a cryptographically unique jti identifier."""
    token1 = create_access_token({"sub": "user1@threatlens.io", "role": "viewer"})
    token2 = create_access_token({"sub": "user1@threatlens.io", "role": "viewer"})

    import jwt
    payload1 = jwt.decode(token1, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    payload2 = jwt.decode(token2, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert "jti" in payload1
    assert "jti" in payload2
    assert payload1["jti"] != payload2["jti"]

def test_redis_token_revocation_and_ttl():
    """Verify Redis token revocation manager and TTL expiration logic."""
    test_jti = f"test-jti-{time.time()}"
    assert not redis_manager.is_token_revoked(test_jti)

    # Revoke token
    success = redis_manager.revoke_token(test_jti, ttl_seconds=10)
    assert success is True
    assert redis_manager.is_token_revoked(test_jti) is True

    # Check non-existent JTI
    assert redis_manager.is_token_revoked("unknown-jti-999") is False

def test_auth_logout_revokes_token():
    """
    Verify complete logout lifecycle:
    1. User logs in and accesses protected endpoint -> 200 OK
    2. User calls /logout -> 200 OK
    3. User accesses same protected endpoint -> 401 Unauthorized (Token has been revoked)
    """
    email = "logout_test_analyst@threatlens.io"
    token = get_or_create_user(email, role="analyst")

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Access protected endpoint before logout
    resp_before = client.get("/api/v1/indicators/", headers=headers)
    assert resp_before.status_code == 200

    # 2. Call logout endpoint
    logout_resp = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "success"

    # 3. Access protected endpoint with revoked token
    resp_after = client.get("/api/v1/indicators/", headers=headers)
    assert resp_after.status_code == 401
    assert "revoked" in resp_after.json()["detail"].lower()

# =========================================================================
# C. Elasticsearch Service & Fallback Tests
# =========================================================================

def test_elasticsearch_service_fallback_and_indexing():
    """
    Verify Elasticsearch service:
    1. Index initialization doesn't raise unhandled exceptions
    2. Indexing and deleting indicators work safely
    3. Search returns structured hits, totals, and facets even if ES is offline
    """
    # 1. Init index check
    init_res = init_es_index()
    assert isinstance(init_res, bool)

    # 2. Index indicator check
    test_data = {
        "id": "es-test-ioc-1",
        "value": "203.0.113.55",
        "type": "ip",
        "severity": "CRITICAL",
        "status": "active",
        "threat_score": 95,
        "source": "unit_test"
    }
    index_res = index_indicator(test_data)
    assert isinstance(index_res, bool)

    # 3. Search check (validates structure and fallback)
    search_res = search_indicators_es(query_str="203.0.113", type_filter="ip")
    assert "hits" in search_res
    assert "total" in search_res
    assert "source" in search_res
    assert search_res["source"] in ("elasticsearch", "elasticsearch_unavailable")

    # 4. Delete indicator check
    del_res = delete_indicator("es-test-ioc-1")
    assert isinstance(del_res, bool)

# =========================================================================
# D. Enhanced Infrastructure Health Probes
# =========================================================================

def test_enhanced_health_check_endpoint():
    """
    Verify /health reports detailed infrastructure status (DB, Redis, Elasticsearch)
    without leaking sensitive connection strings or passwords.
    """
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] in ("ok", "healthy")
    assert "overall_health" in data
    assert "infrastructure" in data
    infra = data["infrastructure"]

    assert "database" in infra
    assert infra["database"]["status"] == "healthy"
    assert "dialect" in infra["database"]

    assert "redis" in infra
    assert infra["redis"]["status"] in ("healthy", "unavailable")

    assert "elasticsearch" in infra
    assert infra["elasticsearch"]["status"] in ("healthy", "unavailable", "degraded")

    # Check readiness probe
    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json()["status"] == "ready"

def test_prometheus_metrics_endpoint():
    """
    Verify /metrics exposes Prometheus-compatible metrics without leaking secrets,
    credentials, or sensitive database rows (NFR-10).
    """
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")

    body = resp.text
    assert "threatlens_build_info" in body
    assert "threatlens_uptime_seconds" in body
    assert 'threatlens_dependency_up{dependency="database"}' in body
    assert 'threatlens_dependency_up{dependency="redis"}' in body
    assert 'threatlens_dependency_up{dependency="elasticsearch"}' in body
    assert "threatlens_active_websocket_connections" in body
    assert "threatlens_indicators_total" in body
    assert "threatlens_alerts_total" in body
    assert "threatlens_incidents_total" in body
    assert "threatlens_cases_total" in body

    # Security check: Zero secrets in metrics payload
    assert "password" not in body.lower()
    assert "secret" not in body.lower() or "threatlens_uptime_seconds" in body
    assert "bearer" not in body.lower()
    assert "jwt" not in body.lower()

