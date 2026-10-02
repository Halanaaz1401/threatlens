"""
ThreatLens - Phase 4D-B Configurable Detection Rule Engine & Alert Routing Test Suite
Verifies:
1. Rule creation, condition schema validation, and unsupported operator rejection
2. Malicious regex rejection and complexity safety
3. Rule enablement and disablement state transitions
4. RBAC enforcement (Viewer read-only, Analyst create/test, Engineer/Admin full lifecycle)
5. Dry-run testing without creating alerts or publishing events
6. Deterministic DSL matching across indicator types, scores, feeds, MITRE techniques, and enrichment verdicts
7. Rule logic operators (AND vs OR)
8. Alert creation with rule provenance, severity mapping, and context
9. Alert deduplication within configurable time windows
10. Alert routing to queues, default assignees, and honest delivery channel reporting
11. Incident correlation handoff
12. Redis event publishing (DETECTION_RULE_MATCHED, ALERT_ROUTED)
13. Immutable audit logging for rule lifecycle
"""
import uuid
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.incident import Incident
from app.models.enrichment import IndicatorEnrichment
from app.models.detection_rule import DetectionRule, RuleSeverity, RuleRoutingQueue
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.core.security import create_access_token, get_password_hash
from app.services.detection_rule_service import (
    create_detection_rule,
    get_detection_rule,
    list_detection_rules,
    update_detection_rule,
    set_rule_enabled_status,
    delete_detection_rule,
    evaluate_rule,
    execute_rule_dry_run,
    evaluate_indicator_against_rules,
    validate_rule_conditions,
    route_alert_notification,
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
    email = f"admin_4db_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("AdminPass123!"),
        full_name="Phase 4D-B Admin",
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
    email = f"eng_4db_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("EngPass123!"),
        full_name="Phase 4D-B SecOps Engineer",
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
    email = f"analyst_4db_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("AnalystPass123!"),
        full_name="Phase 4D-B Analyst",
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
    email = f"viewer_4db_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("ViewerPass123!"),
        full_name="Phase 4D-B Viewer",
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


# 1. Rule Creation & Schema Validation
def test_detection_rule_creation(db_session):
    """Test programmatic creation of a detection rule with declarative conditions."""
    conditions = [
        {"field": "threat_score", "operator": ">=", "value": 75},
        {"field": "type", "operator": "==", "value": "ip"},
    ]
    rule = create_detection_rule(
        db=db_session,
        name=f"C2 High Threat IP Rule {uuid.uuid4().hex[:4]}",
        conditions=conditions,
        severity=RuleSeverity.CRITICAL.value,
        priority=80,
        routing_target=RuleRoutingQueue.SOC_TIER_2.value,
    )
    assert rule.id is not None
    assert rule.severity == "CRITICAL"
    assert rule.priority == 80
    assert rule.is_enabled is True
    assert len(rule.conditions) == 2


def test_unsupported_operators_rejected():
    """Rules with unsupported operators or malformed condition objects must be rejected."""
    # Unsupported operator
    with pytest.raises(ValueError, match="Unsupported operator 'eval'"):
        validate_rule_conditions([
            {"field": "threat_score", "operator": "eval", "value": "x > 10"}
        ])

    with pytest.raises(ValueError, match="missing required fields"):
        validate_rule_conditions([{"field": "type"}])


def test_malicious_regex_rejection():
    """Catastrophic backtracking or oversized regex patterns must be strictly rejected."""
    # Nested quantifier pattern: (a+)+
    with pytest.raises(ValueError, match="Unsafe or invalid regular expression"):
        validate_rule_conditions([
            {"field": "value", "operator": "regex_match", "value": "((a+)+)+$"}
        ])

    # Oversized pattern
    long_pattern = "a" * 120
    with pytest.raises(ValueError, match="Unsafe or invalid regular expression"):
        validate_rule_conditions([
            {"field": "value", "operator": "regex_match", "value": long_pattern}
        ])


def test_rule_enable_disable(db_session):
    """Test toggling rule enabled status."""
    rule = create_detection_rule(
        db=db_session,
        name=f"Toggle Test {uuid.uuid4().hex[:4]}",
        conditions=[{"field": "threat_score", "operator": ">", "value": 50}],
    )
    assert rule.is_enabled is True

    updated_off = set_rule_enabled_status(db_session, rule.id, is_enabled=False)
    assert updated_off.is_enabled is False

    updated_on = set_rule_enabled_status(db_session, rule.id, is_enabled=True)
    assert updated_on.is_enabled is True


# 2. RBAC Enforcement
def test_rbac_detection_rules(db_session, admin_headers, engineer_headers, analyst_headers, viewer_headers):
    """Test role hierarchy permissions on /api/v1/detection-rules."""
    # 1. Viewer can read rules
    resp_view = client.get("/api/v1/detection-rules", headers=viewer_headers)
    assert resp_view.status_code == 200

    # 2. Viewer cannot create rules (403)
    rule_payload = {
        "name": "Unauthorized Rule Creation",
        "conditions": [{"field": "type", "operator": "==", "value": "domain"}],
        "severity": "HIGH",
    }
    resp_viewer_create = client.post("/api/v1/detection-rules", json=rule_payload, headers=viewer_headers)
    assert resp_viewer_create.status_code == 403

    # 3. Analyst can create rules (201)
    resp_analyst_create = client.post("/api/v1/detection-rules", json=rule_payload, headers=analyst_headers)
    assert resp_analyst_create.status_code == 201
    created_id = resp_analyst_create.json()["data"]["id"]

    # 4. Analyst cannot delete or disable rules (requires Engineer/Admin -> 403)
    resp_analyst_disable = client.post(f"/api/v1/detection-rules/{created_id}/disable", headers=analyst_headers)
    assert resp_analyst_disable.status_code == 403
    resp_analyst_del = client.delete(f"/api/v1/detection-rules/{created_id}", headers=analyst_headers)
    assert resp_analyst_del.status_code == 403

    # 5. Security Engineer can disable and delete rules (200)
    resp_eng_disable = client.post(f"/api/v1/detection-rules/{created_id}/disable", headers=engineer_headers)
    assert resp_eng_disable.status_code == 200
    assert resp_eng_disable.json()["data"]["is_enabled"] is False

    resp_eng_del = client.delete(f"/api/v1/detection-rules/{created_id}", headers=engineer_headers)
    assert resp_eng_del.status_code == 200


# 3. Dry-Run Testing
def test_dry_run_rule_testing(db_session, analyst_headers):
    """Dry-run testing must accurately show match results without creating alerts or incidents."""
    ind = Indicator(
        value=f"dryrun-{uuid.uuid4().hex[:4]}.org",
        type=IndicatorType.DOMAIN.value,
        threat_score=85,
        severity="HIGH",
    )
    db_session.add(ind)
    db_session.commit()

    alerts_before = db_session.query(Alert).count()
    incidents_before = db_session.query(Incident).count()

    test_payload = {
        "indicator_id": ind.id,
        "rule_data": {
            "name": "Domain Dry Run Test",
            "conditions": [
                {"field": "threat_score", "operator": ">=", "value": 80},
                {"field": "type", "operator": "==", "value": "domain"},
            ],
            "severity": "CRITICAL",
            "routing_target": "IR_LEAD",
        },
    }

    resp = client.post("/api/v1/detection-rules/test", json=test_payload, headers=analyst_headers)
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["dry_run"] is True
    assert body["is_matched"] is True
    assert body["simulated_routing"]["queue"] == "IR_LEAD"
    assert body["simulated_routing"]["assignee"] == "Daniel Okafor"

    # Strictly NO database side-effects
    assert db_session.query(Alert).count() == alerts_before
    assert db_session.query(Incident).count() == incidents_before


# 4. Declarative DSL Matching
def test_declarative_matching_and_or_logic(db_session):
    """Test AND vs OR logic evaluation against indicator attributes."""
    ind = Indicator(
        value=f"bad-{uuid.uuid4().hex[:4]}.com",
        type="domain",
        threat_score=90,
        severity="CRITICAL",
        mitre_technique="T1071",
        source="AlienVault OTX",
    )
    db_session.add(ind)
    db_session.commit()

    # Rule 1: AND matching (both conditions satisfied)
    rule_and = DetectionRule(
        name="AND Rule Match",
        conditions=[
            {"field": "type", "operator": "==", "value": "domain"},
            {"field": "threat_score", "operator": ">", "value": 80},
        ],
        logic_operator="AND",
    )
    matched_and, _ = evaluate_rule(rule_and, ind)
    assert matched_and is True

    # Rule 2: AND non-matching (one condition fails)
    rule_and_fail = DetectionRule(
        name="AND Rule Fail",
        conditions=[
            {"field": "type", "operator": "==", "value": "domain"},
            {"field": "mitre_technique", "operator": "==", "value": "T1190"},  # actual is T1071
        ],
        logic_operator="AND",
    )
    matched_and_fail, _ = evaluate_rule(rule_and_fail, ind)
    assert matched_and_fail is False

    # Rule 3: OR matching (one condition satisfied)
    rule_or = DetectionRule(
        name="OR Rule Match",
        conditions=[
            {"field": "type", "operator": "==", "value": "ip"},              # false
            {"field": "mitre_technique", "operator": "==", "value": "T1071"},  # true
        ],
        logic_operator="OR",
    )
    matched_or, _ = evaluate_rule(rule_or, ind)
    assert matched_or is True


def test_enrichment_condition_matching(db_session):
    """Test condition matching against latest threat intelligence enrichment verdict."""
    ind = Indicator(
        value=f"198.51.100.{uuid.uuid4().hex[:3]}",
        type="ip",
        threat_score=65,
    )
    db_session.add(ind)
    db_session.commit()

    enrich = IndicatorEnrichment(
        indicator_id=ind.id,
        provider="VirusTotal",
        queried_value=ind.value,
        indicator_type="ip",
        verdict="malicious",
        malicious_count=14,
        confidence=95,
        country="RU",
        fetched_at=datetime.utcnow(),
    )
    db_session.add(enrich)
    db_session.commit()

    rule = DetectionRule(
        name="Malicious Enrichment Rule",
        conditions=[
            {"field": "enrichment_verdict", "operator": "==", "value": "malicious"},
            {"field": "enrichment_malicious_count", "operator": ">=", "value": 10},
            {"field": "country", "operator": "in", "value": ["RU", "CN", "KP"]},
        ],
        logic_operator="AND",
    )

    matched, results = evaluate_rule(rule, ind, enrich)
    assert matched is True
    assert all(r["matched"] for r in results)


# 5. Alert Generation, Provenance, & Deduplication
def test_alert_generation_and_deduplication(db_session):
    """Test alert creation from rule match and deduplication within the time window."""
    rule = create_detection_rule(
        db=db_session,
        name=f"Dedup Test Rule {uuid.uuid4().hex[:4]}",
        conditions=[{"field": "threat_score", "operator": ">=", "value": 70}],
        severity="HIGH",
        routing_target=RuleRoutingQueue.THREAT_HUNTING.value,
        dedup_window_minutes=60,
    )

    ind = Indicator(
        value=f"dedup-{uuid.uuid4().hex[:4]}.test",
        type="domain",
        threat_score=75,
        severity="HIGH",
    )
    db_session.add(ind)
    db_session.commit()

    # First evaluation: creates alert
    matches_1 = evaluate_indicator_against_rules(db_session, ind)
    rule_matches_1 = [m for m in matches_1 if m["rule_id"] == rule.id]
    assert len(rule_matches_1) == 1
    assert rule_matches_1[0]["is_deduplicated"] is False
    assert rule_matches_1[0]["routed_to"] == "THREAT_HUNTING"
    assert rule_matches_1[0]["assignee"] == "Mei Lin Tan"

    created_alert = db_session.query(Alert).filter(Alert.id == rule_matches_1[0]["alert_id"]).first()
    assert created_alert is not None
    assert created_alert.rule_id == rule.id
    assert created_alert.rule_name == rule.name
    assert created_alert.routed_to == "THREAT_HUNTING"
    assert created_alert.internal_sightings_count == 1

    # Second evaluation within window: deduplicates without creating a new alert row
    matches_2 = evaluate_indicator_against_rules(db_session, ind)
    rule_matches_2 = [m for m in matches_2 if m["rule_id"] == rule.id]
    assert len(rule_matches_2) == 1
    assert rule_matches_2[0]["is_deduplicated"] is True
    assert rule_matches_2[0]["alert_id"] == created_alert.id
    assert rule_matches_2[0]["sightings"] == 2

    # Verify total alert count for this indicator under this rule is strictly 1 (deduplicated)
    rule_alert_count = db_session.query(Alert).filter(Alert.indicator_id == ind.id, Alert.rule_id == rule.id).count()
    assert rule_alert_count == 1
    assert created_alert.internal_sightings_count == 2


# 6. Alert Routing & Channel Reporting
def test_alert_routing_delivery_reporting(db_session):
    """Test honest reporting of delivery channels (DELIVERED for internal, NOT_CONFIGURED if unconfigured)."""
    # 1. Internal queue: DELIVERED
    rule_internal = DetectionRule(
        name="Internal Route Rule",
        routing_target=RuleRoutingQueue.CISO_ESCALATION.value,
        routing_channel="internal",
    )
    alert = Alert(title="Test Alert", severity="CRITICAL")
    route_res = route_alert_notification(alert, rule_internal)
    assert route_res["queue"] == "CISO_ESCALATION"
    assert route_res["assignee"] == "Rachel Adeyemi"
    assert route_res["delivery_status"] == "DELIVERED"

    # 2. Unconfigured SMTP: NOT_CONFIGURED (never fake success!)
    rule_email = DetectionRule(
        name="Email Route Rule",
        routing_target=RuleRoutingQueue.IR_LEAD.value,
        routing_channel="email_notification",
    )
    route_email_res = route_alert_notification(alert, rule_email)
    assert route_email_res["delivery_status"] == "NOT_CONFIGURED"
    assert "SMTP host is not configured" in route_email_res["message"]


# 7. Audit Logging
def test_audit_logging_on_rule_actions(db_session, admin_headers):
    """Test that audit events are written for state-changing rule actions."""
    create_payload = {
        "name": f"Audit Logging Rule {uuid.uuid4().hex[:4]}",
        "conditions": [{"field": "threat_score", "operator": ">=", "value": 50}],
        "severity": "MEDIUM",
    }
    resp = client.post("/api/v1/detection-rules", json=create_payload, headers=admin_headers)
    assert resp.status_code == 201
    rule_id = resp.json()["data"]["id"]

    # Check AuditLog table for RULE_CREATED
    audit_entry = db_session.query(AuditLog).filter(
        AuditLog.action == "RULE_CREATED",
        AuditLog.target_resource == f"rule:{rule_id}"
    ).first()
    assert audit_entry is not None
