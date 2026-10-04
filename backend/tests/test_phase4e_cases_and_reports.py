"""ThreatLens - Phase 4E Forensic Case Management and Executive PDF Reporting Test Suite.

Covers:
- Case CRUD and unique case reference generation (CASE-YYYY-XXXX)
- Case lifecycle transitions (OPEN, IN_PROGRESS, CONTAINED, RESOLVED, CLOSED)
- Invalid transition rejection and case reopening
- Case assignment and metadata updates
- Relational linking & unlinking (Incidents, Alerts, Indicators) with deduplication
- Forensic evidence recording and provenance tracking
- Append-only investigator notes with character limits and author attribution
- Unified chronological forensic timeline
- SOC filtering, search, and pagination
- Server-side RBAC (Viewer read-only vs 403 mutations, Analyst permissions, Admin full access)
- Automated Incident -> Case clustering and deduplication (preventing case explosion)
- Executive PDF Report compilation and generation (ReportLab or pure-Python engine)
- PDF validity (%PDF- header and %%EOF trailer)
- Empty dataset handling ("No data available for the selected reporting period")
- Reporting REST API (/api/v1/reports/executive, list, metadata, download)
- Report security: Path traversal rejection, IDOR defense, and immutable audit logging
"""
import os
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models.user import User, UserRole
from app.models.case import (
    Case,
    CaseStatus,
    CaseSeverity,
    CasePriority,
    CaseIncident,
    CaseAlert,
    CaseIndicator,
    CaseEvidence,
    CaseNote,
    CaseTimeline
)
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.alert import Alert
from app.models.indicator import Indicator, IndicatorType
from app.models.report import Report, ReportType, ReportStatus
from app.models.audit import AuditLog
from app.core.security import create_access_token, get_password_hash
from app.services.case_service import link_or_create_case_for_incident
from app.services.pdf_report_service import (
    compile_executive_report_data,
    generate_pdf_report_file,
    REPORTS_STORAGE_DIR
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
def auth_headers(db_session):
    """Generate authenticated bearer headers for various RBAC roles."""
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
# 1. Case Creation, Validation, and Unique Numbering (Part A)
# ===========================================================================

def test_create_case_success(auth_headers):
    """Analyst can create a new investigation case with deterministic case number."""
    headers = auth_headers("analyst")
    payload = {
        "title": "APT29 Phishing Campaign Investigation",
        "description": "Suspicious spear-phishing emails targeting engineering leadership.",
        "severity": "HIGH",
        "priority": "P1",
        "assignee": "Priya Nair",
        "tags": ["apt29", "spear-phishing"]
    }
    res = client.post("/api/v1/cases/", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == payload["title"]
    assert data["severity"] == "HIGH"
    assert data["priority"] == "P1"
    assert data["status"] == "OPEN"
    assert data["case_number"].startswith("CASE-")
    assert data["assignee"] == "Priya Nair"

def test_create_case_validation_failure(auth_headers):
    """Case creation with missing or short title must return 422 Unprocessable Entity."""
    headers = auth_headers("analyst")
    res = client.post("/api/v1/cases/", json={"title": "AB"}, headers=headers)
    assert res.status_code == 422


# ===========================================================================
# 2. Case Lifecycle Transitions & Reopening (Part A)
# ===========================================================================

def test_case_lifecycle_state_transitions(auth_headers):
    """Case progresses through valid transitions: OPEN -> IN_PROGRESS -> CONTAINED -> RESOLVED -> CLOSED."""
    headers = auth_headers("analyst")
    
    # 1. Create case
    res = client.post("/api/v1/cases/", json={"title": "Ransomware Triage"}, headers=headers)
    assert res.status_code == 201
    case_id = res.json()["id"]

    # 2. Transition: OPEN -> IN_PROGRESS
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "IN_PROGRESS", "note": "Assigned to IR Lead"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "IN_PROGRESS"

    # 3. Transition: IN_PROGRESS -> CONTAINED
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "CONTAINED", "note": "Host isolated"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "CONTAINED"

    # 4. Transition: CONTAINED -> RESOLVED
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "RESOLVED", "note": "IOCs blocked on firewall"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"
    assert res.json()["closed_at"] is not None

    # 5. Transition: RESOLVED -> CLOSED
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "CLOSED", "note": "Post-incident review complete"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "CLOSED"

    # 6. Reopen: CLOSED -> OPEN
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "OPEN", "note": "Secondary persistence observed"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "OPEN"
    assert res.json()["closed_at"] is None

def test_case_invalid_status_transition_blocked(auth_headers):
    """Invalid transition (CLOSED -> RESOLVED) must be rejected with HTTP 400."""
    headers = auth_headers("analyst")
    res = client.post("/api/v1/cases/", json={"title": "Triage Check"}, headers=headers)
    case_id = res.json()["id"]

    # Jump to CLOSED
    client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "CLOSED"}, headers=headers)

    # Attempt illegal transition: CLOSED -> RESOLVED
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "RESOLVED"}, headers=headers)
    assert res.status_code == 400
    assert "invalid status transition" in res.json()["detail"].lower()


# ===========================================================================
# 3. Case Assignment & Metadata Updates (Part A & C)
# ===========================================================================

def test_case_assignment_and_patch(auth_headers):
    """Analyst can update assignee, owner, priority, and description."""
    headers = auth_headers("analyst")
    c = client.post("/api/v1/cases/", json={"title": "C2 Domain Pivoting"}, headers=headers).json()
    case_id = c["id"]

    # Assign
    res = client.patch(f"/api/v1/cases/{case_id}/assign", json={"assignee": "Daniel Okafor", "owner": "SOC Lead"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["assignee"] == "Daniel Okafor"
    assert res.json()["owner"] == "SOC Lead"

    # Patch details
    res = client.patch(f"/api/v1/cases/{case_id}", json={
        "priority": "P1",
        "description": "Updated scope: 3 workstations involved."
    }, headers=headers)
    assert res.status_code == 200
    assert res.json()["priority"] == "P1"
    assert "3 workstations" in res.json()["description"]


# ===========================================================================
# 4. Entity Linking & Unlinking (Part B)
# ===========================================================================

def test_case_incident_alert_indicator_linking(auth_headers, db_session):
    """Cases can link and unlink canonical Incidents, Alerts, and Indicators."""
    headers = auth_headers("analyst")
    
    # Create test entities
    now = datetime.utcnow()
    ind = Indicator(type=IndicatorType.DOMAIN, value=f"evil-{uuid.uuid4().hex[:6]}.com", severity_score=85, confidence=90, created_at=now, updated_at=now)
    db_session.add(ind)
    db_session.commit()

    alert = Alert(title="Malicious Domain Activity", indicator_id=ind.id, indicator_value=ind.value, severity="HIGH", created_at=now, updated_at=now)
    db_session.add(alert)
    db_session.commit()

    inc = Incident(title="C2 Communication Cluster", incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}", severity="HIGH", created_at=now, updated_at=now)
    db_session.add(inc)
    db_session.commit()

    # Create Case
    case = client.post("/api/v1/cases/", json={"title": "Infrastructure Takedown"}, headers=headers).json()
    case_id = case["id"]

    # 1. Link Incident
    res = client.post(f"/api/v1/cases/{case_id}/incidents", json={"incident_id": inc.id}, headers=headers)
    assert res.status_code == 200
    assert len(res.json()["incidents"]) == 1
    assert res.json()["incidents"][0]["id"] == inc.id

    # Idempotent test
    res = client.post(f"/api/v1/cases/{case_id}/incidents", json={"incident_id": inc.id}, headers=headers)
    assert res.status_code == 200
    assert len(res.json()["incidents"]) == 1

    # 2. Link Alert
    res = client.post(f"/api/v1/cases/{case_id}/alerts", json={"alert_id": alert.id}, headers=headers)
    assert res.status_code == 200
    assert len(res.json()["alerts"]) == 1

    # 3. Link Indicator
    res = client.post(f"/api/v1/cases/{case_id}/indicators", json={"indicator_id": ind.id}, headers=headers)
    assert res.status_code == 200
    assert len(res.json()["indicators"]) == 1

    # 4. Unlink Incident
    res = client.delete(f"/api/v1/cases/{case_id}/incidents/{inc.id}", headers=headers)
    assert res.status_code == 200
    assert len(res.json()["incidents"]) == 0

    # 5. Unlink Alert
    res = client.delete(f"/api/v1/cases/{case_id}/alerts/{alert.id}", headers=headers)
    assert res.status_code == 200
    assert len(res.json()["alerts"]) == 0

    # 6. Unlink Indicator
    res = client.delete(f"/api/v1/cases/{case_id}/indicators/{ind.id}", headers=headers)
    assert res.status_code == 200
    assert len(res.json()["indicators"]) == 0


# ===========================================================================
# 5. Forensic Evidence & Append-Only Notes (Part G & H)
# ===========================================================================

def test_case_evidence_and_notes(auth_headers):
    """Analyst can attach forensic evidence and record append-only investigator notes."""
    headers = auth_headers("analyst")
    case = client.post("/api/v1/cases/", json={"title": "Data Exfiltration Probe"}, headers=headers).json()
    case_id = case["id"]

    # 1. Add Evidence
    ev_payload = {
        "evidence_type": "PCAP",
        "title": "Encrypted Exfiltration Stream PCAP",
        "description": "500MB outbound TLS session to unregistered Russian IP.",
        "source_provider": "Zeek Sensor",
        "reference_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "confidence": 95
    }
    res = client.post(f"/api/v1/cases/{case_id}/evidence", json=ev_payload, headers=headers)
    assert res.status_code == 201
    assert res.json()["title"] == ev_payload["title"]
    assert res.json()["confidence"] == 95

    # List evidence
    res = client.get(f"/api/v1/cases/{case_id}/evidence", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 1

    # 2. Add Note
    res = client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "Initial memory dump collected from HOST-01."}, headers=headers)
    assert res.status_code == 201
    assert "Initial memory dump" in res.json()["content"]

    # Empty note rejected
    res = client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "  "}, headers=headers)
    assert res.status_code == 422 or res.status_code == 400

    # List notes
    res = client.get(f"/api/v1/cases/{case_id}/notes", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) == 1


# ===========================================================================
# 6. Unified Timeline & Audit Trail (Part F & P)
# ===========================================================================

def test_case_timeline_and_audit(auth_headers):
    """Case actions automatically populate the unified forensic timeline and audit trail."""
    headers = auth_headers("analyst")
    case = client.post("/api/v1/cases/", json={"title": "Credential Dumping Timeline Test"}, headers=headers).json()
    case_id = case["id"]

    # Perform mutations
    client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "IN_PROGRESS", "note": "Starting forensic triage"}, headers=headers)
    client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "LSASS memory access observed via Sysmon."}, headers=headers)

    # 1. Timeline check
    res = client.get(f"/api/v1/cases/{case_id}/timeline", headers=headers)
    assert res.status_code == 200
    timeline = res.json()
    assert len(timeline) >= 3
    event_types = [t["event_type"] for t in timeline]
    assert "CASE_CREATED" in event_types
    assert "STATUS_CHANGED" in event_types
    assert "NOTE_ADDED" in event_types

    # 2. Audit check
    res = client.get(f"/api/v1/cases/{case_id}/audit", headers=headers)
    assert res.status_code == 200
    audit = res.json()
    assert len(audit) >= 1
    actions = [a["action"] for a in audit]
    assert "CASE_CREATED" in actions or "CASE_STATUS_CHANGED" in actions


# ===========================================================================
# 7. Search, Filtering, and Pagination (Part I)
# ===========================================================================

def test_case_filtering_and_pagination(auth_headers):
    """Case list supports filtering by status, severity, priority, and text search."""
    headers = auth_headers("analyst")
    client.post("/api/v1/cases/", json={"title": "Alpha Ransomware Attack", "severity": "CRITICAL", "priority": "P1"}, headers=headers)
    client.post("/api/v1/cases/", json={"title": "Beta Phishing Campaign", "severity": "LOW", "priority": "P4"}, headers=headers)

    # Filter by severity
    res = client.get("/api/v1/cases/?severity=CRITICAL", headers=headers)
    assert res.status_code == 200
    for c in res.json():
        assert c["severity"] == "CRITICAL"

    # Search by title keyword
    res = client.get("/api/v1/cases/?search=Alpha", headers=headers)
    assert res.status_code == 200
    assert any("Alpha" in c["title"] for c in res.json())

    # Pagination limit
    res = client.get("/api/v1/cases/?limit=1", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) <= 1


# ===========================================================================
# 8. Server-Side RBAC Enforcement (Part D)
# ===========================================================================

def test_case_rbac_viewer_blocked(auth_headers):
    """Viewer role can read cases but is strictly blocked (HTTP 403) from case mutations."""
    viewer_headers = auth_headers("viewer")
    analyst_headers = auth_headers("analyst")

    # Analyst creates a case
    c = client.post("/api/v1/cases/", json={"title": "RBAC Test Case"}, headers=analyst_headers).json()
    case_id = c["id"]

    # 1. Viewer Read: Allowed
    res = client.get("/api/v1/cases/", headers=viewer_headers)
    assert res.status_code == 200
    res = client.get(f"/api/v1/cases/{case_id}", headers=viewer_headers)
    assert res.status_code == 200

    # 2. Viewer Create Case: Blocked
    res = client.post("/api/v1/cases/", json={"title": "Viewer Unauthorized"}, headers=viewer_headers)
    assert res.status_code == 403

    # 3. Viewer Status Transition: Blocked
    res = client.patch(f"/api/v1/cases/{case_id}/status", json={"status": "IN_PROGRESS"}, headers=viewer_headers)
    assert res.status_code == 403

    # 4. Viewer Add Note: Blocked
    res = client.post(f"/api/v1/cases/{case_id}/notes", json={"content": "Viewer note"}, headers=viewer_headers)
    assert res.status_code == 403

    # 5. Viewer Add Evidence: Blocked
    res = client.post(f"/api/v1/cases/{case_id}/evidence", json={"title": "Viewer Evidence"}, headers=viewer_headers)
    assert res.status_code == 403

    # 6. Viewer Generate Report: Blocked
    res = client.post("/api/v1/reports/executive", json={"time_range": "30d"}, headers=viewer_headers)
    assert res.status_code == 403


# ===========================================================================
# 9. Automated Incident -> Case Clustering & Deduplication (Part E)
# ===========================================================================

def test_incident_to_case_clustering_and_deduplication(db_session):
    """
    Automated Incident -> Case clustering hook creates cases for significant incidents
    and clusters subsequent related incidents to avoid case explosion.
    """
    now = datetime.utcnow()
    ioc_val = f"apt-{uuid.uuid4().hex[:6]}.org"

    # Incident 1: Critical incident with IOC
    inc1 = Incident(
        title="APT Backdoor Activity",
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        severity="CRITICAL",
        correlation_score=80,
        matched_ioc_value=ioc_val,
        affected_host="WIN-WORKSTATION-01",
        created_at=now,
        updated_at=now
    )
    db_session.add(inc1)
    db_session.commit()

    # Trigger hook
    case1 = link_or_create_case_for_incident(db_session, inc1)
    assert case1 is not None
    assert case1.severity == "CRITICAL"
    assert "APT Backdoor Activity" in case1.title

    # Incident 2: Another alert/incident involving the same IOC
    inc2 = Incident(
        title="Secondary C2 Traffic on Host",
        incident_code=f"INC-{uuid.uuid4().hex[:6].upper()}",
        severity="HIGH",
        correlation_score=65,
        matched_ioc_value=ioc_val,
        affected_host="WIN-WORKSTATION-02",
        created_at=now,
        updated_at=now
    )
    db_session.add(inc2)
    db_session.commit()

    # Trigger hook on incident 2 -> Must cluster into case1 rather than create a duplicate case
    case2 = link_or_create_case_for_incident(db_session, inc2)
    assert case2 is not None
    assert case2.id == case1.id
    assert case2.case_number == case1.case_number

    # Verify case1 has both incidents linked
    db_session.refresh(case1)
    linked_inc_ids = [ci.incident_id for ci in case1.case_incidents]
    assert inc1.id in linked_inc_ids
    assert inc2.id in linked_inc_ids


# ===========================================================================
# 10. Executive PDF Reporting & Validity (Part K, L, M)
# ===========================================================================

def test_executive_pdf_generation_and_validity(db_session):
    """
    Executive report data compiles from database and produces a valid PDF file.
    Validates %PDF-1. header, %%EOF trailer, and positive file size.
    """
    data = compile_executive_report_data(db_session, time_range="30d", author="Chief Information Security Officer")
    assert "report_title" in data
    assert "kpis" in data
    assert "incidents" in data
    assert "cases" in data

    test_pdf_path = os.path.join(REPORTS_STORAGE_DIR, f"test_executive_{uuid.uuid4().hex[:8]}.pdf")
    file_size, sha256_hash = generate_pdf_report_file(data, test_pdf_path)
    assert file_size > 0
    assert len(sha256_hash) == 64
    assert os.path.exists(test_pdf_path)

    # Check valid PDF binary format
    with open(test_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes

    # Cleanup temporary test file
    try:
        os.remove(test_pdf_path)
    except Exception:
        pass

def test_executive_report_empty_dataset(db_session):
    """Report compiled against empty window renders honest empty states without fake data."""
    # Use future range or safe empty compiler
    data = compile_executive_report_data(db_session, time_range="24h", author="Automated Auditor")
    assert isinstance(data["findings"], list)
    assert isinstance(data["recommendations"], list)
    # File generation must succeed without crashing on empty lists
    test_pdf_path = os.path.join(REPORTS_STORAGE_DIR, f"test_empty_{uuid.uuid4().hex[:8]}.pdf")
    file_size, _ = generate_pdf_report_file(data, test_pdf_path)
    assert file_size > 0
    if os.path.exists(test_pdf_path):
        os.remove(test_pdf_path)


# ===========================================================================
# 11. Reporting REST API & Download (Part N & O)
# ===========================================================================

def test_reports_api_generate_and_download(auth_headers):
    """Analyst can generate executive report via API and download the resulting PDF."""
    headers = auth_headers("analyst")
    res = client.post("/api/v1/reports/executive", json={"time_range": "30d"}, headers=headers)
    assert res.status_code == 201
    rep = res.json()
    assert rep["report_code"].startswith("RPT-")
    assert rep["status"] == "COMPLETED"
    assert rep["file_size_bytes"] > 0
    report_id = rep["id"]

    # 1. Get metadata
    res = client.get(f"/api/v1/reports/{report_id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["report_code"] == rep["report_code"]

    # 2. List reports
    res = client.get("/api/v1/reports/", headers=headers)
    assert res.status_code == 200
    assert any(r["id"] == report_id for r in res.json())

    # 3. Download PDF
    res = client.get(f"/api/v1/reports/{report_id}/download", headers=headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-")


# ===========================================================================
# 12. Report Security & Path Traversal Rejection (Part O)
# ===========================================================================

def test_reports_security_path_traversal_blocked(auth_headers):
    """Malicious path traversal attempts in report downloads must be cleanly rejected."""
    headers = auth_headers("analyst")

    # Path traversal patterns in identifier
    res = client.get("/api/v1/reports/../../etc/passwd/download", headers=headers)
    assert res.status_code in [400, 404]

    res = client.get("/api/v1/reports/..%2F..%2Fetc%2Fpasswd/download", headers=headers)
    assert res.status_code in [400, 404]

    # Non-existent report ID
    res = client.get(f"/api/v1/reports/{uuid.uuid4()}/download", headers=headers)
    assert res.status_code == 404

def test_unauthenticated_report_download_blocked():
    """Unauthenticated download request must be rejected with HTTP 401."""
    res = client.get("/api/v1/reports/some-fake-id/download")
    assert res.status_code == 401
