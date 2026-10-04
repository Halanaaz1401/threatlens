import html
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from pydantic import BaseModel, Field

from app.db.session import get_db
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
    CaseTimeline,
    is_valid_case_status_transition,
    VALID_CASE_STATUS_TRANSITIONS
)
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.indicator import Indicator
from app.models.audit import AuditLog
from app.models.user import User
from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    require_admin
)
from app.services.case_service import (
    create_case as svc_create_case,
    update_case_status as svc_update_case_status,
    update_case as svc_update_case,
    link_incident_to_case as svc_link_incident,
    unlink_incident_from_case as svc_unlink_incident,
    link_alert_to_case as svc_link_alert,
    unlink_alert_from_case as svc_unlink_alert,
    link_indicator_to_case as svc_link_indicator,
    unlink_indicator_from_case as svc_unlink_indicator,
    add_case_evidence as svc_add_evidence,
    add_case_note as svc_add_note
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class CaseCreatePayload(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Case title")
    description: Optional[str] = Field(None, max_length=5000, description="Investigation synopsis")
    severity: str = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    priority: str = Field("P2", description="P1, P2, P3, P4")
    assignee: Optional[str] = Field(None, max_length=100)
    owner: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = Field(default_factory=list)
    source: str = Field("Manual", max_length=100)

class CaseUpdatePayload(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    severity: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = Field(None, max_length=100)
    owner: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = None
    note: Optional[str] = Field(None, max_length=1000)

class CaseStatusUpdatePayload(BaseModel):
    status: str = Field(..., description="Target status: OPEN, IN_PROGRESS, CONTAINED, RESOLVED, CLOSED")
    note: Optional[str] = Field(None, max_length=1000, description="Reason / forensic transition notes")

class CaseAssignPayload(BaseModel):
    assignee: Optional[str] = Field(None, max_length=100)
    owner: Optional[str] = Field(None, max_length=100)

class CaseLinkIncidentPayload(BaseModel):
    incident_id: str = Field(..., description="ID or incident_code of the incident to link")

class CaseLinkAlertPayload(BaseModel):
    alert_id: str = Field(..., description="ID or alert_code of the alert to link")

class CaseLinkIndicatorPayload(BaseModel):
    indicator_id: str = Field(..., description="ID of the indicator to link")

class CaseEvidencePayload(BaseModel):
    evidence_type: str = Field("INDICATOR", max_length=100, description="INDICATOR, ALERT, INCIDENT, LOG, ENRICHMENT, PCAP, FILE_HASH, RULE_MATCH")
    title: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    source_entity: Optional[str] = Field(None, max_length=100)
    source_provider: Optional[str] = Field(None, max_length=100)
    reference_hash: Optional[str] = Field(None, max_length=128)
    confidence: int = Field(80, ge=0, le=100)
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    observed_at: Optional[datetime] = None

class CaseNotePayload(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000, description="Investigator note text")

# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------

def serialize_case_summary(case: Case) -> Dict[str, Any]:
    """Serialize case entity into clean summary representation."""
    return {
        "id": str(case.id),
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "priority": case.priority,
        "status": case.status,
        "owner": case.owner,
        "assignee": case.assignee,
        "source": case.source,
        "tags": case.tags or [],
        "created_by": case.created_by,
        "closed_by": case.closed_by,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "incidents_count": len(case.case_incidents) if case.case_incidents else 0,
        "alerts_count": len(case.case_alerts) if case.case_alerts else 0,
        "indicators_count": len(case.case_indicators) if case.case_indicators else 0,
        "evidence_count": len(case.evidence) if case.evidence else 0,
        "notes_count": len(case.notes) if case.notes else 0,
    }

def serialize_case_detail(case: Case) -> Dict[str, Any]:
    """Serialize comprehensive case view with linked entities, evidence, and notes."""
    incidents = []
    for ci in (case.case_incidents or []):
        inc = ci.incident
        if inc:
            incidents.append({
                "id": str(inc.id),
                "incident_code": inc.incident_code,
                "title": inc.title,
                "severity": str(inc.severity),
                "status": str(inc.status),
                "correlation_score": inc.correlation_score or 0,
                "matched_ioc": inc.matched_ioc_value or inc.primary_indicator,
                "affected_host": inc.affected_host,
                "linked_at": ci.linked_at.isoformat() if ci.linked_at else None,
                "linked_by": ci.linked_by,
            })

    alerts = []
    for ca in (case.case_alerts or []):
        al = ca.alert
        if al:
            alerts.append({
                "id": str(al.id),
                "alert_code": al.alert_code,
                "title": al.title,
                "severity": str(al.severity),
                "severity_score": al.severity_score,
                "indicator_value": al.indicator_value,
                "source": al.source,
                "linked_at": ca.linked_at.isoformat() if ca.linked_at else None,
            })

    indicators = []
    for cind in (case.case_indicators or []):
        ind = cind.indicator
        if ind:
            indicators.append({
                "id": str(ind.id),
                "value": ind.value,
                "type": str(ind.type),
                "severity_score": ind.severity_score,
                "confidence": ind.confidence,
                "tlp": getattr(ind, "tlp", "AMBER"),
                "status": getattr(ind, "status", "active"),
                "linked_at": cind.linked_at.isoformat() if cind.linked_at else None,
            })

    evidence_list = []
    for ev in (case.evidence or []):
        evidence_list.append({
            "id": str(ev.id),
            "evidence_type": ev.evidence_type,
            "title": ev.title,
            "description": ev.description,
            "source_entity": ev.source_entity,
            "source_provider": ev.source_provider,
            "reference_hash": ev.reference_hash,
            "confidence": ev.confidence,
            "data": ev.data or {},
            "observed_at": ev.observed_at.isoformat() if ev.observed_at else None,
            "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
            "collected_by": ev.collected_by,
        })

    notes_list = []
    for note in (case.notes or []):
        notes_list.append({
            "id": str(note.id),
            "author": note.author,
            "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        })

    summary = serialize_case_summary(case)
    summary.update({
        "incidents": incidents,
        "alerts": alerts,
        "indicators": indicators,
        "evidence": evidence_list,
        "notes": notes_list,
    })
    return summary

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_cases(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, IN_PROGRESS, CONTAINED, RESOLVED, CLOSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1, P2, P3, P4)"),
    assignee: Optional[str] = Query(None, description="Filter by assignee"),
    search: Optional[str] = Query(None, description="Search case number, title, or description"),
    start_date: Optional[datetime] = Query(None, description="Created on or after"),
    end_date: Optional[datetime] = Query(None, description="Created on or before"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """List forensic investigation cases with SOC filters and pagination (Authenticated)."""
    query = db.query(Case)

    if status:
        query = query.filter(Case.status.ilike(status.strip()))
    if severity:
        query = query.filter(Case.severity.ilike(severity.strip()))
    if priority:
        query = query.filter(Case.priority.ilike(priority.strip()))
    if assignee:
        query = query.filter(Case.assignee.ilike(f"%{assignee.strip()}%"))
    if start_date:
        query = query.filter(Case.created_at >= start_date)
    if end_date:
        query = query.filter(Case.created_at <= end_date)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(or_(
            Case.case_number.ilike(s),
            Case.title.ilike(s),
            Case.description.ilike(s)
        ))

    cases = query.order_by(desc(Case.updated_at), desc(Case.created_at)).offset(skip).limit(limit).all()
    return [serialize_case_summary(c) for c in cases]

@router.post("/", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreatePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Open a new forensic investigation case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    
    # Sanitize title and description
    safe_title = html.escape(payload.title.strip())
    safe_desc = html.escape(payload.description.strip()) if payload.description else None

    new_case = svc_create_case(
        db=db,
        title=safe_title,
        description=safe_desc,
        severity=payload.severity,
        priority=payload.priority,
        creator=actor,
        source=payload.source,
        tags=payload.tags,
        owner=payload.owner or actor,
        assignee=payload.assignee
    )
    return serialize_case_detail(new_case)

@router.get("/{case_id}")
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve full details of an investigation case by UUID or case_number (Authenticated)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return serialize_case_detail(case)

@router.patch("/{case_id}")
def patch_case(
    case_id: str,
    payload: CaseUpdatePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update general metadata or lifecycle of a case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        # If status transition requested
        if payload.status and payload.status.upper() != case.status:
            case = svc_update_case_status(
                db=db,
                case_id=case.id,
                new_status=payload.status,
                actor=actor,
                note=payload.note
            )

        # Update remaining fields
        safe_title = html.escape(payload.title.strip()) if payload.title else None
        safe_desc = html.escape(payload.description.strip()) if payload.description is not None else None

        updated = svc_update_case(
            db=db,
            case_id=case.id,
            title=safe_title,
            description=safe_desc,
            severity=payload.severity,
            priority=payload.priority,
            assignee=payload.assignee,
            owner=payload.owner,
            tags=payload.tags,
            actor=actor
        )
        return serialize_case_detail(updated)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{case_id}/status")
def patch_case_status(
    case_id: str,
    payload: CaseStatusUpdatePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Transition case lifecycle status with server-side validation (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        updated = svc_update_case_status(
            db=db,
            case_id=case_id,
            new_status=payload.status,
            actor=actor,
            note=payload.note
        )
        return serialize_case_detail(updated)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{case_id}/assign")
def assign_case(
    case_id: str,
    payload: CaseAssignPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Reassign case owner or lead investigator (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    updated = svc_update_case(
        db=db,
        case_id=case.id,
        assignee=payload.assignee,
        owner=payload.owner,
        actor=actor
    )
    return serialize_case_detail(updated)

# ---------------------------------------------------------------------------
# Linking Endpoints
# ---------------------------------------------------------------------------

@router.post("/{case_id}/incidents")
def link_incident(
    case_id: str,
    payload: CaseLinkIncidentPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Link an Incident to this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        svc_link_incident(db, case_id, payload.incident_id, actor=actor)
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{case_id}/incidents/{incident_id}")
def unlink_incident(
    case_id: str,
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Unlink an Incident from this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        removed = svc_unlink_incident(db, case_id, incident_id, actor=actor)
        if not removed:
            raise HTTPException(status_code=404, detail="Incident link not found")
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{case_id}/alerts")
def link_alert(
    case_id: str,
    payload: CaseLinkAlertPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Link an Alert to this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        svc_link_alert(db, case_id, payload.alert_id, actor=actor)
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{case_id}/alerts/{alert_id}")
def unlink_alert(
    case_id: str,
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Unlink an Alert from this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        removed = svc_unlink_alert(db, case_id, alert_id, actor=actor)
        if not removed:
            raise HTTPException(status_code=404, detail="Alert link not found")
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{case_id}/indicators")
def link_indicator(
    case_id: str,
    payload: CaseLinkIndicatorPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Link an Indicator to this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        svc_link_indicator(db, case_id, payload.indicator_id, actor=actor)
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{case_id}/indicators/{indicator_id}")
def unlink_indicator(
    case_id: str,
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Unlink an Indicator from this Case (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    try:
        removed = svc_unlink_indicator(db, case_id, indicator_id, actor=actor)
        if not removed:
            raise HTTPException(status_code=404, detail="Indicator link not found")
        case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
        return serialize_case_detail(case)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# ---------------------------------------------------------------------------
# Forensic Evidence & Notes Endpoints
# ---------------------------------------------------------------------------

@router.get("/{case_id}/evidence")
def get_case_evidence(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve all forensic evidence attached to a Case (Authenticated)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence = db.query(CaseEvidence).filter(CaseEvidence.case_id == case.id).order_by(desc(CaseEvidence.created_at)).all()
    return [
        {
            "id": str(e.id),
            "evidence_type": e.evidence_type,
            "title": e.title,
            "description": e.description,
            "source_entity": e.source_entity,
            "source_provider": e.source_provider,
            "reference_hash": e.reference_hash,
            "confidence": e.confidence,
            "data": e.data or {},
            "observed_at": e.observed_at.isoformat() if e.observed_at else None,
            "collected_at": e.collected_at.isoformat() if e.collected_at else None,
            "collected_by": e.collected_by,
        }
        for e in evidence
    ]

@router.post("/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def add_case_evidence_endpoint(
    case_id: str,
    payload: CaseEvidencePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Add a forensic evidence item with provenance metadata (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    safe_title = html.escape(payload.title.strip())
    safe_desc = html.escape(payload.description.strip()) if payload.description else None

    ev = svc_add_evidence(
        db=db,
        case_id=case.id,
        evidence_type=payload.evidence_type,
        title=safe_title,
        description=safe_desc,
        source_entity=payload.source_entity,
        source_provider=payload.source_provider,
        reference_hash=payload.reference_hash,
        confidence=payload.confidence,
        data=payload.data,
        collected_by=actor,
        observed_at=payload.observed_at
    )
    return {
        "id": str(ev.id),
        "evidence_type": ev.evidence_type,
        "title": ev.title,
        "description": ev.description,
        "source_provider": ev.source_provider,
        "confidence": ev.confidence,
        "collected_by": ev.collected_by,
        "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
    }

@router.get("/{case_id}/notes")
def get_case_notes(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve chronological investigation notes for a Case (Authenticated)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    notes = db.query(CaseNote).filter(CaseNote.case_id == case.id).order_by(CaseNote.created_at.asc()).all()
    return [
        {
            "id": str(n.id),
            "author": n.author,
            "content": n.content,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in notes
    ]

@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_case_note_endpoint(
    case_id: str,
    payload: CaseNotePayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Add an append-only investigator note ensuring forensic integrity (Analyst+)."""
    actor = current_user.email or current_user.username or current_user.full_name or "SOC Analyst"
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Sanitize note content against XSS/HTML injection while preserving line breaks
    safe_content = html.escape(payload.content.strip())

    try:
        note = svc_add_note(
            db=db,
            case_id=case.id,
            author=actor,
            content=safe_content,
            author_id=str(current_user.id)
        )
        return {
            "id": str(note.id),
            "author": note.author,
            "content": note.content,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{case_id}/timeline")
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve ordered forensic timeline for an investigation case (Authenticated)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    timeline_entries = db.query(CaseTimeline).filter(
        CaseTimeline.case_id == case.id
    ).order_by(CaseTimeline.created_at.asc()).all()

    return [
        {
            "id": str(t.id),
            "case_id": str(t.case_id),
            "event_type": t.event_type,
            "title": t.title,
            "details": t.details,
            "actor": t.actor,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in timeline_entries
    ]

@router.get("/{case_id}/audit")
def get_case_audit(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve immutable audit trail specifically targeting this Case (Authenticated)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    target = f"case:{case.id}"
    logs = db.query(AuditLog).filter(
        or_(
            AuditLog.target_resource == target,
            AuditLog.details.ilike(f"%{case.id}%"),
            AuditLog.details.ilike(f"%{case.case_number}%")
        )
    ).order_by(desc(AuditLog.timestamp)).limit(100).all()

    return [
        {
            "id": str(log.id),
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "actor": log.actor,
            "action": log.action,
            "target_resource": log.target_resource,
            "details": log.details,
            "ip_address": log.ip_address,
        }
        for log in logs
    ]
