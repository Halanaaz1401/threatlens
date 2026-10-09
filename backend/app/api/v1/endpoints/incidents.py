from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.models.incident import (
    Incident,
    IncidentStatus,
    IncidentSeverity,
    IncidentTimeline,
    is_valid_status_transition,
    VALID_STATUS_TRANSITIONS
)
from app.models.alert import Alert
from app.models.user import User
from app.services.correlation_service import (
    correlate_and_create_incident,
    update_incident_status as svc_update_incident_status,
    update_incident_severity as svc_update_incident_severity
)
from app.services.audit_service import log_action
from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
)

router = APIRouter()

class SecurityEventPayload(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    event_type: str = "NETWORK_TRAFFIC"
    raw_log: Optional[str] = None

class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="New incident status (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, CLOSED)")
    assignee: Optional[str] = None
    note: Optional[str] = None

class IncidentSeverityUpdate(BaseModel):
    severity: str = Field(..., description="New incident severity (LOW, MEDIUM, HIGH, CRITICAL)")
    reason: Optional[str] = None

def serialize_incident(inc: Incident) -> Dict[str, Any]:
    """Serialize Incident entity into clean API dictionary representation."""
    alert_ids = [str(a.id) for a in (inc.alerts or [])]
    return {
        "id": str(inc.id),
        "incident_code": inc.incident_code or f"INC-{str(inc.id)[:8].upper()}",
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
        "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status),
        "correlation_score": inc.correlation_score or 0,
        "assignee": inc.assignee,
        "indicator_id": str(inc.indicator_id) if inc.indicator_id else None,
        "matched_ioc_value": inc.matched_ioc_value or inc.primary_indicator,
        "primary_indicator": inc.primary_indicator or inc.matched_ioc_value,
        "primary_source": inc.primary_source,
        "mitre_techniques": inc.mitre_techniques or [],
        "affected_host": inc.affected_host,
        "alert_ids": alert_ids,
        "alerts_count": len(alert_ids),
        "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
        "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }

def serialize_alert(alert: Alert) -> Dict[str, Any]:
    """Serialize Alert entity into clean API representation."""
    return {
        "id": str(alert.id),
        "alert_code": alert.alert_code,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
        "severity_score": alert.severity_score,
        "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
        "indicator_id": str(alert.indicator_id) if alert.indicator_id else None,
        "indicator_value": alert.indicator_value,
        "rule_name": alert.rule_name,
        "source": alert.source,
        "mitre_technique": alert.mitre_technique,
        "internal_host": alert.internal_host,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }

@router.post("/correlate-event")
def ingest_and_correlate(
    payload: SecurityEventPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Ingest internal telemetry and trigger automated IOC correlation (Analyst+)."""
    incident = correlate_and_create_incident(db, payload.dict())
    if incident:
        return {
            "status": "INCIDENT_CREATED",
            "incident_id": str(incident.id),
            "incident_code": incident.incident_code,
            "matched_ioc": incident.matched_ioc_value or incident.primary_indicator,
            "severity": incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity)
        }
    return {"status": "LOG_PROCESSED_NO_MATCH"}

@router.get("/")
@router.get("")
def get_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filter by status (OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, CLOSED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    mitre_technique: Optional[str] = Query(None, description="Filter by MITRE ATT&CK technique (e.g. T1071)"),
    source: Optional[str] = Query(None, description="Filter by intelligence source"),
    affected_host: Optional[str] = Query(None, description="Filter by affected host / workstation"),
    min_score: Optional[int] = Query(None, description="Minimum correlation score"),
    start_time: Optional[datetime] = Query(None, description="Filter incidents active after start_time"),
    end_time: Optional[datetime] = Query(None, description="Filter incidents active before end_time"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    Retrieve all correlated incidents with multi-dimensional SOC filters (Authenticated).
    Supports status, severity, MITRE technique, host, source, min_score, and temporal range.
    """
    query = db.query(Incident)

    if status:
        query = query.filter(Incident.status.ilike(status.strip()))
    if severity:
        query = query.filter(Incident.severity.ilike(severity.strip()))
    if source:
        query = query.filter(Incident.primary_source.ilike(f"%{source.strip()}%"))
    if affected_host:
        query = query.filter(Incident.affected_host.ilike(f"%{affected_host.strip()}%"))
    if min_score is not None:
        query = query.filter(Incident.correlation_score >= min_score)
    if start_time:
        query = query.filter(Incident.last_seen >= start_time)
    if end_time:
        query = query.filter(Incident.first_seen <= end_time)
    if mitre_technique:
        query = query.filter(Incident.mitre_techniques.ilike(f"%{mitre_technique.strip()}%"))

    incidents = query.order_by(desc(Incident.last_seen), desc(Incident.created_at)).offset(skip).limit(limit).all()
    return [serialize_incident(inc) for inc in incidents]

@router.get("/{incident_id}")
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve detailed view of a single incident by ID or incident_code (Authenticated)."""
    incident = db.query(Incident).filter(
        or_(Incident.id == incident_id, Incident.incident_code == incident_id)
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return serialize_incident(incident)

@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve chronological investigation timeline for an incident (Authenticated)."""
    incident = db.query(Incident).filter(
        or_(Incident.id == incident_id, Incident.incident_code == incident_id)
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    entries = db.query(IncidentTimeline).filter(
        IncidentTimeline.incident_id == incident.id
    ).order_by(IncidentTimeline.created_at.asc()).all()

    return [
        {
            "id": str(t.id),
            "incident_id": str(t.incident_id),
            "action": t.action,
            "details": t.details,
            "actor": t.actor,
            "created_at": t.created_at.isoformat() if t.created_at else None
        }
        for t in entries
    ]

@router.get("/{incident_id}/alerts")
def get_incident_alerts(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve all correlated alerts attached to this incident (Authenticated)."""
    incident = db.query(Incident).filter(
        or_(Incident.id == incident_id, Incident.incident_code == incident_id)
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.created_at.desc()).all()
    return [serialize_alert(a) for a in alerts]

@router.patch("/{incident_id}/status")
def patch_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Update incident lifecycle status with strict server-side state transition validation (Analyst+).
    Valid transitions: OPEN -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED.
    """
    actor_name = current_user.email or current_user.full_name or "SOC Analyst"
    try:
        updated = svc_update_incident_status(
            db=db,
            incident_id=incident_id,
            new_status=payload.status,
            actor=actor_name,
            note=payload.note
        )
        if payload.assignee:
            updated.assignee = payload.assignee
            db.commit()
            db.refresh(updated)
        return serialize_incident(updated)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{incident_id}/severity")
def patch_incident_severity(
    incident_id: str,
    payload: IncidentSeverityUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Manually update incident severity with audit logging and timeline entry (Analyst+).
    Allowed: LOW, MEDIUM, HIGH, CRITICAL.
    """
    actor_name = current_user.email or current_user.full_name or "SOC Analyst"
    try:
        updated = svc_update_incident_severity(
            db=db,
            incident_id=incident_id,
            new_severity=payload.severity,
            actor=actor_name,
            reason=payload.reason
        )
        return serialize_incident(updated)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{incident_id}")
def update_incident_legacy(
    incident_id: str,
    payload: IncidentStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Legacy update endpoint (delegates to validated status update) (Analyst+)."""
    return patch_incident_status(incident_id, payload, request, db, current_user)