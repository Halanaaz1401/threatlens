from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentTimeline
from app.models.user import User
from app.services.correlation_service import correlate_and_create_incident
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
    status: IncidentStatus
    assignee: Optional[str] = None
    note: Optional[str] = None

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
            "matched_ioc": incident.matched_ioc_value,
            "severity": incident.severity.value
        }
    return {"status": "LOG_PROCESSED_NO_MATCH"}

@router.get("/")
def get_incidents(
    skip: int = 0,
    limit: int = 50,
    status: Optional[IncidentStatus] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve all correlated incidents (Authenticated)."""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve chronological investigation timeline for an incident (Authenticated)."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.timeline

@router.patch("/{incident_id}")
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update incident status and automatically append to investigation timeline (Analyst+)."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status.value if hasattr(incident.status, "value") else str(incident.status)
    new_status = payload.status.value if hasattr(payload.status, "value") else str(payload.status)

    incident.status = payload.status
    if payload.assignee:
        incident.assignee = payload.assignee

    actor_name = current_user.email or current_user.full_name or "SOC Analyst"

    # Append timeline entry
    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        action=f"STATUS_CHANGED: {old_status} -> {new_status}",
        details=payload.note or f"Assigned to {payload.assignee or 'Analyst'}",
        actor=actor_name
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(incident)

    # Audit log
    log_action(
        db,
        action="INCIDENT_STATUS_UPDATE",
        actor=current_user.email,
        user_id=current_user.id,
        target_resource=f"incident:{incident.id}",
        details={"old_status": old_status, "new_status": new_status, "assignee": incident.assignee},
        request=request
    )

    return incident