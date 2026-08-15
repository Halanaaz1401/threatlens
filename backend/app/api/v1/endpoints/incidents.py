import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentTimeline
from app.services.correlation_service import correlate_and_create_incident

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
    db: Session = Depends(get_db)
):
    """Ingest internal telemetry and trigger automated IOC correlation."""
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
    db: Session = Depends(get_db)
):
    """Retrieve all correlated incidents."""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db)
):
    """Retrieve chronological investigation timeline for an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.timeline

@router.patch("/{incident_id}")
def update_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
    """Update incident status and automatically append to investigation timeline."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status.value
    incident.status = payload.status
    if payload.assignee:
        incident.assignee = payload.assignee

    # Append timeline entry
    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        action=f"STATUS_CHANGED: {old_status} -> {payload.status.value}",
        details=payload.note or f"Assigned to {payload.assignee or 'Analyst'}",
        actor=payload.assignee or "SOC Analyst"
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(incident)
    return incident