import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, SmallInteger, Text, DateTime
from app.database import get_db, Base, engine
from app.models.indicator import AuditLog

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = {'extend_existing': True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    indicator_value = Column(Text, nullable=False)
    severity_score = Column(SmallInteger, default=70)
    status = Column(String(50), default="new", index=True) # new -> acknowledged -> in_progress -> resolved -> closed
    assignee = Column(String(100), default="Unassigned")
    source = Column(String(100), default="ThreatLens Stream")
    mitre_technique = Column(String(50), default="T1071")
    internal_sightings_count = Column(SmallInteger, default=1)
    internal_host = Column(String(100), default="host-wkstn-04.corp.local")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

Base.metadata.create_all(bind=engine)

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts & Correlation"])

class AlertStatusUpdate(BaseModel):
    status: str
    assignee: Optional[str] = None

@router.get("/")
def get_alerts(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    alerts = query.order_by(Alert.severity_score.desc()).all()
    
    # Auto-seed mock active alert if empty
    if not alerts:
        seed_alert = Alert(
            id=str(uuid.uuid4()),
            title="Active C2 Ingress - Emotet Payload Beacon",
            indicator_value="185.220.101.4",
            severity_score=92,
            status="new",
            assignee="Priya Nair",
            source="Feodo Tracker",
            mitre_technique="T1071.001",
            internal_sightings_count=3,
            internal_host="host-wkstn-04.corp.local"
        )
        db.add(seed_alert)
        db.commit()
        alerts = [seed_alert]
        
    return {"status": "success", "count": len(alerts), "data": alerts}

@router.patch("/{alert_id}")
def update_alert(alert_id: str, update: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    valid_states = ["new", "acknowledged", "in_progress", "resolved", "closed"]
    if update.status not in valid_states:
        raise HTTPException(status_code=400, detail=f"Invalid state. Must be one of: {valid_states}")
    
    alert.status = update.status
    if update.assignee:
        alert.assignee = update.assignee
    alert.updated_at = datetime.utcnow()
    
    # Append-only Audit Log
    audit = AuditLog(
        id=str(uuid.uuid4()),
        actor=update.assignee or "SOC Operator",
        action=f"ALERT_STATE_CHANGED_{update.status.upper()}",
        target_resource=f"/api/v1/alerts/{alert_id}",
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)
    return {"status": "success", "message": f"Alert transitioned to {alert.status}", "data": alert}
