import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.core.websocket import ws_manager

# Yeh line zaroori hai:
router = APIRouter()

class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    assignee: Optional[str] = None

@router.get("/")
def get_alerts(
    skip: int = 0,
    limit: int = 50,
    status: Optional[AlertStatus] = None,
    severity: Optional[AlertSeverity] = None,
    db: Session = Depends(get_db)
):
    """Retrieve all alerts with status and severity filters (PRD Section 10.2)."""
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    
    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

@router.patch("/{alert_id}")
def update_alert_lifecycle(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Manage alert lifecycle state: NEW -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status
    if payload.assignee:
        alert.assignee = payload.assignee
    
    db.commit()
    db.refresh(alert)
    return alert

@router.websocket("/ws")
async def websocket_alerts_stream(websocket: WebSocket):
    """WebSocket stream for real-time alert broadcasts (PRD Section 10.3)."""
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)