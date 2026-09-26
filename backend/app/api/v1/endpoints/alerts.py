from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.user import User
from app.core.websocket import ws_manager
from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    get_ws_current_user,
)
from app.services.audit_service import log_action

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
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve all alerts with status and severity filters (Authenticated)."""
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    
    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

@router.patch("/{alert_id}")
def update_alert_lifecycle(
    alert_id: str,
    payload: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Manage alert lifecycle state: NEW -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED (Analyst+)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    old_status = alert.status.value if hasattr(alert.status, "value") else str(alert.status)
    new_status = payload.status.value if hasattr(payload.status, "value") else str(payload.status)

    alert.status = payload.status
    if payload.assignee:
        alert.assignee = payload.assignee
    
    db.commit()
    db.refresh(alert)

    # Audit log alert lifecycle change
    log_action(
        db,
        action="ALERT_STATUS_UPDATE",
        actor=current_user.email,
        user_id=current_user.id,
        target_resource=f"alert:{alert.id}",
        details={"old_status": old_status, "new_status": new_status, "assignee": alert.assignee},
        request=request
    )

    return alert

@router.websocket("/ws")
async def websocket_alerts_stream(
    websocket: WebSocket,
    user: Optional[User] = Depends(get_ws_current_user)
):
    """Protected WebSocket stream for real-time alert broadcasts (Requires valid JWT)."""
    if user is None:
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)