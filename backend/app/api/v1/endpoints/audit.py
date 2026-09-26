from typing import Optional
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.services.audit_service import log_action as record_audit_action
from app.core.rbac import require_admin

router = APIRouter()

@router.get("/")
def get_audit_logs(
    skip: int = 0,
    limit: int = 50,
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Administrator-only: retrieve platform audit trail."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "status": "success",
        "total_records": total,
        "logs": [
            {
                "id": str(log.id),
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user": log.actor or log.user_id or "System",
                "role": getattr(log, "role", "admin"),
                "action": log.action,
                "target_resource": log.target_resource,
                "details": log.details,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]
    }

@router.post("/record")
def record_action(
    user: str,
    role: str,
    action: str,
    details: str,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Administrator-only: manually append entry to audit trail."""
    entry = record_audit_action(
        db,
        action=action,
        actor=user,
        target_resource="audit",
        details={"role": role, "note": details},
        request=request
    )
    return {
        "status": "recorded",
        "entry": {
            "id": str(entry.id),
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "user": entry.actor,
            "action": entry.action,
            "details": entry.details,
        }
    }