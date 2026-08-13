import json
from sqlalchemy.orm import Session
from app.models.audit import AuditLog
from fastapi import Request
from typing import Optional, Dict, Any

def log_action(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None
):
    ip_address = None
    if request:
        ip_address = request.client.host if request.client else None

    # Convert dict to JSON string for PostgreSQL compatibility
    details_data = details or {}
    if isinstance(details_data, dict):
        try:
            details_data = json.dumps(details_data)
        except Exception:
            details_data = str(details_data)

    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details_data,
        ip_address=ip_address
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
