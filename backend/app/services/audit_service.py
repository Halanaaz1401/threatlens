import json
from typing import Optional, Dict, Any, Union
from sqlalchemy.orm import Session
from fastapi import Request
from app.models.audit import AuditLog

def log_action(
    db: Session,
    action: str,
    user_id: Optional[Union[str, int]] = None,
    actor: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    target_resource: Optional[str] = None,
    request: Optional[Request] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """Log an administrative or system action to the canonical AuditLog table."""
    client_ip = ip_address
    if request and not client_ip:
        client_ip = request.client.host if request.client else None

    # Determine actor string
    actor_str = actor or (str(user_id) if user_id else "System")

    # Serialize details to JSON string
    details_str = "{}"
    if details is not None:
        if isinstance(details, (dict, list)):
            try:
                details_str = json.dumps(details)
            except Exception:
                details_str = str(details)
        else:
            details_str = str(details)

    target_res = target_resource or action or "system"
    log_entry = AuditLog(
        user_id=str(user_id) if user_id is not None else None,
        actor=actor_str,
        action=action,
        target_resource=target_res,
        details=details_str,
        ip_address=client_ip,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
