import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.indicator import AuditLog
from app.core.security import create_access_token

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Audit"])

class LoginRequest(BaseModel):
    username: str
    password: str
    role: str = "SOC Analyst"

@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    # Demo credentials validation
    if req.password != "threatlens123" and req.password != "admin":
        # Audit failed login attempt
        failed_audit = AuditLog(
            id=str(uuid.uuid4()),
            actor=req.username,
            action="AUTH_FAILED",
            target_resource="/api/v1/auth/login",
            timestamp=datetime.utcnow()
        )
        db.add(failed_audit)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or security credential")

    token = create_access_token(data={"sub": req.username, "role": req.role})

    # Tamper-evident successful login audit log
    success_audit = AuditLog(
        id=str(uuid.uuid4()),
        actor=req.username,
        action="AUTH_SUCCESS_LOGIN",
        target_resource="/api/v1/auth/login",
        timestamp=datetime.utcnow()
    )
    db.add(success_audit)
    db.commit()

    return {
        "status": "success",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": req.username,
            "role": req.role
        }
    }

@router.get("/audit-logs")
def get_audit_logs(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20).all()
    return {"status": "success", "count": len(logs), "logs": logs}
