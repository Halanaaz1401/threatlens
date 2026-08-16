from fastapi import APIRouter
import datetime

router = APIRouter()

AUDIT_TRAIL = []

@router.get("/")
def get_audit_logs():
    return {
        "status": "success",
        "total_records": len(AUDIT_TRAIL),
        "logs": list(reversed(AUDIT_TRAIL))
    }

@router.post("/record")
def log_action(user: str, role: str, action: str, details: str):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "user": user,
        "role": role,
        "action": action,
        "details": details
    }
    AUDIT_TRAIL.append(entry)
    return {"status": "recorded", "entry": entry}