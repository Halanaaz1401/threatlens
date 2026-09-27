from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import uuid

from app.db.session import get_db
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.services.feed_service import (
    fetch_urlhaus_recent_urls,
    fetch_threatfox_recent_iocs,
    fetch_feodo_tracker_ips,
    fetch_malwarebazaar_recent_hashes,
    fetch_cisa_kev_cves,
    fetch_alienvault_otx_indicators,
)
from app.services.audit_service import log_action
from app.services.scoring_service import calculate_ioc_severity
from app.services.search_service import index_indicator
from app.services.alert_service import evaluate_ioc_for_alerts

from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    require_engineer,
)
from app.models.user import User

router = APIRouter()

# Schemas
class IOCCreate(BaseModel):
    value: str
    type: IndicatorType
    source: str = "manual"
    confidence: int = 80
    tags: Optional[List[str]] = []
    context: Optional[dict] = {}

class IOCStatusUpdate(BaseModel):
    status: IndicatorStatus

@router.get("/")
def get_indicators(
    skip: int = 0,
    limit: int = 50,
    type: Optional[IndicatorType] = None,
    severity: Optional[ThreatSeverity] = None,
    status: Optional[IndicatorStatus] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Filter and search indicators with pagination."""
    query = db.query(Indicator)

    if type:
        query = query.filter(Indicator.type == type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if status:
        query = query.filter(Indicator.status == status)
    if search:
        query = query.filter(Indicator.value.ilike(f"%{search}%"))

    items = query.order_by(Indicator.last_seen.desc()).offset(skip).limit(limit).all()
    serialized = [
        {
            "id": str(i.id),
            "value": i.value,
            "type": str(i.type.value if hasattr(i.type, "value") else i.type),
            "source": i.source,
            "confidence": i.confidence,
            "threat_score": i.threat_score,
            "severity_score": i.threat_score,
            "severity": str(i.severity.value if hasattr(i.severity, "value") else i.severity),
            "status": str(i.status.value if hasattr(i.status, "value") else i.status),
            "sightings": i.sightings,
            "tags": i.tags or [],
            "context": i.context or {},
            "mitre_technique": (i.context or {}).get("mitre_technique", "T1071.001"),
            "first_seen": i.first_seen.isoformat() if i.first_seen else None,
            "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            "created_at": i.first_seen.isoformat() if i.first_seen else None,
            "updated_at": i.last_seen.isoformat() if i.last_seen else None,
        }
        for i in items
    ]
    return {
        "status": "success",
        "data": serialized,
        "total": len(serialized)
    }

@router.post("/create")
def create_manual_ioc(
    ioc_in: IOCCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Manually add an IOC with dynamic threat scoring & Elasticsearch projection (Analyst+)."""
    existing = db.query(Indicator).filter(Indicator.value == ioc_in.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="Indicator already exists in the system")

    # Dynamic Scoring Engine
    scoring = calculate_ioc_severity(
        confidence=ioc_in.confidence,
        source=ioc_in.source,
        sightings_count=1
    )

    # Convert severity string to ThreatSeverity Enum safely
    severity_value = ThreatSeverity[scoring["severity"]] if hasattr(ThreatSeverity, scoring["severity"]) else ThreatSeverity.MEDIUM

    new_ioc = Indicator(
        value=ioc_in.value,
        type=ioc_in.type,
        source=ioc_in.source,
        confidence=ioc_in.confidence,
        threat_score=scoring["score"],
        severity=severity_value,
        status=IndicatorStatus.ACTIVE,
        tags=ioc_in.tags or [],
        context=ioc_in.context or {}
    )
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    # Elasticsearch Projection
    try:
        index_indicator({
            "id": str(new_ioc.id),
            "value": new_ioc.value,
            "type": str(new_ioc.type.value if hasattr(new_ioc.type, "value") else new_ioc.type),
            "source": new_ioc.source,
            "severity": str(new_ioc.severity.value if hasattr(new_ioc.severity, "value") else new_ioc.severity),
            "status": str(new_ioc.status.value if hasattr(new_ioc.status, "value") else new_ioc.status),
            "threat_score": new_ioc.threat_score,
            "confidence": new_ioc.confidence,
            "tags": new_ioc.tags,
            "created_at": new_ioc.first_seen.isoformat() if new_ioc.first_seen else None
        })
    except Exception:
        pass

    # Trigger real-time alert evaluation (creates Alert and publishes to Redis Pub/Sub if high/critical)
    try:
        evaluate_ioc_for_alerts(db, new_ioc)
    except Exception:
        pass

    # Audit Logging
    try:
        log_action(
            db,
            action="IOC_MANUAL_CREATE",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"indicator:{new_ioc.id}",
            details={"ioc_id": str(new_ioc.id), "value": new_ioc.value, "severity": str(new_ioc.severity)},
            request=request
        )
    except Exception:
        pass

    return new_ioc

@router.patch("/{indicator_id}/status")
def update_ioc_status(
    indicator_id: str,
    status_update: IOCStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update IOC status and update Elasticsearch projection (Analyst+)."""
    ioc = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")

    old_status = str(ioc.status)
    ioc.status = status_update.status
    db.commit()
    db.refresh(ioc)

    # Update Elasticsearch Projection
    try:
        index_indicator({
            "id": str(ioc.id),
            "value": ioc.value,
            "type": str(ioc.type.value if hasattr(ioc.type, "value") else ioc.type),
            "source": ioc.source,
            "severity": str(ioc.severity.value if hasattr(ioc.severity, "value") else ioc.severity),
            "status": str(ioc.status.value if hasattr(ioc.status, "value") else ioc.status),
            "threat_score": ioc.threat_score,
            "confidence": ioc.confidence,
            "tags": ioc.tags
        })
    except Exception:
        pass

    # Audit Logging
    try:
        log_action(
            db,
            action="IOC_STATUS_UPDATE",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"indicator:{ioc.id}",
            details={"ioc_id": str(ioc.id), "old_status": old_status, "new_status": str(ioc.status)},
            request=request
        )
    except Exception:
        pass

    return {"message": "Status updated successfully", "indicator": ioc}

@router.post("/sync-feeds")
@router.post("/fetch-feed")
async def trigger_feed_ingestion(
    source: Optional[str] = "all",
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Ingest live threat intelligence feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar).
    """
    results = {}
    
    if source in ["all", "urlhaus"]:
        results["urlhaus"] = await fetch_urlhaus_recent_urls(db)
    if source in ["all", "threatfox"]:
        results["threatfox"] = await fetch_threatfox_recent_iocs(db)
    if source in ["all", "feodo"]:
        results["feodo_tracker"] = await fetch_feodo_tracker_ips(db)
    if source in ["all", "malwarebazaar"]:
        results["malwarebazaar"] = await fetch_malwarebazaar_recent_hashes(db)
    if source in ["all", "cisa", "cisa_kev"]:
        results["cisa_kev"] = await fetch_cisa_kev_cves(db)
    if source in ["all", "otx", "alienvault_otx"]:
        results["alienvault_otx"] = await fetch_alienvault_otx_indicators(db)

    try:
        log_action(
            db, 
            action="MULTI_FEED_INGESTION_TRIGGERED", 
            details=results, 
            request=request
        )
    except Exception:
        pass
    
    return {"status": "success", "summary": results}