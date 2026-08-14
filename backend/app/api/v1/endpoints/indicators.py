from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import uuid

from app.db.session import get_db
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.services.feed_service import fetch_urlhaus_recent_urls
from app.services.audit_service import log_action
from app.services.scoring_service import calculate_ioc_severity
from app.services.search_service import index_indicator

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
    db: Session = Depends(get_db)
):
    """Filter and search indicators with pagination (PostgreSQL)."""
    query = db.query(Indicator)

    if type:
        query = query.filter(Indicator.type == type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if status:
        query = query.filter(Indicator.status == status)
    if search:
        query = query.filter(Indicator.value.ilike(f"%{search}%"))

    return query.offset(skip).limit(limit).all()

@router.post("/create")
def create_manual_ioc(ioc_in: IOCCreate, request: Request, db: Session = Depends(get_db)):
    """Manually add an IOC with dynamic threat scoring & Elasticsearch projection."""
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

    # Audit Logging
    try:
        log_action(
            db,
            action="IOC_MANUAL_CREATE",
            details={"ioc_id": str(new_ioc.id), "value": new_ioc.value, "severity": str(new_ioc.severity)},
            request=request
        )
    except Exception:
        pass

    return new_ioc

@router.patch("/{indicator_id}/status")
def update_ioc_status(
    indicator_id: uuid.UUID,
    status_update: IOCStatusUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update IOC status and update Elasticsearch projection."""
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
            details={"ioc_id": str(ioc.id), "old_status": old_status, "new_status": str(ioc.status)},
            request=request
        )
    except Exception:
        pass

    return {"message": "Status updated successfully", "indicator": ioc}

@router.post("/fetch-feed")
async def trigger_feed_ingestion(request: Request, db: Session = Depends(get_db)):
    result = await fetch_urlhaus_recent_urls(db)
    
    try:
        log_action(
            db, 
            action="FEED_INGESTION_TRIGGERED", 
            details=result if isinstance(result, dict) else {"status": "completed"}, 
            request=request
        )
    except Exception:
        pass
    
    return result