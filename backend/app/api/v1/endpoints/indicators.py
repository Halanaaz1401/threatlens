from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
import uuid

from app.db.session import get_db
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.services.feed_service import fetch_urlhaus_recent_urls
from app.services.audit_service import log_action
from app.services.scoring_service import calculate_ioc_severity

router = APIRouter()

# Schemas for IOC Management
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

    return query.offset(skip).limit(limit).all()

@router.post("/create")
def create_manual_ioc(ioc_in: IOCCreate, request: Request, db: Session = Depends(get_db)):
    """Manually add an IOC with dynamic threat scoring."""
    existing = db.query(Indicator).filter(Indicator.value == ioc_in.value).first()
    if existing:
        raise HTTPException(status_code=400, detail="Indicator already exists in the system")

    # Dynamic Scoring Engine
    scoring = calculate_ioc_severity(
        confidence=ioc_in.confidence,
        source=ioc_in.source,
        sightings_count=1
    )

    new_ioc = Indicator(
        value=ioc_in.value,
        type=ioc_in.type,
        source=ioc_in.source,
        confidence=ioc_in.confidence,
        threat_score=scoring["score"],
        severity=scoring["severity"],
        status=IndicatorStatus.ACTIVE,
        tags=ioc_in.tags,
        context=ioc_in.context
    )
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    # Audit Logging
    log_action(
        db,
        action="IOC_MANUAL_CREATE",
        details={"ioc_id": str(new_ioc.id), "value": new_ioc.value, "severity": str(new_ioc.severity)},
        request=request
    )

    return new_ioc

@router.patch("/{indicator_id}/status")
def update_ioc_status(
    indicator_id: uuid.UUID,
    status_update: IOCStatusUpdate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Update IOC status (e.g. ACTIVE -> FALSE_POSITIVE or REVOKED)."""
    ioc = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")

    old_status = str(ioc.status)
    ioc.status = status_update.status
    db.commit()
    db.refresh(ioc)

    # Audit Logging
    log_action(
        db,
        action="IOC_STATUS_UPDATE",
        details={"ioc_id": str(ioc.id), "old_status": old_status, "new_status": str(ioc.status)},
        request=request
    )

    return {"message": "Status updated successfully", "indicator": ioc}

@router.post("/fetch-feed")
async def trigger_feed_ingestion(request: Request, db: Session = Depends(get_db)):
    result = await fetch_urlhaus_recent_urls(db)
    
    log_action(
        db, 
        action="FEED_INGESTION_TRIGGERED", 
        details=result if isinstance(result, dict) else {"status": "completed"}, 
        request=request
    )
    
    return result