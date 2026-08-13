from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.models.indicator import Indicator
from app.services.feed_service import fetch_urlhaus_recent_urls
from app.services.audit_service import log_action

router = APIRouter()

@router.get("/")
def get_indicators(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    indicators = db.query(Indicator).offset(skip).limit(limit).all()
    return indicators

@router.post("/fetch-feed")
async def trigger_feed_ingestion(request: Request, db: Session = Depends(get_db)):
    result = await fetch_urlhaus_recent_urls(db)
    
    # AUDIT LOG (Wired into state-changing action)
    log_action(
        db, 
        action="FEED_INGESTION_TRIGGERED", 
        details=result if isinstance(result, dict) else {"status": "completed"}, 
        request=request
    )
    
    return result