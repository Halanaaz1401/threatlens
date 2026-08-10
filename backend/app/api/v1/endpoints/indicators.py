from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.models.indicator import Indicator
from app.services.feed_service import fetch_urlhaus_recent_urls

router = APIRouter()

@router.get("/")
def get_indicators(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    indicators = db.query(Indicator).offset(skip).limit(limit).all()
    return indicators

@router.post("/fetch-feed")
async def trigger_feed_ingestion(db: Session = Depends(get_db)):
    result = await fetch_urlhaus_recent_urls(db)
    return result