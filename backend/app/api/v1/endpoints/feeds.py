from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone

from app.db.session import get_db
from app.models.feed import Feed
from app.models.user import User
from app.services.feed_service import (
    fetch_urlhaus_recent_urls,
    fetch_threatfox_recent_iocs,
    fetch_feodo_tracker_ips,
    fetch_malwarebazaar_recent_hashes,
    fetch_cisa_kev_cves,
    fetch_alienvault_otx_indicators,
    fetch_all_feeds,
)
from app.services.audit_service import log_action
from app.core.rbac import (
    require_authenticated_user,
    require_engineer,
)

router = APIRouter()

class FeedCreate(BaseModel):
    name: str
    enabled: bool = True
    poll_interval_seconds: int = 3600

class FeedToggle(BaseModel):
    enabled: bool

@router.get("/")
def list_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """List all registered threat intelligence feeds (Authenticated)."""
    feeds = db.query(Feed).all()
    if not feeds:
        # Default configured feeds if none seeded in DB (All 6 PRD feeds)
        default_names = ["urlhaus", "threatfox", "feodo_tracker", "malwarebazaar", "cisa_kev", "alienvault_otx"]
        for name in default_names:
            feed = Feed(name=name, enabled=True, poll_interval_seconds=3600)
            db.add(feed)
        db.commit()
        feeds = db.query(Feed).all()
    return feeds

@router.post("/fetch")
@router.post("/fetch-feed")
async def trigger_feed_fetch(
    source: Optional[str] = "all",
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Ingest live threat intelligence feeds (Security Engineer+).
    """
    results = {}
    if source in ["all", "urlhaus"]:
        results["urlhaus"] = await fetch_urlhaus_recent_urls(db)
    if source in ["all", "threatfox"]:
        results["threatfox"] = await fetch_threatfox_recent_iocs(db)
    if source in ["all", "feodo", "feodo_tracker"]:
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
            action="FEED_INGESTION_MANUAL",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{source}",
            details=results,
            request=request
        )
    except Exception:
        pass

    return {"status": "success", "summary": results}

@router.patch("/{feed_id}/toggle")
def toggle_feed(
    feed_id: str,
    payload: FeedToggle,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """Toggle feed enabled/disabled state (Security Engineer+)."""
    feed = db.query(Feed).filter(Feed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    
    old_state = feed.enabled
    feed.enabled = payload.enabled
    db.commit()
    db.refresh(feed)

    log_action(
        db,
        action="FEED_TOGGLED",
        actor=current_user.email,
        user_id=current_user.id,
        target_resource=f"feed:{feed.name}",
        details={"old_enabled": old_state, "new_enabled": feed.enabled},
        request=request
    )

    return feed
