from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from app.db.session import get_db
from app.models.feed import Feed
from app.models.user import User
from app.services.feed_service import (
    ensure_default_feeds,
    fetch_urlhaus_recent_urls,
    fetch_threatfox_recent_iocs,
    fetch_feodo_tracker_ips,
    fetch_malwarebazaar_recent_hashes,
    fetch_cisa_kev_cves,
    fetch_alienvault_otx_indicators,
    fetch_all_feeds,
)
from app.services.audit_service import log_action
from app.core.redis import publish_feed_event
from app.core.rbac import (
    require_authenticated_user,
    require_engineer,
    require_admin,
)

router = APIRouter()

class FeedCreate(BaseModel):
    name: str
    display_name: Optional[str] = None
    provider: Optional[str] = None
    feed_type: Optional[str] = "multi"
    endpoint_url: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    poll_interval_seconds: int = 3600

class FeedConfigUpdate(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    poll_interval_seconds: Optional[int] = Field(None, ge=60, le=86400)
    endpoint_url: Optional[str] = None
    enabled: Optional[bool] = None

class FeedToggle(BaseModel):
    enabled: bool

def serialize_feed(feed: Feed) -> Dict[str, Any]:
    """Serialize feed safely without exposing API secrets or authorization headers."""
    return {
        "id": str(feed.id),
        "name": feed.name,
        "display_name": feed.display_name or feed.name.replace("_", " ").title(),
        "provider": feed.provider or "Community",
        "feed_type": feed.feed_type or "multi",
        "endpoint_url": feed.endpoint_url,
        "description": feed.description,
        "enabled": bool(feed.enabled),
        "status": feed.status or ("active" if feed.enabled else "disabled"),
        "poll_interval_seconds": feed.poll_interval_seconds or 3600,
        "last_polled_at": feed.last_polled_at.isoformat() if feed.last_polled_at else None,
        "last_successful_fetch_at": feed.last_successful_fetch_at.isoformat() if feed.last_successful_fetch_at else None,
        "last_attempted_fetch_at": feed.last_attempted_fetch_at.isoformat() if feed.last_attempted_fetch_at else None,
        "error_message": feed.error_message,
        "total_indicators_ingested": feed.total_indicators_ingested or 0,
        "last_ingested_count": feed.last_ingested_count or 0,
        "created_at": feed.created_at.isoformat() if feed.created_at else None,
        "updated_at": feed.updated_at.isoformat() if feed.updated_at else None,
    }

def _find_feed(db: Session, identifier: str) -> Optional[Feed]:
    """Find feed by UUID or by canonical name."""
    feed = db.query(Feed).filter(Feed.id == identifier).first()
    if not feed:
        feed = db.query(Feed).filter(Feed.name == identifier).first()
    return feed

@router.get("/")
def list_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    FR-05: List all registered threat intelligence feeds with full provenance,
    scheduling, and honest operational status (Authenticated).
    """
    feeds = ensure_default_feeds(db)
    return [serialize_feed(f) for f in feeds]

@router.get("/{feed_id}")
def inspect_feed(
    feed_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    FR-05: Inspect detailed configuration and operational metrics of a specific feed (Authenticated).
    """
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return serialize_feed(feed)

@router.post("/{feed_id}/enable")
def enable_feed(
    feed_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    FR-05: Enable a threat intelligence feed (Security Engineer+).
    """
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed.enabled = True
    feed.status = "active"
    feed.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(feed)

    # Redis Event
    try:
        publish_feed_event("FEED_ENABLED", {
            "feed_id": str(feed.id),
            "feed_name": feed.name,
            "enabled": True,
            "status": feed.status,
            "actor": current_user.email,
        })
    except Exception:
        pass

    # Audit Logging
    try:
        log_action(
            db,
            action="FEED_ENABLED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{feed.name}",
            details={"feed_id": str(feed.id), "feed_name": feed.name, "enabled": True},
            request=request
        )
    except Exception:
        pass

    return serialize_feed(feed)

@router.post("/{feed_id}/disable")
def disable_feed(
    feed_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    FR-05: Disable a threat intelligence feed (Security Engineer+).
    """
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed.enabled = False
    feed.status = "disabled"
    feed.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(feed)

    # Redis Event
    try:
        publish_feed_event("FEED_DISABLED", {
            "feed_id": str(feed.id),
            "feed_name": feed.name,
            "enabled": False,
            "status": feed.status,
            "actor": current_user.email,
        })
    except Exception:
        pass

    # Audit Logging
    try:
        log_action(
            db,
            action="FEED_DISABLED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{feed.name}",
            details={"feed_id": str(feed.id), "feed_name": feed.name, "enabled": False},
            request=request
        )
    except Exception:
        pass

    return serialize_feed(feed)

@router.put("/{feed_id}")
@router.patch("/{feed_id}")
def update_feed_config(
    feed_id: str,
    config_in: FeedConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    FR-05: Update feed configuration like polling interval, display name, description (Security Engineer+).
    """
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    changes: Dict[str, Any] = {}
    if config_in.display_name is not None:
        changes["display_name"] = {"old": feed.display_name, "new": config_in.display_name}
        feed.display_name = config_in.display_name

    if config_in.description is not None:
        changes["description"] = {"old": feed.description, "new": config_in.description}
        feed.description = config_in.description

    if config_in.poll_interval_seconds is not None:
        changes["poll_interval_seconds"] = {"old": feed.poll_interval_seconds, "new": config_in.poll_interval_seconds}
        feed.poll_interval_seconds = config_in.poll_interval_seconds

    if config_in.endpoint_url is not None:
        changes["endpoint_url"] = {"old": feed.endpoint_url, "new": config_in.endpoint_url}
        feed.endpoint_url = config_in.endpoint_url

    if config_in.enabled is not None:
        changes["enabled"] = {"old": feed.enabled, "new": config_in.enabled}
        feed.enabled = config_in.enabled
        feed.status = "active" if config_in.enabled else "disabled"

    feed.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(feed)

    # Audit Logging
    try:
        log_action(
            db,
            action="FEED_CONFIG_UPDATE",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{feed.name}",
            details={"feed_id": str(feed.id), "feed_name": feed.name, "changes": changes},
            request=request
        )
    except Exception:
        pass

    return serialize_feed(feed)

@router.patch("/{feed_id}/toggle")
def toggle_feed(
    feed_id: str,
    payload: FeedToggle,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """Toggle feed enabled/disabled state (Security Engineer+)."""
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    
    old_state = feed.enabled
    feed.enabled = payload.enabled
    feed.status = "active" if payload.enabled else "disabled"
    feed.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(feed)

    try:
        log_action(
            db,
            action="FEED_TOGGLED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{feed.name}",
            details={"old_enabled": old_state, "new_enabled": feed.enabled},
            request=request
        )
    except Exception:
        pass

    return serialize_feed(feed)

@router.post("/{feed_id}/fetch")
async def trigger_single_feed_fetch(
    feed_id: str,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Trigger immediate ingestion for a specific feed (Security Engineer+).
    """
    feed = _find_feed(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed_name = feed.name
    res: Dict[str, Any] = {}
    if feed_name == "urlhaus":
        res = await fetch_urlhaus_recent_urls(db)
    elif feed_name == "threatfox":
        res = await fetch_threatfox_recent_iocs(db)
    elif feed_name in ["feodo", "feodo_tracker"]:
        res = await fetch_feodo_tracker_ips(db)
    elif feed_name == "malwarebazaar":
        res = await fetch_malwarebazaar_recent_hashes(db)
    elif feed_name in ["cisa", "cisa_kev"]:
        res = await fetch_cisa_kev_cves(db)
    elif feed_name in ["otx", "alienvault_otx"]:
        res = await fetch_alienvault_otx_indicators(db)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported feed '{feed_name}'")

    db.refresh(feed)
    try:
        log_action(
            db,
            action="FEED_INGESTION_MANUAL",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{feed_name}",
            details=res,
            request=request
        )
    except Exception:
        pass

    return {"status": "success", "feed": serialize_feed(feed), "result": res}

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
