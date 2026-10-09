from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone, timedelta
import uuid

from app.db.session import get_db
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus, IndicatorSource
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
from app.services.indicator_service import (
    normalize_and_validate_ioc,
    calculate_expiration_date,
    serialize_indicator_detail,
    get_indicator_by_id,
)
from app.services.expiration_service import expire_stale_indicators
from app.core.redis import publish_ioc_event

from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    require_engineer,
    require_admin,
    normalize_role,
)
from app.models.user import User

router = APIRouter()

# Schemas
class IOCCreate(BaseModel):
    value: str
    type: Union[IndicatorType, str]
    source: str = "manual"
    confidence: int = 80
    tags: Optional[List[str]] = []
    context: Optional[dict] = {}
    mitre_technique: Optional[str] = None
    ttl_days: Optional[int] = 30
    expires_at: Optional[datetime] = None
    analyst_notes: Optional[str] = None

class IOCUpdate(BaseModel):
    confidence: Optional[int] = None
    severity: Optional[ThreatSeverity] = None
    threat_score: Optional[int] = None
    tlp: Optional[str] = None
    tags: Optional[List[str]] = None
    context: Optional[dict] = None
    mitre_technique: Optional[str] = None
    ttl_days: Optional[int] = None
    expires_at: Optional[datetime] = None
    analyst_notes: Optional[str] = None
    status: Optional[IndicatorStatus] = None
    revoked_reason: Optional[str] = None

class IOCStatusUpdate(BaseModel):
    status: IndicatorStatus
    revoked_reason: Optional[str] = None

class ExpireStaleRequest(BaseModel):
    batch_size: int = 100

@router.get("/")
@router.get("")
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
    """Filter and search indicators with pagination (Authenticated)."""
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
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    serialized = []
    for i in items:
        is_expired = False
        if i.status == IndicatorStatus.EXPIRED.value:
            is_expired = True
        elif i.expires_at and i.expires_at <= now_utc:
            is_expired = True

        serialized.append({
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
            "tlp": i.tlp or "amber",
            "tags": i.tags or [],
            "context": i.context or {},
            "mitre_technique": i.mitre_technique or (i.context or {}).get("mitre_technique", "T1071.001"),
            "expires_at": i.expires_at.isoformat() if i.expires_at else None,
            "ttl_days": i.ttl_days,
            "is_expired": is_expired,
            "analyst_notes": i.analyst_notes,
            "revoked_reason": i.revoked_reason,
            "first_seen": i.first_seen.isoformat() if i.first_seen else None,
            "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            "created_at": i.first_seen.isoformat() if i.first_seen else None,
            "updated_at": i.last_seen.isoformat() if i.last_seen else None,
        })

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
    """
    Manually add an IOC with strict normalization, validation, dynamic scoring,
    TTL assignment, and Elasticsearch projection (Analyst+).
    """
    try:
        norm_val, norm_type = normalize_and_validate_ioc(ioc_in.value, ioc_in.type)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))

    existing = db.query(Indicator).filter(Indicator.value == norm_val).first()
    if existing:
        raise HTTPException(status_code=400, detail="Indicator already exists in the system")

    # Dynamic Scoring Engine
    scoring = calculate_ioc_severity(
        confidence=ioc_in.confidence,
        source=ioc_in.source,
        sightings_count=1
    )

    severity_value = ThreatSeverity[scoring["severity"]] if hasattr(ThreatSeverity, scoring["severity"]) else ThreatSeverity.MEDIUM

    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = ioc_in.expires_at or calculate_expiration_date(ioc_in.ttl_days or 30, base_time=now_dt)

    new_ioc = Indicator(
        value=norm_val,
        type=norm_type.value if hasattr(norm_type, "value") else str(norm_type),
        source=ioc_in.source,
        confidence=ioc_in.confidence,
        threat_score=scoring["score"],
        severity=severity_value,
        status=IndicatorStatus.ACTIVE.value,
        tags=ioc_in.tags or [],
        context=ioc_in.context or {},
        mitre_technique=ioc_in.mitre_technique or (ioc_in.context or {}).get("mitre_technique"),
        expires_at=expires_at,
        ttl_days=ioc_in.ttl_days or 30,
        analyst_notes=ioc_in.analyst_notes,
        sightings=1,
        first_seen=now_dt,
        last_seen=now_dt,
        created_at=now_dt,
        updated_at=now_dt
    )
    db.add(new_ioc)
    db.flush()

    # Initial provenance
    try:
        prov = IndicatorSource(
            indicator_id=new_ioc.id,
            source_name=ioc_in.source,
            confidence=ioc_in.confidence,
            reported_at=now_dt
        )
        db.add(prov)
    except Exception:
        pass

    db.commit()
    db.refresh(new_ioc)

    # Elasticsearch Projection
    try:
        index_indicator({
            "id": str(new_ioc.id),
            "value": new_ioc.value,
            "type": str(new_ioc.type),
            "source": new_ioc.source,
            "severity": str(new_ioc.severity.value if hasattr(new_ioc.severity, "value") else new_ioc.severity),
            "status": str(new_ioc.status.value if hasattr(new_ioc.status, "value") else new_ioc.status),
            "threat_score": new_ioc.threat_score,
            "confidence": new_ioc.confidence,
            "tags": new_ioc.tags,
            "expires_at": new_ioc.expires_at.isoformat() if new_ioc.expires_at else None,
            "created_at": new_ioc.first_seen.isoformat() if new_ioc.first_seen else None
        })
    except Exception:
        pass

    # Trigger real-time alert evaluation
    try:
        evaluate_ioc_for_alerts(db, new_ioc)
    except Exception:
        pass

    # Redis event
    try:
        publish_ioc_event("IOC_CREATED", {
            "indicator_id": str(new_ioc.id),
            "value": new_ioc.value,
            "type": str(new_ioc.type),
            "severity": str(new_ioc.severity),
            "status": str(new_ioc.status),
            "created_by": current_user.email,
        })
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
            details={
                "ioc_id": str(new_ioc.id),
                "value": new_ioc.value,
                "type": str(new_ioc.type),
                "severity": str(new_ioc.severity),
                "ttl_days": new_ioc.ttl_days,
                "expires_at": new_ioc.expires_at.isoformat() if new_ioc.expires_at else None
            },
            request=request
        )
    except Exception:
        pass

    return serialize_indicator_detail(new_ioc, db=db)

@router.get("/{indicator_id}")
def get_indicator(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    FR-07: Get individual IOC full details, including provenance,
    lifecycle state, and expiration metadata (Authenticated).
    """
    ioc = get_indicator_by_id(db, indicator_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return serialize_indicator_detail(ioc, db=db)

@router.put("/{indicator_id}")
@router.patch("/{indicator_id}")
def update_indicator(
    indicator_id: str,
    update_in: IOCUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    FR-07: Update IOC metadata, tags, context, TLP, TTL/expiration,
    and analyst notes while preserving provenance (Analyst+).
    """
    ioc = get_indicator_by_id(db, indicator_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")

    changes: Dict[str, Any] = {}
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)

    if update_in.confidence is not None:
        changes["confidence"] = {"old": ioc.confidence, "new": update_in.confidence}
        ioc.confidence = update_in.confidence

    if update_in.severity is not None:
        old_sev = str(ioc.severity)
        ioc.severity = update_in.severity.value if hasattr(update_in.severity, "value") else str(update_in.severity)
        changes["severity"] = {"old": old_sev, "new": ioc.severity}

    if update_in.threat_score is not None:
        changes["threat_score"] = {"old": ioc.threat_score, "new": update_in.threat_score}
        ioc.threat_score = update_in.threat_score

    if update_in.tlp is not None:
        changes["tlp"] = {"old": ioc.tlp, "new": update_in.tlp}
        ioc.tlp = update_in.tlp

    if update_in.tags is not None:
        changes["tags"] = {"old": ioc.tags, "new": update_in.tags}
        ioc.tags = update_in.tags

    if update_in.context is not None:
        changes["context"] = {"old": ioc.context, "new": update_in.context}
        ioc.context = update_in.context

    if update_in.mitre_technique is not None:
        changes["mitre_technique"] = {"old": ioc.mitre_technique, "new": update_in.mitre_technique}
        ioc.mitre_technique = update_in.mitre_technique

    if update_in.analyst_notes is not None:
        changes["analyst_notes"] = {"old": ioc.analyst_notes, "new": update_in.analyst_notes}
        ioc.analyst_notes = update_in.analyst_notes

    if update_in.ttl_days is not None:
        changes["ttl_days"] = {"old": ioc.ttl_days, "new": update_in.ttl_days}
        ioc.ttl_days = update_in.ttl_days
        # Update expires_at automatically if not explicitly given
        if update_in.expires_at is None:
            new_exp = calculate_expiration_date(update_in.ttl_days, base_time=now_dt)
            changes["expires_at"] = {"old": ioc.expires_at.isoformat() if ioc.expires_at else None, "new": new_exp.isoformat()}
            ioc.expires_at = new_exp

    if update_in.expires_at is not None:
        changes["expires_at"] = {"old": ioc.expires_at.isoformat() if ioc.expires_at else None, "new": update_in.expires_at.isoformat()}
        ioc.expires_at = update_in.expires_at

    if update_in.status is not None:
        new_status_val = update_in.status.value if hasattr(update_in.status, "value") else str(update_in.status)
        if new_status_val == IndicatorStatus.REVOKED.value:
            reason = update_in.revoked_reason or "Revoked by analyst"
            ioc.revoked_reason = reason
            changes["revoked_reason"] = reason

        changes["status"] = {"old": str(ioc.status), "new": new_status_val}
        ioc.status = new_status_val

    if update_in.revoked_reason is not None:
        ioc.revoked_reason = update_in.revoked_reason
        changes["revoked_reason"] = update_in.revoked_reason

    ioc.updated_at = now_dt
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
            "tags": ioc.tags,
            "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
        })
    except Exception:
        pass

    # Redis Event
    try:
        publish_ioc_event("IOC_UPDATED", {
            "indicator_id": str(ioc.id),
            "value": ioc.value,
            "changes": changes,
            "updated_by": current_user.email,
        })
    except Exception:
        pass

    # Audit Logging
    try:
        log_action(
            db,
            action="IOC_UPDATE",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"indicator:{ioc.id}",
            details={"indicator_id": str(ioc.id), "changes": changes},
            request=request
        )
    except Exception:
        pass

    return serialize_indicator_detail(ioc, db=db)

@router.delete("/{indicator_id}")
def delete_or_revoke_indicator(
    indicator_id: str,
    request: Request,
    reason: Optional[str] = Query(None, description="Reason for revocation / deletion"),
    hard_delete: bool = Query(False, description="Physical delete (Admin only)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    FR-06/FR-07: Delete or Revoke an indicator.
    - Soft-delete / Revoke (Default, Analyst+): Sets status='revoked', preserving audit history and provenance.
    - Hard delete (Admin only): Physically deletes indicator and related records.
    """
    ioc = get_indicator_by_id(db, indicator_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")

    user_role = normalize_role(current_user.role)

    if hard_delete:
        if user_role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Physical deletion requires administrator privileges"
            )

        ioc_id = str(ioc.id)
        ioc_val = ioc.value
        db.delete(ioc)
        db.commit()

        # Audit
        try:
            log_action(
                db,
                action="IOC_HARD_DELETE",
                actor=current_user.email,
                user_id=current_user.id,
                target_resource=f"indicator:{ioc_id}",
                details={"indicator_id": ioc_id, "value": ioc_val, "reason": reason or "Admin purge"},
                request=request
            )
        except Exception:
            pass

        # Redis Event
        try:
            publish_ioc_event("IOC_DELETED", {
                "indicator_id": ioc_id,
                "value": ioc_val,
                "deleted_by": current_user.email,
            })
        except Exception:
            pass

        return {
            "status": "success",
            "message": f"Indicator {ioc_val} permanently deleted",
            "indicator_id": ioc_id
        }

    # Soft-delete / Revoke
    revocation_reason = reason or "Revoked by analyst"
    ioc.status = IndicatorStatus.REVOKED.value
    ioc.revoked_reason = revocation_reason
    ioc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(ioc)

    # Audit
    try:
        log_action(
            db,
            action="IOC_REVOKED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"indicator:{ioc.id}",
            details={"indicator_id": str(ioc.id), "value": ioc.value, "reason": revocation_reason},
            request=request
        )
    except Exception:
        pass

    # Redis Event
    try:
        publish_ioc_event("IOC_REVOKED", {
            "indicator_id": str(ioc.id),
            "value": ioc.value,
            "reason": revocation_reason,
            "revoked_by": current_user.email,
        })
    except Exception:
        pass

    return {
        "status": "success",
        "message": f"Indicator {ioc.value} marked as revoked",
        "indicator": serialize_indicator_detail(ioc, db=db)
    }

@router.patch("/{indicator_id}/status")
def update_ioc_status(
    indicator_id: str,
    status_update: IOCStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update IOC lifecycle status and project changes to Elasticsearch (Analyst+)."""
    ioc = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="Indicator not found")

    old_status = str(ioc.status)
    new_status_val = status_update.status.value if hasattr(status_update.status, "value") else str(status_update.status)
    ioc.status = new_status_val

    if new_status_val == IndicatorStatus.REVOKED.value:
        ioc.revoked_reason = status_update.revoked_reason or "Revoked by analyst"

    ioc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
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
            "tags": ioc.tags,
            "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
        })
    except Exception:
        pass

    # Redis Event
    try:
        publish_ioc_event("IOC_UPDATED", {
            "indicator_id": str(ioc.id),
            "value": ioc.value,
            "status": str(ioc.status),
            "updated_by": current_user.email,
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

    return {"message": "Status updated successfully", "indicator": serialize_indicator_detail(ioc, db=db)}

@router.post("/expire-stale")
def trigger_expiration_worker(
    request: Request,
    payload: Optional[ExpireStaleRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    FR-08: Trigger background TTL expiration worker (Security Engineer+).
    Deterministically transitions stale active indicators to 'expired'.
    """
    batch_size = payload.batch_size if payload else 100
    res = expire_stale_indicators(db, batch_size=batch_size)

    try:
        log_action(
            db,
            action="TTL_EXPIRATION_TRIGGERED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource="indicators:ttl_worker",
            details=res,
            request=request
        )
    except Exception:
        pass

    return {
        "status": "success",
        "result": res
    }

@router.post("/sync-feeds")
@router.post("/fetch-feed")
async def trigger_feed_ingestion(
    source: Optional[str] = "all",
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Ingest live threat intelligence feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, CISA KEV, AlienVault OTX).
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
            action="MULTI_FEED_INGESTION_TRIGGERED", 
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"feed:{source}",
            details=results, 
            request=request
        )
    except Exception:
        pass
    
    return {"status": "success", "summary": results}

class EnrichRequest(BaseModel):
    force_refresh: bool = False

@router.post("/{indicator_id}/enrich")
async def trigger_indicator_enrichment(
    indicator_id: str,
    request: Request,
    enrich_in: Optional[EnrichRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Trigger multi-provider threat intelligence enrichment (VirusTotal, AbuseIPDB, AlienVault OTX).
    Requires Analyst+ role.
    """
    from app.services.enrichment_service import enrich_indicator

    force_refresh = enrich_in.force_refresh if enrich_in else False
    try:
        result = await enrich_indicator(
            db,
            indicator_id=indicator_id,
            force_refresh=force_refresh,
            actor=current_user.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enrichment error: {str(e)}")

    try:
        log_action(
            db,
            action="INDICATOR_ENRICHMENT_TRIGGERED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"indicator:{indicator_id}",
            details={"indicator_id": indicator_id, "force_refresh": force_refresh, "status": result.get("status")},
            request=request,
        )
    except Exception:
        pass

    return result

@router.get("/{indicator_id}/enrichment")
def get_indicator_enrichment_summary(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Retrieve all stored enrichment records and synthesized context for an indicator."""
    from app.services.enrichment_service import get_indicator_enrichments, calculate_aggregate_intelligence
    from app.services.enrichment.base import NormalizedEnrichmentResult

    indicator = db.query(Indicator).filter(Indicator.id == str(indicator_id)).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    enrichments = get_indicator_enrichments(db, indicator_id)
    normalized_records = [
        NormalizedEnrichmentResult(
            provider=r["provider"],
            queried_value=r["queried_value"],
            indicator_type=r["indicator_type"],
            verdict=r["verdict"],
            confidence=r["confidence"],
            malicious_count=r["malicious_count"],
            suspicious_count=r["suspicious_count"],
            tags=r["tags"],
            malware_families=r["malware_families"],
            threat_actors=r["threat_actors"],
            success=r["success"],
        )
        for r in enrichments
    ]
    aggregate = calculate_aggregate_intelligence(normalized_records)

    return {
        "status": "success",
        "indicator_id": str(indicator.id),
        "value": indicator.value,
        "type": str(indicator.type.value if hasattr(indicator.type, "value") else indicator.type),
        "aggregate": aggregate,
        "enrichments": enrichments,
    }

@router.get("/{indicator_id}/enrichment/{provider}")
def get_indicator_enrichment_provider(
    indicator_id: str,
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Retrieve enrichment results for a specific provider (virustotal, abuseipdb, alienvault_otx)."""
    from app.services.enrichment_service import get_indicator_enrichment_by_provider

    indicator = db.query(Indicator).filter(Indicator.id == str(indicator_id)).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    enrichment = get_indicator_enrichment_by_provider(db, indicator_id, provider)
    if not enrichment:
        raise HTTPException(status_code=404, detail=f"No enrichment found from provider '{provider}'")

    return {
        "status": "success",
        "indicator_id": str(indicator.id),
        "provider": provider,
        "enrichment": enrichment,
    }