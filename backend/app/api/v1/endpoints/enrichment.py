from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.indicator import Indicator
from app.services.enrichment_service import (
    get_ip_enrichment,
    get_domain_enrichment,
    enrich_indicator,
    get_indicator_enrichments,
    get_indicator_enrichment_by_provider,
    refresh_expired_enrichments,
    calculate_aggregate_intelligence,
)
from app.services.enrichment import get_available_providers
from app.services.enrichment.base import NormalizedEnrichmentResult
from app.services.audit_service import log_action
from app.core.rbac import require_authenticated_user, require_analyst

router = APIRouter()

class RefreshRequest(BaseModel):
    limit: Optional[int] = 50

class EnrichRequest(BaseModel):
    force_refresh: bool = False

@router.get("/providers")
def list_threat_intel_providers(
    current_user: User = Depends(require_authenticated_user),
):
    """
    List registered external threat intelligence providers and their operational status.
    Never exposes provider API keys or credentials.
    """
    providers = get_available_providers()
    return {
        "status": "success",
        "providers": [p.health_check() for p in providers],
    }

@router.post("/refresh")
async def batch_refresh_enrichments(
    request: Request,
    refresh_in: Optional[RefreshRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Batch refresh expired threat intelligence enrichments across indicators (Analyst+).
    """
    limit = refresh_in.limit if refresh_in and refresh_in.limit else 50
    result = await refresh_expired_enrichments(db, limit=limit)

    try:
        log_action(
            db,
            action="ENRICHMENT_BATCH_REFRESH",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource="indicators:enrichment",
            details=result,
            request=request,
        )
    except Exception:
        pass

    return result

@router.post("/indicators/{indicator_id}/enrich")
async def trigger_enrichment_alias(
    indicator_id: str,
    request: Request,
    enrich_in: Optional[EnrichRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Enrich indicator endpoint mounted under /enrichment prefix."""
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

@router.get("/indicators/{indicator_id}")
def get_enrichment_summary_alias(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Retrieve enrichment summary for indicator mounted under /enrichment prefix."""
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

@router.get("/indicators/{indicator_id}/{provider}")
def get_enrichment_provider_alias(
    indicator_id: str,
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Retrieve specific provider enrichment for indicator."""
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

@router.get("/ip/{ip_address}")
async def enrich_ip(
    ip_address: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Perform IP geolocation and ASN lookup (Authenticated)."""
    result = await get_ip_enrichment(ip_address)
    try:
        log_action(
            db,
            action="ENRICH_IP_LOOKUP",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"ip:{ip_address}",
            details={"ip": ip_address},
            request=request,
        )
    except Exception:
        pass
    return result

@router.get("/domain/{domain_name}")
async def enrich_domain(
    domain_name: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Perform domain intelligence enrichment (Authenticated)."""
    result = await get_domain_enrichment(domain_name)
    try:
        log_action(
            db,
            action="ENRICH_DOMAIN_LOOKUP",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"domain:{domain_name}",
            details={"domain": domain_name},
            request=request,
        )
    except Exception:
        pass
    return result