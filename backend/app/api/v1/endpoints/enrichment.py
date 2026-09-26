from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.services.enrichment_service import get_ip_enrichment, get_domain_enrichment
from app.services.audit_service import log_action
from app.core.rbac import require_authenticated_user

router = APIRouter()

@router.get("/ip/{ip_address}")
async def enrich_ip(
    ip_address: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Perform IP geolocation and ASN lookup (Authenticated)."""
    result = await get_ip_enrichment(ip_address)
    log_action(
        db,
        action="ENRICH_IP_LOOKUP",
        actor=current_user.email,
        user_id=current_user.id,
        target_resource=f"ip:{ip_address}",
        details={"ip": ip_address},
        request=request
    )
    return result

@router.get("/domain/{domain_name}")
async def enrich_domain(
    domain_name: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Perform domain intelligence enrichment (Authenticated)."""
    result = await get_domain_enrichment(domain_name)
    log_action(
        db,
        action="ENRICH_DOMAIN_LOOKUP",
        actor=current_user.email,
        user_id=current_user.id,
        target_resource=f"domain:{domain_name}",
        details={"domain": domain_name},
        request=request
    )
    return result