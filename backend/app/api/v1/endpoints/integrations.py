"""ThreatLens - Inbound SIEM/EDR Integrations and Webhook Endpoints (Phase 4D-D, FR-29).

Mounted under /api/v1/integrations/
Provides:
- Inbound webhook receivers for Splunk, QRadar, Sentinel, CrowdStrike, and Elastic Security
- Inbound security event authentication (Secret token, Bearer header, or HMAC SHA-256)
- Replay attack mitigation and rate limiting
- Event normalization, deduplication, rule evaluation, and incident correlation
- Management endpoints for listing, enabling, disabling, and inspecting integration configs
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.models.integration import WebhookConfig
from app.models.user import User
from app.core.config import settings
from app.core.rbac import (
    require_authenticated_user,
    require_engineer,
    require_admin
)
from app.services.webhook_service import (
    SUPPORTED_PROVIDERS,
    InboundSecurityEventPayload,
    adapt_inbound_provider_payload,
    ensure_default_webhook_configs,
    check_rate_limit,
    verify_webhook_authentication,
    process_inbound_security_event,
)
from app.services.audit_service import log_action

router = APIRouter()


class WebhookConfigUpdate(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    secret_token: Optional[str] = None
    hmac_secret: Optional[str] = None


def serialize_webhook_config(cfg: WebhookConfig) -> Dict[str, Any]:
    """Serialize WebhookConfig without exposing secrets."""
    return {
        "id": str(cfg.id),
        "provider": cfg.provider,
        "display_name": cfg.display_name,
        "description": cfg.description,
        "is_enabled": bool(cfg.is_enabled),
        "has_secret": bool(cfg.secret_token),
        "has_hmac": bool(cfg.hmac_secret),
        "total_events_received": int(cfg.total_events_received or 0),
        "last_received_at": cfg.last_received_at.isoformat() if cfg.last_received_at else None,
        "last_status": cfg.last_status,
        "last_error": cfg.last_error,
        "created_at": cfg.created_at.isoformat() if cfg.created_at else None,
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


# ===========================================================================
# 1. Inbound Webhook Receiver Endpoint (FR-29)
# ===========================================================================

@router.post("/webhooks/{provider}", status_code=status.HTTP_200_OK)
async def receive_inbound_webhook(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    x_threatlens_webhook_secret: Optional[str] = Header(None, alias="X-ThreatLens-Webhook-Secret"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_threatlens_signature: Optional[str] = Header(None, alias="X-ThreatLens-Signature"),
    x_threatlens_timestamp: Optional[str] = Header(None, alias="X-ThreatLens-Timestamp"),
):
    """
    Inbound security-event webhook receiver for SIEM/EDR providers (FR-29).
    Supported providers: splunk, qradar, sentinel, crowdstrike, elastic.
    Authenticates via X-ThreatLens-Webhook-Secret, Authorization Bearer, or HMAC signature.
    """
    clean_provider = provider.strip().lower()
    if clean_provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported webhook provider '{provider}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )

    # 1. Rate limiting check
    if not check_rate_limit(clean_provider):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for provider '{clean_provider}'. Please retry later."
        )

    # 2. Payload size check
    body_bytes = await request.body()
    if len(body_bytes) > settings.WEBHOOK_MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload size exceeds maximum allowed ({settings.WEBHOOK_MAX_PAYLOAD_BYTES} bytes)"
        )

    # 3. Ensure defaults initialized
    ensure_default_webhook_configs(db)

    # 4. Authenticate inbound webhook
    secret_candidate = x_threatlens_webhook_secret or authorization
    is_authenticated, auth_reason = verify_webhook_authentication(
        db=db,
        provider=clean_provider,
        secret_header=secret_candidate,
        signature_header=x_threatlens_signature,
        timestamp_header=x_threatlens_timestamp,
        raw_body=body_bytes
    )

    if not is_authenticated:
        # Audit authentication failure
        try:
            log_action(
                db=db,
                action="WEBHOOK_AUTH_FAILED",
                actor=f"integration:{clean_provider}",
                target_resource=f"provider:{clean_provider}",
                details={"reason": auth_reason, "ip": request.client.host if request.client else "unknown"}
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Webhook authentication failed: {auth_reason}"
        )

    # 5. Parse and validate JSON schema
    try:
        raw_json = await request.json()
    except Exception as json_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON body: {str(json_err)}"
        )

    try:
        event_payload = adapt_inbound_provider_payload(clean_provider, raw_json)
    except Exception as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid security event schema: {str(val_err)}"
        )

    # 6. Process through ThreatLens canonical pipeline
    raw_text = body_bytes.decode("utf-8", errors="replace")
    result = process_inbound_security_event(
        db=db,
        provider=clean_provider,
        payload=event_payload,
        raw_body_text=raw_text
    )

    return result


# ===========================================================================
# 2. Integration Management Endpoints (Authenticated)
# ===========================================================================

@router.get("/webhooks", response_model=List[Dict[str, Any]])
def list_webhook_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    List all configured inbound SIEM/EDR integrations with status and telemetry.
    """
    ensure_default_webhook_configs(db)
    configs = db.query(WebhookConfig).order_by(WebhookConfig.provider.asc()).all()
    return [serialize_webhook_config(c) for c in configs]


@router.get("/webhooks/{provider}", response_model=Dict[str, Any])
def get_webhook_integration(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    Inspect individual SIEM/EDR integration configuration and operational stats.
    """
    clean_provider = provider.strip().lower()
    ensure_default_webhook_configs(db)
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == clean_provider).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Integration provider '{clean_provider}' not found")
    return serialize_webhook_config(config)


@router.post("/webhooks/{provider}/enable", response_model=Dict[str, Any])
def enable_webhook_integration(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Enable inbound webhook integration for a specific provider (Security Engineer+).
    """
    clean_provider = provider.strip().lower()
    ensure_default_webhook_configs(db)
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == clean_provider).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Integration provider '{clean_provider}' not found")

    config.is_enabled = True
    config.last_error = None
    db.commit()
    db.refresh(config)

    try:
        log_action(
            db=db,
            action="INTEGRATION_ENABLED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"integration:{clean_provider}",
            details={"provider": clean_provider},
            request=request
        )
    except Exception:
        pass

    return {"status": "success", "message": f"Provider '{clean_provider}' enabled", "config": serialize_webhook_config(config)}


@router.post("/webhooks/{provider}/disable", response_model=Dict[str, Any])
def disable_webhook_integration(
    provider: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Disable inbound webhook integration for a specific provider (Security Engineer+).
    """
    clean_provider = provider.strip().lower()
    ensure_default_webhook_configs(db)
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == clean_provider).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Integration provider '{clean_provider}' not found")

    config.is_enabled = False
    db.commit()
    db.refresh(config)

    try:
        log_action(
            db=db,
            action="INTEGRATION_DISABLED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"integration:{clean_provider}",
            details={"provider": clean_provider},
            request=request
        )
    except Exception:
        pass

    return {"status": "success", "message": f"Provider '{clean_provider}' disabled", "config": serialize_webhook_config(config)}


@router.put("/webhooks/{provider}", response_model=Dict[str, Any])
@router.patch("/webhooks/{provider}", response_model=Dict[str, Any])
def update_webhook_integration(
    provider: str,
    payload: WebhookConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    """
    Update configuration for a SIEM/EDR integration (Security Engineer+).
    """
    clean_provider = provider.strip().lower()
    ensure_default_webhook_configs(db)
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == clean_provider).first()
    if not config:
        raise HTTPException(status_code=404, detail=f"Integration provider '{clean_provider}' not found")

    if payload.display_name is not None:
        config.display_name = payload.display_name.strip()
    if payload.description is not None:
        config.description = payload.description.strip()
    if payload.is_enabled is not None:
        config.is_enabled = payload.is_enabled
    if payload.secret_token is not None:
        config.secret_token = payload.secret_token.strip()
    if payload.hmac_secret is not None:
        config.hmac_secret = payload.hmac_secret.strip()

    db.commit()
    db.refresh(config)

    try:
        log_action(
            db=db,
            action="INTEGRATION_CONFIG_UPDATED",
            actor=current_user.email,
            user_id=current_user.id,
            target_resource=f"integration:{clean_provider}",
            details={"provider": clean_provider, "enabled": config.is_enabled},
            request=request
        )
    except Exception:
        pass

    return {"status": "success", "message": f"Provider '{clean_provider}' configuration updated", "config": serialize_webhook_config(config)}
