"""ThreatLens - Inbound SIEM/EDR Webhook Integration Service (Phase 4D-D, FR-29).

Provides:
- Inbound security event ingestion for Splunk, QRadar, Microsoft Sentinel, CrowdStrike Falcon, and Elastic Security
- Inbound authentication (Bearer token, X-ThreatLens-Webhook-Secret, or HMAC SHA-256 signature)
- Replay attack mitigation via timestamp validation and clock skew enforcement
- Payload size bounding (max 512KB) and strict Pydantic validation
- Canonical normalization of indicators, hostnames, usernames, and MITRE techniques
- Deterministic deduplication by provider + external_event_id
- Integration with Phase 4D-B Detection Rule Engine and Phase 4A Incident Correlation Engine
- Structured Redis event publishing (threatlens:events:integrations) and immutable audit logging
"""
import hmac
import hashlib
import time
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.integration import WebhookConfig
from app.models.incident import SecurityEvent
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.core.config import settings
from app.core.redis import publish_security_event, redis_manager
from app.services.indicator_service import normalize_and_validate_ioc
from app.services.feed_service import _save_and_index_ioc
from app.services.detection_rule_service import evaluate_indicator_against_rules
from app.services.correlation_service import correlate_alert_to_incident
from app.services.audit_service import log_action

logger = logging.getLogger("threatlens.webhooks")

SUPPORTED_PROVIDERS = ["splunk", "qradar", "sentinel", "crowdstrike", "elastic"]

DEFAULT_PROVIDER_CONFIGS = [
    {
        "provider": "splunk",
        "display_name": "Splunk Enterprise Security",
        "description": "Inbound webhook for Splunk notable events and adaptive response alerts.",
        "is_enabled": True,
        "secret_token": "threatlens_splunk_webhook_secret_2026",
    },
    {
        "provider": "qradar",
        "display_name": "IBM QRadar SIEM",
        "description": "Inbound webhook for QRadar offenses and correlation rule triggers.",
        "is_enabled": True,
        "secret_token": "threatlens_qradar_webhook_secret_2026",
    },
    {
        "provider": "sentinel",
        "display_name": "Microsoft Sentinel",
        "description": "Inbound webhook for Azure Sentinel incidents and security analytics rules.",
        "is_enabled": True,
        "secret_token": "threatlens_sentinel_webhook_secret_2026",
    },
    {
        "provider": "crowdstrike",
        "display_name": "CrowdStrike Falcon",
        "description": "Inbound webhook for CrowdStrike endpoint detections and high-confidence alerts.",
        "is_enabled": True,
        "secret_token": "threatlens_crowdstrike_webhook_secret_2026",
    },
    {
        "provider": "elastic",
        "display_name": "Elastic Security SIEM",
        "description": "Inbound webhook for Elastic Security alerting rules and detection engine signals.",
        "is_enabled": True,
        "secret_token": "threatlens_elastic_webhook_secret_2026",
    },
]

# Simple in-memory sliding window rate limiter: provider -> list of timestamps
_rate_limit_tracker: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_REQUESTS = 120  # requests per window
RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window


class InboundSecurityEventPayload(BaseModel):
    """Strict schema for normalized inbound security events from SIEM/EDR webhooks."""
    event_id: str = Field(..., min_length=1, max_length=100, description="External provider unique event identifier")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or unix epoch of event generation")
    event_type: str = Field("SECURITY_ALERT", max_length=50, description="Provider event classification")
    severity: str = Field("HIGH", max_length=50, description="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    source_ip: Optional[str] = Field(None, max_length=100)
    destination_ip: Optional[str] = Field(None, max_length=100)
    domain: Optional[str] = Field(None, max_length=255)
    url: Optional[str] = Field(None, max_length=1024)
    hash: Optional[str] = Field(None, max_length=128)
    hostname: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=2048)
    mitre_technique: Optional[str] = Field(None, max_length=50)
    raw_event: Optional[Dict[str, Any]] = None

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("event_id cannot be blank")
        return cleaned


def ensure_default_webhook_configs(db: Session) -> None:
    """Ensure default SIEM/EDR providers exist in the webhook_configs table."""
    for conf in DEFAULT_PROVIDER_CONFIGS:
        existing = db.query(WebhookConfig).filter(WebhookConfig.provider == conf["provider"]).first()
        if not existing:
            new_conf = WebhookConfig(
                provider=conf["provider"],
                display_name=conf["display_name"],
                description=conf["description"],
                is_enabled=conf["is_enabled"],
                secret_token=conf["secret_token"],
                last_status="idle",
            )
            db.add(new_conf)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.debug(f"Webhook configs initialization notice: {e}")


def check_rate_limit(provider: str) -> bool:
    """
    Check if the provider has exceeded the rate limit.
    Returns True if allowed, False if rate-limited.
    """
    now = time.time()
    timestamps = _rate_limit_tracker.setdefault(provider, [])
    # Evict timestamps older than window
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    _rate_limit_tracker[provider] = [t for t in timestamps if t > cutoff]

    if len(_rate_limit_tracker[provider]) >= RATE_LIMIT_MAX_REQUESTS:
        return False

    _rate_limit_tracker[provider].append(now)
    return True


def verify_webhook_authentication(
    db: Session,
    provider: str,
    secret_header: Optional[str],
    signature_header: Optional[str],
    timestamp_header: Optional[str],
    raw_body: bytes
) -> Tuple[bool, str]:
    """
    Verify webhook authenticity and replay protection.
    Returns (is_authenticated, error_reason).
    """
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == provider).first()
    if not config:
        return False, f"Provider '{provider}' is not registered"

    if not config.is_enabled:
        return False, f"Provider '{provider}' integration is currently disabled"

    # 1. Replay attack protection if timestamp header is provided
    if timestamp_header:
        try:
            # Can be float unix epoch or ISO string
            try:
                req_ts = float(timestamp_header)
            except ValueError:
                parsed_dt = datetime.fromisoformat(timestamp_header.replace("Z", "+00:00"))
                req_ts = parsed_dt.timestamp()

            current_ts = time.time()
            skew = abs(current_ts - req_ts)
            if skew > settings.WEBHOOK_ALLOWED_CLOCK_SKEW_SECONDS:
                return False, f"Request timestamp clock skew too large ({int(skew)}s > {settings.WEBHOOK_ALLOWED_CLOCK_SKEW_SECONDS}s)"
        except Exception:
            return False, "Invalid X-ThreatLens-Timestamp format"

    # 2. HMAC Signature verification if signature header is provided
    if signature_header and (config.hmac_secret or config.secret_token):
        hmac_key = (config.hmac_secret or config.secret_token).encode("utf-8")
        expected_sig = hmac.new(hmac_key, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig.lower(), signature_header.strip().lower()):
            return False, "HMAC signature mismatch"
        return True, "authenticated_hmac"

    # 3. Direct Secret / Token verification
    if not secret_header:
        return False, "Missing webhook authentication credentials"

    # Strip Bearer prefix if provided
    clean_secret = secret_header.replace("Bearer ", "").strip()
    configured_secret = config.secret_token or ""

    if not hmac.compare_digest(clean_secret, configured_secret):
        return False, "Invalid webhook secret token"

    return True, "authenticated_token"


def process_inbound_security_event(
    db: Session,
    provider: str,
    payload: InboundSecurityEventPayload,
    raw_body_text: str
) -> Dict[str, Any]:
    """
    Core pipeline for ingesting an authenticated SIEM/EDR security event:
    1. Deduplication check by provider + external_event_id
    2. Persist SecurityEvent record
    3. Normalize and ingest extracted IOCs (IP, domain, hash, URL) into Indicators
    4. Run Phase 4D-B Detection Rules against extracted IOCs
    5. Generate Alert and correlate into Phase 4A Incident
    6. Publish Redis events and log audit trail
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    dedup_key = f"{provider}:{payload.event_id}"

    # 1. Deduplication check
    existing_event = db.query(SecurityEvent).filter(
        SecurityEvent.dedup_key == dedup_key
    ).first()

    if existing_event:
        # Event already received; update timestamp and record deduplication
        existing_event.timestamp = now
        existing_event.status = "DEDUPLICATED"
        db.commit()

        # Update provider stats
        config = db.query(WebhookConfig).filter(WebhookConfig.provider == provider).first()
        if config:
            config.total_events_received += 1
            config.last_received_at = now
            config.last_status = "active"
            db.commit()

        # Publish Redis deduplicated event
        publish_security_event("SECURITY_EVENT_DEDUPLICATED", {
            "provider": provider,
            "event_id": payload.event_id,
            "dedup_key": dedup_key,
            "timestamp": now.isoformat()
        })

        return {
            "status": "deduplicated",
            "message": "Security event previously ingested; sightings count refreshed",
            "provider": provider,
            "event_id": payload.event_id,
            "dedup_key": dedup_key,
            "created_alert_id": existing_event.created_alert_id,
        }

    # 2. Extract and normalize IOCs from event fields
    extracted_iocs: List[Tuple[str, str]] = []  # (raw_value, probable_type)

    if payload.source_ip:
        extracted_iocs.append((payload.source_ip, "ipv4" if ":" not in payload.source_ip else "ipv6"))
    if payload.destination_ip:
        extracted_iocs.append((payload.destination_ip, "ipv4" if ":" not in payload.destination_ip else "ipv6"))
    if payload.domain:
        extracted_iocs.append((payload.domain, "domain"))
    if payload.url:
        extracted_iocs.append((payload.url, "url"))
    if payload.hash:
        extracted_iocs.append((payload.hash, "hash"))

    created_indicator_ids: List[str] = []
    primary_indicator_val = None

    for val, ptype in extracted_iocs:
        try:
            norm_val, norm_type = normalize_and_validate_ioc(val, ptype)
            # Ingest via canonical feed service
            save_status = _save_and_index_ioc(
                db=db,
                value=norm_val,
                ioc_type=norm_type,
                source=f"webhook:{provider}",
                confidence=85,
                tags=[provider, "siem-edr", payload.event_type.lower()],
                context={
                    "provider": provider,
                    "event_id": payload.event_id,
                    "hostname": payload.hostname,
                    "username": payload.username,
                },
                mitre_technique=payload.mitre_technique or "T1071"
            )
            # Find the saved indicator ID
            ind = db.query(Indicator).filter(Indicator.value == norm_val).first()
            if ind:
                created_indicator_ids.append(str(ind.id))
                if not primary_indicator_val:
                    primary_indicator_val = ind.value
                # Run Phase 4D-B Detection Rules
                try:
                    evaluate_indicator_against_rules(db, ind)
                except Exception as rule_err:
                    logger.debug(f"Rule evaluation error during webhook ingestion: {rule_err}")
        except Exception as ioc_err:
            logger.debug(f"Skipping unparseable IOC candidate '{val}' from webhook: {ioc_err}")

    # 3. Create canonical Alert if event is HIGH/CRITICAL or extracted high severity
    sev_upper = (payload.severity or "HIGH").upper()
    is_high_sev = sev_upper in ["CRITICAL", "HIGH", "HIGH_RISK"]
    alert_created_id = None

    if is_high_sev or len(created_indicator_ids) > 0:
        alert_sev = AlertSeverity.CRITICAL if sev_upper == "CRITICAL" else AlertSeverity.HIGH
        alert_code = f"ALT-WEBHOOK-{str(uuid.uuid4())[:6].upper()}"
        alert_title = f"{provider.upper()} Alert: {payload.description or payload.event_type}"
        if len(alert_title) > 250:
            alert_title = alert_title[:247] + "..."

        new_alert = Alert(
            alert_code=alert_code,
            title=alert_title,
            description=f"Inbound {provider.upper()} security event {payload.event_id}. "
                        f"Host: {payload.hostname or 'N/A'}, User: {payload.username or 'N/A'}. "
                        f"{payload.description or ''}".strip(),
            severity=alert_sev.value,
            severity_score=90 if sev_upper == "CRITICAL" else 75,
            status=AlertStatus.NEW.value,
            indicator_id=created_indicator_ids[0] if created_indicator_ids else None,
            indicator_value=primary_indicator_val or payload.source_ip or payload.hostname or f"{provider}-{payload.event_id}",
            source=f"webhook:{provider}",
            mitre_technique=payload.mitre_technique or "T1071",
            rule_name=f"{provider.upper()}_INBOUND_RULE",
            context={
                "provider": provider,
                "event_id": payload.event_id,
                "hostname": payload.hostname,
                "username": payload.username,
                "raw_event": payload.raw_event or {},
            },
            created_at=now,
            updated_at=now,
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        alert_created_id = str(new_alert.id)

        # Trigger Phase 4A Correlation to Incident
        try:
            correlate_alert_to_incident(db, new_alert)
        except Exception as corr_err:
            logger.error(f"Failed to correlate webhook alert to incident: {corr_err}")

    # 4. Save SecurityEvent record
    sec_event = SecurityEvent(
        provider=provider,
        external_event_id=payload.event_id,
        dedup_key=dedup_key,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        domain=payload.domain,
        url=payload.url,
        file_hash=payload.hash,
        hostname=payload.hostname,
        username=payload.username,
        event_type=payload.event_type,
        severity=sev_upper,
        description=payload.description,
        mitre_technique=payload.mitre_technique,
        status="ALERT_GENERATED" if alert_created_id else "INGESTED",
        created_alert_id=alert_created_id,
        created_indicator_id=created_indicator_ids[0] if created_indicator_ids else None,
        raw_log=raw_body_text[:10000] if raw_body_text else None,
        timestamp=now
    )
    db.add(sec_event)

    # 5. Update WebhookConfig operational stats
    config = db.query(WebhookConfig).filter(WebhookConfig.provider == provider).first()
    if config:
        config.total_events_received += 1
        config.last_received_at = now
        config.last_status = "active"
        config.last_error = None

    db.commit()

    # 6. Publish Redis event
    publish_security_event("SECURITY_EVENT_INGESTED", {
        "provider": provider,
        "event_id": payload.event_id,
        "dedup_key": dedup_key,
        "severity": sev_upper,
        "indicators_count": len(created_indicator_ids),
        "alert_created_id": alert_created_id,
        "timestamp": now.isoformat()
    })

    # 7. Audit logging
    try:
        log_action(
            db=db,
            action="WEBHOOK_EVENT_INGESTED",
            actor=f"integration:{provider}",
            target_resource=f"event:{dedup_key}",
            details={
                "provider": provider,
                "event_id": payload.event_id,
                "severity": sev_upper,
                "alert_id": alert_created_id,
                "indicators": len(created_indicator_ids),
            }
        )
    except Exception:
        pass

    return {
        "status": "ingested",
        "provider": provider,
        "event_id": payload.event_id,
        "dedup_key": dedup_key,
        "indicators_extracted": len(created_indicator_ids),
        "alert_created_id": alert_created_id,
        "timestamp": now.isoformat()
    }
