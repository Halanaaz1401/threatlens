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


# ===========================================================================
# Provider-Specific Native SIEM/EDR Payload Adapters (Finding-4DD-01)
# ===========================================================================

def adapt_splunk_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map native Splunk notable events, alerts, and search exports."""
    res = raw.get("result") if isinstance(raw.get("result"), dict) else raw
    event_id = str(
        raw.get("sid") or raw.get("event_id") or raw.get("search_id") or
        raw.get("alert_id") or res.get("event_id") or res.get("rid") or ""
    )

    return {
        "event_id": event_id,
        "timestamp": str(res.get("_time") or res.get("timestamp") or raw.get("timestamp") or ""),
        "event_type": str(raw.get("event_type") or res.get("event_type") or "SPLUNK_NOTABLE_EVENT"),
        "severity": str(res.get("urgency") or res.get("severity") or raw.get("severity") or "HIGH").upper(),
        "source_ip": res.get("src_ip") or res.get("src") or res.get("source_ip"),
        "destination_ip": res.get("dest_ip") or res.get("dest") or res.get("destination_ip"),
        "domain": res.get("query") or res.get("domain"),
        "url": res.get("url"),
        "hash": res.get("file_hash") or res.get("hash"),
        "hostname": res.get("dest_host") or res.get("host") or res.get("hostname"),
        "username": res.get("src_user") or res.get("user") or res.get("username"),
        "description": res.get("description") or raw.get("search_name") or raw.get("description"),
        "mitre_technique": res.get("mitre_technique_id") or res.get("mitre_technique") or raw.get("mitre_technique"),
        "raw_event": raw,
    }


def adapt_qradar_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map native IBM QRadar offenses, correlations, and event exports."""
    event_id = str(raw.get("offense_id") or raw.get("id") or raw.get("event_id") or "")

    # QRadar numeric severity (1-10) mapping
    raw_sev = raw.get("severity")
    if isinstance(raw_sev, (int, float)):
        sev = "CRITICAL" if raw_sev >= 8 else "HIGH" if raw_sev >= 6 else "MEDIUM" if raw_sev >= 4 else "LOW"
    elif isinstance(raw_sev, str) and raw_sev.isdigit():
        val = int(raw_sev)
        sev = "CRITICAL" if val >= 8 else "HIGH" if val >= 6 else "MEDIUM" if val >= 4 else "LOW"
    else:
        sev = str(raw_sev or "HIGH").upper()

    return {
        "event_id": event_id,
        "timestamp": str(raw.get("start_time") or raw.get("timestamp") or ""),
        "event_type": str(raw.get("event_type") or "QRADAR_OFFENSE"),
        "severity": sev,
        "source_ip": raw.get("offense_source") or raw.get("source_address") or raw.get("source_ip"),
        "destination_ip": raw.get("destination_address") or raw.get("destination_ip"),
        "domain": raw.get("domain_name") or raw.get("domain"),
        "url": raw.get("url"),
        "hash": raw.get("file_hash") or raw.get("hash"),
        "hostname": raw.get("offense_target") or raw.get("hostname"),
        "username": raw.get("assigned_to") or raw.get("username"),
        "description": raw.get("description") or raw.get("offense_type_name"),
        "mitre_technique": raw.get("mitre_technique"),
        "raw_event": raw,
    }


def adapt_sentinel_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map native Microsoft Sentinel incidents and analytic rule alerts."""
    props = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    entities = raw.get("entities") if isinstance(raw.get("entities"), list) else []

    event_id = str(
        raw.get("id") or raw.get("incident_number") or raw.get("IncidentId") or
        props.get("incidentNumber") or raw.get("event_id") or ""
    )

    source_ip = raw.get("source_ip") or props.get("source_ip")
    destination_ip = raw.get("destination_ip") or props.get("destination_ip")
    domain = raw.get("domain") or props.get("domain")
    url = raw.get("url") or props.get("url")
    file_hash = raw.get("hash") or props.get("hash")
    hostname = raw.get("hostname") or props.get("hostname") or props.get("HostName")
    username = raw.get("username") or props.get("username") or props.get("AccountName")

    for ent in entities:
        if isinstance(ent, dict):
            kind = ent.get("kind", "").lower()
            if kind == "ip":
                if not source_ip:
                    source_ip = ent.get("address")
                elif not destination_ip and ent.get("address") != source_ip:
                    destination_ip = ent.get("address")
            elif kind == "host" and not hostname:
                hostname = ent.get("hostName") or ent.get("netBiosName")
            elif kind == "account" and not username:
                username = ent.get("name") or ent.get("upnSuffix")
            elif kind == "dnsresolution" and not domain:
                domain = ent.get("domainName")
            elif kind == "filehash" and not file_hash:
                file_hash = ent.get("value")

    sev = str(raw.get("severity") or props.get("severity") or raw.get("Severity") or "HIGH").upper()

    return {
        "event_id": event_id,
        "timestamp": str(raw.get("created_time") or props.get("createdTimeUtc") or raw.get("timestamp") or ""),
        "event_type": str(raw.get("event_type") or "SENTINEL_INCIDENT"),
        "severity": sev,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "domain": domain,
        "url": url,
        "hash": file_hash,
        "hostname": hostname,
        "username": username,
        "description": raw.get("title") or props.get("title") or raw.get("IncidentName") or raw.get("description"),
        "mitre_technique": raw.get("mitre_technique") or (props.get("techniques", [None])[0] if isinstance(props.get("techniques"), list) and props.get("techniques") else None),
        "raw_event": raw,
    }


def adapt_crowdstrike_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map native CrowdStrike Falcon detection and endpoint telemetry webhooks."""
    evt = raw.get("event") if isinstance(raw.get("event"), dict) else raw

    event_id = str(
        raw.get("CompositeId") or raw.get("detect_id") or raw.get("detection_id") or
        raw.get("event_id") or evt.get("detect_id") or ""
    )

    sev = str(evt.get("SeverityName") or raw.get("SeverityName") or raw.get("severity") or "HIGH").upper()

    return {
        "event_id": event_id,
        "timestamp": str(evt.get("ProcessStartTime") or raw.get("timestamp") or ""),
        "event_type": str(raw.get("event_type") or "CROWDSTRIKE_DETECTION"),
        "severity": sev,
        "source_ip": evt.get("LocalIP") or evt.get("source_ip") or raw.get("source_ip"),
        "destination_ip": evt.get("RemoteIP") or evt.get("destination_ip") or raw.get("destination_ip"),
        "domain": evt.get("DomainName") or raw.get("domain"),
        "url": evt.get("Url") or raw.get("url"),
        "hash": evt.get("SHA256String") or evt.get("MD5String") or raw.get("hash"),
        "hostname": evt.get("ComputerName") or raw.get("hostname"),
        "username": evt.get("UserName") or raw.get("username"),
        "description": evt.get("DetectDescription") or raw.get("description"),
        "mitre_technique": evt.get("Technique") or evt.get("Tactic") or raw.get("mitre_technique"),
        "raw_event": raw,
    }


def adapt_elastic_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map native Elastic Security alert signals and Kibana alerting rule triggers."""
    sig = raw.get("signal") if isinstance(raw.get("signal"), dict) else {}
    rule = sig.get("rule", {}) if isinstance(sig.get("rule"), dict) else (raw.get("rule", {}) if isinstance(raw.get("rule"), dict) else {})

    event_id = str(
        raw.get("id") or raw.get("alert_id") or raw.get("signal_id") or
        raw.get("event_id") or sig.get("id") or ""
    )

    # Source IP
    src_ip = None
    if isinstance(raw.get("source_ip"), str):
        src_ip = raw.get("source_ip")
    elif isinstance(raw.get("source.ip"), str):
        src_ip = raw.get("source.ip")
    elif isinstance(raw.get("source"), dict) and isinstance(raw.get("source", {}).get("ip"), str):
        src_ip = raw.get("source", {}).get("ip")
    elif isinstance(sig.get("source_ip"), str):
        src_ip = sig.get("source_ip")

    # Destination IP
    dest_ip = None
    if isinstance(raw.get("destination_ip"), str):
        dest_ip = raw.get("destination_ip")
    elif isinstance(raw.get("destination.ip"), str):
        dest_ip = raw.get("destination.ip")
    elif isinstance(raw.get("destination"), dict) and isinstance(raw.get("destination", {}).get("ip"), str):
        dest_ip = raw.get("destination", {}).get("ip")
    elif isinstance(sig.get("destination_ip"), str):
        dest_ip = sig.get("destination_ip")

    # URL and Domain
    url_raw = raw.get("url")
    url = None
    domain = None

    if isinstance(url_raw, dict):
        url = url_raw.get("full") or url_raw.get("original")
        domain = url_raw.get("domain")
    elif isinstance(url_raw, str):
        url = url_raw

    if not domain:
        if isinstance(raw.get("domain"), str):
            domain = raw.get("domain")
        elif isinstance(raw.get("url.domain"), str):
            domain = raw.get("url.domain")
        elif isinstance(raw.get("dns"), dict) and isinstance(raw.get("dns", {}).get("question", {}).get("name"), str):
            domain = raw.get("dns", {}).get("question", {}).get("name")

    if not url and isinstance(raw.get("url.full"), str):
        url = raw.get("url.full")

    # Hash
    file_hash = None
    if isinstance(raw.get("hash"), str):
        file_hash = raw.get("hash")
    elif isinstance(raw.get("file.hash.sha256"), str):
        file_hash = raw.get("file.hash.sha256")
    elif isinstance(raw.get("file"), dict):
        f_hash = raw.get("file", {}).get("hash")
        if isinstance(f_hash, dict):
            file_hash = f_hash.get("sha256") or f_hash.get("md5")
        elif isinstance(f_hash, str):
            file_hash = f_hash

    # Hostname
    hostname = None
    if isinstance(raw.get("hostname"), str):
        hostname = raw.get("hostname")
    elif isinstance(raw.get("host.name"), str):
        hostname = raw.get("host.name")
    elif isinstance(raw.get("host"), dict) and isinstance(raw.get("host", {}).get("name"), str):
        hostname = raw.get("host", {}).get("name")

    # Username
    username = None
    if isinstance(raw.get("username"), str):
        username = raw.get("username")
    elif isinstance(raw.get("user.name"), str):
        username = raw.get("user.name")
    elif isinstance(raw.get("user"), dict) and isinstance(raw.get("user", {}).get("name"), str):
        username = raw.get("user", {}).get("name")

    # Severity
    sev = str(raw.get("kibana.alert.severity") or rule.get("severity") or raw.get("severity") or "HIGH").upper()
    # Description
    desc = raw.get("kibana.alert.rule.name") or rule.get("name") or raw.get("description")

    # MITRE Technique
    mitre = raw.get("mitre_technique")
    if not mitre and isinstance(rule.get("threat"), list) and rule.get("threat"):
        threat = rule.get("threat")[0]
        if isinstance(threat, dict) and isinstance(threat.get("technique"), list) and threat.get("technique"):
            tech = threat.get("technique")[0]
            if isinstance(tech, dict):
                mitre = tech.get("id")

    return {
        "event_id": event_id,
        "timestamp": str(raw.get("@timestamp") or raw.get("timestamp") or ""),
        "event_type": str(raw.get("event_type") or "ELASTIC_SECURITY_SIGNAL"),
        "severity": sev,
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "domain": domain,
        "url": url,
        "hash": file_hash,
        "hostname": hostname,
        "username": username,
        "description": desc,
        "mitre_technique": mitre,
        "raw_event": raw,
    }


PROVIDER_ADAPTERS = {
    "splunk": adapt_splunk_payload,
    "qradar": adapt_qradar_payload,
    "sentinel": adapt_sentinel_payload,
    "crowdstrike": adapt_crowdstrike_payload,
    "elastic": adapt_elastic_payload,
}


def adapt_inbound_provider_payload(provider: str, raw_json: Dict[str, Any]) -> InboundSecurityEventPayload:
    """
    Map native SIEM/EDR provider payloads into canonical InboundSecurityEventPayload.
    Deterministic, explicit, zero eval/exec.
    Rejects malformed payloads missing mandatory event identity.
    """
    clean_provider = provider.strip().lower()
    adapter = PROVIDER_ADAPTERS.get(clean_provider)

    if adapter:
        mapped_dict = adapter(raw_json)
    else:
        mapped_dict = raw_json

    cleaned = {k: v for k, v in mapped_dict.items() if v is not None}

    if not cleaned.get("event_id"):
        raise ValueError(
            f"Provider '{clean_provider}' payload is missing mandatory event identity "
            f"(e.g. event_id, offense_id, id, CompositeId)"
        )

    return InboundSecurityEventPayload(**cleaned)


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
