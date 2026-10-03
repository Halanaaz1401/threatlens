import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any, List, Union
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException, Request

from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus, IndicatorSource
from app.models.enrichment import IndicatorEnrichment
from app.models.relationship import IndicatorRelationship
from app.models.user import User
from app.services.scoring_service import calculate_ioc_severity
from app.services.search_service import index_indicator
from app.services.alert_service import evaluate_ioc_for_alerts
from app.services.audit_service import log_action
from app.core.redis import publish_ioc_event

# Regex patterns
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)
CVE_REGEX = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE
)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

MAX_IOC_VALUE_LENGTH = 2048

def normalize_and_validate_ioc(value: str, ioc_type: Union[str, IndicatorType]) -> Tuple[str, IndicatorType]:
    """
    Strict server-side validation and canonical normalization for all supported IOC types.
    Supports IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256, Generic Hash, CVE.
    Rejects malformed, oversized, or unsupported values with ValueError.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Indicator value must be a non-empty string")

    clean_value = value.strip()
    if not clean_value:
        raise ValueError("Indicator value cannot be empty or pure whitespace")

    if len(clean_value) > MAX_IOC_VALUE_LENGTH:
        raise ValueError(f"Indicator value exceeds maximum allowed length ({MAX_IOC_VALUE_LENGTH} characters)")

    # Normalize type string
    raw_type = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
    type_str = raw_type.strip().lower()

    # Alias mappings
    if type_str in ["ipv4", "ipv6", "ip_address", "ip"]:
        type_str = "ip"
    elif type_str in ["fqdn", "hostname", "domain"]:
        type_str = "domain"
    elif type_str in ["uri", "url"]:
        type_str = "url"
    elif type_str in ["md5", "hash_md5"]:
        type_str = "hash_md5"
    elif type_str in ["sha1", "hash_sha1"]:
        type_str = "hash_sha1"
    elif type_str in ["sha256", "hash_sha256"]:
        type_str = "hash_sha256"
    elif type_str in ["hash", "filehash"]:
        type_str = "hash"
    elif type_str in ["mail", "email"]:
        type_str = "email"
    elif type_str in ["vulnerability", "cve"]:
        type_str = "cve"

    # Validation and normalization per type
    if type_str == "ip":
        try:
            ip_obj = ipaddress.ip_address(clean_value)
            normalized_value = str(ip_obj)
            return normalized_value, IndicatorType.IP
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{clean_value}'")

    elif type_str == "domain":
        # Disallow schemes in domains
        if "://" in clean_value or "/" in clean_value:
            raise ValueError(f"Domain must not contain URL scheme or path: '{clean_value}'")
        norm_domain = clean_value.lower().rstrip(".")
        if len(norm_domain) > 253 or not DOMAIN_REGEX.match(norm_domain):
            raise ValueError(f"Invalid domain name format: '{clean_value}'")
        return norm_domain, IndicatorType.DOMAIN

    elif type_str == "url":
        # Disallow leading/trailing whitespace
        parsed = urlparse(clean_value)
        if not parsed.scheme or parsed.scheme.lower() not in ["http", "https", "ftp"]:
            raise ValueError(f"URL must have a valid scheme (http, https, ftp): '{clean_value}'")
        if not parsed.netloc:
            raise ValueError(f"URL must contain a valid host/netloc: '{clean_value}'")
        return clean_value, IndicatorType.URL

    elif type_str == "email":
        norm_email = clean_value.lower()
        if not EMAIL_REGEX.match(norm_email):
            raise ValueError(f"Invalid email address format: '{clean_value}'")
        return norm_email, IndicatorType.EMAIL

    elif type_str == "hash_md5":
        if not MD5_REGEX.match(clean_value):
            raise ValueError(f"Invalid MD5 hash format (must be 32 hex characters): '{clean_value}'")
        return clean_value.lower(), IndicatorType.HASH_MD5

    elif type_str == "hash_sha1":
        if not SHA1_REGEX.match(clean_value):
            raise ValueError(f"Invalid SHA1 hash format (must be 40 hex characters): '{clean_value}'")
        return clean_value.lower(), IndicatorType.HASH_SHA1

    elif type_str == "hash_sha256":
        if not SHA256_REGEX.match(clean_value):
            raise ValueError(f"Invalid SHA256 hash format (must be 64 hex characters): '{clean_value}'")
        return clean_value.lower(), IndicatorType.HASH_SHA256

    elif type_str == "hash":
        # Infer hash type from length
        norm_hash = clean_value.lower()
        if MD5_REGEX.match(norm_hash):
            return norm_hash, IndicatorType.HASH_MD5
        elif SHA1_REGEX.match(norm_hash):
            return norm_hash, IndicatorType.HASH_SHA1
        elif SHA256_REGEX.match(norm_hash):
            return norm_hash, IndicatorType.HASH_SHA256
        else:
            raise ValueError(f"Invalid hash format (must be 32, 40, or 64 hex characters): '{clean_value}'")

    elif type_str == "cve":
        if not CVE_REGEX.match(clean_value):
            raise ValueError(f"Invalid CVE format (expected format CVE-YYYY-NNNN+): '{clean_value}'")
        return clean_value.upper(), IndicatorType.CVE

    else:
        raise ValueError(f"Unsupported indicator type: '{ioc_type}'")

def calculate_expiration_date(ttl_days: Optional[int] = 30, base_time: Optional[datetime] = None) -> datetime:
    """Calculate deterministic UTC expiration date based on TTL days."""
    if base_time is None:
        base_time = datetime.now(timezone.utc).replace(tzinfo=None)
    effective_ttl = ttl_days if ttl_days and ttl_days > 0 else 30
    return base_time + timedelta(days=effective_ttl)

def get_indicator_by_id(db: Session, indicator_id: str) -> Optional[Indicator]:
    """Retrieve individual indicator with all relationships."""
    return db.query(Indicator).filter(Indicator.id == str(indicator_id)).first()

def serialize_indicator_detail(indicator: Indicator, db: Optional[Session] = None) -> Dict[str, Any]:
    """Serialize full indicator details including lifecycle, TTL, provenance and counts."""
    sources_data = [
        {
            "id": str(s.id),
            "source_name": s.source_name,
            "confidence": s.confidence,
            "reported_at": s.reported_at.isoformat() if s.reported_at else None
        }
        for s in (indicator.sources or [])
    ]

    enrichments_count = len(indicator.enrichments) if indicator.enrichments else 0
    relationships_count = (
        (len(indicator.outgoing_relationships) if indicator.outgoing_relationships else 0) +
        (len(indicator.incoming_relationships) if indicator.incoming_relationships else 0)
    )

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    is_expired = False
    if indicator.status == IndicatorStatus.EXPIRED.value:
        is_expired = True
    elif indicator.expires_at and indicator.expires_at <= now_utc:
        is_expired = True

    return {
        "id": str(indicator.id),
        "value": indicator.value,
        "type": str(indicator.type.value if hasattr(indicator.type, "value") else indicator.type),
        "severity_score": indicator.threat_score,
        "threat_score": indicator.threat_score,
        "severity": str(indicator.severity.value if hasattr(indicator.severity, "value") else indicator.severity),
        "confidence": indicator.confidence,
        "source": indicator.source,
        "sightings": indicator.sightings,
        "tlp": indicator.tlp,
        "status": str(indicator.status.value if hasattr(indicator.status, "value") else indicator.status),
        "tags": indicator.tags or [],
        "context": indicator.context or {},
        "mitre_technique": indicator.mitre_technique,
        "expires_at": indicator.expires_at.isoformat() if indicator.expires_at else None,
        "ttl_days": indicator.ttl_days,
        "is_expired": is_expired,
        "analyst_notes": indicator.analyst_notes,
        "revoked_reason": indicator.revoked_reason,
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
        "created_at": indicator.created_at.isoformat() if indicator.created_at else None,
        "updated_at": indicator.updated_at.isoformat() if indicator.updated_at else None,
        "sources": sources_data,
        "enrichments_count": enrichments_count,
        "relationships_count": relationships_count,
    }
