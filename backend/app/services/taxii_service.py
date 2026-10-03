"""ThreatLens - TAXII 2.1 Feed Client and Ingestion Engine (Phase 4D-D, FR-04).

Provides:
- TAXII 2.1 Server Discovery (/taxii2/)
- API Root Inspection and Version Verification
- Collection Discovery (/collections/)
- Authenticated and Anonymous Collection Polling
- Safe STIX 2.1 Bundle and Object Parsing (Bounded regex parsing, zero eval/exec)
- Mapping STIX Indicators to ThreatLens Canonical IOC Model
- Incremental Polling State Tracking (last_added_after timestamp cursor)
- SSRF Protection, Timeouts, and Response Size Bounding
- Structured Redis Event Publishing and Immutable Audit Logging
"""
import re
import urllib.parse
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union

import httpx
from sqlalchemy.orm import Session

from app.models.feed import Feed
from app.models.indicator import Indicator, IndicatorType
from app.core.config import settings
from app.core.redis import publish_security_event, publish_feed_event
from app.services.indicator_service import normalize_and_validate_ioc
from app.services.feed_service import _save_and_index_ioc
from app.services.detection_rule_service import evaluate_indicator_against_rules
from app.services.audit_service import log_action

logger = logging.getLogger("threatlens.taxii")

TAXII21_CONTENT_TYPE = "application/taxii+json;version=2.1"
TAXII_REQUEST_TIMEOUT = 10.0  # seconds
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB

# Blocked SSRF addresses and cloud metadata services
BLOCKED_SSRF_HOSTS = {
    "169.254.169.254",          # AWS / GCP / Azure link-local metadata
    "metadata.google.internal", # GCP metadata DNS
    "instance-data",            # OpenStack metadata
}

# Safe STIX 2.1 pattern extraction regex rules (Zero eval / Zero exec)
STIX_PATTERN_REGEXES = [
    # IPv4 address
    (r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", "ipv4"),
    # IPv6 address
    (r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", "ipv6"),
    # Domain
    (r"\[domain-name:value\s*=\s*'([^']+)'\]", "domain"),
    # URL
    (r"\[url:value\s*=\s*'([^']+)'\]", "url"),
    # SHA-256
    (r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", "sha256"),
    (r"\[file:hashes\.'SHA256'\s*=\s*'([^']+)'\]", "sha256"),
    # MD5
    (r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", "md5"),
    (r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]", "md5"),
    # SHA-1
    (r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]", "sha1"),
    (r"\[file:hashes\.'SHA1'\s*=\s*'([^']+)'\]", "sha1"),
    # Email
    (r"\[email-addr:value\s*=\s*'([^']+)'\]", "email"),
]


def validate_taxii_url_safety(url: str, allow_local: bool = True) -> str:
    """
    Validate TAXII server/collection URL to prevent SSRF and unsafe schemes.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only http and https are permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("URL must include a valid hostname.")

    if hostname in BLOCKED_SSRF_HOSTS:
        raise ValueError(f"SSRF violation: Host '{hostname}' is forbidden.")

    # Check if host resolves to IP address
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.is_link_local:
            raise ValueError(f"SSRF violation: Link-local IP '{hostname}' is forbidden.")
        if not allow_local and (ip.is_loopback or ip.is_private):
            raise ValueError(f"SSRF violation: Local/private network '{hostname}' is not allowed in production.")

    return url.strip()


def parse_stix_indicator_pattern(pattern: str) -> Optional[Tuple[str, str]]:
    """
    Safely extract indicator value and type from a STIX 2.1 pattern using bounded regexes.
    Guaranteed zero dynamic code execution.
    Returns (clean_value, ioc_type) or None if unsupported/unmatched.
    """
    if not pattern or not isinstance(pattern, str):
        return None

    clean_pattern = pattern.strip()

    for regex, ioc_type in STIX_PATTERN_REGEXES:
        match = re.search(regex, clean_pattern, re.IGNORECASE)
        if match:
            raw_val = match.group(1).strip()
            return raw_val, ioc_type

    logger.debug(f"Unsupported STIX 2.1 pattern form: {clean_pattern}")
    return None


async def discover_taxii_server(
    server_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None
) -> Dict[str, Any]:
    """
    Perform TAXII 2.1 Server Discovery (GET /taxii2/).
    Returns server metadata and available API roots.
    """
    safe_url = validate_taxii_url_safety(server_url)
    # Ensure endpoint targets /taxii2/ or root if already specified
    if not safe_url.endswith("/taxii2/") and not safe_url.endswith("/taxii2"):
        if safe_url.endswith("/"):
            discovery_url = safe_url + "taxii2/"
        else:
            discovery_url = safe_url + "/taxii2/"
    else:
        discovery_url = safe_url if safe_url.endswith("/") else safe_url + "/"

    auth = (username, password) if username and password else None
    headers = {
        "Accept": TAXII21_CONTENT_TYPE,
        "User-Agent": "ThreatLens-TAXII/2.1"
    }

    should_close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=TAXII_REQUEST_TIMEOUT, verify=True)
        should_close_client = True

    try:
        response = await client.get(discovery_url, headers=headers, auth=auth)
        if response.status_code == 404 and discovery_url != safe_url:
            # Fallback to direct URL if /taxii2/ was already included in path
            response = await client.get(safe_url, headers=headers, auth=auth)

        response.raise_for_status()

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError(f"TAXII discovery response exceeds maximum allowed size ({MAX_RESPONSE_BYTES} bytes)")

        data = response.json()
        api_roots = data.get("api_roots", [])
        return {
            "title": data.get("title", "TAXII 2.1 Server"),
            "description": data.get("description", ""),
            "default": data.get("default", ""),
            "api_roots": api_roots,
            "status": "success"
        }
    finally:
        if should_close_client:
            await client.aclose()


async def get_taxii_collections(
    api_root_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None
) -> List[Dict[str, Any]]:
    """
    Fetch collection list from a TAXII 2.1 API Root (GET {api_root}/collections/).
    """
    safe_url = validate_taxii_url_safety(api_root_url)
    endpoint = safe_url if safe_url.endswith("/collections/") else safe_url.rstrip("/") + "/collections/"

    auth = (username, password) if username and password else None
    headers = {
        "Accept": TAXII21_CONTENT_TYPE,
        "User-Agent": "ThreatLens-TAXII/2.1"
    }

    should_close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=TAXII_REQUEST_TIMEOUT, verify=True)
        should_close_client = True

    try:
        response = await client.get(endpoint, headers=headers, auth=auth)
        response.raise_for_status()
        data = response.json()
        collections = data.get("collections", [])
        return [
            {
                "id": str(col.get("id")),
                "title": col.get("title", "Untitled Collection"),
                "description": col.get("description", ""),
                "can_read": bool(col.get("can_read", True)),
                "can_write": bool(col.get("can_write", False)),
                "media_types": col.get("media_types", [])
            }
            for col in collections
        ]
    finally:
        if should_close_client:
            await client.aclose()


async def poll_taxii_collection(
    db: Session,
    feed: Feed,
    client: Optional[httpx.AsyncClient] = None
) -> Dict[str, Any]:
    """
    Poll objects from a configured TAXII 2.1 collection, extract STIX indicators,
    normalize into canonical IOCs, evaluate rules, update poll state, and publish events.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    feed.last_attempted_fetch_at = now

    if not feed.endpoint_url:
        feed.status = "error"
        feed.error_message = "TAXII feed missing endpoint_url"
        db.commit()
        return {"status": "error", "error": feed.error_message}

    # Construct objects URL: {endpoint_url}/collections/{collection_id}/objects/
    base_url = feed.endpoint_url.rstrip("/")
    if feed.taxii_collection_id:
        if "/collections/" not in base_url:
            objects_url = f"{base_url}/collections/{feed.taxii_collection_id}/objects/"
        else:
            objects_url = f"{base_url}/objects/"
    else:
        objects_url = base_url if base_url.endswith("/objects/") else base_url + "/objects/"

    params = {}
    if feed.last_added_after:
        params["added_after"] = feed.last_added_after

    safe_url = validate_taxii_url_safety(objects_url)

    auth = None
    if feed.taxii_username and feed.taxii_password_hash:
        auth = (feed.taxii_username, feed.taxii_password_hash)

    headers = {
        "Accept": TAXII21_CONTENT_TYPE,
        "User-Agent": "ThreatLens-TAXII/2.1"
    }

    publish_security_event("TAXII_POLL_STARTED", {
        "feed_id": str(feed.id),
        "feed_name": feed.name,
        "collection_id": feed.taxii_collection_id,
        "timestamp": now.isoformat()
    })

    should_close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=TAXII_REQUEST_TIMEOUT, verify=True)
        should_close_client = True

    try:
        response = await client.get(safe_url, params=params, headers=headers, auth=auth)
        response.raise_for_status()

        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError(f"TAXII response payload exceeds limit of {MAX_RESPONSE_BYTES} bytes")

        envelope = response.json()
        objects = envelope.get("objects", [])

        ingested_count = 0
        latest_timestamp = feed.last_added_after

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type != "indicator":
                continue

            pattern = obj.get("pattern")
            parsed_pattern = parse_stix_indicator_pattern(pattern)
            if not parsed_pattern:
                continue

            raw_val, ptype = parsed_pattern

            try:
                norm_val, norm_type = normalize_and_validate_ioc(raw_val, ptype)
                stix_id = obj.get("id", "indicator--unknown")
                confidence = int(obj.get("confidence", 75))
                labels = obj.get("labels", [])
                created_ts = obj.get("created")
                modified_ts = obj.get("modified")

                if modified_ts and (latest_timestamp is None or modified_ts > latest_timestamp):
                    latest_timestamp = modified_ts

                # Save via canonical feed service
                status_code = _save_and_index_ioc(
                    db=db,
                    value=norm_val,
                    ioc_type=norm_type,
                    source=f"taxii:{feed.name}",
                    confidence=confidence,
                    tags=["taxii2", feed.name] + labels,
                    context={
                        "stix_id": stix_id,
                        "collection_id": feed.taxii_collection_id,
                        "created": created_ts,
                        "modified": modified_ts,
                    },
                    mitre_technique="T1071"
                )

                if status_code in ["created", "updated"]:
                    ingested_count += 1

                # Trigger detection rules
                saved_ioc = db.query(Indicator).filter(Indicator.value == norm_val).first()
                if saved_ioc:
                    try:
                        evaluate_indicator_against_rules(db, saved_ioc)
                    except Exception:
                        pass

            except Exception as parse_err:
                logger.debug(f"Error ingesting STIX indicator '{raw_val}': {parse_err}")

        # Update Feed state
        feed.last_successful_fetch_at = now
        feed.status = "active"
        feed.error_message = None
        feed.total_indicators_ingested = (feed.total_indicators_ingested or 0) + ingested_count
        feed.last_ingested_count = ingested_count
        if latest_timestamp:
            feed.last_added_after = latest_timestamp
        db.commit()

        # Publish events
        publish_security_event("TAXII_POLL_SUCCEEDED", {
            "feed_id": str(feed.id),
            "feed_name": feed.name,
            "collection_id": feed.taxii_collection_id,
            "indicators_ingested": ingested_count,
            "timestamp": now.isoformat()
        })
        publish_feed_event("FEED_FETCH_SUCCEEDED", {
            "feed_name": feed.name,
            "ingested_count": ingested_count,
            "total": feed.total_indicators_ingested,
            "timestamp": now.isoformat()
        })

        # Audit
        try:
            log_action(
                db=db,
                action="TAXII_POLL_EXECUTED",
                actor=f"taxii:{feed.name}",
                target_resource=f"feed:{feed.name}",
                details={
                    "collection_id": feed.taxii_collection_id,
                    "ingested": ingested_count,
                    "total": feed.total_indicators_ingested
                }
            )
        except Exception:
            pass

        return {
            "status": "success",
            "feed": feed.name,
            "collection_id": feed.taxii_collection_id,
            "indicators_ingested": ingested_count,
            "total_indicators": feed.total_indicators_ingested,
            "timestamp": now.isoformat()
        }

    except Exception as e:
        feed.status = "error"
        feed.error_message = str(e)
        db.commit()

        publish_security_event("TAXII_POLL_FAILED", {
            "feed_id": str(feed.id),
            "feed_name": feed.name,
            "error": str(e),
            "timestamp": now.isoformat()
        })
        publish_feed_event("FEED_FETCH_FAILED", {
            "feed_name": feed.name,
            "error": str(e),
            "timestamp": now.isoformat()
        })
        logger.error(f"TAXII poll failed for feed '{feed.name}': {e}")
        return {"status": "error", "feed": feed.name, "error": str(e)}

    finally:
        if should_close_client:
            await client.aclose()
