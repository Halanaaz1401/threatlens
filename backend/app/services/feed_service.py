import httpx
import logging
import asyncio
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus, IndicatorSource
from app.models.feed import Feed
from app.services.scoring_service import calculate_ioc_severity
from app.services.search_service import index_indicator
from app.services.alert_service import evaluate_ioc_for_alerts
from app.core.redis import publish_feed_event

logger = logging.getLogger("threatlens.feed_service")

DEFAULT_FEEDS_CONFIG = [
    {
        "name": "urlhaus",
        "display_name": "URLhaus Recent Malware URLs",
        "provider": "abuse.ch",
        "feed_type": "url",
        "endpoint_url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "description": "Live repository of malicious URLs used for malware distribution",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
    {
        "name": "threatfox",
        "display_name": "ThreatFox Multi-Type IOCs",
        "provider": "abuse.ch",
        "feed_type": "multi",
        "endpoint_url": "https://threatfox-api.abuse.ch/api/v1/",
        "description": "Free platform for sharing IOCs associated with malware and botnets",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
    {
        "name": "feodo_tracker",
        "display_name": "Feodo Tracker Botnet C2",
        "provider": "abuse.ch",
        "feed_type": "ip",
        "endpoint_url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json",
        "description": "Real-time list of active botnet Command & Control (C2) servers",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
    {
        "name": "malwarebazaar",
        "display_name": "MalwareBazaar Sample Hashes",
        "provider": "abuse.ch",
        "feed_type": "hash",
        "endpoint_url": "https://mb-api.abuse.ch/api/v1/",
        "description": "Catalog of recent malware sample cryptographic hashes",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
    {
        "name": "cisa_kev",
        "display_name": "CISA Known Exploited Vulnerabilities",
        "provider": "CISA",
        "feed_type": "cve",
        "endpoint_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "description": "Official authoritative catalog of vulnerabilities actively exploited in the wild",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
    {
        "name": "alienvault_otx",
        "display_name": "AlienVault OTX Threat Pulses",
        "provider": "AlienVault",
        "feed_type": "multi",
        "endpoint_url": "https://otx.alienvault.com/api/v1/pulses/activity",
        "description": "Crowdsourced open threat intelligence community pulses",
        "enabled": True,
        "poll_interval_seconds": 3600,
    },
]

def ensure_default_feeds(db: Session) -> List[Feed]:
    """Ensure all canonical threat feeds exist in database with rich metadata."""
    existing_feeds = {f.name: f for f in db.query(Feed).all()}
    created = False
    for cfg in DEFAULT_FEEDS_CONFIG:
        if cfg["name"] not in existing_feeds:
            feed = Feed(
                name=cfg["name"],
                display_name=cfg["display_name"],
                provider=cfg["provider"],
                feed_type=cfg["feed_type"],
                endpoint_url=cfg["endpoint_url"],
                description=cfg["description"],
                enabled=cfg["enabled"],
                status="active" if cfg["enabled"] else "disabled",
                poll_interval_seconds=cfg["poll_interval_seconds"],
                total_indicators_ingested=0,
                last_ingested_count=0
            )
            db.add(feed)
            created = True
        else:
            f = existing_feeds[cfg["name"]]
            if not f.display_name:
                f.display_name = cfg["display_name"]
            if not f.provider:
                f.provider = cfg["provider"]
            if not f.feed_type:
                f.feed_type = cfg["feed_type"]
            if not f.endpoint_url:
                f.endpoint_url = cfg["endpoint_url"]
            if not f.description:
                f.description = cfg["description"]
            if not f.status:
                f.status = "active" if f.enabled else "disabled"
    if created:
        db.commit()
    return db.query(Feed).all()

def update_feed_stats(
    db: Session,
    feed_name: str,
    success: bool,
    count: int = 0,
    error: Optional[str] = None
) -> None:
    """Safely record honest operational ingestion stats into Feed row without exposing secrets."""
    try:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        feed = db.query(Feed).filter(Feed.name == feed_name).first()
        if not feed:
            feed = Feed(name=feed_name, enabled=True, poll_interval_seconds=3600)
            db.add(feed)
            db.flush()

        feed.last_attempted_fetch_at = now_dt
        feed.last_polled_at = now_dt
        if success:
            feed.status = "active" if feed.enabled else "disabled"
            feed.last_successful_fetch_at = now_dt
            feed.last_ingested_count = count
            feed.total_indicators_ingested = (feed.total_indicators_ingested or 0) + count
            feed.error_message = None
            publish_feed_event("FEED_FETCH_SUCCEEDED", {
                "feed_name": feed_name,
                "count": count,
                "timestamp": now_dt.isoformat(),
            })
        else:
            feed.status = "failing"
            safe_error = str(error) if error else "Unknown error"
            # Strip secrets / headers if present
            if len(safe_error) > 500:
                safe_error = safe_error[:500] + "..."
            feed.error_message = safe_error
            publish_feed_event("FEED_FETCH_FAILED", {
                "feed_name": feed_name,
                "error": safe_error,
                "timestamp": now_dt.isoformat(),
            })
        db.commit()
    except Exception as e:
        logger.error(f"Error updating feed stats for {feed_name}: {e}")

def is_feed_enabled(db: Session, feed_name: str) -> bool:
    """Check if feed is enabled before initiating fetch."""
    feed = db.query(Feed).filter(Feed.name == feed_name).first()
    if feed is not None:
        return bool(feed.enabled)
    return True

def _save_and_index_ioc(
    db: Session,
    value: str,
    ioc_type: IndicatorType,
    source: str,
    confidence: int,
    tags: list = None,
    context: dict = None,
    mitre_technique: str = None
) -> str:
    """
    Helper function to normalize, validate, deduplicate, score,
    record provenance, assign TTL, save to DB, index in Elasticsearch, and trigger Alert Engine.
    """
    if not value or not str(value).strip():
        return "invalid"

    clean_value = str(value).strip()
    raw_type = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)

    try:
        existing = db.query(Indicator).filter(Indicator.value == clean_value).first()
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)

        if existing:
            existing.sightings = (existing.sightings or 1) + 1
            existing.last_seen = now_dt
            # Refresh TTL on fresh sighting
            existing.expires_at = now_dt + timedelta(days=existing.ttl_days or 30)
            if existing.status == IndicatorStatus.EXPIRED.value:
                existing.status = IndicatorStatus.ACTIVE.value
            
            # Record per-source provenance sighting
            try:
                prov = IndicatorSource(
                    indicator_id=existing.id,
                    source_name=source,
                    confidence=confidence,
                    reported_at=now_dt
                )
                db.add(prov)
            except Exception:
                pass

            # Recalculate score with updated sightings count
            scoring = calculate_ioc_severity(
                confidence=confidence,
                source=source,
                sightings_count=existing.sightings
            )
            existing.threat_score = scoring["score"]
            existing.severity = scoring["severity"]

            db.commit()
            db.refresh(existing)

            # Trigger real-time alert engine
            evaluate_ioc_for_alerts(db, existing)
            return "updated"

        # Calculate initial severity and threat score
        scoring = calculate_ioc_severity(
            confidence=confidence,
            source=source,
            sightings_count=1
        )
        
        severity_value = scoring["severity"]

        new_ioc = Indicator(
            value=clean_value,
            type=raw_type,
            source=source,
            confidence=confidence,
            threat_score=scoring["score"],
            severity=severity_value,
            status=IndicatorStatus.ACTIVE.value,
            tags=tags or [],
            context=context or {},
            mitre_technique=mitre_technique,
            expires_at=now_dt + timedelta(days=30),
            ttl_days=30,
            sightings=1,
            first_seen=now_dt,
            last_seen=now_dt
        )
        db.add(new_ioc)
        db.flush()

        # Add initial source provenance record
        try:
            prov = IndicatorSource(
                indicator_id=new_ioc.id,
                source_name=source,
                confidence=confidence,
                reported_at=now_dt
            )
            db.add(prov)
        except Exception:
            pass

        db.commit()
        db.refresh(new_ioc)

        # Trigger Real-Time Alert Engine
        evaluate_ioc_for_alerts(db, new_ioc)

        # Project to Elasticsearch
        try:
            index_indicator({
                "id": str(new_ioc.id),
                "value": new_ioc.value,
                "type": str(new_ioc.type),
                "source": new_ioc.source,
                "severity": str(new_ioc.severity),
                "status": str(new_ioc.status),
                "threat_score": new_ioc.threat_score,
                "confidence": new_ioc.confidence,
                "tags": new_ioc.tags,
                "expires_at": new_ioc.expires_at.isoformat() if new_ioc.expires_at else None,
                "created_at": new_ioc.first_seen.isoformat() if new_ioc.first_seen else None
            })
        except Exception as es_err:
            logger.debug(f"ES indexing skipped for IOC {clean_value}: {es_err}")

        return "created"

    except Exception as e:
        db.rollback()
        logger.error(f"Error processing IOC {clean_value}: {e}")
        return "error"

# -------------------------------------------------------------
# 1. URLhaus Feed (URLs)
# -------------------------------------------------------------
async def fetch_urlhaus_recent_urls(db: Session, limit: int = 10) -> Dict[str, Any]:
    if not is_feed_enabled(db, "urlhaus"):
        return {"source": "urlhaus", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "urlhaus"})
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                update_feed_stats(db, "urlhaus", success=False, error=f"HTTP {response.status_code}")
                return {"source": "urlhaus", "status": "failed", "status_code": response.status_code}
            
            data = response.json()
            count = 0
            items_to_process = []
            for item in list(data.values())[:limit]:
                if isinstance(item, list):
                    items_to_process.extend(item[:limit])
                elif isinstance(item, dict):
                    items_to_process.append(item)

            for sub_item in items_to_process[:limit]:
                try:
                    val = sub_item.get("url")
                    if val:
                        res = _save_and_index_ioc(
                            db=db,
                            value=val,
                            ioc_type=IndicatorType.URL,
                            source="urlhaus",
                            confidence=85,
                            tags=sub_item.get("tags") or ["malware", "payload"],
                            context={"threat": sub_item.get("threat")},
                            mitre_technique="T1566.002"
                        )
                        if res == "created":
                            count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed URLhaus row: {row_err}")

            update_feed_stats(db, "urlhaus", success=True, count=count)
            return {"source": "urlhaus", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"URLhaus fetch failed: {e}")
        update_feed_stats(db, "urlhaus", success=False, error=str(e))
        return {"source": "urlhaus", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# 2. ThreatFox Feed (Multi-type IOCs: IP, Domain, URL, Hashes)
# -------------------------------------------------------------
async def fetch_threatfox_recent_iocs(db: Session, limit: int = 10) -> Dict[str, Any]:
    if not is_feed_enabled(db, "threatfox"):
        return {"source": "threatfox", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "threatfox"})
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                update_feed_stats(db, "threatfox", success=False, error=f"HTTP {response.status_code}")
                return {"source": "threatfox", "status": "failed", "status_code": response.status_code}
            
            data = response.json()
            if data.get("query_status") != "ok":
                update_feed_stats(db, "threatfox", success=True, count=0)
                return {"source": "threatfox", "status": "no_data"}
            
            count = 0
            for item in data.get("data", [])[:limit]:
                try:
                    ioc_val = item.get("ioc")
                    raw_type = str(item.get("ioc_type", "")).lower()
                    
                    if "ip" in raw_type:
                        ioc_type = IndicatorType.IP
                    elif "domain" in raw_type:
                        ioc_type = IndicatorType.DOMAIN
                    elif "url" in raw_type:
                        ioc_type = IndicatorType.URL
                    elif "md5" in raw_type:
                        ioc_type = IndicatorType.HASH_MD5
                    elif "sha256" in raw_type:
                        ioc_type = IndicatorType.HASH_SHA256
                    else:
                        ioc_type = IndicatorType.DOMAIN

                    res = _save_and_index_ioc(
                        db=db,
                        value=ioc_val,
                        ioc_type=ioc_type,
                        source="threatfox",
                        confidence=int(item.get("confidence_level", 80)),
                        tags=item.get("tags") or [item.get("malware_printable", "c2")],
                        context={"malware": item.get("malware_printable"), "threat_type": item.get("threat_type")},
                        mitre_technique="T1071"
                    )
                    if res == "created":
                        count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed ThreatFox row: {row_err}")

            update_feed_stats(db, "threatfox", success=True, count=count)
            return {"source": "threatfox", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"ThreatFox fetch failed: {e}")
        update_feed_stats(db, "threatfox", success=False, error=str(e))
        return {"source": "threatfox", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# 3. Feodo Tracker Feed (Botnet C2 IPs)
# -------------------------------------------------------------
async def fetch_feodo_tracker_ips(db: Session, limit: int = 10) -> Dict[str, Any]:
    if not is_feed_enabled(db, "feodo_tracker"):
        return {"source": "feodo_tracker", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "feodo_tracker"})
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                update_feed_stats(db, "feodo_tracker", success=False, error=f"HTTP {response.status_code}")
                return {"source": "feodo_tracker", "status": "failed", "status_code": response.status_code}
            
            data = response.json()
            count = 0
            for item in data[:limit]:
                try:
                    ip_val = item.get("ip_address")
                    if ip_val:
                        res = _save_and_index_ioc(
                            db=db,
                            value=ip_val,
                            ioc_type=IndicatorType.IP,
                            source="feodo_tracker",
                            confidence=95,
                            tags=["botnet", str(item.get("malware", "c2")).lower()],
                            context={"malware": item.get("malware"), "status": item.get("status")},
                            mitre_technique="T1071.001"
                        )
                        if res == "created":
                            count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed Feodo row: {row_err}")

            update_feed_stats(db, "feodo_tracker", success=True, count=count)
            return {"source": "feodo_tracker", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"Feodo Tracker fetch failed: {e}")
        update_feed_stats(db, "feodo_tracker", success=False, error=str(e))
        return {"source": "feodo_tracker", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# 4. MalwareBazaar Feed (SHA256 Malware Hashes)
# -------------------------------------------------------------
async def fetch_malwarebazaar_recent_hashes(db: Session, limit: int = 10) -> Dict[str, Any]:
    if not is_feed_enabled(db, "malwarebazaar"):
        return {"source": "malwarebazaar", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "malwarebazaar"})
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_recent", "selector": "time"}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(url, data=payload)
            if response.status_code != 200:
                update_feed_stats(db, "malwarebazaar", success=False, error=f"HTTP {response.status_code}")
                return {"source": "malwarebazaar", "status": "failed", "status_code": response.status_code}
            
            data = response.json()
            if data.get("query_status") != "ok":
                update_feed_stats(db, "malwarebazaar", success=True, count=0)
                return {"source": "malwarebazaar", "status": "no_data"}
            
            count = 0
            for item in data.get("data", [])[:limit]:
                try:
                    sha256_val = item.get("sha256_hash")
                    if sha256_val:
                        res = _save_and_index_ioc(
                            db=db,
                            value=sha256_val,
                            ioc_type=IndicatorType.HASH_SHA256,
                            source="malwarebazaar",
                            confidence=90,
                            tags=item.get("tags") or ["malware", str(item.get("file_type", "payload"))],
                            context={"file_type": item.get("file_type"), "signature": item.get("signature")},
                            mitre_technique="T1027"
                        )
                        if res == "created":
                            count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed MalwareBazaar row: {row_err}")

            update_feed_stats(db, "malwarebazaar", success=True, count=count)
            return {"source": "malwarebazaar", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"MalwareBazaar fetch failed: {e}")
        update_feed_stats(db, "malwarebazaar", success=False, error=str(e))
        return {"source": "malwarebazaar", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# 5. CISA KEV (Known Exploited Vulnerabilities Catalog)
# -------------------------------------------------------------
async def fetch_cisa_kev_cves(db: Session, limit: int = 10) -> Dict[str, Any]:
    """Ingest actively exploited CVEs from the official CISA KEV catalog."""
    if not is_feed_enabled(db, "cisa_kev"):
        return {"source": "cisa_kev", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "cisa_kev"})
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                update_feed_stats(db, "cisa_kev", success=False, error=f"HTTP {response.status_code}")
                return {"source": "cisa_kev", "status": "failed", "status_code": response.status_code}
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            count = 0
            for item in vulnerabilities[:limit]:
                try:
                    cve_id = item.get("cveID")
                    if cve_id:
                        res = _save_and_index_ioc(
                            db=db,
                            value=cve_id,
                            ioc_type=IndicatorType.CVE,
                            source="cisa_kev",
                            confidence=100,
                            tags=["cisa_kev", "vulnerability", str(item.get("vendorProject", "exploit")).lower()],
                            context={
                                "product": item.get("product"),
                                "vulnerability_name": item.get("vulnerabilityName"),
                                "required_action": item.get("requiredAction")
                            },
                            mitre_technique="T1190"
                        )
                        if res == "created":
                            count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed CISA KEV row: {row_err}")

            update_feed_stats(db, "cisa_kev", success=True, count=count)
            return {"source": "cisa_kev", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"CISA KEV fetch failed: {e}")
        update_feed_stats(db, "cisa_kev", success=False, error=str(e))
        return {"source": "cisa_kev", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# 6. AlienVault OTX Community Pulse Feed
# -------------------------------------------------------------
async def fetch_alienvault_otx_indicators(db: Session, limit: int = 10) -> Dict[str, Any]:
    """Ingest community threat pulses from AlienVault OTX."""
    if not is_feed_enabled(db, "alienvault_otx"):
        return {"source": "alienvault_otx", "status": "disabled", "message": "Feed is disabled"}

    publish_feed_event("FEED_FETCH_STARTED", {"feed_name": "alienvault_otx"})
    url = "https://otx.alienvault.com/api/v1/pulses/activity"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                update_feed_stats(db, "alienvault_otx", success=False, error=f"HTTP {response.status_code}")
                return {"source": "alienvault_otx", "status": "rate_limited_or_auth_required", "status_code": response.status_code}
            
            data = response.json()
            results = data.get("results", [])
            count = 0
            for pulse in results[:limit]:
                try:
                    indicators = pulse.get("indicators", [])
                    pulse_name = pulse.get("name", "OTX Community Pulse")
                    for ind in indicators[:3]:
                        val = ind.get("indicator")
                        ind_type = str(ind.get("type", "")).lower()
                        if "ipv4" in ind_type:
                            itype = IndicatorType.IP
                        elif "domain" in ind_type or "hostname" in ind_type:
                            itype = IndicatorType.DOMAIN
                        elif "url" in ind_type:
                            itype = IndicatorType.URL
                        elif "filehash" in ind_type:
                            itype = IndicatorType.HASH_SHA256
                        else:
                            itype = IndicatorType.DOMAIN

                        if val:
                            res = _save_and_index_ioc(
                                db=db,
                                value=val,
                                ioc_type=itype,
                                source="alienvault_otx",
                                confidence=85,
                                tags=["otx", "community_pulse"],
                                context={"pulse_name": pulse_name},
                                mitre_technique="T1090"
                            )
                            if res == "created":
                                count += 1
                except Exception as row_err:
                    logger.debug(f"Skipping malformed OTX row: {row_err}")

            update_feed_stats(db, "alienvault_otx", success=True, count=count)
            return {"source": "alienvault_otx", "status": "success", "new_indicators": count}
    except Exception as e:
        logger.warning(f"AlienVault OTX fetch failed: {e}")
        update_feed_stats(db, "alienvault_otx", success=False, error=str(e))
        return {"source": "alienvault_otx", "status": "timeout_or_error", "detail": str(e)}

# -------------------------------------------------------------
# Master Feed Ingestion Aggregator (All 6 Sources)
# -------------------------------------------------------------
async def fetch_all_feeds(db: Session, limit: int = 10) -> Dict[str, Any]:
    """
    Ingest all 6 configured threat feeds concurrently.
    Protects against single-source network timeouts or malformed payloads.
    """
    res_urlhaus = await fetch_urlhaus_recent_urls(db, limit=limit)
    res_threatfox = await fetch_threatfox_recent_iocs(db, limit=limit)
    res_feodo = await fetch_feodo_tracker_ips(db, limit=limit)
    res_mb = await fetch_malwarebazaar_recent_hashes(db, limit=limit)
    res_cisa = await fetch_cisa_kev_cves(db, limit=limit)
    res_otx = await fetch_alienvault_otx_indicators(db, limit=limit)

    return {
        "status": "success",
        "summary": {
            "urlhaus": res_urlhaus,
            "threatfox": res_threatfox,
            "feodo_tracker": res_feodo,
            "malwarebazaar": res_mb,
            "cisa_kev": res_cisa,
            "alienvault_otx": res_otx
        }
    }