import httpx
import logging
import asyncio
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.services.scoring_service import calculate_ioc_severity
from app.services.search_service import index_indicator

logger = logging.getLogger(__name__)

def _save_and_index_ioc(db: Session, value: str, ioc_type: IndicatorType, source: str, confidence: int, tags: list = None, context: dict = None):
    """Helper function to deduplicate, score, save to DB and project to Elasticsearch."""
    try:
        existing = db.query(Indicator).filter(Indicator.value == value).first()
        if existing:
            existing.sightings += 1
            existing.last_seen = datetime.utcnow()
            db.commit()
            return "updated"

        # Calculate severity and threat score
        scoring = calculate_ioc_severity(
            confidence=confidence,
            source=source,
            sightings_count=1
        )
        
        severity_value = ThreatSeverity[scoring["severity"]] if hasattr(ThreatSeverity, scoring["severity"]) else ThreatSeverity.MEDIUM

        new_ioc = Indicator(
            value=value,
            type=ioc_type,
            source=source,
            confidence=confidence,
            threat_score=scoring["score"],
            severity=severity_value,
            status=IndicatorStatus.ACTIVE,
            tags=tags or [],
            context=context or {}
        )
        db.add(new_ioc)
        db.commit()
        db.refresh(new_ioc)

        # Project to Elasticsearch
        try:
            index_indicator({
                "id": str(new_ioc.id),
                "value": new_ioc.value,
                "type": str(new_ioc.type.value if hasattr(new_ioc.type, "value") else new_ioc.type),
                "source": new_ioc.source,
                "severity": str(new_ioc.severity.value if hasattr(new_ioc.severity, "value") else new_ioc.severity),
                "status": str(new_ioc.status.value if hasattr(new_ioc.status, "value") else new_ioc.status),
                "threat_score": new_ioc.threat_score,
                "confidence": new_ioc.confidence,
                "tags": new_ioc.tags,
                "created_at": new_ioc.first_seen.isoformat() if new_ioc.first_seen else None
            })
        except Exception:
            pass

        return "created"
    except Exception as e:
        db.rollback()
        logger.error(f"Error processing IOC {value}: {e}")
        return "error"

# 1. URLhaus Feed (URLs)
async def fetch_urlhaus_recent_urls(db: Session, limit: int = 10):
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return {"source": "urlhaus", "status": "failed"}
            
            data = response.json()
            count = 0
            for item in list(data.values())[:limit]:
                if isinstance(item, list):
                    for sub_item in item[:limit]:
                        val = sub_item.get("url")
                        if val:
                            res = _save_and_index_ioc(
                                db=db,
                                value=val,
                                ioc_type=IndicatorType.URL,
                                source="urlhaus",
                                confidence=85,
                                tags=sub_item.get("tags") or ["malware"],
                                context={"threat": sub_item.get("threat")}
                            )
                            if res == "created":
                                count += 1
                elif isinstance(item, dict):
                    val = item.get("url")
                    if val:
                        res = _save_and_index_ioc(
                            db=db,
                            value=val,
                            ioc_type=IndicatorType.URL,
                            source="urlhaus",
                            confidence=85,
                            tags=item.get("tags") or ["malware"],
                            context={"threat": item.get("threat")}
                        )
                        if res == "created":
                            count += 1
            return {"source": "urlhaus", "status": "success", "new_indicators": count}
    except Exception as e:
        return {"source": "urlhaus", "status": "timeout_or_error", "detail": str(e)}

# 2. ThreatFox Feed (Multi-type IOCs)
async def fetch_threatfox_recent_iocs(db: Session, limit: int = 10):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                return {"source": "threatfox", "status": "failed"}
            
            data = response.json()
            if data.get("query_status") != "ok":
                return {"source": "threatfox", "status": "no_data"}
            
            count = 0
            for item in data.get("data", [])[:limit]:
                ioc_val = item.get("ioc")
                raw_type = item.get("ioc_type", "").lower()
                
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
                    context={"malware": item.get("malware_printable"), "threat_type": item.get("threat_type")}
                )
                if res == "created":
                    count += 1
            return {"source": "threatfox", "status": "success", "new_indicators": count}
    except Exception as e:
        return {"source": "threatfox", "status": "timeout_or_error", "detail": str(e)}

# 3. Feodo Tracker Feed (Botnet C2 IPs)
async def fetch_feodo_tracker_ips(db: Session, limit: int = 10):
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recent.json"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return {"source": "feodo_tracker", "status": "failed"}
            
            data = response.json()
            count = 0
            for item in data[:limit]:
                ip_val = item.get("ip_address")
                if ip_val:
                    res = _save_and_index_ioc(
                        db=db,
                        value=ip_val,
                        ioc_type=IndicatorType.IP,
                        source="feodo_tracker",
                        confidence=95,
                        tags=["botnet", item.get("malware", "c2").lower()],
                        context={"malware": item.get("malware"), "status": item.get("status")}
                    )
                    if res == "created":
                        count += 1
            return {"source": "feodo_tracker", "status": "success", "new_indicators": count}
    except Exception as e:
        return {"source": "feodo_tracker", "status": "timeout_or_error", "detail": str(e)}

# 4. MalwareBazaar Feed (SHA256 Hashes)
async def fetch_malwarebazaar_recent_hashes(db: Session, limit: int = 10):
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_recent", "selector": "time"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, data=payload)
            if response.status_code != 200:
                return {"source": "malwarebazaar", "status": "failed"}
            
            data = response.json()
            if data.get("query_status") != "ok":
                return {"source": "malwarebazaar", "status": "no_data"}
            
            count = 0
            for item in data.get("data", [])[:limit]:
                sha256_val = item.get("sha256_hash")
                if sha256_val:
                    res = _save_and_index_ioc(
                        db=db,
                        value=sha256_val,
                        ioc_type=IndicatorType.HASH_SHA256,
                        source="malwarebazaar",
                        confidence=90,
                        tags=item.get("tags") or ["malware", item.get("file_type", "payload")],
                        context={"file_type": item.get("file_type"), "signature": item.get("signature")}
                    )
                    if res == "created":
                        count += 1
            return {"source": "malwarebazaar", "status": "success", "new_indicators": count}
    except Exception as e:
        return {"source": "malwarebazaar", "status": "timeout_or_error", "detail": str(e)}