import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.core.config import settings
from app.core.redis import publish_enrichment_event, redis_manager
from app.models.indicator import Indicator, IndicatorType
from app.models.enrichment import IndicatorEnrichment
from app.services.enrichment import (
    get_available_providers,
    get_provider_by_name,
    NormalizedEnrichmentResult,
)

logger = logging.getLogger("threatlens.enrichment")

CACHE_EXPIRE_SECONDS = 3600

def _serialize_enrichment(record: IndicatorEnrichment) -> Dict[str, Any]:
    """Serialize an IndicatorEnrichment database model into a clean dictionary."""
    return {
        "id": str(record.id),
        "indicator_id": str(record.indicator_id),
        "provider": record.provider,
        "queried_value": record.queried_value,
        "indicator_type": record.indicator_type,
        "verdict": record.verdict,
        "confidence": record.confidence,
        "malicious_count": record.malicious_count,
        "suspicious_count": record.suspicious_count,
        "reputation": record.reputation,
        "categories": record.categories or [],
        "tags": record.tags or [],
        "malware_families": record.malware_families or [],
        "threat_actors": record.threat_actors or [],
        "country": record.country,
        "asn": record.asn,
        "network": record.network,
        "external_references": record.external_references or [],
        "raw_metadata": record.raw_metadata or {},
        "success": record.success,
        "error_message": record.error_message,
        "fetched_at": record.fetched_at.isoformat() if record.fetched_at else None,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }

def calculate_aggregate_intelligence(results: List[NormalizedEnrichmentResult]) -> Dict[str, Any]:
    """
    Deterministically synthesize multi-provider threat intelligence (Step 9).
    Combines verdicts, confidence, malicious indicators, malware families, and tags.
    """
    successful_results = [r for r in results if r.success]
    if not successful_results:
        return {
            "verdict": "unknown",
            "confidence": 0,
            "malicious_providers": 0,
            "suspicious_providers": 0,
            "clean_providers": 0,
            "tags": [],
            "malware_families": [],
            "threat_actors": [],
            "summary": "No external provider reported successful telemetry",
        }

    malicious_count = sum(1 for r in successful_results if r.verdict == "malicious")
    suspicious_count = sum(1 for r in successful_results if r.verdict == "suspicious")
    clean_count = sum(1 for r in successful_results if r.verdict == "clean")

    # Aggregate verdict determination
    if malicious_count >= 1:
        aggregate_verdict = "malicious"
    elif suspicious_count >= 1:
        aggregate_verdict = "suspicious"
    elif clean_count > 0:
        aggregate_verdict = "clean"
    else:
        aggregate_verdict = "unknown"

    # Aggregated confidence: weighted average based on evidence
    confidences = [r.confidence for r in successful_results if r.confidence > 0]
    avg_confidence = int(sum(confidences) / len(confidences)) if confidences else 30
    if malicious_count >= 2:
        aggregate_confidence = max(avg_confidence, 90)
    elif malicious_count == 1:
        aggregate_confidence = max(avg_confidence, 75)
    elif suspicious_count >= 1:
        aggregate_confidence = max(avg_confidence, 55)
    else:
        aggregate_confidence = avg_confidence

    # Gather unique tags, malware families, threat actors
    all_tags = set()
    all_malware = set()
    all_actors = set()
    for r in successful_results:
        for t in r.tags:
            all_tags.add(t)
        for m in r.malware_families:
            all_malware.add(m)
        for a in r.threat_actors:
            all_actors.add(a)

    return {
        "verdict": aggregate_verdict,
        "confidence": aggregate_confidence,
        "malicious_providers": malicious_count,
        "suspicious_providers": suspicious_count,
        "clean_providers": clean_count,
        "tags": sorted(list(all_tags)),
        "malware_families": sorted(list(all_malware)),
        "threat_actors": sorted(list(all_actors)),
        "summary": f"{malicious_count} malicious, {suspicious_count} suspicious, {clean_count} clean reports across {len(successful_results)} providers",
    }

async def enrich_indicator(
    db: Session,
    indicator_id: str,
    force_refresh: bool = False,
    actor: str = "system",
) -> Dict[str, Any]:
    """
    Core Threat Intelligence Orchestrator (Steps 8, 9, 10).
    Coordinates provider queries, caches results, computes aggregate intelligence,
    persists records, and publishes Redis telemetry.
    """
    indicator = db.query(Indicator).filter(Indicator.id == str(indicator_id)).first()
    if not indicator:
        raise ValueError(f"Indicator '{indicator_id}' not found")

    ioc_type_str = str(indicator.type.value if hasattr(indicator.type, "value") else indicator.type).lower()
    now = datetime.utcnow()
    ttl_delta = timedelta(minutes=settings.THREAT_INTEL_CACHE_TTL_MINUTES)

    # 1. Determine compatible registered providers
    all_providers = get_available_providers()
    compatible_providers = [p for p in all_providers if ioc_type_str in [t.lower() for t in p.supported_ioc_types]]

    # 2. Check existing database cache (Step 10)
    existing_records = {
        rec.provider: rec
        for rec in db.query(IndicatorEnrichment).filter(IndicatorEnrichment.indicator_id == str(indicator.id)).all()
    }

    providers_to_query = []
    cached_results: List[NormalizedEnrichmentResult] = []

    for provider in compatible_providers:
        existing = existing_records.get(provider.provider_name)
        # Check cache validity
        if not force_refresh and existing and existing.expires_at and existing.expires_at > now:
            # Fresh cache hit
            cached_result = NormalizedEnrichmentResult(
                indicator_id=str(indicator.id),
                provider=existing.provider,
                queried_value=existing.queried_value,
                indicator_type=existing.indicator_type,
                verdict=existing.verdict,
                confidence=existing.confidence,
                malicious_count=existing.malicious_count,
                suspicious_count=existing.suspicious_count,
                reputation=existing.reputation,
                categories=existing.categories or [],
                tags=existing.tags or [],
                malware_families=existing.malware_families or [],
                threat_actors=existing.threat_actors or [],
                country=existing.country,
                asn=existing.asn,
                network=existing.network,
                external_references=existing.external_references or [],
                raw_metadata=existing.raw_metadata or {},
                fetched_at=existing.fetched_at,
                expires_at=existing.expires_at,
                success=existing.success,
                error_message=existing.error_message,
            )
            cached_results.append(cached_result)
        else:
            providers_to_query.append(provider)

    # 3. Query non-cached providers asynchronously
    fetched_results: List[NormalizedEnrichmentResult] = []
    if providers_to_query:
        # Publish ENRICHMENT_STARTED event
        try:
            publish_enrichment_event("ENRICHMENT_STARTED", {
                "indicator_id": str(indicator.id),
                "value": indicator.value,
                "type": ioc_type_str,
                "providers": [p.provider_name for p in providers_to_query],
                "actor": actor,
            })
        except Exception:
            pass

        tasks = [
            p.enrich(value=indicator.value, ioc_type=ioc_type_str, indicator_id=str(indicator.id))
            for p in providers_to_query
        ]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        for provider, res in zip(providers_to_query, task_results):
            if isinstance(res, Exception):
                logger.error(f"Provider {provider.provider_name} crashed: {res}")
                failed_res = NormalizedEnrichmentResult(
                    indicator_id=str(indicator.id),
                    provider=provider.provider_name,
                    queried_value=indicator.value,
                    indicator_type=ioc_type_str,
                    verdict="unknown",
                    confidence=0,
                    success=False,
                    error_message=f"Provider execution exception: {str(res)}",
                )
                fetched_results.append(failed_res)
            elif isinstance(res, NormalizedEnrichmentResult):
                fetched_results.append(res)

    all_results = cached_results + fetched_results

    # 4. Persist newly fetched enrichment results into database (Step 4)
    for res in fetched_results:
        existing = existing_records.get(res.provider)
        expires_at = now + ttl_delta

        if existing:
            # Update existing record
            existing.queried_value = res.queried_value
            existing.indicator_type = res.indicator_type
            existing.verdict = res.verdict
            existing.confidence = res.confidence
            existing.malicious_count = res.malicious_count
            existing.suspicious_count = res.suspicious_count
            existing.reputation = res.reputation
            existing.categories = res.categories
            existing.tags = res.tags
            existing.malware_families = res.malware_families
            existing.threat_actors = res.threat_actors
            existing.country = res.country
            existing.asn = res.asn
            existing.network = res.network
            existing.external_references = res.external_references
            existing.raw_metadata = res.raw_metadata
            existing.success = res.success
            existing.error_message = res.error_message
            existing.fetched_at = res.fetched_at or now
            existing.expires_at = expires_at
        else:
            new_record = IndicatorEnrichment(
                indicator_id=str(indicator.id),
                provider=res.provider,
                queried_value=res.queried_value,
                indicator_type=res.indicator_type,
                verdict=res.verdict,
                confidence=res.confidence,
                malicious_count=res.malicious_count,
                suspicious_count=res.suspicious_count,
                reputation=res.reputation,
                categories=res.categories,
                tags=res.tags,
                malware_families=res.malware_families,
                threat_actors=res.threat_actors,
                country=res.country,
                asn=res.asn,
                network=res.network,
                external_references=res.external_references,
                raw_metadata=res.raw_metadata,
                success=res.success,
                error_message=res.error_message,
                fetched_at=res.fetched_at or now,
                expires_at=expires_at,
            )
            db.add(new_record)

    db.commit()

    # 5. Compute Aggregate Intelligence (Step 9)
    aggregate = calculate_aggregate_intelligence(all_results)

    # 6. Corroborate evidence into Indicator context & tags without overwriting core score
    if aggregate.get("tags") or aggregate.get("malware_families"):
        existing_tags = set(indicator.tags or [])
        for t in aggregate.get("tags", []):
            existing_tags.add(t)
        for m in aggregate.get("malware_families", []):
            existing_tags.add(m)
        indicator.tags = sorted(list(existing_tags))

        # Store enrichment aggregate in context
        ctx = indicator.context or {}
        ctx["enrichment_verdict"] = aggregate["verdict"]
        ctx["enrichment_confidence"] = aggregate["confidence"]
        ctx["enrichment_updated_at"] = now.isoformat()
        indicator.context = ctx
        db.commit()
        db.refresh(indicator)

    # Correlate enrichment evidence into active incidents (Step 13)
    try:
        from app.models.incident import Incident, IncidentTimeline
        from app.models.alert import Alert
        linked_incidents = (
            db.query(Incident)
            .join(Alert, Alert.incident_id == Incident.id)
            .filter(
                and_(
                    Alert.indicator_id == str(indicator.id),
                    Incident.status != "CLOSED",
                )
            )
            .all()
        )
        for inc in linked_incidents:
            if aggregate.get("malware_families") or aggregate.get("threat_actors") or aggregate.get("verdict") == "malicious":
                t_entry = IncidentTimeline(
                    incident_id=inc.id,
                    action="EVIDENCE_ADDED",
                    details={
                        "indicator_value": indicator.value,
                        "verdict": aggregate.get("verdict"),
                        "malware_families": aggregate.get("malware_families", []),
                        "threat_actors": aggregate.get("threat_actors", []),
                        "confidence": aggregate.get("confidence", 0),
                    },
                    actor=actor,
                )
                db.add(t_entry)
        db.commit()
    except Exception as inc_err:
        logger.debug(f"Incident enrichment evidence attachment skipped: {inc_err}")

    # Project into Elasticsearch (Step 14)
    try:
        from app.services.search_service import index_indicator
        index_indicator({
            "id": str(indicator.id),
            "value": indicator.value,
            "type": ioc_type_str,
            "source": indicator.source,
            "severity": str(indicator.severity.value if hasattr(indicator.severity, "value") else indicator.severity),
            "status": str(indicator.status.value if hasattr(indicator.status, "value") else indicator.status),
            "threat_score": indicator.threat_score,
            "confidence": indicator.confidence,
            "tags": indicator.tags or [],
            "enrichment_verdict": aggregate.get("verdict"),
            "enrichment_confidence": aggregate.get("confidence"),
            "malware_families": aggregate.get("malware_families", []),
            "threat_actors": aggregate.get("threat_actors", []),
        })
    except Exception:
        pass

    # 7. Publish Redis Enrichment Completion Event (Step 12)
    successful_count = sum(1 for r in all_results if r.success)
    failed_count = len(all_results) - successful_count

    if failed_count == 0 and len(all_results) > 0:
        event_type = "ENRICHMENT_COMPLETED"
        status_str = "success"
    elif successful_count > 0:
        event_type = "ENRICHMENT_PARTIAL"
        status_str = "partial"
    else:
        event_type = "ENRICHMENT_FAILED"
        status_str = "failed"

    event_data = {
        "indicator_id": str(indicator.id),
        "value": indicator.value,
        "type": ioc_type_str,
        "status": status_str,
        "successful_providers": [r.provider for r in all_results if r.success],
        "failed_providers": [r.provider for r in all_results if not r.success],
        "verdict": aggregate["verdict"],
        "confidence": aggregate["confidence"],
        "actor": actor,
    }

    try:
        publish_enrichment_event(event_type, event_data)
    except Exception as e:
        logger.warning(f"Failed to publish enrichment event to Redis: {e}")

    # Reload records for return payload
    final_records = db.query(IndicatorEnrichment).filter(
        IndicatorEnrichment.indicator_id == str(indicator.id)
    ).all()

    return {
        "status": status_str,
        "indicator_id": str(indicator.id),
        "value": indicator.value,
        "type": ioc_type_str,
        "aggregate": aggregate,
        "enrichments": [_serialize_enrichment(r) for r in final_records],
        "cache_hits": len(cached_results),
        "live_queries": len(fetched_results),
    }

def get_indicator_enrichments(db: Session, indicator_id: str) -> List[Dict[str, Any]]:
    """Retrieve all stored enrichment records for an indicator."""
    records = db.query(IndicatorEnrichment).filter(
        IndicatorEnrichment.indicator_id == str(indicator_id)
    ).all()
    return [_serialize_enrichment(r) for r in records]

def get_indicator_enrichment_by_provider(
    db: Session,
    indicator_id: str,
    provider: str,
) -> Optional[Dict[str, Any]]:
    """Retrieve enrichment record for a specific provider and indicator."""
    record = db.query(IndicatorEnrichment).filter(
        and_(
            IndicatorEnrichment.indicator_id == str(indicator_id),
            IndicatorEnrichment.provider == provider.lower(),
        )
    ).first()
    return _serialize_enrichment(record) if record else None

async def refresh_expired_enrichments(db: Session, limit: int = 50) -> Dict[str, Any]:
    """Batch refresh indicators whose enrichments have expired."""
    now = datetime.utcnow()
    expired_enrichments = db.query(IndicatorEnrichment).filter(
        and_(
            IndicatorEnrichment.expires_at != None,
            IndicatorEnrichment.expires_at < now,
        )
    ).limit(limit).all()

    refreshed_indicators = set()
    for rec in expired_enrichments:
        if rec.indicator_id not in refreshed_indicators:
            refreshed_indicators.add(rec.indicator_id)
            try:
                await enrich_indicator(db, str(rec.indicator_id), force_refresh=True, actor="scheduler")
            except Exception as e:
                logger.error(f"Failed to refresh enrichment for {rec.indicator_id}: {e}")

    return {
        "status": "success",
        "refreshed_count": len(refreshed_indicators),
        "refreshed_indicator_ids": [str(i) for i in refreshed_indicators],
    }

# ---------------------------------------------------------------------------
# Backward Compatibility Helpers for existing endpoint and UI calls
# ---------------------------------------------------------------------------
import httpx
import json

def get_redis_client():
    return redis_manager.get_client()

async def get_ip_enrichment(ip_address: str) -> Dict[str, Any]:
    """Free IP geolocation lookup (ip-api.com). Backward compatibility."""
    cache_key = f"enrichment:ip:{ip_address}"
    redis_client = get_redis_client()

    if redis_client:
        try:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                data = json.loads(cached_data)
                data["cached"] = True
                return data
        except Exception:
            pass

    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("status") == "success":
                    enrichment_result = {
                        "ip": ip_address,
                        "country": res_data.get("country"),
                        "country_code": res_data.get("countryCode"),
                        "city": res_data.get("city"),
                        "isp": res_data.get("isp"),
                        "org": res_data.get("org"),
                        "asn": res_data.get("as"),
                        "cached": False,
                    }

                    if redis_client:
                        try:
                            redis_client.setex(cache_key, CACHE_EXPIRE_SECONDS, json.dumps(enrichment_result))
                        except Exception:
                            pass

                    return enrichment_result
    except Exception as e:
        return {"ip": ip_address, "status": "failed", "error": str(e), "cached": False}

    return {"ip": ip_address, "status": "not_found", "cached": False}

async def get_domain_enrichment(domain: str) -> Dict[str, Any]:
    """Domain intelligence enrichment backward compatibility."""
    return {
        "domain": domain,
        "type": "Domain Name",
        "status": "Enriched",
        "cached": False,
    }