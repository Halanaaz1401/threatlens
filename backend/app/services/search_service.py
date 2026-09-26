import time
import logging
from typing import Dict, Any, Optional, List
from app.core.config import settings

logger = logging.getLogger("threatlens.search")

try:
    from elasticsearch import Elasticsearch
except ImportError:
    Elasticsearch = None

def get_es_client() -> Optional[Any]:
    """Instantiate and verify Elasticsearch 8.x client using environment settings."""
    if Elasticsearch is None:
        return None
    try:
        kwargs: Dict[str, Any] = {
            "request_timeout": 3.0,
            "max_retries": 2,
            "retry_on_timeout": True
        }
        if settings.ELASTICSEARCH_USERNAME and settings.ELASTICSEARCH_PASSWORD:
            kwargs["basic_auth"] = (
                settings.ELASTICSEARCH_USERNAME,
                settings.ELASTICSEARCH_PASSWORD
            )
        es = Elasticsearch(settings.ELASTICSEARCH_URL, **kwargs)
        if es.ping():
            return es
    except Exception as e:
        logger.debug(f"Elasticsearch ping failed for {settings.ELASTICSEARCH_URL}: {e}")
    return None

def init_es_index() -> bool:
    """Create the indicators index with proper mappings for full-text and faceted search."""
    es = get_es_client()
    if not es:
        return False

    index_name = settings.ELASTICSEARCH_INDEX
    try:
        if not es.indices.exists(index=index_name):
            mapping = {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "value": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 512}
                            }
                        },
                        "type": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "threat_score": {"type": "integer"},
                        "severity_score": {"type": "integer"},
                        "confidence": {"type": "integer"},
                        "tlp": {"type": "keyword"},
                        "mitre_technique": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "last_seen": {"type": "date"}
                    }
                }
            }
            es.indices.create(index=index_name, body=mapping)
            logger.info(f"Initialized Elasticsearch index: {index_name}")
        return True
    except Exception as e:
        logger.warning(f"Elasticsearch index initialization failed: {e}")
        return False

def index_indicator(indicator_data: Dict[str, Any]) -> bool:
    """Sync/Project an indicator document into Elasticsearch."""
    es = get_es_client()
    if not es:
        return False
    try:
        doc_id = str(indicator_data.get("id"))
        es.index(index=settings.ELASTICSEARCH_INDEX, id=doc_id, document=indicator_data)
        return True
    except Exception as e:
        logger.warning(f"Failed to index indicator {indicator_data.get('id')}: {e}")
        return False

def delete_indicator(doc_id: str) -> bool:
    """Remove an indicator document from Elasticsearch."""
    es = get_es_client()
    if not es:
        return False
    try:
        es.delete(index=settings.ELASTICSEARCH_INDEX, id=str(doc_id), ignore=[404])
        return True
    except Exception as e:
        logger.warning(f"Failed to delete indicator from ES: {e}")
        return False

def search_indicators_es(
    query_str: Optional[str] = None,
    type_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    from_: int = 0,
    size: int = 50
) -> Dict[str, Any]:
    """
    Execute full-text and faceted search with aggregations against Elasticsearch.
    Falls back gracefully when Elasticsearch is unavailable.
    """
    es = get_es_client()
    index_name = settings.ELASTICSEARCH_INDEX

    if not es:
        return {
            "hits": [],
            "total": 0,
            "facets": {},
            "source": "elasticsearch_unavailable",
            "message": "Elasticsearch service offline. Using graceful fallback."
        }

    must_clauses: List[Dict[str, Any]] = []

    # 1. Full-Text Query
    if query_str and query_str.strip():
        must_clauses.append({
            "multi_match": {
                "query": query_str.strip(),
                "fields": ["value^3", "tags", "source", "mitre_technique", "context.*"],
                "fuzziness": "AUTO"
            }
        })
    else:
        must_clauses.append({"match_all": {}})

    # 2. Filters
    filter_clauses: List[Dict[str, Any]] = []
    if type_filter:
        filter_clauses.append({"term": {"type": type_filter.lower()}})
    if severity_filter:
        filter_clauses.append({"term": {"severity": severity_filter.upper()}})
    if status_filter:
        filter_clauses.append({"term": {"status": status_filter.lower()}})

    # 3. Faceted Search / Aggregations
    aggs = {
        "by_type": {"terms": {"field": "type", "size": 10}},
        "by_severity": {"terms": {"field": "severity", "size": 10}},
        "by_status": {"terms": {"field": "status", "size": 10}},
        "by_source": {"terms": {"field": "source", "size": 10}}
    }

    body = {
        "from": from_,
        "size": size,
        "query": {
            "bool": {
                "must": must_clauses,
                "filter": filter_clauses
            }
        },
        "aggs": aggs
    }

    try:
        response = es.search(index=index_name, body=body)
        hits = [hit["_source"] for hit in response["hits"]["hits"]]
        total = response["hits"]["total"]["value"]

        facets = {
            "type": {b["key"]: b["doc_count"] for b in response.get("aggregations", {}).get("by_type", {}).get("buckets", [])},
            "severity": {b["key"]: b["doc_count"] for b in response.get("aggregations", {}).get("by_severity", {}).get("buckets", [])},
            "status": {b["key"]: b["doc_count"] for b in response.get("aggregations", {}).get("by_status", {}).get("buckets", [])},
            "source": {b["key"]: b["doc_count"] for b in response.get("aggregations", {}).get("by_source", {}).get("buckets", [])},
        }

        return {
            "hits": hits,
            "total": total,
            "facets": facets,
            "source": "elasticsearch"
        }
    except Exception as e:
        logger.warning(f"Elasticsearch search failed: {e}")
        return _fallback_db_search(
            query_str=query_str,
            type_filter=type_filter,
            severity_filter=severity_filter,
            status_filter=status_filter,
            skip=from_,
            limit=size,
            error=str(e)
        )

def _fallback_db_search(
    query_str: Optional[str] = None,
    type_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    error: Optional[str] = None
) -> Dict[str, Any]:
    """Resilient fallback querying database directly when Elasticsearch is offline."""
    from app.db.session import SessionLocal
    from app.models.indicator import Indicator
    from sqlalchemy import or_

    db = SessionLocal()
    try:
        q = db.query(Indicator)
        if query_str and query_str.strip():
            term = f"%{query_str.strip()}%"
            q = q.filter(
                or_(
                    Indicator.value.ilike(term),
                    Indicator.source.ilike(term),
                    Indicator.mitre_technique.ilike(term)
                )
            )
        if type_filter:
            q = q.filter(Indicator.type == type_filter.lower())
        if severity_filter:
            q = q.filter(Indicator.severity == severity_filter.upper())
        if status_filter:
            q = q.filter(Indicator.status == status_filter.lower())

        total = q.count()
        records = q.offset(skip).limit(limit).all()

        hits = [
            {
                "id": str(r.id),
                "value": r.value,
                "type": r.type,
                "severity": r.severity,
                "threat_score": r.threat_score or r.severity_score or 0,
                "confidence": r.confidence,
                "status": r.status,
                "source": r.source,
                "tags": r.tags if isinstance(r.tags, list) else [],
                "created_at": r.created_at.isoformat() if r.created_at else None
            }
            for r in records
        ]

        result = {
            "hits": hits,
            "total": total,
            "facets": {},
            "source": "elasticsearch_fallback_database"
        }
        if error:
            result["warning"] = f"Elasticsearch unavailable: {error}"
        return result
    except Exception as e:
        logger.error(f"Fallback search query failed: {e}")
        return {"hits": [], "total": 0, "facets": {}, "source": "elasticsearch_unavailable"}
    finally:
        db.close()

def get_es_health() -> Dict[str, Any]:
    """Return Elasticsearch health report without leaking secrets."""
    start = time.time()
    es = get_es_client()
    if es:
        try:
            cluster_health = es.cluster.health()
            latency_ms = round((time.time() - start) * 1000, 2)
            return {
                "status": "healthy",
                "backend": "elasticsearch",
                "cluster_name": cluster_health.get("cluster_name", "threatlens-cluster"),
                "cluster_status": cluster_health.get("status", "green"),
                "latency_ms": latency_ms
            }
        except Exception as e:
            return {"status": "degraded", "backend": "elasticsearch", "error": str(e)}
    return {
        "status": "unavailable",
        "backend": "database_fallback",
        "message": "Elasticsearch service not responding, using resilient database search fallback"
    }

__all__ = [
    "get_es_client",
    "init_es_index",
    "index_indicator",
    "delete_indicator",
    "search_indicators_es",
    "get_es_health"
]