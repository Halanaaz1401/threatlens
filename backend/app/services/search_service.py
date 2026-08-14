from elasticsearch import Elasticsearch
from typing import Dict, Any, Optional, List

# Elasticsearch Connection
ES_HOST = "http://localhost:9200"
INDEX_NAME = "indicators"

def get_es_client():
    try:
        es = Elasticsearch(ES_HOST, request_timeout=3)
        if es.ping():
            return es
    except Exception:
        pass
    return None

def init_es_index():
    """Create the indicators index with proper mappings for faceted search."""
    es = get_es_client()
    if not es:
        return

    if not es.indices.exists(index=INDEX_NAME):
        mapping = {
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "type": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "threat_score": {"type": "integer"},
                    "confidence": {"type": "integer"},
                    "tags": {"type": "keyword"},
                    "created_at": {"type": "date"}
                }
            }
        }
        es.indices.create(index=INDEX_NAME, body=mapping)

def index_indicator(indicator_data: Dict[str, Any]):
    """Sync/Project an indicator document into Elasticsearch."""
    es = get_es_client()
    if not es:
        return None
    try:
        doc_id = str(indicator_data.get("id"))
        es.index(index=INDEX_NAME, id=doc_id, document=indicator_data)
    except Exception:
        pass

def search_indicators_es(
    query_str: Optional[str] = None,
    type_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    from_: int = 0,
    size: int = 50
) -> Dict[str, Any]:
    """Execute full-text and faceted search with aggregations."""
    es = get_es_client()
    if not es:
        return {"hits": [], "total": 0, "facets": {}, "source": "elasticsearch_unavailable"}

    must_clauses = []

    # 1. Full-Text Query
    if query_str:
        must_clauses.append({
            "multi_match": {
                "query": query_str,
                "fields": ["value^3", "tags", "source", "context.*"],
                "fuzziness": "AUTO"
            }
        })
    else:
        must_clauses.append({"match_all": {}})

    # 2. Filters
    filter_clauses = []
    if type_filter:
        filter_clauses.append({"term": {"type": type_filter}})
    if severity_filter:
        filter_clauses.append({"term": {"severity": severity_filter}})
    if status_filter:
        filter_clauses.append({"term": {"status": status_filter}})

    # 3. Faceted Search / Aggregations
    aggs = {
        "by_type": {"terms": {"field": "type"}},
        "by_severity": {"terms": {"field": "severity"}},
        "by_status": {"terms": {"field": "status"}},
        "by_source": {"terms": {"field": "source"}}
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
        response = es.search(index=INDEX_NAME, body=body)
        
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
        return {"hits": [], "total": 0, "facets": {}, "error": str(e)}