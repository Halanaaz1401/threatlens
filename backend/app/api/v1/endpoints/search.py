from fastapi import APIRouter, Query
from typing import Optional
from app.services.search_service import search_indicators_es

router = APIRouter()

@router.get("/indicators")
def search_indicators(
    q: Optional[str] = Query(None, description="Full-text search query (IP, domain, hash, tag, or context)"),
    type: Optional[str] = Query(None, description="Filter by indicator type (ip, domain, url, hash_md5, hash_sha256)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    status: Optional[str] = Query(None, description="Filter by status (ACTIVE, REVOKED, FALSE_POSITIVE)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100)
):
    """
    Elasticsearch Full-Text and Faceted Search API.
    Returns matched records along with faceted bucket aggregations.
    """
    results = search_indicators_es(
        query_str=q,
        type_filter=type,
        severity_filter=severity,
        status_filter=status,
        from_=skip,
        size=limit
    )
    return results