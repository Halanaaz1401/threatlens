from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.database import get_db
from app.models.indicator import Indicator

router = APIRouter(prefix="/api/v1/search", tags=["Search & Discovery"])

@router.get("/")
def search_intelligence(
    q: Optional[str] = Query(None, description="Free text query (value, tag, mitre)"),
    ioc_type: Optional[str] = Query(None, description="ip, domain, url, hash_sha256, cve"),
    min_score: Optional[int] = Query(0, description="Minimum severity score"),
    db: Session = Depends(get_db)
):
    query = db.query(Indicator).filter(Indicator.severity_score >= min_score)
    
    if ioc_type:
        query = query.filter(Indicator.type == ioc_type)
        
    if q:
        query = query.filter(
            or_(
                Indicator.value.ilike(f"%{q}%"),
                Indicator.tags.ilike(f"%{q}%"),
                Indicator.mitre_technique.ilike(f"%{q}%")
            )
        )
        
    results = query.order_by(Indicator.severity_score.desc()).limit(100).all()
    
    # Generate Facet Aggregations
    facets = {
        "by_type": {},
        "high_severity_count": len([r for r in results if r.severity_score >= 80]),
        "total_matches": len(results)
    }
    for item in results:
        facets["by_type"][item.type] = facets["by_type"].get(item.type, 0) + 1
        
    return {
        "status": "success",
        "query": q,
        "facets": facets,
        "results": results
    }
