"""
ThreatLens - Phase 4C Canonical Threat Analytics Endpoints
Mounted under /api/v1/analytics/
Exposes real database-backed metrics, executive KPIs, severity breakdowns,
time-series trends, and MITRE/geographic aggregations.
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.core.rbac import require_authenticated_user
from app.services import analytics_service

router = APIRouter(prefix="/analytics", tags=["analytics"])

@router.get("/overview")
def get_analytics_overview(
    time_range: str = Query("24h", pattern="^(24h|7d|30d|90d)$", description="Bounded time window (24h, 7d, 30d, 90d)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Combined executive dashboard overview including KPIs, severity distribution,
    and continuous threat ingestion velocity.
    """
    try:
        kpis = analytics_service.get_executive_kpis(db, time_range)
        trends = analytics_service.get_threat_trends(db, time_range)
        severity = analytics_service.get_severity_distribution(db)
        types_dist = analytics_service.get_indicator_type_distribution(db)
        return {
            "status": "success",
            "time_range": time_range,
            "kpis": kpis,
            "trends": trends,
            "severity": severity,
            "indicator_types": types_dist
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Analytics overview failed: {str(e)}")

@router.get("/kpis")
def get_kpis(
    time_range: str = Query("24h", pattern="^(24h|7d|30d|90d)$", description="Bounded time window"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Retrieve board-ready Executive Risk Posture, MTTD, MTTR, and SEV-1 active metrics.
    """
    try:
        return analytics_service.get_executive_kpis(db, time_range)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/trends")
def get_trends(
    time_range: str = Query("24h", pattern="^(24h|7d|30d|90d)$", description="Bounded time window"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Continuous, zero-filled time-series threat velocity and high-severity ingestion rate.
    """
    try:
        return analytics_service.get_threat_trends(db, time_range)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/severity")
def get_severity(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Distribution of threat severity across indicators, alerts, and incidents.
    """
    return analytics_service.get_severity_distribution(db)

@router.get("/indicator-types")
def get_indicator_types(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Distribution of canonical indicator types (IP, domain, URL, hash, CVE).
    """
    return analytics_service.get_indicator_type_distribution(db)

@router.get("/incidents")
def get_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Aggregated incident lifecycle metrics: status breakdown, severity, and alert correlation ratio.
    """
    return analytics_service.get_incident_analytics(db)

@router.get("/mitre")
def get_mitre_techniques(
    limit: int = Query(15, ge=1, le=50, description="Max techniques to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    MITRE ATT&CK technique frequencies from ingested telemetry.
    Returns has_data=false when no techniques are present.
    """
    return analytics_service.get_mitre_analytics(db, limit)

@router.get("/geography")
def get_geography(
    limit: int = Query(10, ge=1, le=50, description="Max countries to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Geographic origin density derived from verified threat intelligence enrichments.
    Returns has_data=false when no country metadata is present.
    """
    return analytics_service.get_geographic_analytics(db, limit)

@router.get("/sources")
def get_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Threat intelligence volume breakdown grouped by feed/source.
    """
    return analytics_service.get_source_analytics(db)
