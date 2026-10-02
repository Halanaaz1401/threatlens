from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    indicators,
    alerts,
    incidents,
    feeds,
    search,
    enrichment,
    export,
    audit,
    websocket,
    analytics,
    hunting,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(indicators.router, prefix="/indicators", tags=["Indicators"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["Threat Feeds"])
api_router.include_router(search.router, prefix="/search", tags=["Search"])
api_router.include_router(enrichment.router, prefix="/enrichment", tags=["Enrichment"])
api_router.include_router(hunting.router, prefix="/hunting", tags=["Hunting"])
api_router.include_router(analytics.router, tags=["Analytics"])
api_router.include_router(export.router, prefix="/export", tags=["Export"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_router.include_router(websocket.router, tags=["WebSocket"])

__all__ = ["api_router"]
