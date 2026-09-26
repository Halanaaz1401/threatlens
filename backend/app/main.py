from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import engine, get_db, init_db
from app.db.base import Base
import app.models  # Ensures all canonical models are registered with Base metadata
from app.api.v1.api import api_router
from app.core.config import settings
from app.core.websocket import ws_manager
from app.core.rbac import get_ws_current_user
from app.models.user import User

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup table verification and graceful shutdown."""
    # Ensure database tables and columns exist
    try:
        init_db()
    except Exception as e:
        print(f"Warning: Database initialization error: {e}")
    yield

app = FastAPI(
    title="ThreatLens Enterprise CTI API",
    description="Cyber Threat Intelligence & Incident Correlation Backend (Phase 1B Hardened)",
    version="1.0.0",
    lifespan=lifespan
)

# Proper CORS for Next.js frontend & production deployment (No wildcard origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
)

# Canonical API Router Tree (Phase 1A/1B)
app.include_router(api_router, prefix="/api/v1")

# Direct WebSocket Gateway for backwards-compatibility (Secured with JWT)
@app.websocket("/ws/alerts")
async def root_websocket_alerts_endpoint(
    websocket: WebSocket,
    user: Optional[User] = Depends(get_ws_current_user)
):
    """Secured root WebSocket gateway alias targeting canonical alert stream."""
    if user is None:
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Health Check Endpoints (Public)
@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """
    Operational & Infrastructure Health Check (Phase 2).
    Monitors application status, database, Redis, and Elasticsearch.
    Distinguishes healthy, degraded, and unavailable states without leaking credentials.
    """
    from app.database import check_db_health
    from app.core.redis import redis_manager
    from app.services.search_service import get_es_health

    db_health = check_db_health()
    redis_health = redis_manager.get_health()
    es_health = get_es_health()

    if db_health["status"] != "healthy":
        overall_status = "unhealthy"
    elif redis_health["status"] != "healthy" or es_health["status"] != "healthy":
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return {
        "status": "ok" if overall_status in ("healthy", "degraded") else "unhealthy",
        "overall_health": overall_status,
        "application": "healthy",
        "database": db_health.get("status", "healthy"),
        "infrastructure": {
            "database": db_health,
            "redis": redis_health,
            "elasticsearch": es_health
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }

@app.get("/health/ready", tags=["System"])
def readiness_check() -> Dict[str, Any]:
    """Readiness probe for container orchestrators (Kubernetes / Docker Compose)."""
    from app.database import check_db_health
    db_health = check_db_health()
    if db_health["status"] != "healthy":
        raise HTTPException(status_code=503, detail="Database persistence not ready")
    return {"status": "ready", "database": db_health["dialect"]}

@app.get("/", tags=["System"])
def root():
    return {
        "platform": "ThreatLens Enterprise CTI & SOC Hub",
        "status": "online",
        "version": "1.0.0",
        "api_v1_docs": "/docs",
        "canonical_tree": "/api/v1"
    }
