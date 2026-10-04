from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Request, Response
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

_APP_START_TIME = datetime.now(timezone.utc)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup table verification, Redis Pub/Sub listener, and graceful shutdown."""
    # Enforce production secrets validation
    settings.validate_production_secrets()

    # Ensure database tables and columns exist
    try:
        init_db()
    except Exception as e:
        print(f"Warning: Database initialization error: {e}")


    # Start Redis Pub/Sub listener
    try:
        await ws_manager.start_redis_listener()
    except Exception as e:
        print(f"Warning: Failed to start Redis Pub/Sub listener: {e}")

    yield

    # Clean shutdown of Redis Pub/Sub listener
    try:
        await ws_manager.stop_redis_listener()
    except Exception:
        pass

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

@app.get("/metrics", tags=["System"])
def prometheus_metrics(
    request: Request,
    db: Session = Depends(get_db)
) -> Response:
    """
    Production-safe Prometheus-compatible metrics endpoint (Phase Hardened, NFR-10).
    Exposes process uptime, dependency health, active websockets,
    and bounded low-cardinality aggregated entity counts.
    Zero secrets, zero credentials, zero raw telemetry payload leakage.
    Protected by optional METRICS_AUTH_TOKEN bearer authentication when configured.
    """
    if settings.METRICS_AUTH_TOKEN:
        auth_hdr = request.headers.get("Authorization", "")
        token = auth_hdr[7:] if auth_hdr.startswith("Bearer ") else request.query_params.get("token", "")
        if token != settings.METRICS_AUTH_TOKEN:
            raise HTTPException(status_code=401, detail="Unauthorized metrics access")

    from app.database import check_db_health
    from app.core.redis import redis_manager
    from app.services.search_service import get_es_health
    from app.models.indicator import Indicator
    from app.models.alert import Alert
    from app.models.incident import Incident
    from app.models.case import Case

    now = datetime.now(timezone.utc)
    uptime_seconds = max(0.0, (now - _APP_START_TIME).total_seconds())

    db_health = check_db_health()
    redis_health = redis_manager.get_health()
    es_health = get_es_health()

    db_up = 1 if db_health.get("status") == "healthy" else 0
    redis_up = 1 if redis_health.get("status") == "healthy" else 0
    es_up = 1 if es_health.get("status") == "healthy" else 0

    active_ws = len(ws_manager.active_connections)

    try:
        ind_count = db.query(Indicator).count()
    except Exception:
        ind_count = 0

    try:
        alert_count = db.query(Alert).count()
    except Exception:
        alert_count = 0

    try:
        inc_count = db.query(Incident).count()
    except Exception:
        inc_count = 0

    try:
        case_count = db.query(Case).count()
    except Exception:
        case_count = 0

    lines = [
        "# HELP threatlens_build_info Build and version metadata",
        "# TYPE threatlens_build_info gauge",
        f'threatlens_build_info{{version="1.0.0",environment="{settings.ENVIRONMENT}"}} 1',
        "",
        "# HELP threatlens_uptime_seconds Total seconds since application process startup",
        "# TYPE threatlens_uptime_seconds gauge",
        f"threatlens_uptime_seconds {uptime_seconds:.2f}",
        "",
        "# HELP threatlens_dependency_up Operational status of backend dependencies (1 = healthy, 0 = degraded/down)",
        "# TYPE threatlens_dependency_up gauge",
        f'threatlens_dependency_up{{dependency="database"}} {db_up}',
        f'threatlens_dependency_up{{dependency="redis"}} {redis_up}',
        f'threatlens_dependency_up{{dependency="elasticsearch"}} {es_up}',
        "",
        "# HELP threatlens_active_websocket_connections Current active WebSocket connections",
        "# TYPE threatlens_active_websocket_connections gauge",
        f"threatlens_active_websocket_connections {active_ws}",
        "",
        "# HELP threatlens_indicators_total Total threat indicators persisted",
        "# TYPE threatlens_indicators_total gauge",
        f"threatlens_indicators_total {ind_count}",
        "",
        "# HELP threatlens_alerts_total Total system alerts",
        "# TYPE threatlens_alerts_total gauge",
        f"threatlens_alerts_total {alert_count}",
        "",
        "# HELP threatlens_incidents_total Total correlated incidents",
        "# TYPE threatlens_incidents_total gauge",
        f"threatlens_incidents_total {inc_count}",
        "",
        "# HELP threatlens_cases_total Total forensic cases",
        "# TYPE threatlens_cases_total gauge",
        f"threatlens_cases_total {case_count}",
        ""
    ]

    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

@app.get("/", tags=["System"])
def root():
    return {
        "platform": "ThreatLens Enterprise CTI & SOC Hub",
        "status": "online",
        "version": "1.0.0",
        "api_v1_docs": "/docs",
        "canonical_tree": "/api/v1"
    }

