from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Models import for DB creation
from app.db.base import Base
from app.db.session import engine
from app.models.indicator import Indicator
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import SecurityEvent, Incident, IncidentTimeline

# Endpoints import
from app.api.v1.endpoints import auth, indicators, enrichment, search, alerts, incidents, export
from app.services.search_service import init_es_index

# Auto-create all DB Tables
Base.metadata.create_all(bind=engine)

# Rate Limiter: 100 requests per minute per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Cyber Threat Intelligence Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Startup Event
@app.on_event("startup")
def startup_event():
    init_es_index()

# CORS Hardening
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OWASP Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Register Routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(indicators.router, prefix="/api/v1/indicators", tags=["Indicators"])
app.include_router(enrichment.router, prefix="/api/v1/enrichment", tags=["Enrichment"])
app.include_router(search.router, prefix="/api/v1/search", tags=["Search"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts & Real-Time"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents & Correlation"])
app.include_router(export.router, prefix="/api/v1/export", tags=["Export & STIX"])

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "ThreatLens CTI API", "version": "1.0.0"}