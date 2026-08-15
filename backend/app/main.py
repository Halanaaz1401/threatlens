from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Models import for DB creation
from app.db.base import Base
from app.db.session import engine
from app.models.indicator import Indicator
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import SecurityEvent, Incident, IncidentTimeline

# Endpoints import
from app.api.v1.endpoints import auth, indicators, enrichment, search, alerts, incidents
from app.services.search_service import init_es_index

# Auto-create all DB Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Cyber Threat Intelligence Platform",
    version="1.0.0"
)

# Startup Event for Elasticsearch
@app.on_event("startup")
def startup_event():
    init_es_index()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(indicators.router, prefix="/api/v1/indicators", tags=["Indicators"])
app.include_router(enrichment.router, prefix="/api/v1/enrichment", tags=["Enrichment"])
app.include_router(search.router, prefix="/api/v1/search", tags=["Search"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts & Real-Time"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents & Correlation"])

@app.get("/")
def read_root():
    return {"message": "Welcome to ThreatLens Cyber Threat Intelligence API"}