from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth, indicators, enrichment, search
from app.db.base import Base
from app.db.session import engine
from app.services.search_service import init_es_index

# Create DB Tables
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

@app.get("/")
def read_root():
    return {"message": "Welcome to ThreatLens Cyber Threat Intelligence API"}