from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import indicators, auth, enrichment

app = FastAPI(
    title="ThreatLens Threat Intelligence Platform API",
    version="1.0.0",
    description="Enterprise Threat Intelligence Platform Backend",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(indicators.router, prefix="/api/v1/indicators", tags=["Indicators"])
app.include_router(enrichment.router, prefix="/api/v1/enrichment", tags=["Enrichment"])

@app.get("/")
def read_root():
    return {"status": "online", "system": "ThreatLens TIP Backend"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}