import asyncio
import random
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.routers import indicators, auth, export, alerts, search
from app.core.websocket import ws_manager

app = FastAPI(
    title="ThreatLens Enterprise CTI API",
    description="Cyber Threat Intelligence & Incident Correlation Backend",
    version="1.0.0"
)

# Proper CORS for Next.js (Localhost & 127.0.0.1 support)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include All REST Routers
app.include_router(indicators.router)
app.include_router(alerts.router)
app.include_router(search.router)
app.include_router(auth.router)
app.include_router(export.router)

# Real-Time alerts.stream WebSocket Gateway
@app.websocket("/ws/alerts")
async def alerts_websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Background Live Alert Broadcaster
@app.on_event("startup")
async def start_alert_broadcaster():
    async def simulate_live_threat_feed():
        threat_samples = [
            {"val": "185.220.101.4", "type": "ip", "score": 92, "source": "Feodo C2", "mitre": "T1071.001"},
            {"val": "http://evil-payload-bank.xyz/drop.exe", "type": "url", "score": 88, "source": "URLhaus", "mitre": "T1566.002"},
            {"val": "45.142.214.22", "type": "ip", "score": 95, "source": "AlienVault OTX", "mitre": "T1090.003"},
            {"val": "CVE-2024-21413", "type": "cve", "score": 98, "source": "CISA KEV", "mitre": "T1190"}
        ]
        while True:
            await asyncio.sleep(6)
            if ws_manager.active_connections:
                sample = random.choice(threat_samples)
                alert_payload = {
                    "event": "NEW_CRITICAL_ALERT",
                    "timestamp": datetime.utcnow().strftime("%H:%M:%S UTC"),
                    "indicator": sample["val"],
                    "type": sample["type"],
                    "severity_score": sample["score"],
                    "source": sample["source"],
                    "mitre": sample["mitre"],
                    "action_required": "Triage & Contain"
                }
                await ws_manager.broadcast_alert(alert_payload)

    asyncio.create_task(simulate_live_threat_feed())

@app.get("/")
def root():
    return {
        "platform": "ThreatLens CTI & SOC Hub",
        "status": "online",
        "version": "v1.0"
    }
