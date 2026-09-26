import sys
from pathlib import Path

# Add backend directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.user import User
from app.core.security import create_access_token, get_password_hash

client = TestClient(app)

def test_health_check():
    """Verify GET /health returns 200 OK and health telemetry (Public)."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["ok", "degraded"]
    assert data["application"] == "healthy"
    assert "database" in data
    assert "timestamp" in data

def test_root_endpoint():
    """Verify root / returns 200 and platform information (Public)."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "ThreatLens" in data["platform"]

def test_canonical_indicators_endpoint():
    """Verify canonical /api/v1/indicators endpoint is protected and operational."""
    # 1. Unauthenticated request is rejected with 401
    unauth_res = client.get("/api/v1/indicators")
    assert unauth_res.status_code == 401

    # 2. Ensure test user exists and authenticate
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "core_test@threatlens.io").first()
        if not user:
            user = User(
                email="core_test@threatlens.io",
                username="core_test",
                hashed_password=get_password_hash("Pass123!"),
                role="admin",
                is_active=True
            )
            db.add(user)
            db.commit()
    finally:
        db.close()

    token = create_access_token({"sub": "core_test@threatlens.io", "role": "admin"})
    response = client.get("/api/v1/indicators", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "data" in data