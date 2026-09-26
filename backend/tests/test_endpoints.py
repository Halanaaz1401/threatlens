import sys
from pathlib import Path

# Add backend directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash, create_access_token

client = TestClient(app)

def get_admin_headers():
    """Helper to ensure admin user exists and return Authorization header."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "endpoint_admin@threatlens.io").first()
        if not admin:
            admin = User(
                email="endpoint_admin@threatlens.io",
                username="endpoint_admin",
                hashed_password=get_password_hash("AdminPass123!"),
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()
    token = create_access_token({"sub": "endpoint_admin@threatlens.io", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}

def test_health():
    """Verify public health endpoint."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["ok", "degraded"]
    assert data["application"] == "healthy"

def test_auth_flow():
    """Verify user registration, login, and token-based /me endpoint."""
    email = "phase1b_user@threatlens.io"
    reg_payload = {
        "email": email,
        "password": "Password123!",
        "full_name": "Phase 1B Test User",
        "role": "viewer"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code in [200, 400]  # 400 if already registered

    # Login
    login_payload = {
        "email": email,
        "password": "Password123!"
    }
    login_res = client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # Verify /me with token
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == email

def test_alerts_endpoint():
    """Verify protected alerts endpoint with authentication."""
    headers = get_admin_headers()
    res = client.get("/api/v1/alerts/", headers=headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_incidents_endpoint():
    """Verify protected incidents endpoint with authentication."""
    headers = get_admin_headers()
    res = client.get("/api/v1/incidents/", headers=headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_feeds_endpoint():
    """Verify protected feeds endpoint with authentication."""
    headers = get_admin_headers()
    res = client.get("/api/v1/feeds/", headers=headers)
    assert res.status_code == 200
    feeds = res.json()
    assert len(feeds) >= 1

def test_export_stix_and_csv():
    """Verify protected export endpoints with authentication."""
    headers = get_admin_headers()
    stix_res = client.get("/api/v1/export/stix", headers=headers)
    assert stix_res.status_code == 200
    assert stix_res.headers["content-type"] == "application/json"

    csv_res = client.get("/api/v1/export/csv", headers=headers)
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]

def test_search_endpoint():
    """Verify protected search endpoint with authentication."""
    headers = get_admin_headers()
    res = client.get("/api/v1/search/indicators?q=malware", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "hits" in data

def test_audit_endpoint():
    """Verify administrator-only audit trail endpoint."""
    headers = get_admin_headers()
    res = client.get("/api/v1/audit/", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "logs" in data
