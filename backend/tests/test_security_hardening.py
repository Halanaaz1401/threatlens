import sys
from pathlib import Path
from datetime import timedelta
import pytest
from starlette.websockets import WebSocketDisconnect

# Add backend directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash, create_access_token

client = TestClient(app)

def create_user_with_role(email: str, role: str, password: str = "SecurePass123!") -> str:
    """Helper to create or update test user and return JWT access token."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                username=email.split("@")[0],
                hashed_password=get_password_hash(password),
                full_name=f"Test {role}",
                role=role,
                is_active=True
            )
            db.add(user)
        else:
            user.role = role
            user.hashed_password = get_password_hash(password)
            user.is_active = True
        db.commit()
        db.refresh(user)
        return create_access_token(data={"sub": user.email, "role": user.role})
    finally:
        db.close()

def test_password_hash_is_not_plaintext():
    """Verify password hashing utilizes Argon2 and never stores plaintext."""
    raw_pass = "SuperSecretPassword2026!"
    hashed = get_password_hash(raw_pass)
    assert hashed != raw_pass
    assert hashed.startswith("$argon2")

def test_valid_login():
    """Verify user can authenticate with valid credentials and receive JWT."""
    email = "valid_user_test@threatlens.io"
    password = "ValidPassword123!"
    create_user_with_role(email, "viewer", password)

    login_res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_invalid_password():
    """Verify invalid password returns 401 Unauthorized."""
    email = "wrong_pass_test@threatlens.io"
    create_user_with_role(email, "viewer", "CorrectPass123!")

    login_res = client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword!"})
    assert login_res.status_code == 401
    assert "Incorrect email or password" in login_res.json()["detail"]

def test_nonexistent_user():
    """Verify nonexistent user returns 401 Unauthorized."""
    login_res = client.post("/api/v1/auth/login", json={"email": "nobody_exists@threatlens.io", "password": "AnyPassword!"})
    assert login_res.status_code == 401

def test_expired_jwt():
    """Verify expired token is rejected with 401."""
    expired_token = create_access_token(
        data={"sub": "expired@threatlens.io", "role": "viewer"},
        expires_delta=timedelta(minutes=-10)
    )
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()

def test_invalid_jwt():
    """Verify tampered/malformed token signature is rejected with 401."""
    res = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.tampered.token"})
    assert res.status_code == 401

def test_protected_endpoint_without_token():
    """Verify protected indicator endpoint rejects unauthenticated requests with 401."""
    res = client.get("/api/v1/indicators/")
    assert res.status_code == 401

def test_protected_endpoint_with_valid_token():
    """Verify protected indicator endpoint accepts valid JWT token."""
    token = create_user_with_role("auth_user@threatlens.io", "viewer")
    res = client.get("/api/v1/indicators/", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["status"] == "success"

def test_client_cannot_self_assign_admin_role():
    """Verify public self-registration rejects client attempts to escalate to Administrator."""
    payload = {
        "email": "hacker_attempt@threatlens.io",
        "password": "Password123!",
        "full_name": "Privilege Escalation Attempt",
        "role": "Administrator"
    }
    res = client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 400
    assert "cannot assign privileged roles" in res.json()["detail"].lower()

def test_viewer_privilege_restriction():
    """Verify Viewer can read indicators but is denied write/create operations."""
    viewer_token = create_user_with_role("viewer_user@threatlens.io", "viewer")
    
    # Read operation succeeds
    read_res = client.get("/api/v1/indicators/", headers={"Authorization": f"Bearer {viewer_token}"})
    assert read_res.status_code == 200

    # Write operation denied with 403 Forbidden
    ioc_payload = {
        "value": "192.168.1.100",
        "type": "ip",
        "source": "manual",
        "confidence": 80
    }
    write_res = client.post("/api/v1/indicators/create", json=ioc_payload, headers={"Authorization": f"Bearer {viewer_token}"})
    assert write_res.status_code == 403

def test_analyst_privilege_restriction():
    """Verify Analyst can perform operational actions but cannot access admin-only audit logs."""
    analyst_token = create_user_with_role("analyst_user@threatlens.io", "analyst")

    # Analyst can create indicators
    ioc_val = "10.0.0.99"
    ioc_payload = {
        "value": ioc_val,
        "type": "ip",
        "source": "manual",
        "confidence": 85
    }
    create_res = client.post("/api/v1/indicators/create", json=ioc_payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert create_res.status_code in [200, 400]  # 400 if already exists

    # Analyst is forbidden from viewing administrator audit logs
    audit_res = client.get("/api/v1/audit/", headers={"Authorization": f"Bearer {analyst_token}"})
    assert audit_res.status_code == 403

def test_administrator_access():
    """Verify Administrator has full access to administrative audit trail and user management."""
    admin_token = create_user_with_role("admin_root@threatlens.io", "admin")

    audit_res = client.get("/api/v1/audit/", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_res.status_code == 200
    assert audit_res.json()["status"] == "success"

    users_res = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert users_res.status_code == 200
    assert isinstance(users_res.json(), list)

def test_websocket_unauthorized_access():
    """Verify unauthenticated WebSocket connection is rejected with policy violation (1008)."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/ws/alerts"):
            pass
    assert exc.value.code == 1008

def test_websocket_authorized_access():
    """Verify authenticated WebSocket connection succeeds with valid JWT."""
    token = create_user_with_role("ws_user@threatlens.io", "analyst")
    with client.websocket_connect(f"/api/v1/ws/alerts?token={token}") as ws:
        # Connection established successfully
        assert ws is not None

def test_cors_configuration():
    """Verify CORS configuration strictly allows approved origins and blocks unapproved origins."""
    # Approved origin
    res_approved = client.options(
        "/api/v1/indicators/",
        headers={
            "Origin": "https://threatlens.ashlynxcyber.in",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert res_approved.status_code == 200
    assert res_approved.headers.get("access-control-allow-origin") == "https://threatlens.ashlynxcyber.in"

    # Unapproved origin
    res_blocked = client.options(
        "/api/v1/indicators/",
        headers={
            "Origin": "https://unauthorized-attacker-site.com",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert res_blocked.headers.get("access-control-allow-origin") != "https://unauthorized-attacker-site.com"
