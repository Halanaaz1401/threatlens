"""
Standalone Phase 1B Security Verification Script
Covers items 1 through 12 of the Verification Checklist.
"""
import sys
from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone
from app.main import app
from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.db.session import SessionLocal
from app.models.user import User

def run_verification():
    client = TestClient(app)
    print("=== ThreatLens Phase 1B Security Verification ===")

    # 1 & 2. Verify /health
    resp = client.get("/health")
    assert resp.status_code == 200, f"/health failed: {resp.text}"
    print("[PASS] 1 & 2: Backend started and /health verified: 200 OK")

    # 3. Register a normal user
    db = SessionLocal()
    # Clean up prior test user if exists
    test_email = "sec_test_user@threatlens.io"
    existing = db.query(User).filter(User.email == test_email).first()
    if existing:
        db.delete(existing)
        db.commit()

    reg_payload = {
        "email": test_email,
        "password": "StrongSecurityPassword!123",
        "full_name": "Security Test User",
        "role": "Administrator"  # Attempt self-escalation
    }
    resp = client.post("/api/v1/auth/register", json=reg_payload)
    # Registration with 'Administrator' must be blocked with 400
    assert resp.status_code == 400, f"Expected 400 for self-escalation attempt, got {resp.status_code}"
    print("[PASS] 3a: Registration privilege escalation rejected with 400 Bad Request")

    # Now register safely without privileged role
    reg_payload["role"] = "viewer"
    resp = client.post("/api/v1/auth/register", json=reg_payload)
    assert resp.status_code == 200 or resp.status_code == 201, f"Safe register failed: {resp.text}"
    user_data = resp.json()
    assert user_data["role"] == "viewer"
    print(f"[PASS] 3b: Normal user registered safely with default role '{user_data['role']}'")

    # 4. Login
    login_resp = client.post("/api/v1/auth/login", json={"email": test_email, "password": "StrongSecurityPassword!123"})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_data = login_resp.json()
    token = token_data["access_token"]
    assert token, "No access token in response"
    print("[PASS] 4: Database-backed login verified successfully")

    # 5. Verify JWT
    import jwt
    decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert decoded["sub"] == test_email
    assert decoded["role"] == "viewer"
    assert "exp" in decoded
    print(f"[PASS] 5: JWT token verified (sub={decoded['sub']}, role={decoded['role']}, exp={decoded['exp']})")

    # 6. Call /me
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200, f"/me failed: {me_resp.text}"
    me_data = me_resp.json()
    assert me_data["email"] == test_email
    print(f"[PASS] 6: /me endpoint returned correct user profile: {me_data['email']}")

    # 7. Test protected endpoint without JWT
    unauth_resp = client.get("/api/v1/indicators/")
    assert unauth_resp.status_code in (401, 403), f"Protected endpoint without JWT returned {unauth_resp.status_code}"
    print(f"[PASS] 7: Protected endpoint without JWT correctly rejected: {unauth_resp.status_code}")

    # 8. Test protected endpoint with JWT
    auth_resp = client.get("/api/v1/indicators/", headers={"Authorization": f"Bearer {token}"})
    assert auth_resp.status_code == 200, f"Protected endpoint with JWT failed: {auth_resp.text}"
    print(f"[PASS] 8: Protected endpoint with valid JWT succeeded: 200 OK")

    # 9. Test each role: Viewer, Analyst, Security Engineer, Admin
    # Ensure users exist in DB for each test role
    roles_to_test = {
        "viewer_user@threatlens.io": "viewer",
        "analyst_user@threatlens.io": "analyst",
        "engineer_user@threatlens.io": "security_engineer",
        "admin_user@threatlens.io": "admin"
    }
    role_tokens = {}
    for email, role in roles_to_test.items():
        u = db.query(User).filter(User.email == email).first()
        if not u:
            u = User(
                email=email,
                hashed_password=get_password_hash("RoleTestPass!123"),
                full_name=role.capitalize(),
                role=role,
                is_active=True
            )
            db.add(u)
            db.commit()
            db.refresh(u)
        role_tokens[role] = create_access_token({"sub": email, "role": role})

    # Viewer: Can read indicators, but cannot create indicator or access audit
    v_read = client.get("/api/v1/indicators/", headers={"Authorization": f"Bearer {role_tokens['viewer']}"})
    assert v_read.status_code == 200
    v_write = client.post("/api/v1/indicators/create", json={"type": "ip", "value": "1.1.1.1", "confidence": 80}, headers={"Authorization": f"Bearer {role_tokens['viewer']}"})
    assert v_write.status_code == 403
    print("[PASS] 9a: Viewer allowed read (200), denied write (403)")

    # Analyst: Can write/patch indicator, but cannot trigger feed fetch or access audit
    a_write = client.patch("/api/v1/alerts/1", json={"status": "investigating"}, headers={"Authorization": f"Bearer {role_tokens['analyst']}"})
    # Even if alert 1 doesn't exist, analyst role is authorized past RoleChecker (returns 404 instead of 403)
    assert a_write.status_code != 403
    a_admin = client.get("/api/v1/audit/", headers={"Authorization": f"Bearer {role_tokens['analyst']}"})
    assert a_admin.status_code == 403
    print("[PASS] 9b: Analyst allowed analyst actions, denied admin audit (403)")

    # Security Engineer: Can fetch feeds, but denied admin audit
    eng_feed = client.post("/api/v1/feeds/fetch", headers={"Authorization": f"Bearer {role_tokens['security_engineer']}"})
    assert eng_feed.status_code != 403
    eng_admin = client.get("/api/v1/audit/", headers={"Authorization": f"Bearer {role_tokens['security_engineer']}"})
    assert eng_admin.status_code == 403
    print("[PASS] 9c: Security Engineer allowed feed operations, denied admin audit (403)")

    # Administrator: Can access audit log
    adm_resp = client.get("/api/v1/audit/", headers={"Authorization": f"Bearer {role_tokens['admin']}"})
    assert adm_resp.status_code == 200
    print("[PASS] 9d: Administrator allowed audit log access (200 OK)")

    # 10. Test invalid JWT
    inv_resp = client.get("/api/v1/indicators/", headers={"Authorization": "Bearer totally.invalid.token"})
    assert inv_resp.status_code in (401, 403)
    print(f"[PASS] 10: Invalid JWT correctly rejected with {inv_resp.status_code}")

    # 11. Test expired JWT
    expired_token = create_access_token({"sub": test_email, "role": "viewer"}, expires_delta=timedelta(seconds=-10))
    exp_resp = client.get("/api/v1/indicators/", headers={"Authorization": f"Bearer {expired_token}"})
    assert exp_resp.status_code == 401
    print(f"[PASS] 11: Expired JWT correctly rejected with 401: {exp_resp.json()}")

    # 12. Test WebSocket authentication
    from starlette.websockets import WebSocketDisconnect
    # Unauthorized WS (no token) -> closes with 1008
    try:
        with client.websocket_connect("/api/v1/ws/alerts") as ws:
            ws.receive_json()
        assert False, "Should have raised WebSocketDisconnect"
    except WebSocketDisconnect as e:
        assert e.code == 1008, f"Expected 1008 Policy Violation, got {e.code}"
        print(f"[PASS] 12a: Unauthorized WebSocket connection correctly rejected with 1008 Policy Violation")

    # Authorized WS (with query token) -> connection accepted
    with client.websocket_connect(f"/api/v1/ws/alerts?token={token}") as ws:
        assert ws is not None
    print("[PASS] 12b: Authorized WebSocket connection established and accepted successfully")

    db.close()
    print("\nALL 12 VERIFICATION STEPS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_verification()
