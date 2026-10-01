import asyncio
import json
import uuid
import urllib.request
import websockets
from datetime import datetime

async def verify_runtime_correlation():
    print("=== STARTING LIVE RUNTIME CORRELATION VERIFICATION ===")

    # 1. Register and Login with a fresh unique analyst account
    email = f"runtime_analyst_{uuid.uuid4().hex[:6]}@threatlens.io"
    password = "SecurePassword2026!"
    
    reg_data = json.dumps({
        "email": email,
        "password": password,
        "full_name": "Runtime Verification Analyst",
        "role": "analyst"
    }).encode()
    reg_req = urllib.request.Request(
        "http://localhost:8000/api/v1/auth/register",
        data=reg_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(reg_req) as resp:
        reg_resp = json.loads(resp.read().decode())
        print(f"1. Registered new test user: {email} (role: {reg_resp.get('role')})")

    login_data = json.dumps({"email": email, "password": password}).encode()
    login_req = urllib.request.Request(
        "http://localhost:8000/api/v1/auth/login",
        data=login_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(login_req) as resp:
        login_resp = json.loads(resp.read().decode())
        token = login_resp.get("access_token")
        print(f"2. Authenticated as {email}, JWT token obtained")

    # 2. Connect to Authenticated WebSocket
    ws_url = f"ws://localhost:8000/api/v1/ws/alerts?token={token}"
    async with websockets.connect(ws_url) as ws:
        print("3. Connected to live Authenticated WebSocket stream")

        # 3. Ingest IOC #1
        ioc_val = f"threat-cluster-{uuid.uuid4().hex[:6]}.darkops.net"
        ioc1_payload = json.dumps({
            "value": ioc_val,
            "type": "domain",
            "threat_score": 78,
            "severity": "HIGH",
            "confidence": 90,
            "source": "DarkOps-ThreatFeed",
            "mitre_technique": "T1071"
        }).encode()
        req1 = urllib.request.Request(
            "http://localhost:8000/api/v1/indicators/create",
            data=ioc1_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req1) as resp:
            ioc1_resp = json.loads(resp.read().decode())
            print(f"4. Ingested IOC #1: {ioc_val}")

        # Read WS events for IOC #1
        events_stage1 = []
        for _ in range(2):
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            events_stage1.append(json.loads(msg))

        event_types_1 = [e.get("type") for e in events_stage1]
        print(f"   -> WS received stage 1 events: {event_types_1}")
        assert any(e in ["NEW_ALERT", "NEW_CRITICAL_ALERT"] for e in event_types_1), "Alert event expected"
        assert any(e == "INCIDENT_CREATED" for e in event_types_1), "INCIDENT_CREATED event expected"

        inc_created_event = next(e for e in events_stage1 if e.get("type") == "INCIDENT_CREATED")
        incident_id = inc_created_event["data"]["incident_id"]
        incident_code = inc_created_event["data"]["incident_code"]
        print(f"   -> Incident Formed: {incident_code} (ID: {incident_id})")

        # 4. Ingest Correlated Alert #2 (Same IOC domain, path payload)
        ioc2_payload = json.dumps({
            "value": f"http://{ioc_val}/beacon.bin",
            "type": "url",
            "threat_score": 84,
            "severity": "HIGH",
            "confidence": 95,
            "source": "DarkOps-ThreatFeed",
            "mitre_technique": "T1071"
        }).encode()
        req2 = urllib.request.Request(
            "http://localhost:8000/api/v1/indicators/create",
            data=ioc2_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req2) as resp:
            ioc2_resp = json.loads(resp.read().decode())
            print(f"5. Ingested Correlated URL IOC #2: http://{ioc_val}/beacon.bin")

        # Read WS events for IOC #2
        events_stage2 = []
        for _ in range(2):
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            events_stage2.append(json.loads(msg))

        event_types_2 = [e.get("type") for e in events_stage2]
        print(f"   -> WS received stage 2 events: {event_types_2}")
        assert any(e in ["INCIDENT_UPDATED", "INCIDENT_SEVERITY_CHANGED"] for e in event_types_2), "INCIDENT_UPDATED event expected"

        # 5. Verify Incident via API
        req_inc = urllib.request.Request(
            f"http://localhost:8000/api/v1/incidents/{incident_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req_inc) as resp:
            inc_data = json.loads(resp.read().decode())
            print(f"6. Incident via API: status={inc_data['status']}, code={inc_data['incident_code']}, attached_alerts={inc_data['alerts_count']}, score={inc_data['correlation_score']}")
            assert inc_data["alerts_count"] >= 2, f"Expected >= 2 alerts, found {inc_data['alerts_count']}"

        # 6. Verify Incident Timeline via API
        req_tl = urllib.request.Request(
            f"http://localhost:8000/api/v1/incidents/{incident_id}/timeline",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req_tl) as resp:
            tl_data = json.loads(resp.read().decode())
            actions = [item["action"] for item in tl_data]
            print(f"7. Chronological Timeline Actions: {actions}")
            assert "INCIDENT_CREATED" in actions[0]
            assert any("ALERT_CORRELATED" in a for a in actions)

        # 7. Update Status: OPEN -> ACKNOWLEDGED via API
        patch_payload = json.dumps({"status": "ACKNOWLEDGED", "note": "Analyst acknowledged for deep dive investigation."}).encode()
        patch_req = urllib.request.Request(
            f"http://localhost:8000/api/v1/incidents/{incident_id}/status",
            data=patch_payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="PATCH"
        )
        with urllib.request.urlopen(patch_req) as resp:
            patched_data = json.loads(resp.read().decode())
            print(f"8. Successfully transitioned incident status: {patched_data['status']}")
            assert patched_data["status"] == "ACKNOWLEDGED"

        # 8. Check that no duplicate incident was created
        search_req = urllib.request.Request(
            f"http://localhost:8000/api/v1/incidents?source=DarkOps-ThreatFeed",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(search_req) as resp:
            found_incidents = json.loads(resp.read().decode())
            matching_for_ioc = [i for i in found_incidents if i.get("primary_indicator") == ioc_val]
            print(f"9. Incidents found for primary indicator {ioc_val}: {len(matching_for_ioc)}")
            assert len(matching_for_ioc) == 1, f"Expected exactly 1 incident, found {len(matching_for_ioc)}"

        print("=== LIVE RUNTIME CORRELATION VERIFICATION: ALL STEPS PASSED! ===")

if __name__ == "__main__":
    asyncio.run(verify_runtime_correlation())
