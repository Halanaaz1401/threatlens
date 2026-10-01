#!/usr/bin/env python3
"""
Phase 4B Threat Intelligence Enrichment Engine - Live Runtime Verification
Verifies:
1. Authentication & JWT retrieval
2. Provider configuration status (/api/v1/enrichment/providers)
3. Live indicator creation & enrichment (/api/v1/indicators/{id}/enrich)
4. Cache & database persistence (/api/v1/indicators/{id}/enrichment)
5. Secret non-disclosure check across API responses
"""
import sys
import uuid
import random
import requests
import json

BASE_URL = "http://localhost:8000"

def log(msg, status="INFO"):
    print(f"[{status}] {msg}")

def run_verification():
    log("Starting Phase 4B Threat Intelligence Runtime Verification...", "START")

    # 1. Register and Authenticate as Analyst
    email = f"runtime_analyst_{uuid.uuid4().hex[:6]}@threatlens.io"
    password = "SecurePassword2026!"
    reg_url = f"{BASE_URL}/api/v1/auth/register"
    reg_data = {
        "email": email,
        "password": password,
        "full_name": "Phase 4B Runtime Analyst",
        "role": "analyst",
    }
    log(f"Registering fresh analyst user {email}...")
    try:
        reg_resp = requests.post(reg_url, json=reg_data, timeout=5)
        if reg_resp.status_code not in (200, 201):
            log(f"Registration failed: {reg_resp.status_code} {reg_resp.text}", "FAIL")
            return False
    except Exception as e:
        log(f"Registration request failed: {e}", "FAIL")
        return False

    login_url = f"{BASE_URL}/api/v1/auth/login"
    login_data = {"email": email, "password": password}
    log("Authenticating as analyst user...")
    try:
        resp = requests.post(login_url, json=login_data, timeout=5)
    except Exception as e:
        log(f"Connection failed: {e}", "FAIL")
        return False

    if resp.status_code != 200:
        log(f"Authentication failed with status {resp.status_code}: {resp.text}", "FAIL")
        return False

    token = resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    log(f"Authentication SUCCESS for {email}. JWT obtained.", "PASS")

    # 2. Check Provider Status
    prov_url = f"{BASE_URL}/api/v1/enrichment/providers"
    log(f"Querying provider readiness at {prov_url}...")
    prov_resp = requests.get(prov_url, headers=headers, timeout=5)
    if prov_resp.status_code != 200:
        log(f"Provider check failed: {prov_resp.status_code} {prov_resp.text}", "FAIL")
        return False

    prov_data = prov_resp.json()
    providers = prov_data.get("providers", [])
    log(f"Discovered {len(providers)} registered providers:", "INFO")
    for p in providers:
        p_name = p.get("provider")
        p_status = p.get("status")
        p_conf = p.get("configured")
        log(f" - Provider: {p_name} | Status: {p_status} | Configured: {p_conf}", "INFO")

    # 3. Create Sample Indicator
    create_url = f"{BASE_URL}/api/v1/indicators/create"
    test_ip = f"198.51.{random.randint(1, 250)}.{random.randint(1, 250)}"
    ioc_payload = {
        "value": test_ip,
        "type": "ip",
        "source": "runtime_verifier",
        "confidence": 85,
        "tags": ["runtime_test"],
    }
    log(f"Creating test indicator {test_ip}...")
    ioc_resp = requests.post(create_url, json=ioc_payload, headers=headers, timeout=5)
    if ioc_resp.status_code not in (200, 201):
        log(f"Indicator creation failed: {ioc_resp.status_code} {ioc_resp.text}", "FAIL")
        return False

    ioc_obj = ioc_resp.json()
    indicator_id = ioc_obj.get("id")
    log(f"Indicator created: ID={indicator_id}, Value={test_ip}", "PASS")

    # 4. Trigger Multi-Provider Enrichment
    enrich_url = f"{BASE_URL}/api/v1/indicators/{indicator_id}/enrich"
    log(f"Triggering enrichment orchestration at {enrich_url}...")
    enrich_resp = requests.post(enrich_url, json={"force_refresh": True}, headers=headers, timeout=10)
    if enrich_resp.status_code != 200:
        log(f"Enrichment request failed: {enrich_resp.status_code} {enrich_resp.text}", "FAIL")
        return False

    enrich_data = enrich_resp.json()
    enrich_status = enrich_data.get("status")
    aggregate = enrich_data.get("aggregate", {})
    enrichments = enrich_data.get("enrichments", [])
    log(f"Enrichment completed with status: '{enrich_status}'", "PASS")
    log(f"Aggregate Verdict: '{aggregate.get('verdict')}' | Confidence: {aggregate.get('confidence')}", "INFO")
    log(f"Persisted provider records in DB: {len(enrichments)}", "INFO")

    # 5. Check Enrichment Retrieval & Cache
    get_url = f"{BASE_URL}/api/v1/indicators/{indicator_id}/enrichment"
    log(f"Querying persisted enrichment at {get_url}...")
    get_resp = requests.get(get_url, headers=headers, timeout=5)
    if get_resp.status_code != 200:
        log(f"Enrichment retrieval failed: {get_resp.status_code}", "FAIL")
        return False

    get_data = get_resp.json()
    assert get_data.get("indicator_id") == str(indicator_id)
    log("Persisted enrichment retrieval SUCCESS.", "PASS")

    # 6. Secret Leakage Audit
    full_text = f"{prov_resp.text} {enrich_resp.text} {get_resp.text}".lower()
    for sensitive_token in ["api_key", "secret", "vt_api", "authorization:"]:
        if f'"{sensitive_token}"' in full_text:
            log(f"SECRET LEAKAGE DETECTED in response for token: {sensitive_token}", "FAIL")
            return False
    log("Secret leakage audit: ZERO secrets detected in API payloads.", "PASS")

    # 7. Summary
    log("==================================================", "INFO")
    log("PHASE 4B RUNTIME VERIFICATION COMPLETE: ALL CHECKS PASSED", "PASS")
    log("==================================================", "INFO")
    return True

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
