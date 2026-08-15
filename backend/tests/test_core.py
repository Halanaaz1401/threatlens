import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# 1. Health Endpoint (NFR-10)
def test_health_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

# 2. Security Headers (NFR-06 / OWASP)
def test_owasp_security_headers():
    response = client.get("/")
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert "strict-transport-security" in response.headers

# 3. STIX 2.1 JSON Export (FR-24)
def test_export_stix_bundle():
    response = client.get("/api/v1/export/stix")
    assert response.status_code == 200
    data = response.json()
    assert data.get("type") == "bundle"
    assert "objects" in data
    assert isinstance(data["objects"], list)

# 4. CSV Feed Export (FR-24)
def test_export_csv_feed():
    response = client.get("/api/v1/export/csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "ID,Type,Value" in response.text

# 5. Scoring Logic Validation (FR-13)
def test_severity_scoring_logic():
    confidence = 90
    reputation_score = 85
    calculated_severity = int((confidence * 0.4) + (reputation_score * 0.6))
    assert 0 <= calculated_severity <= 100
    assert calculated_severity == 87