import pytest
import uuid
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType, ThreatSeverity, IndicatorStatus
from app.models.enrichment import IndicatorEnrichment
from app.models.incident import Incident, IncidentTimeline
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.user import User, UserRole
from app.core.security import create_access_token, get_password_hash
from app.core.config import settings
from app.core.redis import redis_manager
from app.services.enrichment import (
    get_available_providers,
    get_provider_by_name,
    VirusTotalProvider,
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    NormalizedEnrichmentResult,
)
from app.services.enrichment.base import sanitize_metadata
from app.services.enrichment_service import (
    enrich_indicator,
    get_indicator_enrichments,
    get_indicator_enrichment_by_provider,
    refresh_expired_enrichments,
    calculate_aggregate_intelligence,
)

client = TestClient(app)

@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def analyst_headers(db_session):
    email = f"analyst_p4b_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4B Analyst",
        role=UserRole.ANALYST.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email, "role": user.role, "user_id": str(user.id)})
    return {"Authorization": f"Bearer {token}", "token": token, "user": user}

@pytest.fixture
def viewer_headers(db_session):
    email = f"viewer_p4b_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("ViewerPass123!"),
        full_name="Phase 4B Viewer",
        role=UserRole.VIEWER.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(data={"sub": user.email, "role": user.role, "user_id": str(user.id)})
    return {"Authorization": f"Bearer {token}", "token": token, "user": user}

@pytest.fixture
def sample_ip_indicator(db_session):
    u = uuid.uuid4().hex
    val = f"10.{int(u[:2], 16)}.{int(u[2:4], 16)}.{int(u[4:6], 16) % 250 + 1}"
    ind = Indicator(
        value=val,
        type="ip",
        severity="HIGH",
        threat_score=85,
        confidence=80,
        status="active",
        source="unit_test",
    )
    db_session.add(ind)
    db_session.commit()
    db_session.refresh(ind)
    return ind

# ---------------------------------------------------------------------------
# Test 1: Provider Interface
# ---------------------------------------------------------------------------
def test_provider_interface():
    providers = get_available_providers()
    assert len(providers) >= 3
    names = [p.provider_name for p in providers]
    assert "virustotal" in names
    assert "abuseipdb" in names
    assert "alienvault_otx" in names

    for p in providers:
        hc = p.health_check()
        assert "provider" in hc
        assert "configured" in hc
        assert "status" in hc
        assert "supported_types" in hc

# ---------------------------------------------------------------------------
# Test 2: Provider Selection by IOC Type
# ---------------------------------------------------------------------------
def test_provider_selection_by_ioc_type():
    all_p = get_available_providers()

    ip_providers = [p.provider_name for p in all_p if "ip" in p.supported_ioc_types]
    assert "abuseipdb" in ip_providers
    assert "virustotal" in ip_providers
    assert "alienvault_otx" in ip_providers

    domain_providers = [p.provider_name for p in all_p if "domain" in p.supported_ioc_types]
    assert "abuseipdb" not in domain_providers
    assert "virustotal" in domain_providers
    assert "alienvault_otx" in domain_providers

    url_providers = [p.provider_name for p in all_p if "url" in p.supported_ioc_types]
    assert "abuseipdb" not in url_providers
    assert "virustotal" in url_providers

# ---------------------------------------------------------------------------
# Test 3: VirusTotal Normalization
# ---------------------------------------------------------------------------
def test_virustotal_normalization():
    async def _run():
        vt = VirusTotalProvider()
        mock_vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 14,
                        "suspicious": 2,
                        "harmless": 40,
                        "undetected": 15,
                    },
                    "tags": ["trojan", "c2", "cobalt-strike"],
                    "reputation": -45,
                    "country": "DE",
                    "as_owner": "AS13335 Cloudflare",
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.cobaltstrike",
                        "popular_threat_category": [{"value": "trojan"}, {"value": "c2"}],
                    },
                }
            }
        }

        with patch.object(vt, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = mock_vt_response
                mock_get.return_value = mock_res

                result = await vt.enrich("198.51.100.10", "ip")
                assert result.success is True
                assert result.verdict == "malicious"
                assert result.malicious_count == 14
                assert result.suspicious_count == 2
                assert "trojan" in result.tags
                assert "trojan.cobaltstrike" in result.malware_families
                assert result.country == "DE"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 4: AbuseIPDB Normalization
# ---------------------------------------------------------------------------
def test_abuseipdb_normalization():
    async def _run():
        abuse = AbuseIPDBProvider()
        mock_body = {
            "data": {
                "ipAddress": "198.51.100.10",
                "abuseConfidenceScore": 88,
                "totalReports": 34,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting",
                "isp": "DigitalOcean, LLC",
                "domain": "digitalocean.com",
                "isWhitelisted": False,
            }
        }

        with patch.object(abuse, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = mock_body
                mock_get.return_value = mock_res

                result = await abuse.enrich("198.51.100.10", "ip")
                assert result.success is True
                assert result.verdict == "malicious"
                assert result.confidence == 88
                assert result.reputation == 12
                assert result.country == "US"
                assert result.asn == "DigitalOcean, LLC"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 5: AlienVault OTX Normalization
# ---------------------------------------------------------------------------
def test_otx_normalization():
    async def _run():
        otx = AlienVaultOTXProvider()
        mock_body = {
            "pulse_info": {
                "count": 4,
                "pulses": [
                    {
                        "name": "APT29 Campaign Wave",
                        "tags": ["apt29", "nobelium"],
                        "adversary": "APT29",
                        "malware_families": [{"display_name": "CobaltStrike"}],
                    }
                ],
            },
            "country_code": "NL",
            "asn": "AS15169",
        }

        with patch.object(otx, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = mock_body
                mock_get.return_value = mock_res

                result = await otx.enrich("198.51.100.10", "ip")
                assert result.success is True
                assert result.verdict == "malicious"
                assert "apt29" in result.tags
                assert "APT29" in result.threat_actors
                assert "CobaltStrike" in result.malware_families
                assert result.country == "NL"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 6: Missing API Key
# ---------------------------------------------------------------------------
def test_missing_api_key():
    async def _run():
        vt = VirusTotalProvider()
        with patch.object(vt, "is_configured", return_value=False):
            result = await vt.enrich("198.51.100.10", "ip")
            assert result.success is False
            assert "not configured" in result.error_message
            assert result.verdict == "unknown"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 7: Provider Timeout
# ---------------------------------------------------------------------------
def test_provider_timeout():
    async def _run():
        import httpx
        vt = VirusTotalProvider()
        with patch.object(vt, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timed out")):
                result = await vt.enrich("198.51.100.10", "ip")
                assert result.success is False
                assert "timed out" in result.error_message.lower()

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 8: Provider HTTP Error
# ---------------------------------------------------------------------------
def test_provider_http_error():
    async def _run():
        abuse = AbuseIPDBProvider()
        with patch.object(abuse, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 503
                mock_get.return_value = mock_res

                result = await abuse.enrich("198.51.100.10", "ip")
                assert result.success is False
                assert "HTTP 503" in result.error_message

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 9: Provider Rate Limit
# ---------------------------------------------------------------------------
def test_provider_rate_limit():
    async def _run():
        vt = VirusTotalProvider()
        with patch.object(vt, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 429
                mock_get.return_value = mock_res

                result = await vt.enrich("198.51.100.10", "ip")
                assert result.success is False
                assert "rate limit exceeded" in result.error_message.lower()

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 10: Malformed Provider Response
# ---------------------------------------------------------------------------
def test_malformed_provider_response():
    async def _run():
        abuse = AbuseIPDBProvider()
        with patch.object(abuse, "is_configured", return_value=True):
            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_res = MagicMock()
                mock_res.status_code = 200
                mock_res.json.return_value = {}  # Empty/malformed payload
                mock_get.return_value = mock_res

                result = await abuse.enrich("198.51.100.10", "ip")
                assert result.success is True
                assert result.verdict == "clean"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 11: Partial Provider Failure
# ---------------------------------------------------------------------------
def test_partial_provider_failure(db_session, sample_ip_indicator):
    async def _run():
        res_success = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=85,
            malicious_count=10,
            success=True,
        )
        res_fail = NormalizedEnrichmentResult(
            provider="abuseipdb",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="unknown",
            confidence=0,
            success=False,
            error_message="Rate limit 429",
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_providers:
            p1 = MagicMock()
            p1.provider_name = "virustotal"
            p1.supported_ioc_types = ["ip"]
            p1.enrich = AsyncMock(return_value=res_success)

            p2 = MagicMock()
            p2.provider_name = "abuseipdb"
            p2.supported_ioc_types = ["ip"]
            p2.enrich = AsyncMock(return_value=res_fail)

            mock_providers.return_value = [p1, p2]

            result = await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)
            assert result["status"] == "partial"
            assert result["aggregate"]["verdict"] == "malicious"

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 12: Successful Enrichment Persistence
# ---------------------------------------------------------------------------
def test_successful_enrichment_persistence(db_session, sample_ip_indicator):
    async def _run():
        res = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=90,
            malicious_count=15,
            tags=["botnet", "phishing"],
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p = MagicMock()
            p.provider_name = "virustotal"
            p.supported_ioc_types = ["ip"]
            p.enrich = AsyncMock(return_value=res)
            mock_p.return_value = [p]

            await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)

            record = db_session.query(IndicatorEnrichment).filter(
                IndicatorEnrichment.indicator_id == str(sample_ip_indicator.id),
                IndicatorEnrichment.provider == "virustotal",
            ).first()

            assert record is not None
            assert record.verdict == "malicious"
            assert record.confidence == 90
            assert "botnet" in record.tags

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 13: Duplicate Enrichment Prevention
# ---------------------------------------------------------------------------
def test_duplicate_enrichment_prevention(db_session, sample_ip_indicator):
    async def _run():
        res1 = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="suspicious",
            confidence=60,
            success=True,
        )
        res2 = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=95,
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p = MagicMock()
            p.provider_name = "virustotal"
            p.supported_ioc_types = ["ip"]
            p.enrich = AsyncMock(side_effect=[res1, res2])
            mock_p.return_value = [p]

            # First run
            await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)
            # Second run (force refresh to update)
            await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)

            count = db_session.query(IndicatorEnrichment).filter(
                IndicatorEnrichment.indicator_id == str(sample_ip_indicator.id),
                IndicatorEnrichment.provider == "virustotal",
            ).count()

            # Must have exactly 1 record, not duplicates
            assert count == 1

            record = db_session.query(IndicatorEnrichment).filter(
                IndicatorEnrichment.indicator_id == str(sample_ip_indicator.id),
                IndicatorEnrichment.provider == "virustotal",
            ).first()
            assert record.verdict == "malicious"
            assert record.confidence == 95

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 14: Cache Hit
# ---------------------------------------------------------------------------
def test_cache_hit(db_session, sample_ip_indicator):
    async def _run():
        res = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="clean",
            confidence=40,
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p = MagicMock()
            p.provider_name = "virustotal"
            p.supported_ioc_types = ["ip"]
            p.enrich = AsyncMock(return_value=res)
            mock_p.return_value = [p]

            # First run: live query
            out1 = await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)
            assert out1["live_queries"] >= 1
            assert p.enrich.call_count == 1

            # Second run without force_refresh: cache hit
            out2 = await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=False)
            assert out2["cache_hits"] >= 1
            assert p.enrich.call_count == 1  # Not called again!

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 15: Cache Expiry
# ---------------------------------------------------------------------------
def test_cache_expiry(db_session, sample_ip_indicator):
    async def _run():
        res = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="clean",
            confidence=40,
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p = MagicMock()
            p.provider_name = "virustotal"
            p.supported_ioc_types = ["ip"]
            p.enrich = AsyncMock(return_value=res)
            mock_p.return_value = [p]

            # Create record already expired
            expired_record = IndicatorEnrichment(
                indicator_id=str(sample_ip_indicator.id),
                provider="virustotal",
                queried_value=sample_ip_indicator.value,
                indicator_type="ip",
                verdict="clean",
                confidence=40,
                expires_at=datetime.utcnow() - timedelta(minutes=10),
                fetched_at=datetime.utcnow() - timedelta(hours=2),
                success=True,
            )
            db_session.add(expired_record)
            db_session.commit()

            # enrich_indicator should detect expired cache and re-query
            out = await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=False)
            assert out["live_queries"] >= 1
            assert p.enrich.call_count == 1

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 16: Redis Enrichment Event
# ---------------------------------------------------------------------------
def test_redis_enrichment_event(db_session, sample_ip_indicator):
    async def _run():
        res = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=90,
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p = MagicMock()
            p.provider_name = "virustotal"
            p.supported_ioc_types = ["ip"]
            p.enrich = AsyncMock(return_value=res)
            mock_p.return_value = [p]

            with patch("app.services.enrichment_service.publish_enrichment_event") as mock_event:
                await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)
                assert mock_event.called
                args, _ = mock_event.call_args
                assert args[0] in ["ENRICHMENT_COMPLETED", "ENRICHMENT_PARTIAL"]
                assert args[1]["indicator_id"] == str(sample_ip_indicator.id)

    asyncio.run(_run())

# ---------------------------------------------------------------------------
# Test 17: Audit Logging
# ---------------------------------------------------------------------------
def test_audit_logging(analyst_headers, sample_ip_indicator, db_session):
    with patch("app.services.enrichment_service.enrich_indicator") as mock_enrich:
        mock_enrich.return_value = {
            "status": "success",
            "indicator_id": str(sample_ip_indicator.id),
            "aggregate": {"verdict": "clean"},
            "enrichments": [],
        }

        resp = client.post(
            f"/api/v1/indicators/{sample_ip_indicator.id}/enrich",
            headers={"Authorization": analyst_headers["Authorization"]},
            json={"force_refresh": True},
        )
        assert resp.status_code == 200

        audit = db_session.query(AuditLog).filter(
            AuditLog.action == "INDICATOR_ENRICHMENT_TRIGGERED",
            AuditLog.target_resource == f"indicator:{sample_ip_indicator.id}",
        ).first()

        assert audit is not None
        assert audit.actor == analyst_headers["user"].email

# ---------------------------------------------------------------------------
# Test 18: RBAC Enforcement
# ---------------------------------------------------------------------------
def test_rbac_enforcement(analyst_headers, viewer_headers, sample_ip_indicator):
    # 1. Unauthenticated request -> 401
    r_unauth = client.post(f"/api/v1/indicators/{sample_ip_indicator.id}/enrich")
    assert r_unauth.status_code in (401, 403)

    # 2. Viewer role attempting mutation -> 403
    r_viewer = client.post(
        f"/api/v1/indicators/{sample_ip_indicator.id}/enrich",
        headers={"Authorization": viewer_headers["Authorization"]},
        json={"force_refresh": False},
    )
    assert r_viewer.status_code == 403

    # 3. Viewer role querying GET -> 200
    r_get = client.get(
        f"/api/v1/indicators/{sample_ip_indicator.id}/enrichment",
        headers={"Authorization": viewer_headers["Authorization"]},
    )
    assert r_get.status_code == 200

# ---------------------------------------------------------------------------
# Test 19: Secret Non-Disclosure
# ---------------------------------------------------------------------------
def test_secret_non_disclosure(analyst_headers):
    # 1. /providers endpoint must not expose keys
    resp = client.get(
        "/api/v1/enrichment/providers",
        headers={"Authorization": analyst_headers["Authorization"]},
    )
    assert resp.status_code == 200
    data_str = resp.text.lower()
    assert "api_key" not in data_str
    assert "secret" not in data_str
    assert "token" not in data_str

    # 2. Sanitize helper scrubs credentials
    test_dict = {
        "provider": "virustotal",
        "api_key": "VT_SUPER_SECRET_12345",
        "nested": {"authorization": "Bearer token123", "safe_val": 42},
    }
    cleaned = sanitize_metadata(test_dict)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["authorization"] == "[REDACTED]"
    assert cleaned["nested"]["safe_val"] == 42

# ---------------------------------------------------------------------------
# Test 20: SSRF Protection
# ---------------------------------------------------------------------------
def test_ssrf_protection():
    # Verify provider internal endpoints are immutable constants
    vt = VirusTotalProvider()
    abuse = AbuseIPDBProvider()
    otx = AlienVaultOTXProvider()

    # Targets cannot be overridden by user input
    assert vt.VT_BASE_URL.startswith("https://www.virustotal.com")
    assert abuse.API_URL.startswith("https://api.abuseipdb.com")
    assert otx.OTX_BASE_URL.startswith("https://otx.alienvault.com")

    # Attacker attempting URL injection in indicator value
    endpoint = vt._get_target_endpoint("http://169.254.169.254/latest/meta-data", "ip")
    # Must only route through official VT host
    assert endpoint.startswith("https://www.virustotal.com/api/v3/ip_addresses/")

# ---------------------------------------------------------------------------
# Test 21: Full Enrichment Orchestration
# ---------------------------------------------------------------------------
def test_full_enrichment_orchestration(db_session, sample_ip_indicator):
    async def _run():
        res_vt = NormalizedEnrichmentResult(
            provider="virustotal",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=90,
            malicious_count=12,
            tags=["c2", "cobalt-strike"],
            malware_families=["CobaltStrike"],
            threat_actors=["APT29"],
            success=True,
        )
        res_abuse = NormalizedEnrichmentResult(
            provider="abuseipdb",
            queried_value=sample_ip_indicator.value,
            indicator_type="ip",
            verdict="malicious",
            confidence=85,
            reputation=15,
            country="RU",
            asn="AS12345",
            success=True,
        )

        with patch("app.services.enrichment_service.get_available_providers") as mock_p:
            p1 = MagicMock()
            p1.provider_name = "virustotal"
            p1.supported_ioc_types = ["ip"]
            p1.enrich = AsyncMock(return_value=res_vt)

            p2 = MagicMock()
            p2.provider_name = "abuseipdb"
            p2.supported_ioc_types = ["ip"]
            p2.enrich = AsyncMock(return_value=res_abuse)

            mock_p.return_value = [p1, p2]

            result = await enrich_indicator(db_session, str(sample_ip_indicator.id), force_refresh=True)

            assert result["status"] == "success"
            assert result["aggregate"]["verdict"] == "malicious"
            assert result["aggregate"]["confidence"] >= 85
            assert "c2" in result["aggregate"]["tags"]
            assert "CobaltStrike" in result["aggregate"]["malware_families"]
            assert "APT29" in result["aggregate"]["threat_actors"]

            # Verify indicator context and tags were enriched
            db_session.refresh(sample_ip_indicator)
            assert "c2" in sample_ip_indicator.tags
            assert sample_ip_indicator.context.get("enrichment_verdict") == "malicious"

    asyncio.run(_run())
