# THREATLENS — PHASE 4B: THREAT INTELLIGENCE ENRICHMENT BASELINE REPORT

**Target Repository:** `Halanaaz1401/threatlens`  
**Execution Date:** October 2026  
**Auditor Mode:** Forensic Analysis & Phase 4B Engineering Plan  

---

## 1. Existing Indicator Architecture

The core indicator schema is defined in `backend/app/models/indicator.py`:
- **Model `Indicator`:** Inherits from `app.db.base.Base`, with fields `id` (String(36) UUID), `value` (unique, indexed string), `type` (`ip`, `domain`, `url`, `hash_md5`, `hash_sha256`, `email`, `cve`), `severity_score` / `threat_score` (SmallInteger 0–100), `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `confidence` (0–100), `source`, `sightings`, `tlp`, `status` (`active`, `inactive`, `expired`, etc.), `tags`, `context`, `mitre_technique`, `first_seen`, `last_seen`, `created_at`, `updated_at`.
- **Relationships:**
  - `sources`: One-to-many relationship with `IndicatorSource` (tracks per-feed provenance, confidence, and timestamps).
  - `alerts`: One-to-many relationship with `Alert`.
- **Missing Enrichment Relationship:** No dedicated table or model exists to store structured external threat intelligence lookups (reputation, engine verdicts, malicious counts, provider-specific threat actor/malware family tags, external references).

---

## 2. Existing Scoring Logic

- **Mathematical Engine (`backend/app/services/scoring.py`):**
  Calculates a 0–100 score based on 4 factors:
  - Reputation factor: 35%
  - Detection engine ratio factor: 35%
  - Recency factor: 15%
  - Sightings frequency factor: 15%
- **Scoring Service (`backend/app/services/scoring_service.py`):**
  Wraps `calculate_threat_score()` to compute scores and map numerical values to severity classifications (`LOW` < 40, `MEDIUM` < 70, `HIGH` < 90, `CRITICAL` $\ge 90$).
- **Evidence-Based Rule for Phase 4B:**
  External threat intelligence provides additional corroborating evidence. It must NOT arbitrarily overwrite the internal scoring system, nor replace existing calculations. Rather, high-confidence external maliciousness can be factored in as additional evidence for risk context.

---

## 3. Existing Source & Provenance Architecture

- Ingested indicators track their telemetry sources in `IndicatorSource` (`indicator_id`, `source_name`, `confidence`, `reported_at`).
- Multiple sightings across independent feeds increment `sightings` on the canonical `Indicator`.
- However, active threat intelligence enrichment (e.g. querying VirusTotal or AbuseIPDB on demand or during alert investigation) is distinct from passive feed ingestion: it produces a point-in-time enrichment report with specific engine verdicts, abuse confidence percentages, and external references that require dedicated model tracking.

---

## 4. Existing External-Feed Support

Current feeds implemented in `backend/app/services/feed_service.py`:
- URLhaus (Abuse.ch): Malicious URLs
- ThreatFox (Abuse.ch): Multi-type IOCs with malware families & tags
- Feodo Tracker (Abuse.ch): Botnet C2 IPs
- MalwareBazaar (Abuse.ch): Malicious file hashes
- CISA KEV: Known exploited vulnerabilities / CVEs
- AlienVault OTX: Recent pulses (in `feed_service.py`)

Current enrichment prototype in `backend/app/services/enrichment_service.py`:
- `get_ip_enrichment()`: Calls `ip-api.com` for geolocation/ASN with basic Redis caching.
- `get_domain_enrichment()`: Returns a static placeholder dictionary.

---

## 5. Existing API Endpoints

- `GET /api/v1/indicators`: Lists indicators with filters (`type`, `severity`, `status`, `search`).
- `POST /api/v1/indicators/create`: Analyst creation with scoring and alert evaluation.
- `PATCH /api/v1/indicators/{indicator_id}/status`: Updates status.
- `GET /api/v1/enrichment/ip/{ip_address}`: Free GeoIP lookup via `ip-api.com`.
- `GET /api/v1/enrichment/domain/{domain_name}`: Placeholder domain enrichment.

Endpoints missing for Phase 4B:
- `POST /api/v1/indicators/{indicator_id}/enrich`: Initiates multi-provider enrichment.
- `GET /api/v1/indicators/{indicator_id}/enrichment`: Retrieves normalized enrichment results across providers.
- `GET /api/v1/indicators/{indicator_id}/enrichment/{provider}`: Retrieves specific provider result.
- `POST /api/v1/enrichment/refresh`: Refreshes expired enrichments with rate-limiting.

---

## 6. Existing Redis Events

Channel infrastructure in `backend/app/core/redis.py`:
- `threatlens:events:alerts`: Real-time alert broadcasts.
- `threatlens:events:incidents`: Real-time incident broadcasts (`INCIDENT_CREATED`, `INCIDENT_UPDATED`, `INCIDENT_SEVERITY_CHANGED`, `INCIDENT_RESOLVED`).
- Missing: Structured enrichment events (`ENRICHMENT_STARTED`, `ENRICHMENT_COMPLETED`, `ENRICHMENT_PARTIAL`, `ENRICHMENT_FAILED`) on `threatlens:events:enrichment` or unified alert/incident bus.

---

## 7. Existing Database Schema

- Tables currently defined:
  - `users`: User identity and roles.
  - `indicators`: Canonical indicators.
  - `indicator_sources`: Feed provenance records.
  - `alerts`: Security alerts.
  - `incidents`: Clustered security incidents.
  - `incident_timeline`: Chronological incident events.
  - `audit_logs`: Immutable security audit logs.
  - `feeds`: Feed configuration metadata.
- **Alembic Head:** `4a1c0rre1at1` (Phase 4A correlation and incidents).
- Need a new table `indicator_enrichments` linked to `indicators.id` with proper indexes, unique constraints (`indicator_id, provider`), and status fields.

---

## 8. Gaps Identified

1. **No Modular Provider Interface:** Enrichment logic is fragmented; no abstract base class or provider registry exists for pluggable threat intel providers.
2. **Missing VirusTotal Provider:** No integration with VirusTotal API v3 (URL, IP, domain, hash lookups) with rate limit and secret isolation.
3. **Missing AbuseIPDB Provider:** No integration with AbuseIPDB API v2 (IP reputation and report history).
4. **Missing AlienVault OTX Provider:** No direct indicator pulse lookup against AlienVault OTX API with API key security.
5. **No Relational Storage for Enrichment:** External intelligence is not persisted in a structured database table.
6. **No Configurable TTL Caching:** `THREAT_INTEL_CACHE_TTL_MINUTES` is not defined in `Settings`.
7. **SSRF and Secret Vulnerability Risk:** Provider URLs must be strictly hardcoded or validated against server configuration to prevent user-supplied SSRF. API keys must never be logged, returned in responses, or committed.

---

## 9. Phase 4B Implementation Plan

1. **Provider Abstraction (`backend/app/services/enrichment/`):**
   - `BaseThreatIntelProvider`: Abstract interface (`provider_name`, `supported_ioc_types`, `is_configured()`, `enrich_indicator()`, `health_check()`).
   - `NormalizedEnrichmentResult`: Pydantic schema for uniform provider output.
2. **Provider Implementations:**
   - `VirusTotalProvider`: Queries VT API v3 for IP, domain, URL, hash. Handles 429, timeouts, missing keys.
   - `AbuseIPDBProvider`: Queries AbuseIPDB API v2 for IP indicators. Handles rate limits and missing keys.
   - `AlienVaultOTXProvider`: Queries OTX indicator endpoints for IP, domain, hash.
3. **Relational Model & Alembic Migration:**
   - Define `IndicatorEnrichment` model in `backend/app/models/enrichment.py`.
   - Create Alembic migration `4b2enr1chment_phase4b_enrichment_engine.py` (revises `4a1c0rre1at1`).
   - Verify upgrade and downgrade against live PostgreSQL.
4. **Enrichment Orchestration & Caching (`backend/app/services/enrichment_service.py`):**
   - `enrich_indicator(indicator_id, force_refresh)`: Checks cache/database TTL (`THREAT_INTEL_CACHE_TTL_MINUTES = 60`), queries compatible configured providers, aggregates evidence, persists results, logs audit records, and emits Redis events.
   - Resilient partial success model: Single provider failure does not abort the entire enrichment.
5. **API Endpoints (`backend/app/api/v1/endpoints/enrichment.py`):**
   - Mount canonical endpoints with JWT authentication and RBAC (`require_analyst` for trigger/refresh).
6. **Redis Events & Audit:**
   - Emit `ENRICHMENT_COMPLETED`, `ENRICHMENT_PARTIAL`, etc. to Redis.
   - Immutable audit logging for enrichment triggers and updates.
7. **Security & Testing:**
   - Secret leakage audit (zero API keys in responses or logs).
   - SSRF protection (provider targets strictly defined server-side).
   - Comprehensive test suite `backend/tests/test_phase4b_enrichment.py` (all 21 test scenarios with mocked HTTP).
