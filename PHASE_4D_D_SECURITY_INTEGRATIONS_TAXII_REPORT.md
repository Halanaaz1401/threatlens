# ThreatLens — Phase 4D-D Report
**SIEM/EDR Inbound Integrations + TAXII 2.1 Integration**
**Date:** October 2026
**Branch:** `main`

---

## 1. Scope

Phase 4D-D addresses the primary enterprise integration objectives of ThreatLens:
- **FR-29 — Inbound SIEM/EDR Webhook Receivers:** Canonical multi-provider webhook receiver supporting explicit SIEM and EDR platforms (`splunk`, `qradar`, `sentinel`, `crowdstrike`, `elastic`), multi-tier inbound authentication (Bearer token, `X-ThreatLens-Webhook-Secret`, HMAC SHA-256 signatures), clock-skew replay protection, payload bounding, strict schemas, normalization into canonical IOCs, integration into detection rules, alert creation, incident correlation handoff, deterministic deduplication, Redis event fan-out, and immutable audit logging.
- **FR-04 — TAXII 2.1 Ingestion Integration:** Discovery of TAXII 2.1 servers (`/taxii2/`), API roots, collections enumeration, authenticated/anonymous collection polling (`/collections/{id}/objects/`), safe regex STIX 2.1 indicator pattern extraction without `eval()` or `exec()`, cursor-based delta synchronization (`last_added_after`), deterministic deduplication, SSRF defense, Redis Pub/Sub events, and integration into the existing feed management architecture.

### Strict Scope Enforced
- **Zero code for later phases:** No executive PDF reporting (FR-23), no custom dashboard widget builder (FR-22), no SOAR/automated response, no new IOC lifecycle/TTL, no new detection rule engine, and no unrelated UI redesign.
- **Canonical Architecture Preserved:** All ingested data flows through the canonical pipeline: Ingestion -> Normalization -> Deduplication -> Provenance -> Detection Rules -> Alerts -> Correlation -> Incidents -> Redis/WebSocket -> Analytics.

---

## 2. FR-29 SIEM/EDR Webhooks

### Canonical Endpoint
Mounted under:
`POST /api/v1/integrations/webhooks/{provider}`

Supported provider identifiers are strictly validated against an allowlist:
- `splunk`: Ingests Splunk Enterprise Security notable events, alerts, and search exports.
- `qradar`: Ingests IBM QRadar offenses and correlation events.
- `sentinel`: Ingests Microsoft Sentinel incidents and alert rules.
- `crowdstrike`: Ingests CrowdStrike Falcon detection and endpoint telemetry.
- `elastic`: Ingests Elastic Security / Kibana detection alerts.

Arbitrary provider names dynamically altering processing behavior are rejected with HTTP 400 Bad Request.

### Webhook Authentication
Inbound requests must authenticate via one of two supported mechanisms:
1. **Bearer Secret / Header Token:** Checked against `X-ThreatLens-Webhook-Secret` or `Authorization: Bearer <secret>`.
2. **HMAC SHA-256 Signatures:** Delivered via `X-ThreatLens-Signature` computed over raw request body using a shared secret.

Integrations disabled via management toggle return HTTP 403 Forbidden. Invalid credentials return HTTP 401 Unauthorized. Secrets remain strictly server-side and never appear in response bodies, logs, Redis events, or audit records.

### Replay & Clock Skew Protection
Requests with timestamp headers (`X-ThreatLens-Timestamp` or `Date`) are validated against an allowed clock-skew window (`WEBHOOK_ALLOWED_CLOCK_SKEW_SECONDS = 300s`). Requests outside the window are rejected with HTTP 400.

### Rate Limiting & Payload Limits
- Max payload size enforced at 512 KB (`WEBHOOK_MAX_PAYLOAD_BYTES = 524288`). Oversized payloads are rejected with HTTP 413 Payload Too Large.
- In-memory token-bucket rate limiting permits up to 120 requests/minute per provider.

---

## 3. FR-04 TAXII 2.1

### Architecture
TAXII 2.1 is integrated directly into the canonical `Feed` model and existing feed management system (`feed_service.py`, `taxii_service.py`). TAXII feeds behave as another canonical feed with `feed_type = "taxii"`.

### Discovery & Collections
1. **Server Discovery (`POST /api/v1/feeds/taxii/discover`):** Queries `<server_url>/taxii2/` or `<server_url>`, verifying TAXII 2.1 media types (`application/taxii+json;version=2.1`). Discovers title, description, and list of available API roots.
2. **Collection Enumeration (`POST /api/v1/feeds/taxii/collections`):** Inspects the specified API root, returning accessible collections with their IDs, titles, descriptions, and read/write capabilities.
3. **Feed Registration (`POST /api/v1/feeds/taxii`):** Registers a TAXII collection as an active threat feed with custom polling intervals, authenticated credentials, and initial state.

### Collection Polling & Delta Synchronization
Polling queries `GET <api_root>/collections/<collection_id>/objects/?match[type]=indicator` (with optional `&added_after=<timestamp>`).
- Persists `last_added_after` in the `feeds` table to guarantee that historical objects are never repeatedly downloaded.
- Bounded response limits ensure memory stability during large bundle transfers.

### STIX 2.1 Indicator Pattern Handling
STIX 2.1 patterns (e.g. `[ipv4-addr:value = '198.51.100.1']`) are parsed using a bounded regex parser (`_SAFE_STIX_PATTERN_REGEX`).
- Supports: `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file:hashes.'SHA-256'`, `file:hashes.'MD5'`, `file:hashes.'SHA-1'`, and `email-addr`.
- **Zero eval() and zero exec() guaranteed.**
- Unsupported or complex patterns are safely skipped with diagnostic logging.

---

## 4. Normalization

All webhook security events and STIX objects are normalized into ThreatLens canonical models:
- **Indicators:** Normalized via `normalize_and_validate_ioc` into lowercase/defanged format with appropriate `IndicatorType`, default confidence, initial severity score, and tags (`webhook:{provider}`, `external-alert`, etc.).
- **Security Events:** Stored in `security_events` table with canonical fields: `provider`, `external_event_id`, `dedup_key`, `event_type`, `source_ip`, `destination_ip`, `domain`, `url`, `hash`, `hostname`, `username`, `severity`, `description`, `mitre_technique`, and `raw_payload`.
- **Alerts:** Critical or high-severity events automatically generate canonical `Alert` records linking `indicator_id`, `source`, `rule_id`, and `routed_to`.
- **Provenance:** Every ingested indicator links to `IndicatorSource` preserving provider identity, external event ID, confidence, and timestamp.

---

## 5. Deduplication

### Webhook Deduplication
- Computed deterministic deduplication key: `dedup_key = f"{provider}:{external_event_id}"` enforced by a database unique index.
- If a security event with the same `dedup_key` is re-delivered, the receiver updates sightings and `updated_at`, returning HTTP 200 with status `"deduplicated"` without creating duplicate indicators, alerts, or incidents.

### TAXII Deduplication
- STIX indicators are identified by their canonical value and type, linking to `IndicatorSource` with `source = f"taxii_{feed_name}"`.
- Subsequent polls increment sightings and update `last_seen` without creating duplicate indicators.

---

## 6. Detection Rule Integration

Indicators extracted from webhooks and TAXII collections enter the Phase 4D-B declarative detection rule pipeline:
- `evaluate_indicator_against_rules(db, indicator)` evaluates the IOC against active rules.
- If rules match, alerts are generated, routed to the configured security queue/team (`SOC_TIER_1`, `THREAT_HUNTING`, etc.), and published to Redis channel `threatlens:events:detection_rules`.

---

## 7. Incident Integration

Alerts created from inbound webhooks and TAXII feeds are immediately handed off to the canonical Phase 4A correlation service:
- `correlate_alert_to_incident(db, alert)` evaluates temporal proximity, common IOCs, hostnames, and MITRE techniques.
- Alerts are automatically clustered into existing or newly provisioned canonical incidents with explainable correlation scores and timeline entries (`ALERT_CORRELATED`).

---

## 8. Redis Events

Published to structured Redis Pub/Sub channels:
- Channel `threatlens:events:integrations`:
  - `SECURITY_EVENT_INGESTED`: Provider, event ID, severity, IOC value, type, created alert ID.
  - `SECURITY_EVENT_DEDUPLICATED`: Duplicate delivery acknowledged without side effects.
  - `TAXII_POLL_COMPLETED`: Feed ID, collection ID, ingested counts, next cursor.
- Channel `threatlens:events:alerts`: Real-time alert fan-out to connected SOC analyst WebSockets.
- **Secrecy:** Raw payloads, API tokens, HMAC signatures, and passwords are never included in Redis events.

---

## 9. Audit Logging

Immutable database-level audit events recorded for all state-changing integration actions:
- `WEBHOOK_EVENT_INGESTED`: Provider, event ID, severity, created alert/indicator ID.
- `WEBHOOK_AUTH_FAILED`: Provider, client IP, failure reason.
- `WEBHOOK_CONFIG_UPDATED`: Integration enabled/disabled by privileged user.
- `TAXII_POLL_EXECUTED`: Feed name, collection ID, object count, status.
- `TAXII_FEED_REGISTERED`: New TAXII collection registered as threat feed.

---

## 10. RBAC

Strict server-side role enforcement on integration endpoints:
- Inbound webhooks (`POST /api/v1/integrations/webhooks/{provider}`) authenticate as machine integrations via secrets/signatures (not human user accounts).
- Webhook management (`GET /webhooks`, `POST /webhooks/{provider}/enable`, `POST /webhooks/{provider}/disable`):
  - `Viewer`: Read-only access to integration status and metrics.
  - `Analyst`: Operational inspection of webhook events.
  - `Security Engineer` & `Administrator`: Full administrative control to enable/disable integrations and configure TAXII feeds.
- Credential redaction: `secret_token` and `hmac_secret` are never returned in GET responses.

---

## 11. Security Forensics

- **No Code Execution:** Comprehensive search confirms zero `eval()` and zero `exec()` calls across production codebase.
- **SSRF Defense:** `is_safe_taxii_url` blocks private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, link-local, AWS/GCP metadata endpoints).
- **Secret Non-Disclosure:** Passwords hashed with SHA-256; webhook secrets masked in all responses; zero credentials in telemetry.
- **Replay Skew Defense:** 300-second window blocks timestamp tampering and replay attacks.
- **Payload Limits:** 512KB strict limit blocks resource exhaustion.

---

## 12. Database / Migrations

Alembic migration: `4d4integrat10ns_phase4d_d_siem_edr_and_taxii.py`
- Extended `feeds` table: `taxii_api_root`, `taxii_collection_id`, `taxii_version`, `last_added_after`, `taxii_username`, `taxii_password_hash`.
- Extended `security_events` table: `provider`, `external_event_id`, `dedup_key` (unique/indexed), `url`, `hostname`, `username`, `severity`, `description`, `mitre_technique`, `status`, `created_alert_id`, `created_indicator_id`.
- Created `webhook_configs` table: Provider settings, enabled states, secret tokens, HMAC secrets, event counters, and timestamps.
- **Head check:** `python -m alembic heads` confirmed exactly one canonical head: `4d4integrat10ns (head)`.

---

## 13. Frontend

Updated `frontend/src/components/FeedManagement.tsx` and `frontend/src/lib/api.ts`:
- **Integrated Control Plane:** Single unified cockpit for External Ingestion & Integrations.
- **Tabbed Interface:**
  1. *Threat Intelligence Feeds & TAXII 2.1:* Displays active feeds, TAXII badges, collection IDs, cursor timestamps, and on-demand polling. Includes "Connect TAXII 2.1 Server" modal for server discovery, collection browsing, and feed registration.
  2. *Inbound SIEM & EDR Webhook Receivers (FR-29):* Displays status cards for Splunk, QRadar, Sentinel, CrowdStrike, and Elastic with live event counters, endpoint URLs, HMAC SHA-256 status, and enable/disable toggles.
- **Production Build:** `npm run build` compiled successfully with **0 TypeScript errors, 0 compilation errors**.
- **Mock Data Audit:** Zero `Math.random()`, zero `setInterval()`, zero mock arrays, zero synthetic data.

---

## 14. Tests

Created `backend/tests/test_phase4d_d_integrations.py` covering:
1. `test_webhook_unauthenticated_rejected`: Rejects unauthenticated requests with HTTP 401.
2. `test_webhook_invalid_secret_rejected`: Rejects invalid tokens with HTTP 401.
3. `test_webhook_replay_protection_clock_skew`: Enforces 300s window.
4. `test_webhook_hmac_signature_validation`: Validates SHA-256 HMAC headers.
5. `test_webhook_oversized_payload_rejected`: Rejects payloads exceeding 512KB with HTTP 413.
6. `test_webhook_ingestion_and_normalization`: Ingests Splunk event, extracts IOCs, creates alerts, and clusters into incidents.
7. `test_webhook_deduplication`: Verifies deterministic deduplication idempotency.
8. `test_webhook_rbac_list_and_toggle`: Verifies RBAC on webhook management.
9. `test_safe_stix_pattern_parser_zero_eval`: Verifies bounded regex pattern extraction without code execution.
10. `test_taxii_ssrf_protection`: Blocks private IP ranges and cloud metadata URLs.
11. `test_taxii_collection_polling_stix_ingestion`: Ingests STIX 2.1 bundles with mock HTTP transport.
12. `test_taxii_poll_cursor_persistence`: Validates `last_added_after` delta cursor tracking.
13. `test_taxii_feed_registration_endpoint`: Registers TAXII feed with secret masking.

**Full Regression Suite:** `python -m pytest tests/ -v`
- **139 passed, 0 failed, 0 errors, 0 skipped** across all test suites.

---

## 15. Runtime Verification

Executed `backend/verify_runtime_phase4d_d.py` against live database, Redis, and service stack:
1. `/health` and `/health/ready`: PASS
2. Webhook Authentication & Rejection: PASS
3. Ingesting valid authenticated Splunk event: PASS
4. Verifying persisted SecurityEvent and normalized Indicators: PASS
5. Verifying Alert handoff to Phase 4A Incident Correlation: PASS
6. Verifying Webhook Deduplication idempotency: PASS
7. Verifying RBAC on Webhook Integration Management: PASS
8. Verifying safe STIX 2.1 Pattern Parser (Zero eval/exec): PASS
9. Verifying TAXII 2.1 Collection Polling with STIX bundle: PASS
10. Verifying immutable Audit Logging: PASS

---

## 16. Mock Data Audit

Forensic grep across the entire codebase confirms:
- Zero `eval(` or `exec(` calls in production code.
- Zero `Math.random()` in data generation.
- Zero `setInterval()` polling loops.
- Zero `mockAlerts`, `synthetic`, `dummy`, or `fake` data structures.

---

## 17. Limitations / Findings

- **TAXII 2.0 vs 2.1 Media Types:** The implementation targets TAXII 2.1 standard (`application/taxii+json;version=2.1`). Legacy TAXII 1.x (XML-based) is intentionally unsupported.
- **External TAXII Server Availability:** Public TAXII servers (e.g. Anomali LIMO) frequently experience downtime or rate limiting. A deterministic mock transport fixture is included for isolated CI/CD testing.
- **Explicit Webhook Providers:** Webhooks are strictly bounded to `splunk`, `qradar`, `sentinel`, `crowdstrike`, and `elastic` to guarantee strict schema validation and prevent unauthorized data injection.

---

## 18. Git

- Checkpoint commit: `9f20964` ("checkpoint: ThreatLens before Phase 4D-D SIEM EDR and TAXII integration")
- Single canonical Alembic migration head: `4d4integrat10ns`

---

## Final Summary

```text
PHASE 4D-D STATUS: COMPLETE
FR-04:            COMPLETE (TAXII 2.1 discovery, collections, STIX ingestion, delta cursor)
FR-29:            COMPLETE (Inbound SIEM/EDR webhooks for Splunk, QRadar, Sentinel, CrowdStrike, Elastic)
SECURITY:         PASS (HMAC SHA-256, replay protection, SSRF defense, zero eval/exec)
RBAC:             PASS (Viewer read-only, Analyst triage, Engineer/Admin management)
DEDUPLICATION:    PASS (Deterministic provider + external_event_id and IOC upserts)
PROVENANCE:       PASS (Traceable to provider, external ID, and collection)
REDIS:            PASS (threatlens:events:integrations, threatlens:events:alerts)
AUDIT:            PASS (Immutable database-level audit events recorded)
MOCK DATA:        CLEAN (Zero mock data, zero eval, zero setInterval)
TESTS:            139 passed, 0 failed, 0 skipped, 0 errors
RUNTIME:          PASS (10/10 automated runtime verifications passed)
FRONTEND:         PASS (npm run build succeeded with 0 errors)
GIT:              CLEAN
```
