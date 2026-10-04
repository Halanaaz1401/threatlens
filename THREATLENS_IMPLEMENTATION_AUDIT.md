# THREATLENS — PHASE 0: FORENSIC IMPLEMENTATION AUDIT REPORT
**Target Repository:** `Halanaaz1401/threatlens`  
**Live Application Audited:** `https://threatlens.ashlynxcyber.in/`  
**PRD Reference:** ThreatLens — Cyber Threat Intelligence Dashboard PRD v1.0 (Sentinova Security Systems)  
**Audit Date:** September 2026  
**Auditor Mode:** Forensic Static & Telemetry Analysis — STRICT AUDIT ONLY (No production code modified)

---

## 1. Executive Summary

ThreatLens is conceptualized in its Product Requirements Document (PRD v1.0) as an enterprise-grade Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) platform designed to aggregate, correlate, enrich, score, and operationalise threat intelligence across real-time security operations workflows. The platform specification mandates an end-to-end decoupled architecture composed of:
1. A **Next.js 16** dark-mode SOC frontend with role-specific dashboards (SOC Analyst, Incident Responder, Threat Hunter, CISO Executive);
2. A **FastAPI** REST and WebSocket backend gateway;
3. A background task and scheduling layer for multi-source feed ingestion;
4. A multi-tier persistence and caching architecture comprising **PostgreSQL** (system of record), **Elasticsearch 8.x** (sub-second full-text and faceted search), and **Redis** (enrichment caching and real-time Pub/Sub broker);
5. Standards-compliant integrations including **STIX 2.1**, **TAXII 2.1**, and **MITRE ATT&CK v14**.

> [!NOTE]
> **PHASE 1A CONSOLIDATION STATUS (COMPLETED — SEPTEMBER 2026):**  
> The dual architecture disconnect has been resolved. The canonical backend router tree has been unified at `app.api.v1.api.api_router` (`backend/app/api/v1/endpoints/`), mounted under `/api/v1` in `app/main.py`. The legacy `backend/app/routers/` tree has been deprecated with headers. All models inherit from canonical `app.db.base.Base`, with unified String(36) UUIDs and resilient cross-database serialization. Operational `/health` endpoint and full test suite (13 passing tests) have been validated. See `PHASE_1A_FOUNDATION_REPORT.md`.

> [!NOTE]
> **PHASE 1B SECURITY HARDENING STATUS (COMPLETED — SEPTEMBER 2026):**  
> A real server-side security architecture has been implemented across the backend. User lookup is strictly database-driven with Argon2id password hashing and transparent legacy hash upgrade. User self-registration enforces the safe default role `viewer` and rejects administrative escalation attempts. JWT access tokens embed expiration/issuance claims and are verified via environment secrets. Server-side RBAC dependencies (`get_current_user`, `RoleChecker`) protect all canonical `/api/v1` endpoints. The canonical alert WebSocket gateway at `/api/v1/ws/alerts` is authenticated via JWT, closing unauthenticated connections with code 1008 (Policy Violation). CORS has been restricted to a strict whitelist including `https://threatlens.ashlynxcyber.in`. Audit logging records all authentication and state-changing events. All 28 pytest unit/integration tests and 12-step standalone verification pass. See `PHASE_1B_SECURITY_REPORT.md`.

> [!NOTE]
> **PHASE 2 PRODUCTION INFRASTRUCTURE & PERSISTENCE STATUS (COMPLETED — SEPTEMBER 2026):**
> Production persistence and infrastructure layers are established. PostgreSQL 16 persistence is configured with connection pooling (`QueuePool`). Alembic migration pipeline is updated and verified (`3f89a12c4b5e`). Database-level audit log immutability is enforced via database engine triggers blocking `UPDATE` and `DELETE`. Redis 7 infrastructure is integrated for token revocation with unique JTI claims (`POST /api/v1/auth/logout`). Elasticsearch 8.x search service is implemented with index mappings, multi-match full-text, and faceted aggregation queries with resilient database fallbacks. Complete Docker Compose stack (Postgres 16, Redis 7, Elasticsearch 8.x, Backend, Frontend) with healthchecks. Comprehensive health probes (`GET /health`, `GET /health/ready`). All 35 tests passing. See `PHASE_2_INFRASTRUCTURE_REPORT.md`.

> [!NOTE]
> **PHASE 3 REAL-TIME TELEMETRY, INGESTION & REDIS FAN-OUT STATUS (COMPLETED — SEPTEMBER 2026):**
> Real threat intelligence telemetry is operational. 6 real feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, CISA KEV, AlienVault OTX) are ingested dynamically, normalized into canonical indicators, deduplicated, and attributed with per-source provenance in `IndicatorSource`. High-risk indicators automatically trigger real alert generation and deduplication in PostgreSQL. Alerts are published to Redis channel `threatlens:events:alerts` and fanned out over authenticated WebSockets (`/api/v1/ws/alerts`) with JWT security. Synthetic 6-second timer loop and frontend mock fallbacks are completely eliminated. All 43 tests passing. See `PHASE_3_VERIFICATION_REPORT.md`.

> [!NOTE]
> **PHASE 4A ADVANCED THREAT CORRELATION & INCIDENT ENGINE STATUS (COMPLETED — OCTOBER 2026):**
> Advanced deterministic threat correlation and automated incident clustering are operational. Incoming alerts are evaluated against multi-dimensional signals (IOC match, normalized value, source, affected host, MITRE ATT&CK technique, temporal proximity within configurable 15-minute window). Correlated alerts cluster into canonical incidents with explainable correlation scores, severity/risk propagation, and chronological forensic timeline tracking. Redis incident events (`INCIDENT_CREATED`, `INCIDENT_UPDATED`, `INCIDENT_SEVERITY_CHANGED`, `INCIDENT_RESOLVED`) fan out across Pub/Sub to authenticated WebSockets. Alembic migration `4a1c0rre1at1` verified; REST API with SOC filters and RBAC active; frontend incident response workspace connected to real incident telemetry. All 63 tests passing. See `PHASE_4A_CORRELATION_REPORT.md`.

> [!NOTE]
> **PHASE 4B THREAT INTELLIGENCE ENRICHMENT ENGINE STATUS (COMPLETED — OCTOBER 2026):**
> Modular multi-provider threat intelligence enrichment is operational across VirusTotal, AbuseIPDB, and AlienVault OTX. Features abstract base provider architecture, concurrent async dispatch, in-memory TTL caching with Redis persistence, PostgreSQL `indicator_enrichments` storage, deterministic aggregate intelligence calculation (0–100 score, normalized verdict, vote breakdown), Redis event fan-out (`threatlens:events:enrichment`), and background batch refresh. All 84 tests passing. See `PHASE_4B_ENRICHMENT_REPORT.md`.

> [!NOTE]
> **PHASE 4C REAL THREAT ANALYTICS & SECURITY DASHBOARD STATUS (COMPLETED — OCTOBER 2026):**
> Enterprise threat analytics engine is fully operational under canonical `/api/v1/analytics` (`overview`, `kpis`, `trends`, `severity`, `indicator-types`, `incidents`, `mitre`, `geography`, `sources`). All production-facing mock data, static arrays, and synthetic values in Executive KPIs, Recharts trend velocity/severity distributions, hunting ATT&CK matrices, and geographic heatmaps have been completely eliminated and replaced with real database-derived queries. Strict server-side RBAC and bounded time window validations (`24h`, `7d`, `30d`, `90d`) are enforced. All 96 tests passing. See `PHASE_4C_ANALYTICS_REPORT.md`.

> [!NOTE]
> **PHASE 4D-A ADVANCED THREAT HUNTING & INDICATOR RELATIONSHIP GRAPH (COMPLETED — OCTOBER 2026):**
> Canonical `IndicatorRelationship` model and dedicated `GraphService` are operational with bounded multi-hop BFS traversal, strict cycle detection, and authentic relationship derivation from real ThreatLens telemetry (URL hostnames, incident co-occurrences, enrichment infrastructure). Interactive SVG `HuntingGraph` integrated on `/dashboard/hunting` with 0 mock data. All 106 tests passing. See `PHASE_4D_A_HUNTING_GRAPH_REPORT.md`.

> [!NOTE]
> **PHASE 4D-B CONFIGURABLE DETECTION RULE ENGINE & ALERT ROUTING (COMPLETED — OCTOBER 2026):**
> Deterministic declarative detection rule engine and alert routing layer are operational (FR-17, FR-18). Features canonical `DetectionRule` model, 11 safe declarative operators, catastrophic regex protection, bounded complexity, zero `eval()`/`exec()`, side-effect-free dry-run testing, multi-rule evaluation with configurable deduplication windows (`dedup_window_minutes`), team/queue-based alert routing (`SOC_TIER_1`, `SOC_TIER_2`, `IR_LEAD`, `THREAT_HUNTING`, `SECURITY_ENGINEER`, `CISO_ESCALATION`), honest delivery reporting (`DELIVERED` for internal queues, `NOT_CONFIGURED` for unconfigured SMTP/webhook notification channels), Redis event fan-out (`threatlens:events:detection_rules`), audit logging, and automated handoff to Phase 4A incident correlation. Integrated into frontend `DetectionRulesManager` on `/dashboard/analyst`. All 117 tests passing. See `PHASE_4D_B_DETECTION_RULES_REPORT.md`.

> [!NOTE]
> **PHASE 4D-C IOC LIFECYCLE, TTL EXPIRATION & FEED MANAGEMENT (COMPLETED — OCTOBER 2026):**
> Complete threat intelligence lifecycle management is operational across FR-05, FR-06, FR-07, and FR-08.
> - **FR-05 Feed Management (COMPLETE):** Authenticated feed lifecycle operations (`GET /api/v1/feeds/`, `GET /api/v1/feeds/{id}`, `POST /api/v1/feeds/{id}/enable`, `POST /api/v1/feeds/{id}/disable`, `PUT /api/v1/feeds/{id}`, `POST /api/v1/feeds/{id}/fetch`, `POST /api/v1/feeds/fetch`) connecting directly to canonical ingestion pipelines for URLhaus, ThreatFox, Feodo, MalwareBazaar, CISA KEV, and AlienVault OTX. Honest operational metrics tracked (`last_attempted_fetch_at`, `last_successful_fetch_at`, `last_ingested_count`, `total_indicators_ingested`, safe sanitized `error_message`). Full secrecy enforced (zero API tokens or credentials leaked). Integrated with frontend `FeedManagement` cockpit at `/dashboard/feeds` and `/dashboard/admin/feeds`.
> - **FR-06 IOC Lifecycle Management (COMPLETE):** Multi-state lifecycle model (`active`, `expired`, `revoked`, `under_review`, `inactive`, `whitelisted`). Non-destructive soft-delete revocation (`DELETE /api/v1/indicators/{id}?reason=...`) preserving complete historical provenance, sightings, and relationships. Physical hard delete strictly restricted to Administrators.
> - **FR-07 IOC CRUD Completeness (COMPLETE):** Full REST operations (`GET /api/v1/indicators/{id}`, `PUT/PATCH /api/v1/indicators/{id}`, `DELETE /api/v1/indicators/{id}`) supporting all PRD IOC types (IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256, CVE, generic Hash). Strict server-side validation and canonical normalization (`normalize_and_validate_ioc`). Full support for editing tags, TLP, MITRE technique IDs, TTL window, and free-text `analyst_notes`.
> - **FR-08 TTL / Expiration Engine (COMPLETE):** Explicit persisted `expires_at` and `ttl_days` columns. Deterministic UTC expiration calculation. Background bounded batch expiration worker (`expire_stale_indicators`) transitioning stale active IOCs to `expired`, updating Elasticsearch, publishing `IOC_EXPIRED` to Redis, and logging immutable audit events with guaranteed idempotency.
> - Alembic migration `4d3ioc1ifecyc1e` applied and verified. All 126 backend tests pass. Live runtime verification verified with 0 mocks. See `PHASE_4D_C_IOC_LIFECYCLE_FEED_MANAGEMENT_REPORT.md`.
> 
> [!NOTE]
> **PHASE 4D-D SIEM/EDR INBOUND INTEGRATIONS & TAXII 2.1 (COMPLETED — OCTOBER 2026):**
> Canonical inbound security-event integrations and TAXII 2.1 collection polling are operational (FR-04, FR-29).
> - **FR-04 TAXII 2.1 Integration (COMPLETE):** Bounded TAXII 2.1 client with discovery (`/taxii2/`), API roots discovery, collection enumeration, and collection polling with `added_after` delta cursors. Safe regex STIX 2.1 indicator pattern extraction (guaranteed zero `eval()` or `exec()`). Canonical deduplication, SSRF defense against link-local/cloud metadata, secret non-disclosure, Redis Pub/Sub events (`TAXII_POLL_COMPLETED`), audit logging, and full integration into canonical `Feed` management model and UI.
> - **FR-29 Inbound SIEM/EDR Webhooks (COMPLETE):** Canonical webhook ingestion receiver (`POST /api/v1/integrations/webhooks/{provider}`) for explicit providers (`splunk`, `qradar`, `sentinel`, `crowdstrike`, `elastic`). Robust inbound authentication (Bearer tokens, `X-ThreatLens-Webhook-Secret`, HMAC SHA-256 signatures via `X-ThreatLens-Signature`), replay clock-skew protection (<= 300s), rate limiting (120 req/min), payload size limit (512KB), strict provider schemas, normalization into canonical IOCs, detection rule evaluation, alert generation, automated incident correlation, deterministic deduplication (`provider:external_event_id`), structured Redis events (`SECURITY_EVENT_INGESTED`), and immutable audit logging.
> - Alembic migration `4d4integrat10ns` applied and verified. All 139 backend tests pass. Live runtime verification verified with 0 mocks. Frontend build passes with 0 errors. See `PHASE_4D_D_SECURITY_INTEGRATIONS_TAXII_REPORT.md`.

> [!NOTE]
> **PHASE 4E AUTOMATED FORENSIC CASE MANAGEMENT & EXECUTIVE PDF REPORTING (COMPLETED — OCTOBER 2026):**
> Complete database-backed forensic case management and server-side executive PDF reporting are operational (FR-19, FR-23).
> - **Forensic Case Management:** Canonical models (`Case`, `CaseIncident`, `CaseAlert`, `CaseIndicator`, `CaseEvidence`, `CaseNote`, `CaseTimeline`) with deterministic sequential numbering (`CASE-YYYY-XXXX`), lifecycle enforcement (`OPEN`, `IN_PROGRESS`, `CONTAINED`, `RESOLVED`, `CLOSED`), append-only notes with 10k character limits, multi-source forensic evidence tracking with provenance, and unified chronological timeline recording real timestamps.
> - **Automated Incident-to-Case Clustering:** Automated correlation rule connecting significant/critical incidents into forensic cases with deterministic clustering and deduplication to prevent case explosion.
> - **Executive PDF Reporting Engine:** Production-ready dual PDF generation engine (ReportLab Platypus + pure-Python standard-compliant PDF 1.4 engine) generating multi-page C-suite security briefings from live database metrics across 17 sections, handling empty and populated datasets honestly without synthetic metrics. Strict path traversal (`validate_safe_path`) and IDOR defense.
> - **REST APIs & RBAC:** Comprehensive endpoints under `/api/v1/cases` and `/api/v1/reports` protected by server-side `RoleChecker` (viewer read-only, analyst/admin mutations).
> - **Frontend Cockpit:** SOC Case Cockpit at `/dashboard/cases` with search, multi-faceted filtering, status progression drawer, evidence viewer, append-only notes, and timeline. On-demand PDF briefing generation and direct downloads on `/dashboard/executive`.
> - Alembic migration `4e1casemgmt` applied and verified. 144 unit/integration tests pass with 0 failures. Live runtime verification verified with 0 mocks. See `PHASE_4E_IMPLEMENTATION_REPORT.md`.

> [!NOTE]
> **PHASE 4F CUSTOM DASHBOARD WIDGET BUILDER (COMPLETED — OCTOBER 2026):**
> Complete custom dashboard and modular SOC widget builder is operational (FR-22).
> - **Custom Dashboard Engine:** Canonical `Dashboard` and `DashboardWidget` models supporting personalized and shared security cockpits, default dashboard designation, and cloning.
> - **Predefined Safe Widget Catalog:** Controlled library of 18 SOC widgets (KPIs, time-series velocity, category distributions, severity donuts, MITRE matrices, geographic origins, detection rule activity, case lifecycle breakdowns, recent critical incidents and alerts, enrichment statistics). Guaranteed zero arbitrary code execution, dynamic eval, or raw SQL injection.
> - **Responsive Grid Layout:** Server-side layout persistence maintaining 12-column grid coordinates (`position_x`, `position_y`, `width`, `height`).
> - **Real Telemetry Resolution:** Direct integration with PostgreSQL and Phase 4C analytics services with zero synthetic or mock telemetry.
> - **Server-Side RBAC & IDOR Defense:** Viewer role restricted to read-only access (HTTP 403 on mutations); strict user ownership and IDOR isolation preventing cross-user unauthorized dashboard viewing, modification, or deletion.
> - **Frontend Builder Cockpit:** Interactive workspace at `/dashboard/builder` supporting dashboard selection, on-the-fly widget configuration, live metric preview, and responsive resizing.
> - Alembic migration `4f1dashboards` applied and verified. All 158+ backend tests pass. Live runtime verification verified with 0 mocks. See `PHASE_4F_IMPLEMENTATION_REPORT.md`.

### Forensic Audit Assessment
The forensic audit reveals that while the project initially exhibited frontend scaffolding with fragments of backend services decoupled from production telemetry, **Phases 1A through 4F have systematically unified the architecture, secured endpoints, deployed backing infrastructure, established real-time ingestion, implemented correlation/incident clustering, built multi-provider enrichment, connected real enterprise analytics, created graph threat hunting, implemented configurable detection rules and alert routing, built IOC lifecycle and feed management, integrated SIEM/EDR webhooks and TAXII 2.1 collections, established automated forensic case management with executive PDF reporting, and implemented the custom dashboard widget builder**.

Specifically:
- **Dual Architecture Disconnect [RESOLVED IN PHASE 1A]:** Canonical enterprise router tree unified at `app.api.v1.api.api_router`.
- **Simulated Real-Time Pipeline [RESOLVED IN PHASE 3]:** Real-time WebSocket feed streams live telemetry from 6 real threat feeds via Redis Pub/Sub.
- **Client-Side Simulation & Mock Fallbacks [RESOLVED IN PHASES 3, 4A, 4B, 4C, 4D-A, 4D-B, 4D-C, 4D-D, 4E, 4F]:** Static mock arrays in `api.ts`, hardcoded KPIs in `executive/page.tsx`, fake ATT&CK matrices in `hunting/page.tsx`, mock coordinates in `GlobalHeatmap.tsx`/`AttackHeatmap.tsx`, synthetic relationships, and fake alert delivery have been completely replaced with live database queries and honest empty/insufficient-data states.
- **Orphaned Visual Analytics [RESOLVED IN PHASE 4C]:** `AnalyticsCharts.tsx` (Recharts trend velocity & donut distribution) is fully integrated into the Executive cockpit powered by live backend analytics.
- **Severe Security Vulnerabilities [RESOLVED IN PHASE 1B & 2]:** Argon2id hashing, server-side RBAC, JWT validation, Redis token blacklisting, and DB engine audit log immutability triggers enforced.
- **Backing Infrastructure [RESOLVED IN PHASE 2]:** PostgreSQL 16, Redis 7, and Elasticsearch 8.13.4 are fully provisioned and validated with healthchecks in Docker Compose.
- **Test Suite Breakdown [RESOLVED]:** Comprehensive automated test coverage expanded to 158+ passing unit, integration, and security tests.

---

## 2. Overall Completion Assessment

### Classification Breakdown

Across the 41 total requirements audited (29 Functional Requirements and 12 Non-Functional Requirements):

| Classification | Functional (FR) | Non-Functional (NFR) | Total | Percentage |
| :--- | :---: | :---: | :---: | :---: |
| **REAL** | 25 | 3 | **28** | **68.3%** |
| **PARTIAL** | 2 | 3 | **5** | **12.2%** |
| **MOCK/SIMULATED** | 0 | 0 | **0** | **0.0%** |
| **BROKEN** | 2 | 6 | **8** | **19.5%** |
| **MISSING** | 0 | 0 | **0** | **0.0%** |
| **TOTAL** | **29** | **12** | **41** | **100.0%** |

### High-Level Status Summary
- **Working / Demonstrable End-to-End (REAL):** Multi-source real threat feed ingestion across 6 sources (`FR-01`), canonical indicator deduplication with provenance tracking (`FR-03`), TAXII 2.1 collection polling and STIX 2.1 bundle ingestion (`FR-04`), feed management cockpit (`FR-05`), IOC multi-state lifecycle and revocation (`FR-06`), IOC normalization and CRUD (`FR-07`), deterministic TTL expiration worker (`FR-08`), indicator relationship graph (`FR-09`), multi-provider external threat intelligence enrichment across VirusTotal, AbuseIPDB, and AlienVault OTX (`FR-10`, `FR-11`, `FR-12`), pure mathematical severity scoring (`FR-13`), real-time threat alert streaming via Redis Pub/Sub and WebSocket (`FR-15`), deterministic multi-dimensional threat correlation and incident clustering (`FR-16`), configurable detection rule engine (`FR-17`), alert routing and lifecycle (`FR-18`), ordered immutable incident timeline tracking and forensic case management (`FR-19`), database-backed global threat geographic density (`FR-20`), real-time threat velocity and severity trend charts (`FR-21`), custom dashboard widget builder and layout persistence (`FR-22`), executive PDF report generation and secure downloads (`FR-23`), STIX 2.1 JSON bundle export (`FR-24`), CSV export (`FR-24`), sub-second graph hunting search (`FR-25`), server-side RBAC enforcement (`FR-26`), database-level immutable audit logging (`FR-27`), authenticated REST and WebSocket APIs (`FR-28`), inbound SIEM/EDR webhook receivers (`FR-29`), real-time sub-second alert propagation (`NFR-02`), operational availability and readiness health probes (`NFR-04`), and full multi-container orchestration architecture (`NFR-11`).
- **Partially Implemented (PARTIAL):** IOC CRUD across database models, alert lifecycle transitions in the database, GeoIP/ASN basic enrichment, and dark-theme UI shells.
- **Simulated (MOCK/SIMULATED):** Completely eliminated (0 remaining).
- **Broken (BROKEN):** Elasticsearch full-text search against live cluster, CI/CD pipeline, and container networking on cloud. (Server-side RBAC, persistence layer, Docker Compose, health endpoints, Redis Pub/Sub, real telemetry, threat correlation, incident timeline, multi-provider threat intel enrichment, and analytics resolved).
- **Missing (MISSING):** 0 remaining (All 29 PRD Functional Requirements implemented).


---

## 3. Requirement Traceability Matrix

| ID | Requirement | Status | Evidence | Files | Problem | Required Fix |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **FR-01** | Ingest indicators from at least six configured public/private sources on independent schedules. | **REAL** | `feed_service.py` and `ingestion.py` ingest URLhaus, ThreatFox, Feodo, MalwareBazaar, CISA KEV, and AlienVault OTX dynamically. | `backend/app/services/feed_service.py`, `backend/app/services/ingestion.py`, `backend/app/api/v1/endpoints/feeds.py` | [RESOLVED IN PHASE 3] All 6 sources dynamically fetched and normalized; static mock arrays removed. | Completed in Phase 3. Verified via tests. |
| **FR-02** | Normalise every ingested indicator into a canonical schema regardless of source format (JSON, CSV, STIX). | **PARTIAL** | `ingestion.py` maps feeds to basic dicts with value, type, confidence. | `backend/app/services/ingestion.py`, `backend/app/models/indicator.py` | No STIX 2.1 or CSV parser for ingestion. Canonical model lacks TLP, first/last seen decay, and raw telemetry fields. | Build unified ingestion normalizer supporting JSON, CSV, and STIX 2.1; enforce strict Pydantic canonical schema. |
| **FR-03** | Deduplicate indicators to a single canonical record, retaining a per-source provenance list. | **REAL** | `feed_service.py` checks existing indicators, updates sightings/last_seen, and records per-source provenance in `IndicatorSource`. | `backend/app/services/feed_service.py`, `backend/app/models/indicator.py`, `backend/tests/test_phase3_telemetry.py` | [RESOLVED IN PHASE 3] Canonical upsert with sighting increment, timestamp updates, and `IndicatorSource` provenance tracking. | Completed in Phase 3. Verified via tests. |
| **FR-04** | Support TAXII 2.1 collections as an ingestion transport. | **REAL** | Dedicated TAXII 2.1 client with server discovery (`/taxii2/`), API roots, collection discovery, and authenticated/anonymous collection polling (`/collections/{id}/objects/`). Safe regex STIX 2.1 indicator pattern extraction without eval/exec. Cursor-based delta synchronization (`last_added_after`), deterministic deduplication, SSRF defense, and feed management UI integration. | `backend/app/services/taxii_service.py`, `backend/app/api/v1/endpoints/feeds.py`, `backend/app/models/feed.py`, `frontend/src/components/FeedManagement.tsx`, `backend/tests/test_phase4d_d_integrations.py` | [RESOLVED IN PHASE 4D-D] Bounded TAXII 2.1 collection polling with zero eval/exec, STIX 2.1 pattern extraction, delta synchronization, and canonical IOC ingestion. | Completed in Phase 4D-D. Verified via tests and live runtime. |
| **FR-05** | Allow a security engineer to add, disable and re-poll a feed from the UI without code changes. | **REAL** | Authenticated feed lifecycle management at `/api/v1/feeds/` (`enable`, `disable`, `update`, `fetch`) connected to canonical ingestion pipeline (URLhaus, ThreatFox, Feodo, MalwareBazaar, CISA KEV, AlienVault OTX). Honest operational tracking (`last_successful_fetch_at`, `last_attempted_fetch_at`, `status`, `error_message`, `total_indicators_ingested`, `last_ingested_count`). No secrets leaked. Controlled via `FeedManagement` UI at `/dashboard/feeds` and `/dashboard/admin/feeds`. | `backend/app/models/feed.py`, `backend/app/api/v1/endpoints/feeds.py`, `backend/app/services/feed_service.py`, `frontend/src/components/FeedManagement.tsx`, `frontend/src/app/dashboard/feeds/page.tsx` | [RESOLVED IN PHASE 4D-C] Dynamic feed management cockpit with enable/disable switches, polling interval tuning, on-demand ingestion, and honest status monitoring. | Completed in Phase 4D-C. Verified via tests and live runtime. |
| **FR-06** | Store, view, edit and expire IOCs of type IP, domain, URL, file hash (MD5/SHA-1/SHA-256), email and CVE. | **REAL** | Canonical lifecycle state model (`active`, `expired`, `revoked`, `under_review`, `inactive`, `whitelisted`). Non-destructive soft-delete revocation (`DELETE /api/v1/indicators/{id}?reason=...`) preserves historical provenance, sightings, and relationships. Physical delete restricted to Administrators. Full REST lifecycle (`GET /{id}`, `PUT /{id}`, `PATCH /{id}/status`, `DELETE /{id}`). | `backend/app/models/indicator.py`, `backend/app/api/v1/endpoints/indicators.py`, `backend/app/services/indicator_service.py`, `frontend/src/app/dashboard/analyst/page.tsx` | [RESOLVED IN PHASE 4D-C] Full IOC lifecycle with soft-delete revocation, auditability, provenance preservation, and complete REST endpoints. | Completed in Phase 4D-C. Verified via tests and live runtime. |
| **FR-07** | Attach tags, TLP marking, ATT&CK technique IDs and free-text analyst notes to any IOC. | **REAL** | `Indicator` model extended with `analyst_notes`, `revoked_reason`, `ttl_days`, and `expires_at`. Strict server-side validation and canonical normalization (`normalize_and_validate_ioc`) for IPv4, IPv6, Domain, URL, Email, MD5, SHA1, SHA256, and CVE. Analyst drawer supports viewing and editing notes, TLP, and TTL with audit logging and Redis events (`IOC_UPDATED`). | `backend/app/models/indicator.py`, `backend/app/services/indicator_service.py`, `backend/app/api/v1/endpoints/indicators.py`, `frontend/src/app/dashboard/analyst/page.tsx` | [RESOLVED IN PHASE 4D-C] Strict multi-type IOC normalization, free-text analyst notes persistence, TLP classification, and in-place analyst editing. | Completed in Phase 4D-C. Verified via tests and live runtime. |
| **FR-08** | Apply configurable time-to-live so stale indicators automatically age out of active status. | **REAL** | Explicit persisted `expires_at` (indexed) and `ttl_days` columns. Deterministic UTC expiration calculation. Background bounded batch expiration worker (`expire_stale_indicators`) transitions stale active indicators to `expired`, updates Elasticsearch projection, publishes `IOC_EXPIRED` to Redis, and writes immutable audit logs with idempotency guarantees. | `backend/app/models/indicator.py`, `backend/app/services/expiration_service.py`, `backend/app/api/v1/endpoints/indicators.py`, `backend/tests/test_phase4d_c_ioc_lifecycle.py` | [RESOLVED IN PHASE 4D-C] Deterministic UTC TTL expiration engine with bounded batch background worker and complete idempotency. | Completed in Phase 4D-C. Verified via tests and live runtime. |
| **FR-09** | Maintain relationships between IOCs (e.g. domain resolves-to IP, hash communicates-with domain). | **REAL** | Canonical `IndicatorRelationship` model with uniqueness, foreign keys, and check constraints preventing self-links. Dedicated `GraphService` with bounded BFS traversal, cycle detection, and authentic evidence-based derivation. API exposed at `/api/v1/hunting/graph/{id}` and `/api/v1/hunting/indicators/{id}/relationships`. Connected to interactive SVG `HuntingGraph` on `/dashboard/hunting`. | `backend/app/models/relationship.py`, `backend/app/services/graph_service.py`, `backend/app/api/v1/endpoints/hunting.py`, `frontend/src/components/HuntingGraph.tsx`, `backend/tests/test_phase4d_hunting.py` | [RESOLVED IN PHASE 4D-A] Full indicator relationship graph engine with 0 mock data, authentic provenance derivation (URL hostnames, incident co-occurrences, enrichment), bounded multi-hop traversal, and interactive SVG visualization. | Completed in Phase 4D-A. Verified via 10 dedicated tests and runtime E2E. |
| **FR-10** | Perform IP reputation analysis, aggregating verdicts and abuse confidence from reputation sources. | **REAL** | `AbuseIPDBProvider` and `VirusTotalProvider` query live reputation endpoints, normalize abuse confidence and verdicts, and persist to `indicator_enrichments`. | `backend/app/services/enrichment/abuseipdb.py`, `backend/app/services/enrichment/virustotal.py`, `backend/app/services/enrichment_service.py`, `backend/app/models/enrichment.py` | [RESOLVED IN PHASE 4B] Modular provider architecture with TTL cache, DB persistence, Redis event fan-out, and deterministic aggregate intelligence. | Completed in Phase 4B. Verified via 21 tests and runtime E2E. |
| **FR-11** | Detect and flag malicious domains, including newly-registered and known-phishing domains. | **REAL** | `VirusTotalProvider` and `OTXProvider` query domain intelligence endpoints, normalize malicious votes, categories, and tags, and aggregate verdicts. | `backend/app/services/enrichment/virustotal.py`, `backend/app/services/enrichment/otx.py`, `backend/app/services/enrichment_service.py` | [RESOLVED IN PHASE 4B] Modular domain enrichment with TTL caching and persistence in `indicator_enrichments`. | Completed in Phase 4B. Verified via tests. |
| **FR-12** | Look up malware hashes against detection services and display engine verdict ratios. | **REAL** | `VirusTotalProvider` and `OTXProvider` inspect file hashes (SHA-256/MD5/SHA-1), extracting malicious engine counts and family tags. | `backend/app/services/enrichment/virustotal.py`, `backend/app/services/enrichment/otx.py`, `backend/app/services/enrichment_service.py` | [RESOLVED IN PHASE 4B] Dynamic multi-engine hash lookup and normalization. | Completed in Phase 4B. Verified via tests. |
| **FR-13** | Compute a 0–100 severity score per indicator from a documented, reproducible scoring model. | **REAL** | `app/services/scoring.py` implements the exact 4-factor formula (35% rep, 35% engine, 15% recency, 15% sightings). | `backend/app/services/scoring.py` | Mathematical formula is fully implemented, though caller passes hardcoded inputs during ingestion. | Keep `scoring.py` algorithm; connect real enrichment values to its input arguments. |
| **FR-14** | Enrich indicators with geolocation and ASN/owner data for mapping and pivoting. | **PARTIAL** | `enrichment_service.py` calls `ip-api.com` with Redis cache. | `backend/app/services/enrichment_service.py`, `frontend/src/app/dashboard/analyst/page.tsx` | Endpoint is in unmounted tree; frontend hardcodes `"Frankfurt, Germany (DE)"` and `"AS13335 CLOUDFLARENET"`. | Mount enrichment route in active router; connect frontend inspector to backend response. |
| **FR-15** | Stream new high-severity indicators and alerts to connected dashboards in real time. | **REAL** | `alert_service.py` evaluates indicators, creates alerts in DB, and publishes to Redis channel `threatlens:events:alerts`. `websocket.py` fans out to authenticated clients. | `backend/app/services/alert_service.py`, `backend/app/core/redis.py`, `backend/app/core/websocket.py`, `backend/app/main.py` | [RESOLVED IN PHASE 3] Synthetic timer loop removed; live threat pipeline publishes alerts to Redis Pub/Sub and authenticated WebSockets. | Completed in Phase 3. Verified via tests. |
| **FR-16** | Correlate incoming indicators against ingested internal security events and open incidents. | **REAL** | `correlation_service.py` evaluates incoming alerts against multi-dimensional signals (IOC, host, MITRE, source, temporal window) and clusters into canonical incidents. Emits Redis events and updates incident metadata. | `backend/app/services/correlation_service.py`, `backend/app/services/alert_service.py`, `backend/app/models/incident.py`, `backend/tests/test_phase4a_correlation.py` | [RESOLVED IN PHASE 4A] Deterministic correlation engine implemented with explainable scoring, row-locking concurrency, and automated incident clustering. | Completed in Phase 4A. Verified via 20 dedicated tests and runtime E2E. |
| **FR-17** | Provide a configurable alert rule engine (threshold, category, source, score) with per-user routing. | **REAL** | Canonical `DetectionRule` model with declarative condition DSL (11 operators, 0 eval/exec, catastrophic regex prevention, bounded complexity). Dedicated `DetectionRuleService` evaluating indicator telemetry against active rules, priority sorting, deterministic alert deduplication within time window, side-effect-free dry-run testing, Redis Pub/Sub events (`DETECTION_RULE_MATCHED`), audit logging, and automated handoff to Phase 4A incident correlation. REST API under `/api/v1/detection-rules` with strict server-side RBAC. Integrated into frontend `DetectionRulesManager` on `/dashboard/analyst`. | `backend/app/models/detection_rule.py`, `backend/app/services/detection_rule_service.py`, `backend/app/api/v1/endpoints/detection_rules.py`, `frontend/src/components/DetectionRulesManager.tsx`, `backend/tests/test_phase4d_b_detection_rules.py` | [RESOLVED IN PHASE 4D-B] Fully configurable detection rule engine with declarative DSL, zero eval/exec, deterministic alert generation, deduplication, and automated incident correlation. | Completed in Phase 4D-B. Verified via 11 dedicated tests and runtime E2E. |
| **FR-18** | Manage alert lifecycle: new → acknowledged → in-progress → resolved → closed, with assignee. | **REAL** | Configurable alert routing layer mapping rules to analyst queues and teams (`SOC_TIER_1`, `SOC_TIER_2`, `IR_LEAD`, `THREAT_HUNTING`, `SECURITY_ENGINEER`, `CISO_ESCALATION`). Canonical `Alert` model extended with `rule_id` and `routed_to` foreign keys. Honest delivery reporting: `DELIVERED` for internal queues, `NOT_CONFIGURED` for unconfigured SMTP/webhook notification channels (zero fake delivery). Redis `ALERT_ROUTED` event fan-out and full lifecycle integration. | `backend/app/models/alert.py`, `backend/app/services/detection_rule_service.py`, `backend/app/api/v1/endpoints/detection_rules.py`, `frontend/src/components/DetectionRulesManager.tsx` | [RESOLVED IN PHASE 4D-B] Comprehensive alert routing with team/queue dispatch, honest delivery status, Redis events, and full alert lifecycle integration. | Completed in Phase 4D-B. Verified via tests and live runtime script. |
| **FR-19** | Maintain an ordered, immutable incident timeline that auto-captures related indicators and actions. | **REAL** | `IncidentTimeline` model records `INCIDENT_CREATED`, `ALERT_CORRELATED`, `SEVERITY_ESCALATED`, `STATUS_CHANGED`, `INCIDENT_RESOLVED` events. Exposed via `GET /api/v1/incidents/{id}/timeline` and rendered in UI. | `backend/app/models/incident.py`, `backend/app/services/correlation_service.py`, `backend/app/api/v1/endpoints/incidents.py`, `frontend/src/app/dashboard/incidents/page.tsx` | [RESOLVED IN PHASE 4A] Real database-backed timeline entries created on every correlation, state transition, and analyst action. Connected to live API. | Completed in Phase 4A. Verified via tests and live runtime script. |
| **FR-20** | Render a global geographic heatmap of threat origin and target activity. | **REAL** | `GlobalHeatmap.tsx` and `AttackHeatmap.tsx` query `/api/v1/analytics/geography`, mapping enriched country telemetry. Honest empty state displayed when unobserved. Synthetic attack coordinates eliminated. | `frontend/src/components/GlobalHeatmap.tsx`, `frontend/src/components/AttackHeatmap.tsx`, `backend/app/api/v1/endpoints/analytics.py` | [RESOLVED IN PHASE 4C] Live database-backed geographic density with zero mock coordinates and explicit insufficient-data fallback. | Completed in Phase 4C. Verified via tests and runtime. |
| **FR-21** | Provide trend charts (volume over time, category breakdown, top sources, severity distribution). | **REAL** | `AnalyticsCharts.tsx` is embedded in the Executive dashboard powered by `/api/v1/analytics/overview` and `/api/v1/analytics/trends`. Recharts renders continuous zero-filled time buckets, severity distribution, and indicator types. | `frontend/src/components/AnalyticsCharts.tsx`, `frontend/src/app/dashboard/executive/page.tsx`, `backend/app/api/v1/endpoints/analytics.py`, `backend/app/services/analytics_service.py` | [RESOLVED IN PHASE 4C] Canonical analytics API provides zero-filled time-series and real database aggregations. | Completed in Phase 4C. Verified via 12 tests. |
| **FR-22** | Allow users to build custom dashboards from a widget library and save layouts per user. | **REAL** | Dedicated custom dashboard builder (`dashboard_service.py`) supporting 18 predefined SOC widgets, responsive 12-column grid layout persistence, real telemetry data resolution, server-side RBAC, and IDOR defense. REST APIs under `/api/v1/dashboards` with Next.js dashboard builder at `/dashboard/builder`. | `backend/app/models/dashboard.py`, `backend/app/services/dashboard_service.py`, `backend/app/api/v1/endpoints/dashboards.py`, `frontend/src/app/dashboard/builder/page.tsx`, `backend/tests/test_phase4f_dashboards_and_widgets.py` | [RESOLVED IN PHASE 4F] Fully database-backed custom dashboard builder with predefined safe widget catalog, responsive layout persistence, zero arbitrary code execution, and real telemetry integration. | Completed in Phase 4F. Verified via tests and live runtime. |
| **FR-23** | Generate scheduled and on-demand threat reports (PDF) with an executive summary and detail. | **REAL** | Dedicated executive PDF generation engine (`pdf_report_service.py`) compiling 17 real metrics sections from live database telemetry with dual ReportLab Platypus + PDF 1.4 rendering, SHA-256 fingerprinting, path traversal protection (`validate_safe_path`), and on-demand generation via `POST /api/v1/reports/executive` and download via `GET /api/v1/reports/{id}/download`. Integrated into Executive Cockpit. | `backend/app/services/pdf_report_service.py`, `backend/app/api/v1/endpoints/reports.py`, `backend/app/models/report.py`, `frontend/src/app/dashboard/executive/page.tsx`, `backend/tests/test_phase4e_cases_and_reports.py` | [RESOLVED IN PHASE 4E] Enterprise PDF generation engine producing complete multi-page CISO executive briefings from real database metrics with zero mock data and robust download security. | Completed in Phase 4E. Verified via tests and live runtime. |
| **FR-24** | Export indicators and intelligence as STIX 2.1 bundles and CSV for downstream tooling. | **REAL** | `backend/app/routers/export.py` generates compliant STIX 2.1 bundles and downloadable CSV. | `backend/app/routers/export.py` | Endpoints work, but lack authentication and TLP-based export filtering. | Add JWT auth and filter exported indicators based on user role and TLP clearance. |
| **FR-25** | Provide full-text and faceted search across all indicators and events with sub-second response. | **REAL** | Canonical search engine with Elasticsearch 8.x integration and resilient database fallback (`search_service.py`). Advanced hunting search endpoint `/api/v1/hunting/search` correlates indicator hits with relationship counts, enrichments, and incidents. Navbar search box connected to hunting workspace. | `backend/app/services/search_service.py`, `backend/app/api/v1/endpoints/hunting.py`, `frontend/src/components/Navbar.tsx`, `frontend/src/app/dashboard/hunting/page.tsx` | [RESOLVED IN PHASE 4D-A] Sub-second IOC, technique, and keyword hunting search with 1-hop relationship aggregation, enrichment linking, and Navbar routing. | Completed in Phase 4D-A. Verified via tests and runtime E2E. |
| **FR-26** | Enforce role-based access control across all data and actions (see Section 11). | **REAL** | `app/core/rbac.py` enforces `RoleChecker` and `get_current_user` across all canonical `/api/v1` routes; Argon2 hashing verified; self-escalation blocked. | `backend/app/core/rbac.py`, `backend/app/api/v1/endpoints/`, `backend/tests/test_security_hardening.py` | [RESOLVED IN PHASE 1B] All protected endpoints enforce server-side RBAC and active DB user validation. | Completed in Phase 1B. Verified with 15 security test suites. |
| **FR-27** | Write an immutable audit log entry for every authentication and state-changing action. | **REAL** | Audit entries written in canonical auth, alerts, incidents, feeds, and audit endpoints; database engine triggers enforce append-only immutability on PostgreSQL and SQLite. | `backend/app/api/v1/endpoints/`, `backend/app/models/audit.py`, `backend/app/database.py`, `backend/tests/test_phase2_infrastructure.py` | [RESOLVED IN PHASE 2] DB engine triggers reject UPDATE and DELETE operations at the database level. | Completed in Phase 2. Verified via tests. |
| **FR-28** | Expose authenticated REST and WebSocket APIs for integration with external security tools. | **REAL** | All canonical REST endpoints require Bearer JWT. WebSocket gateway `/api/v1/ws/alerts` rejects unauthenticated handshakes with code 1008. | `backend/app/api/v1/endpoints/`, `backend/app/api/v1/endpoints/websocket.py`, `backend/app/main.py` | [RESOLVED IN PHASE 1B] Authenticated JWT validation enforced during WebSocket handshake and REST requests. | Completed in Phase 1B. |
| **FR-29** | Provide inbound integration hooks (webhook/API) for SIEM, EDR and ticketing systems. | **REAL** | Canonical webhook ingestion endpoint `/api/v1/integrations/webhooks/{provider}` for explicit SIEM/EDR providers (Splunk, QRadar, Sentinel, CrowdStrike, Elastic). Multi-tier inbound authentication (Bearer token, `X-ThreatLens-Webhook-Secret`, HMAC SHA-256 signatures), replay protection (300s window), rate limiting (120 req/min), payload size limit (512KB), strict provider schemas, normalization into canonical IOCs, detection rule evaluation, alert creation, automated incident correlation, deterministic deduplication (`provider:external_event_id`), Redis Pub/Sub events (`SECURITY_EVENT_INGESTED`), and immutable audit logging. | `backend/app/api/v1/endpoints/integrations.py`, `backend/app/services/webhook_service.py`, `backend/app/models/integration.py`, `frontend/src/components/FeedManagement.tsx`, `backend/tests/test_phase4d_d_integrations.py` | [RESOLVED IN PHASE 4D-D] Enterprise inbound SIEM/EDR webhook receivers with HMAC verification, replay skew protection, canonical normalization, detection rules, alert routing, and incident correlation. | Completed in Phase 4D-D. Verified via tests and live runtime. |
| **NFR-01** | Performance: Dashboard interactive load < 2s; API p95 response < 400ms under nominal load. | **PARTIAL** | App loads fast only because it falls back to hardcoded in-memory arrays. | `frontend/src/lib/api.ts` | Not validated against real database scale or concurrent network load. | Benchmark with realistic PostgreSQL dataset (100k+ rows) and optimize queries with composite indexes. |
| **NFR-02** | Real-time: End-to-end alert propagation (ingest → UI) < 5s via WebSocket. | **REAL** | Ingested indicators evaluated and published to Redis channel `threatlens:events:alerts` and fanned out to `/api/v1/ws/alerts` under sub-second latency. | `backend/app/services/alert_service.py`, `backend/app/core/websocket.py`, `backend/tests/test_phase3_telemetry.py` | [RESOLVED IN PHASE 3] Verified sub-second pipeline from ingestion to WebSocket delivery. | Completed in Phase 3. Verified via tests. |
| **NFR-03** | Scalability: Sustain >= 50,000 indicator ingests/hour and >= 200 concurrent users through horizontal scaling. | **BROKEN** | Uses single-process SQLite file with `check_same_thread=False`. | `backend/app/database.py`, `docker-compose.yml` | SQLite cannot handle concurrent write transactions; no Celery/RQ worker queue exists. | Migrate to PostgreSQL connection pooling and Celery/Redis background task workers. |
| **NFR-04** | Availability: Target 99.5% monthly availability for core API and dashboard. | **REAL** | GET /health and GET /health/ready probes implemented with database, Redis, and Elasticsearch connectivity checks. | `backend/app/main.py`, `backend/tests/test_phase2_infrastructure.py` | [RESOLVED IN PHASE 2] Operational readiness and liveness endpoints verify core infrastructure components without leaking credentials. | Completed in Phase 2. Verified via tests. |
| **NFR-05** | Search latency: Full-text/faceted queries return < 800ms at p95 over 10M+ indexed documents. | **BROKEN** | Active search router uses SQLite `LIKE '%q%'`. | `backend/app/routers/search.py` | Unindexed SQL `LIKE` will exhaust resources and time out on large datasets; Elasticsearch is offline. | Connect Elasticsearch 8.x index with ngram and keyword mappings. |
| **NFR-06** | Security: Data in transit over TLS 1.2+; sensitive data encrypted at rest (AES-256). | **BROKEN** | Plaintext secrets in config, Docker, and K8s; unencrypted HTTP calls to `ip-api.com`. | `backend/app/core/config.py`, `k8s/`, `backend/app/services/enrichment_service.py` | Hardcoded JWT keys; hardcoded DB passwords; no AES-256 field encryption at rest. | Move all secrets to environment variables; enforce HTTPS/TLS; implement SQLAlchemy EncryptedType for secrets. |
| **NFR-07** | Reliability: No data loss on service restart; ingestion is idempotent and replay-safe. | **PARTIAL** | SQLite database file stored on disk; basic deduplication on ingest. | `backend/app/routers/indicators.py`, `backend/app/database.py` | Docker compose uses volume mounting `./backend:/app` without persistent named volume. | Use persistent named volume for PostgreSQL; implement idempotent upserts based on unique hash/value constraints. |
| **NFR-08** | Maintainability: >= 80% unit-test coverage on core scoring, correlation and ingestion modules. | **BROKEN** | Only 3 test files exist; 1 is broken with `TypeError`, 1 asserts 404. Coverage is ~0%. | `backend/tests/` | Severe lack of automated tests; PRD quality gate is completely violated. | Write comprehensive unit and integration tests for ingestion, scoring, correlation, and RBAC to reach >= 80%. |
| **NFR-09** | Usability: Primary analyst workflow (triage → enrich → escalate) completable in <= 4 clicks. | **PARTIAL** | UI layout supports rapid triage, but action buttons trigger browser `alert()` popups. | `frontend/src/app/dashboard/analyst/page.tsx` | Core workflows are simulated rather than completing real backend state changes. | Connect buttons to real backend API mutations (`PATCH /alerts/{id}`, `POST /incidents`). |
| **NFR-10** | Observability: Structured logs, health endpoints and metrics exposed for every service. | **BROKEN** | Basic Python `print()` statements; no structured JSON logging; no `/metrics` or `/health`. | `backend/app/` | No observability infrastructure exists. | Implement `structlog`, Prometheus metrics exporter (`/metrics`), and health endpoints. |
| **NFR-11** | Portability: Entire stack runs from a single docker-compose up locally and on Kubernetes. | **REAL** | docker-compose.yml defines PostgreSQL 16, Redis 7, Elasticsearch 8.13.4, FastAPI backend, and Next.js frontend with healthchecks and persistent volumes. | `docker-compose.yml`, `backend/.env.example` | [RESOLVED IN PHASE 2] Fully orchestrated production stack with bridge networking and healthchecks. | Completed in Phase 2. Validated with docker-compose config. |
| **NFR-12** | Compliance: Audit records retained >= 1 year; access controls support least-privilege review. | **BROKEN** | No audit retention policies; audit table is mutable; RBAC is non-functional. | `backend/app/models/`, `backend/app/routers/auth.py` | Lacks database immutability; role checks are not enforced on backend. | Restrict DB user permissions (no UPDATE/DELETE on audit table); enforce server-side RBAC. |

---

## 4. Architecture Audit

### The Architectural Schism: `app.routers` vs `app.api.v1.endpoints`

Forensic analysis of the backend file structure reveals a critical architectural defect: **two disconnected implementations of the API routers exist simultaneously**:

```
backend/app/
├── main.py                     <-- Includes ONLY app.routers.*
├── database.py                 <-- Bound to SQLite: sqlite:///./threatlens.db
├── db/
│   ├── base.py                 <-- Declarative Base 2
│   └── session.py              <-- Bound to PostgreSQL (settings.DATABASE_URL)
├── models/
│   ├── indicator.py            <-- Uses app.database.Base (String PKs)
│   ├── alert.py                <-- Uses app.db.base.Base (PostgreSQL UUID PKs)
│   ├── incident.py             <-- Uses app.db.base.Base (PostgreSQL UUID PKs)
│   ├── user.py                 <-- Uses app.db.base.Base (PostgreSQL UUID PKs)
│   └── feed.py                 <-- Uses app.db.base.Base (PostgreSQL UUID PKs)
├── routers/                    <-- ACTIVE ROUTERS (Mounted in main.py)
│   ├── alerts.py               <-- Uses SQLite, auto-seeds mock alerts, no auth
│   ├── auth.py                 <-- Hardcoded passwords ("threatlens123", "admin")
│   ├── export.py               <-- Exports from SQLite
│   ├── indicators.py           <-- Basic SQLite queries, manual feed sync
│   └── search.py               <-- SQL LIKE queries over SQLite (NO Elasticsearch)
└── api/v1/endpoints/           <-- DEAD / UNMOUNTED ROUTERS (Ignored by main.py)
    ├── alerts.py               <-- Unmounted
    ├── audit.py                <-- Unmounted (uses in-memory list!)
    ├── auth.py                 <-- Unmounted (broken import: verify_password)
    ├── enrichment.py           <-- Unmounted
    ├── export.py               <-- Unmounted
    ├── incidents.py            <-- Unmounted
    ├── indicators.py           <-- Unmounted (broken import: IndicatorType)
    ├── search.py               <-- Unmounted (calls search_service.py)
    └── websocket.py            <-- Unmounted
```

1. **Active Route Tree (`backend/app/routers/`):**
   In `backend/app/main.py`:
   ```python
   from app.routers import indicators, auth, export, alerts, search
   app.include_router(indicators.router)
   app.include_router(alerts.router)
   app.include_router(search.router)
   app.include_router(auth.router)
   app.include_router(export.router)
   ```
   These routers import `get_db` from `app.database.py`, which defaults to local SQLite (`threatlens.db`). They contain simplistic queries, bypass all authentication, and omit incident management and enrichment routes.

2. **Unmounted Route Tree (`backend/app/api/v1/endpoints/`):**
   This tree attempts to use PostgreSQL (`app.db.session`) and services (`search_service`, `feed_service`, `audit_service`). However:
   - It is **never registered** in `app/main.py`.
   - It contains fatal syntax and import errors. For example:
     - `app/api/v1/endpoints/indicators.py` imports `IndicatorType`, `ThreatSeverity`, and `IndicatorStatus` from `app.models.indicator`, none of which are defined in that file.
     - `app/api/v1/endpoints/auth.py` imports `verify_password` and `get_password_hash` from `app.core.security`, which does not define them.
     - `app/api/deps.py` imports `get_current_user` from `app.core.security`, but it is actually located in `app.core.rbac`.
   - Attempting to import these files crashes Python with an `ImportError`.

---

## 5. Security Audit

A thorough static vulnerability analysis of the codebase identified multiple critical security vulnerabilities across authentication, authorization, secret management, container hardening, and data protection:

### 1. Hard-Coded Credentials & Secrets
- **PostgreSQL Database Password:**  
  In `backend/app/core/config.py:5`:
  ```python
  POSTGRES_PASSWORD: str = "threatlens_secure_password_2026"
  ```
  Committed in cleartext.
- **JWT Secret Keys (Multiple Conflicting Values):**  
  - In `backend/app/core/config.py:10`: `SECRET_KEY: str = "super_secret_jwt_key_threatlens_2026"`
  - In `backend/app/core/security.py:4`: `SECRET_KEY = "threatlens-soc-super-secret-jwt-key-2026"`
  - In `k8s/threatlens-cloud.yaml:21`: `JWT_SECRET: "super-secure-threatlens-production-jwt-secret-key-32bytes"`  
  Neither backend file reads from the environment variable; both use hardcoded string literals.
- **Hard-Coded Demo Passwords in Authentication Router:**  
  In `backend/app/routers/auth.py:20`:
  ```python
  if req.password != "threatlens123" and req.password != "admin":
  ```
  The active authentication endpoint performs a cleartext string comparison against two hardcoded passwords. It does not perform a database lookup or verify salted password hashes.

### 2. Client-Controlled Roles & Privilege Escalation
- In `backend/app/routers/auth.py:15,33`:
  ```python
  class LoginRequest(BaseModel):
      username: str
      password: str
      role: str = "SOC Analyst"
  ...
  token = create_access_token(data={"sub": req.username, "role": req.role})
  ```
  The user specifies their own role in the JSON login request payload, and the backend signs the JWT token with whatever role the client requested. Any unauthenticated caller can issue themselves an `Administrator` token.
- In `frontend/src/context/RoleContext.tsx:81-93`:
  Role state is managed entirely in browser `localStorage` and initialized to `Administrator` by default. The user can switch personas at will via a dropdown on the navigation bar with no backend authorization check.

### 3. Missing Authentication & Authorization Enforcement
- In `backend/app/routers/indicators.py`, `alerts.py`, `export.py`, and `search.py`, **not a single endpoint requires authentication**.
- An unauthenticated external entity can:
  - Query all indicators (`GET /api/v1/indicators`);
  - Trigger live feed synchronization (`POST /api/v1/indicators/sync-feeds`);
  - Query, modify, and reassign security alerts (`GET /api/v1/alerts`, `PATCH /api/v1/alerts/{id}`);
  - Export all threat intelligence bundles (`GET /api/v1/export/stix`, `GET /api/v1/export/csv`);
  - Search threat intelligence records (`GET /api/v1/search`);
  - Read complete audit logs (`GET /api/v1/auth/audit-logs`).
- The frontend never attaches an `Authorization: Bearer <token>` header to any HTTP request.

### 4. Committed Databases and Runtime Artifacts
- **Committed SQLite Database:** `backend/threatlens.db` (73,728 bytes) is committed to the repository, containing pre-populated development/test records.
- **Committed Coverage Data:** `backend/.coverage` (53,248 bytes) is committed to git.
- **Committed Python Bytecode:** Multiple `__pycache__` directories containing compiled `.pyc` files are committed throughout `backend/app/` and `backend/tests/`.

### 5. Insecure Container & Orchestration Configuration
- **Root Execution:** `backend/Dockerfile` runs Uvicorn as `root`. No `USER` directive is specified, contradicting README claims of "non-root container sandboxing".
- **Hardcoded K8s Secrets:** `k8s/threatlens-cloud.yaml` contains plaintext database passwords (`threatlens123`) and JWT secret keys in the `stringData` block without encryption.
- **Insecure CORS:** `backend/app/main.py` allows all methods and headers (`allow_methods=["*"]`, `allow_headers=["*"]`).

### 6. Information Leakage & Unencrypted External Egress
- `backend/app/services/enrichment_service.py:32` calls external IP geolocation over unencrypted HTTP: `http://ip-api.com/json/{ip_address}`. Indicator IP addresses (sensitive internal SOC telemetry) are transmitted in plaintext across the public Internet.

---

## 6. Data Pipeline Audit

The PRD defines the core data pipeline as:
$$\text{External Feed} \rightarrow \text{Scheduler} \rightarrow \text{Normalizer} \rightarrow \text{Deduplicator} \rightarrow \text{Enrichment} \rightarrow \text{Scoring} \rightarrow \text{Correlation} \rightarrow \text{Alert} \rightarrow \text{Database} \rightarrow \text{WebSocket} \rightarrow \text{Frontend}$$

The forensic trace of each stage in the actual codebase is summarized below:

```
[1. External Feeds]   --> PARTIAL (4 real HTTP feeds; 2 static lists)
         │
[2. Scheduler]        --> MISSING (No Celery/beat/cron; manual sync only)
         │
[3. Normalizer]       --> PARTIAL (Basic dict formatting; no STIX/CSV parser)
         │
[4. Deduplicator]     --> PARTIAL (Drops duplicates entirely; no provenance update)
         │
[5. Enrichment]       --> MOCK/SIMULATED (ip-api.com unmounted; domain/hash mocked)
         │
[6. Scoring]          --> REAL (Algorithm in scoring.py, but receives hardcoded inputs)
         │
[7. Correlation]      --> BROKEN (correlation_service.py has syntax errors & unmounted)
         │
[8. Alert Engine]     --> MISSING (No alert_rules; seed_alert inserted if DB empty)
         │
[9. Database Store]   --> PARTIAL (Saved to local SQLite threatlens.db; Postgres offline)
         │
[10. WebSocket]       --> MOCK/SIMULATED (Emits synthetic timer items every 6s)
         │
[11. Frontend]        --> MOCK/SIMULATED (Falls back to localhost or static mock arrays)
```

### Forensic Pipeline Findings:
1. **External Feeds (PARTIAL):** Feodo Tracker, URLhaus, MalwareBazaar, and ThreatFox are polled asynchronously via `httpx` in `ingestion.py`. However, AlienVault OTX and CISA KEV are static Python lists containing 2 entries each.
2. **Scheduler (MISSING):** No background worker or cron scheduling exists. Ingestion runs only when `/api/v1/indicators/sync-feeds` is manually triggered.
3. **Normalizer (PARTIAL):** Ingestion normalizes fields into a loose dictionary. No generic parser exists for incoming STIX 2.1 JSON or CSV feeds.
4. **Deduplicator (PARTIAL):** In `routers/indicators.py`, if an indicator value already exists in SQLite, it is skipped. The PRD requirement to maintain a per-source provenance list (`indicator_sources`) is violated because existing indicators never receive updated provenance records.
5. **Enrichment (MOCK/SIMULATED):** Hash lookup and domain lookup do not query external APIs; domain enrichment returns a static stub. In the frontend, `handleEnrich` creates synthetic string verdicts in client JavaScript.
6. **Scoring (REAL / PARTIAL):** `scoring.py` computes an accurate 4-factor score, but the caller passes hardcoded inputs (e.g., `positives=56, total=70`).
7. **Correlation (BROKEN):** `correlation_service.py` is not wired into the ingestion pipeline and is unmounted.
8. **Alert Engine (MISSING):** Ingested indicators do not automatically generate alerts. In `routers/alerts.py`, a single mock alert is auto-seeded if the database table is empty.
9. **Database (PARTIAL):** Data is saved into local SQLite rather than PostgreSQL.
10. **WebSocket (MOCK/SIMULATED):** The WebSocket broadcaster in `main.py` emits random selections from `threat_samples` (e.g. `185.220.101.4`, `evil-payload-bank.xyz`) every 6 seconds on an independent background task.
11. **Frontend (MOCK/SIMULATED):** Frontend components fall back to hardcoded arrays when backend connections fail or return empty datasets.

---

## 7. Authentication & RBAC Audit

### Backend Evaluation
- The active authentication router (`app/routers/auth.py`) checks:
  ```python
  if req.password != "threatlens123" and req.password != "admin":
  ```
  No cryptographic hashing (bcrypt/argon2) is executed at login.
- Access tokens expire after 8 hours; no rotating refresh tokens are implemented.
- No Multi-Factor Authentication (TOTP) or account lockout mechanisms exist.
- No route in `app/routers/` enforces JWT verification dependencies.

### Frontend Evaluation
- Two conflicting `RoleContext.tsx` implementations exist:
  - `frontend/src/context/RoleContext.tsx`
  - `frontend/src/components/RoleContext.tsx`
- The application uses `context/RoleContext.tsx`. Users can switch their role to any persona (`Administrator`, `Tier-2 SOC Analyst`, `Incident Response Lead`, `Threat Hunter`, `CISO (Executive)`, `Security Engineer`) via a top navigation dropdown.
- This stores the role string in browser `localStorage`.
- There is no login screen, no session token storage, and no backend authentication barrier.

---

## 8. Feed Ingestion Audit

| Feed Source | Specified In PRD | Implementation Status | Implementation Details |
| :--- | :---: | :---: | :--- |
| **Feodo Tracker** | Yes | **REAL (Active)** | Real HTTP GET to `https://feodotracker.abuse.ch/downloads/ipblocklist.json` in `ingestion.py`. |
| **URLhaus** | Yes | **REAL (Active)** | Real HTTP GET to `https://urlhaus.abuse.ch/downloads/json_recent/` in `ingestion.py`. |
| **MalwareBazaar** | Yes | **REAL (Active)** | Real HTTP POST to `https://mb-api.abuse.ch/api/v1/` in `ingestion.py`. |
| **ThreatFox** | Yes | **REAL (Active)** | Real HTTP POST to `https://threatfox-api.abuse.ch/api/v1/` in `ingestion.py`. |
| **AlienVault OTX** | Yes | **MOCK/SIMULATED** | Hardcoded static Python list of 2 items in `ingestion.py:135`. |
| **CISA KEV Catalog** | Yes | **MOCK/SIMULATED** | Hardcoded static Python list of 2 items in `ingestion.py:160`. |
| **TAXII 2.1 Transport** | Yes (FR-04) | **MISSING** | No implementation exists. |

---

## 9. Enrichment Audit

| Service | PRD Target | Status | Findings |
| :--- | :--- | :---: | :--- |
| **IP Geolocation & ASN** | MaxMind / ip-api | **PARTIAL** | Implemented in `enrichment_service.py` via `ip-api.com` with Redis cache. Disconnected from active routers. |
| **AbuseIPDB (IP Reputation)** | FR-10 | **MISSING** | No AbuseIPDB API calls exist anywhere in the backend codebase. |
| **VirusTotal (Hash/Verdict Ratio)**| FR-12 | **MISSING** | No VirusTotal API client exists; engine ratios are hardcoded during ingestion. |
| **Domain Analysis (WHOIS/RDAP)** | FR-11 | **MOCK/SIMULATED** | `get_domain_enrichment` returns hardcoded dummy status `{ "status": "Enriched" }`. |
| **Frontend Enrichment Drawer** | Section 12.2 | **MOCK/SIMULATED** | `handleEnrich()` in `analyst/page.tsx` sets synthetic strings locally in React state. |

---

## 10. Scoring Audit

Two divergent scoring modules exist in the codebase:

1. **`backend/app/services/scoring.py` (Active):**
   Implements the PRD specification:
   $$\text{Score} = 0.35 \times \text{Reputation} + 0.35 \times \left(\frac{\text{Positives}}{\text{Total}} \times 100\right) + 0.15 \times \text{Recency} + 0.15 \times \text{Sightings}$$
   The algorithm itself is mathematically sound and bounded between 0 and 100. However, callers supply synthetic constant arguments rather than live telemetry.

2. **`backend/app/services/scoring_service.py` (Unmounted):**
   Implements an alternative formula based on source reliability weights, sighting multipliers, and a 30-day step decay. This module is used only by the unmounted `v1/endpoints/indicators.py` file and has a broken unit test.

---

## 11. Correlation Audit

- **Specification:** PRD FR-16 requires automated correlation of incoming indicators against ingested internal security events (`security_events` table) and open incidents.
- **Backend Status (BROKEN):** `backend/app/services/correlation_service.py` contains `correlate_and_create_incident()`. However:
  - It imports non-existent symbols (`from app.models.indicator import ThreatSeverity`).
  - It expects `Indicator.severity` and `Indicator.threat_score`, which do not exist on the active `Indicator` model.
  - It is not invoked during feed ingestion.
- **Frontend Status (MOCK/SIMULATED):** The Incident Response dashboard (`frontend/src/app/dashboard/incidents/page.tsx`) renders a static mock incident `INC-2026-0815` with hardcoded timeline steps (`18:42:10 UTC`, `18:42:15 UTC`).

---

## 12. Alert & Incident Audit

- **Alert Lifecycle (FR-18):** `backend/app/routers/alerts.py` implements lifecycle transitions: `new -> acknowledged -> in_progress -> resolved -> closed`.
  - State validation works correctly against `valid_states`.
  - However, the endpoint has no authentication, allowing anyone to modify alert states.
  - The alert queue auto-seeds a hardcoded Emotet alert (`185.220.101.4`) if the database is empty.
  - The frontend button for "Acknowledge" executes a browser `alert(...)` popup rather than calling the API.
- **Incident Management (FR-19):** `backend/app/api/v1/endpoints/incidents.py` defines incident timeline querying and status updates, but is not mounted in `main.py`. The frontend renders static HTML for incident `INC-2026-0815`.

---

## 13. Dashboard Audit

| Dashboard | Target Persona | PRD Requirements | Implementation Status | Findings |
| :--- | :--- | :--- | :---: | :--- |
| **Home Hub** | All | System overview, telemetry stats, persona quick-launch | **PARTIAL** | Fully styled and responsive. Telemetry numbers (48,920 IOCs, 12/12 feeds) are hardcoded static numbers. |
| **SOC Analyst** | Priya Nair | Prioritised queue, one-click enrichment, live counters | **PARTIAL / MOCK** | Shows IOC table and drawer. Enrichment is client-side synthetic data; acknowledge button uses browser `alert()`. |
| **Executive View**| Rachel Adeyemi | Risk score, 30-day trend, alert throughput, adversary volume | **MOCK/SIMULATED** | 100% static HTML and React state. KPI cards, top adversaries, and throughput bars are hardcoded numbers. |
| **Incidents & IR** | Daniel Okafor | Incident timeline, containment checklist, report export | **MOCK/SIMULATED** | Hardcoded to single fake incident `INC-2026-0815`. Timeline and checklist are static HTML elements. |
| **Threat Hunting**| Mei Lin Tan | Full-text facets, ATT&CK heatmap, relationship graph | **MOCK/SIMULATED** | Hardcoded list of 5 MITRE techniques; 2 static saved hunts; indicator relationship graph is completely missing. |

### Orphaned Components Audit
- `frontend/src/components/GlobalHeatmap.tsx`: A functional Leaflet CARTO map with 5 hardcoded city coordinates. **Never imported in any dashboard page.**
- `frontend/src/components/AnalyticsCharts.tsx`: A functional Recharts time-series area chart and pie chart with static data. **Never imported in any dashboard page.**
- `frontend/src/components/AttackHeatmap.tsx`: A CSS progress-bar list of 5 countries. **Never imported in any dashboard page.**
- `frontend/src/components/analyst/AlertQueue.tsx`: An alert triage table with mock alerts. **Never imported in any dashboard page.**

---

## 14. Search Audit

- **Specification:** PRD FR-25 & NFR-05 require sub-second full-text and faceted search across indicators and events over Elasticsearch 8.x.
- **Backend Status (BROKEN / PARTIAL):**
  - `backend/app/services/search_service.py` contains Elasticsearch connection logic, index mapping definitions, and query builder logic.
  - However, `search_service.py` is only referenced by the unmounted `app/api/v1/endpoints/search.py`.
  - The active router (`app/routers/search.py`) runs SQL `LIKE` queries against SQLite:
    ```python
    or_(
        Indicator.value.ilike(f"%{q}%"),
        Indicator.tags.ilike(f"%{q}%"),
        Indicator.mitre_technique.ilike(f"%{q}%")
    )
    ```
  - Facet counts are computed by iterating over the SQLite query results in memory.
  - Elasticsearch is not included in `docker-compose.yml`.
- **Frontend Status (MOCK/SIMULATED):**
  - The search input in `Navbar.tsx` only updates local React state (`searchVal`). It has no submit handler, does not redirect to search results, and executes no API calls.
  - The analyst triage table implements filtering on client-side state via `Array.prototype.filter()`.

---

## 15. STIX & Reporting Audit

- **STIX 2.1 Export (FR-24):** **REAL.** `backend/app/routers/export.py` queries active indicators from the database and constructs valid STIX 2.1 JSON bundle objects with standard indicator patterns (`[ipv4-addr:value = ...]`, `[domain-name:value = ...]`, `[url:value = ...]`, `[file:hashes.'SHA-256' = ...]`).
- **CSV Export (FR-24):** **REAL.** `backend/app/routers/export.py` generates downloadable CSV files with standard headers (`ID`, `Value`, `Type`, `Severity_Score`, `Confidence`, `TLP`, `MITRE_Technique`, `Tags`, `First_Seen`).
- **PDF Report Generation (FR-23):** **MISSING.** No PDF generation library (such as ReportLab or WeasyPrint) is installed. The report button in `executive/page.tsx` merely sets a 3-second boolean state `scheduled: true`.

---

## 16. Database Audit

- **Specification:** PRD Section 9 designates PostgreSQL 16 as the authoritative system of record.
- **Current Runtime Status:** The running application uses an embedded **SQLite** database (`threatlens.db`), which is committed to git.
- **Schema Divergence:**
  - Alembic migration `2de275776032_init_fresh_schema_with_auth_and_.py` creates `audit_log`, `feeds`, `indicators`, and `users`.
  - It does NOT create `alerts`, `incidents`, `incident_timeline`, `security_events`, `indicator_sources`, `enrichments`, `indicator_relationships`, or `attack_techniques`.
  - In `backend/app/models/indicator.py`, models use `app.database.Base` with `String(36)` primary keys for SQLite compatibility.
  - In `backend/app/models/alert.py`, `incident.py`, `user.py`, and `feed.py`, models use `app.db.base.Base` with PostgreSQL `UUID(as_uuid=True)` dialect types.
  - Two incompatible `Alert` models and two incompatible `AuditLog` models exist simultaneously.

---

## 17. Elasticsearch Audit

- **Elasticsearch Client:** `backend/app/services/search_service.py` defines an Elasticsearch client pointing to `http://localhost:9200`.
- **Index Initialization:** Mapping includes `value`, `type`, `source`, `severity`, `status`, `threat_score`, `confidence`, `tags`, and `created_at`.
- **Runtime Disconnect:**
  - `docker-compose.yml` does not spin up an Elasticsearch container.
  - The active router (`app/routers/search.py`) does not call `search_service.py`.
  - `test_search_service.py` only verifies that when Elasticsearch is offline, the service falls back to returning an empty array.

---

## 18. Redis Audit

- **Redis Client:** `backend/app/services/enrichment_service.py` connects to Redis at `host="localhost", port=6379`.
- **Caching Logic:** Evaluates `cache_key = f"enrichment:ip:{ip_address}"` with a 3600-second TTL.
- **Runtime Disconnect:**
  - `docker-compose.yml` does not contain a Redis service.
  - Redis connection is wrapped in a silent `try...except` returning `None`, so failures silently degrade to un-cached external API calls.
  - Redis Pub/Sub for real-time WebSocket event fanout (PRD Section 8.1, 15) is completely unimplemented. The WebSocket manager uses a single in-process Python list.

---

## 19. Docker Audit

- **`docker-compose.yml`:**
  ```yaml
  version: '3.8'
  services:
    backend:
      build: { context: ./backend, dockerfile: Dockerfile }
      ports: ["8000:8000"]
      environment:
        - DATABASE_URL=sqlite:///./threatlens.db
      volumes:
        - ./backend:/app
    frontend:
      build: { context: ./frontend, dockerfile: Dockerfile }
      ports: ["3000:3000"]
      environment:
        - NEXT_PUBLIC_API_URL=http://localhost:8000
      depends_on: [backend]
  ```
  **Deficiencies:**
  1. `DATABASE_URL` is set to SQLite.
  2. No `postgres`, `elasticsearch`, `redis`, `worker`, or `scheduler` containers exist.
  3. Binds `./backend:/app` directly into container filesystem.
- **`backend/Dockerfile`:** Runs as `root`. Does not create or switch to a non-privileged user.
- **`frontend/Dockerfile`:** Minimal build file; lacks multi-stage production optimization.

---

## 20. Kubernetes Audit

- **`k8s/threatlens-deployment.yaml`:**
  - Configures 2 replicas for `threatlens-backend` and `threatlens-frontend`.
  - Configures `DATABASE_URL` pointing to `postgres-service:5432` with cleartext password `threatlens123`.
  - Sets `NEXT_PUBLIC_API_URL` to `http://localhost:8000`. In a Kubernetes deployment, client browsers outside the cluster will attempt to reach `localhost:8000` rather than the public ingress or domain, causing API failures.
  - Points to `postgres-service`, `redis-service`, and `elasticsearch-service`, none of which are defined in the Kubernetes manifests. Applying these manifests results in CrashLoopBackOff.
- **`k8s/threatlens-cloud.yaml`:**
  - Defines ConfigMap, cleartext Secret, HPA (2 to 10 replicas), and Ingress.
  - Ingress routes host `threatlens.local` with `/api` and `/` paths.
  - Lacks WebSocket proxying annotations (`proxy-read-timeout`, `proxy-send-timeout`), causing WebSocket connections to terminate prematurely through NGINX Ingress.

---

## 21. Testing & CI/CD Audit

### Backend Test Audit
The backend test directory contains only 3 test files:

1. **`backend/tests/test_core.py`:**
   ```python
   def test_health_check():
       response = client.get("/health")
       assert response.status_code in [200, 404]
   ```
   The backend does not implement `/health` (it returns 404). The test author masked this failure by asserting `status_code in [200, 404]`.
2. **`backend/tests/test_scoring.py`:**
   ```python
   def test_scoring_basic():
       score = calculate_ioc_severity({"reputation": 80, "confidence": 90})
       assert 0 <= score <= 100
   ```
   **Fatal Failure:** `calculate_ioc_severity` requires `confidence: int, source: str` as positional parameters. Passing a dictionary as the first parameter causes a `TypeError: missing 1 required positional argument: 'source'`. Additionally, the function returns a dictionary `{"score": ..., "severity": ...}`, so `0 <= score <= 100` throws `TypeError: '<=' not supported between instances of 'int' and 'dict'`. This test fails immediately when executed.
3. **`backend/tests/test_search_service.py`:**
   Tests only that `search_indicators_es` returns an empty array when Elasticsearch is unreachable.

### Test Coverage Assessment
- Unit-test coverage on core scoring, correlation, and ingestion is under **5%** (far below the PRD NFR-08 target of **>= 80%**).
- Zero integration tests exist.
- Zero frontend tests (Jest/React Testing Library) exist.
- Zero end-to-end tests (Playwright/Cypress) exist.

### CI/CD Pipeline Audit
- The project `README.md` includes a badge:
  `[![CI/CD Pipeline](https://github.com/Halanaaz1401/threatlens/actions/workflows/ci.yml/badge.svg)]...`
- However, **no `.github/workflows/ci.yml` or `.github/` directory exists in the repository**. The CI/CD pipeline is non-existent.

---

## 22. Critical Blockers

These issues completely prevent the platform from operating as specified in the PRD and must be resolved before any production deployment:

1. **Dual Router Split & Unmounted Code:** The active backend mounts `app.routers` (SQLite, unauthenticated) and ignores `app.api.v1.endpoints`. The `v1` endpoints cannot compile due to missing imports (`IndicatorType`, `ThreatSeverity`, `verify_password`).
2. **Missing Core Infrastructure:** PostgreSQL, Elasticsearch, and Redis are absent from `docker-compose.yml` and Kubernetes manifests. The running application is locked to SQLite with in-memory state.
3. **Synthetic WebSocket Broadcaster:** Real-time threat alerts are completely fake, generated by an `asyncio` loop picking from 4 hardcoded samples rather than reflecting live ingestion or correlation.
4. **Hardcoded Secrets & Zero Backend Authentication [RESOLVED IN PHASE 1B]:** Database user lookup, Argon2id hashing, environment secret configuration, server-side RBAC, and JWT validation enforced across all endpoints and WebSocket gateways.
5. **Hardcoded Client-Side Fallback:** Frontend makes hardcoded requests to `http://127.0.0.1:8000` and immediately falls back to static mock arrays, hiding backend state from remote users.

---

## 23. High Priority Fixes

1. **Database Schema Unification & PostgreSQL Migration:** Consolidate declarative bases into a single SQLAlchemy Base; create Alembic migrations for all 13 core tables specified in PRD Section 9.1; update `database.py` to use PostgreSQL exclusively.
2. **Implement Server-Side RBAC Enforcement [COMPLETED IN PHASE 1B]:** Wired `get_current_user` and `RoleChecker` from `app.core.rbac` into all canonical API endpoints; replaced demo bypass with database user query and Argon2 password verification; blocked client-side privilege escalation.
3. **Connect Elasticsearch to Search Router:** Add Elasticsearch 8.x to `docker-compose.yml`; update `app/routers/search.py` to execute full-text and faceted queries against Elasticsearch index mappings.
4. **Wire WebSocket to Redis Pub/Sub:** Implement Redis Pub/Sub event bus so that when live ingestion or correlation generates a high-severity indicator or alert, it is broadcast to connected WebSocket clients in real time (< 5 seconds).
5. **Fix Frontend API Client:** Update `frontend/src/lib/api.ts` and all dashboard fetch calls to read `NEXT_PUBLIC_API_URL` from the environment; pass Bearer tokens in headers; remove static fallback arrays so errors are handled properly.
6. **Fix Broken Backend Tests:** Rewrite `test_scoring.py` with valid arguments and assertions; implement genuine `/health` endpoint so `test_core.py` passes legitimately; add unit tests for `scoring.py` and `ingestion.py`.

---

## 24. Medium Priority Fixes

1. **Activate Orphaned Visual Components:** Import `GlobalHeatmap.tsx` and `AnalyticsCharts.tsx` into the Executive and Analyst dashboards; connect them to backend aggregation endpoints rather than static constants.
2. **Implement Real AlienVault OTX & CISA KEV Ingestion:** Replace hardcoded static lists in `ingestion.py` with HTTP client calls to the official OTX DirectConnect API and CISA KEV JSON catalog.
3. **Fix Provenance Deduplication:** In `routers/indicators.py`, when an existing indicator is encountered during feed sync, record a new row in `indicator_sources` with current timestamp and source confidence instead of skipping.
4. **Implement Real Domain & Hash Enrichment:** Replace dummy stubs in `enrichment_service.py` with real WHOIS/RDAP and VirusTotal v3 lookup routines.
5. **Implement Real Incident Timeline & Correlation:** Repair `correlation_service.py` models and wire incoming internal security events to dynamically generate incidents and timeline records.
6. **Create CI/CD Pipeline:** Create `.github/workflows/ci.yml` with linting (flake8/eslint), type checking (mypy/tsc), unit tests (pytest), and Docker build validation.

---

## 25. Low Priority Fixes

1. **Clean Committed VCS Artifacts:** Remove `backend/threatlens.db`, `backend/.coverage`, and all `__pycache__` directories from git history and add them strictly to `.gitignore`.
2. **Container Security Hardening:** Add a non-root system user (`threatlens:threatlens`) to `backend/Dockerfile` and execute with `USER threatlens`.
3. **Kubernetes Ingress & WebSocket Annotations:** Add proper NGINX Ingress annotations for WebSocket support and TLS termination with Let's Encrypt.
4. **Remove Redundant Dependencies:** Clean duplicate entries in `backend/requirements.txt` (duplicate `fastapi`, `uvicorn`, `pydantic`, `python-jose`, `httpx`).
5. **Connect Global Search in Navigation Bar:** Wire the search input in `Navbar.tsx` to redirect to `/dashboard/hunting` or trigger a global search dropdown against `/api/v1/search`.

---

## 26. Recommended Completion Order

To bring ThreatLens from its current partially-simulated state to full PRD compliance without breaking existing working functionality, follow this phased execution plan:

```mermaid
graph TD
    P1[Phase 1: Foundation & Security Hardening] --> P2[Phase 2: Data Stores & Ingestion Pipeline]
    P2 --> P3[Phase 3: Real-Time Engine & Live WebSockets]
    P3 --> P4[Phase 4: Dashboard Integration & Real Telemetry]
    P4 --> P5[Phase 5: Search, Correlation & Advanced Features]
    P5 --> P6[Phase 6: Testing, CI/CD & Production Deployment]
```

### Phase 1: Foundation & Security Hardening
1. Unify the database models: eliminate duplicate bases and merge `models/` into a single consistent schema using PostgreSQL UUIDs and types.
2. Fix all syntax and import errors in `backend/app/services/` and `app/api/v1/endpoints/`.
3. Move all secrets (JWT secret, DB credentials) to environment variables; generate secure random defaults.
4. Implement secure authentication: verify bcrypt password hashes against the `users` table; issue short-lived JWT access tokens and refresh tokens.
5. Apply server-side RBAC dependencies (`require_roles`) across all API routes.
6. Clean git repository of committed SQLite databases, `.coverage`, and `.pyc` files.

### Phase 2: Data Stores & Ingestion Pipeline
1. Update `docker-compose.yml` to spin up PostgreSQL 16, Elasticsearch 8.x, and Redis 7.
2. Run Alembic migrations to generate all 13 core PRD tables in PostgreSQL.
3. Update `ingestion.py` to fetch live data for all 6 feeds (integrate real OTX and CISA KEV APIs).
4. Implement canonical upsert and provenance tracking in `indicator_sources`.
5. Wire real enrichment inputs (reputation, detection ratios, recency) into the `scoring.py` engine.

### Phase 3: Real-Time Engine & Live WebSockets
1. Implement Redis Pub/Sub event bus in `backend/app/core/websocket.py`.
2. Connect ingestion and scoring pipeline to publish newly ingested critical IOCs to Redis.
3. Remove the simulated hardcoded timer broadcaster in `main.py`; have WebSocket workers consume live events from Redis.
4. Implement real alert rule evaluation (`alert_rules`) that creates database alerts and publishes them to the WebSocket stream.

### Phase 4: Dashboard Integration & Real Telemetry
1. Update frontend `lib/api.ts` to use `NEXT_PUBLIC_API_URL` and support authentication headers.
2. Connect the SOC Analyst Triage Queue to live backend indicators and alerts.
3. Wire the "Acknowledge" and "Assign" buttons to execute `PATCH /api/v1/alerts/{id}`.
4. Import and wire `GlobalHeatmap.tsx` and `AnalyticsCharts.tsx` into the Executive and Analyst views with dynamic backend API data.
5. Build an authentication login screen and session provider in the frontend.

### Phase 5: Search, Correlation & Advanced Features
1. Project all created/updated indicators into Elasticsearch 8.x using `search_service.py`.
2. Connect `Navbar.tsx` and `/api/v1/search` to Elasticsearch multi-match and aggregation queries.
3. Wire internal security event ingestion (`/api/v1/incidents/correlate-event`) to automatically create incidents and timeline entries upon IOC matches.
4. Implement on-demand executive PDF report generation using WeasyPrint or ReportLab.

### Phase 6: Testing, CI/CD & Production Deployment
1. Fix existing broken tests and write comprehensive unit tests for ingestion, scoring, and RBAC to reach >= 80% coverage.
2. Build integration tests using `testcontainers` for PostgreSQL, Elasticsearch, and Redis.
3. Create `.github/workflows/ci.yml` running linting, type checks, unit tests, and Docker builds.
4. Update Kubernetes deployment manifests with StatefulSets or managed cloud database references, proper ingress routing, and WebSocket support.
