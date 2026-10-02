# ThreatLens — Phase 4D Pre-Implementation Baseline & Forensic Gap Analysis Report
## Comprehensive Architecture Review, PRD Traceability, and Phase 4D Candidate Scoping

**Date:** October 2, 2026  
**Auditor:** ThreatLens Engineering Architecture & QA Lead  
**Current Baseline Commit:** `638c3fe`  
**Repository Branch:** `main`  
**Working Tree Status:** Clean  
**Test Suite State:** 96 passed, 0 failed, 0 skipped, 0 errors (8.03s duration)  
**Implementation Phase Status:** Phase 4C Post-QA Complete; Phase 4D NOT STARTED (Baseline & Gap Analysis Only)

---

### 1. Executive Summary

ThreatLens has completed Phases 0 through 4C, establishing a fully functional Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) incident platform. The current baseline features:
- Ingestion from 6 live threat feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, CISA KEV, AlienVault OTX) with canonical indicator deduplication and provenance tracking.
- Multi-provider threat intelligence enrichment (VirusTotal, AbuseIPDB, AlienVault OTX) with in-memory and Redis TTL caching.
- Pure deterministic mathematical scoring (0–100) and multi-signal alert correlation into canonical security incidents.
- Chronological, forensic incident timelines with audit-logged state transitions (`OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED`).
- Real-time Redis Pub/Sub fan-out and authenticated WebSockets (`/api/v1/ws/alerts`).
- Full PostgreSQL-backed analytics engine (`/api/v1/analytics/*`) with bounded time windows (`24h`, `7d`, `30d`, `90d`) and 100% elimination of mock, synthetic, and hardcoded analytics across the frontend.
- Zero failures across 96 automated backend unit, integration, and security tests.

This document establishes the pre-implementation baseline for **Phase 4D**. In accordance with engineering governance rules, **no Phase 4D features, endpoints, migrations, or UI modifications have been implemented**. This report identifies remaining gaps between the PRD v1.0 specification and current source code, evaluates threat hunting and investigation capabilities, and outlines five distinct architectural candidate areas for Phase 4D execution.

---

### 2. Current Architecture

ThreatLens is architected as an asynchronous, decoupled, multi-container system:

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Next.js 16 SOC Frontend                        │
│   - Home Hub (/)                    - SOC Analyst (/dashboard/analyst) │
│   - Executive (/dashboard/executive)- IR (/dashboard/incidents)        │
│   - Hunting (/dashboard/hunting)    - Navbar Search & Role Selector    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / WebSocket (JWT Bearer)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FastAPI API Gateway (v1)                        │
│   /auth       /indicators   /alerts     /incidents   /feeds            │
│   /search     /enrichment   /analytics  /export      /audit     /ws    │
└───────────┬───────────────────────┬──────────────────────┬─────────────┘
            │                       │                      │
            ▼                       ▼                      ▼
┌──────────────────────┐ ┌────────────────────┐ ┌────────────────────────┐
│    PostgreSQL 16     │ │   Redis 7 Alpine   │ │  Elasticsearch 8.13.4  │
│ - System of Record   │ │ - Token Blacklist  │ │ - Full-Text / Keyword  │
│ - Core Entities      │ │ - Pub/Sub Broker   │ │ - Faceted Bucketing    │
│ - Immutable Audits   │ │ - TTL Cache Layer  │ │ - DB Query Fallback    │
└──────────────────────┘ └────────────────────┘ └────────────────────────┘
```

#### Canonical Backend Tree (`backend/app/api/v1/endpoints/`):
- `auth.py`: User registration (safe default `viewer`), Argon2id hashing, JWT login/refresh/logout.
- `indicators.py`: IOC pagination, manual creation, feed sync, status update, live enrichment trigger.
- `alerts.py`: Alert query, lifecycle update (`PATCH /alerts/{id}`), authenticated WebSocket handler.
- `incidents.py`: Internal security event ingestion (`/correlate-event`), incident query, detail, timeline, status and severity updates.
- `feeds.py`: List feeds, manual fetch trigger (`/fetch`), enabled/disabled toggle.
- `search.py`: Full-text query (`/indicators?q=...`) dispatching to Elasticsearch with database fallback.
- `enrichment.py`: Provider health checks, batch refresh, indicator-level multi-provider intelligence summary.
- `analytics.py`: 9 endpoints (`overview`, `kpis`, `trends`, `severity`, `indicator-types`, `incidents`, `mitre`, `geography`, `sources`).
- `export.py`: STIX 2.1 JSON bundle and CSV exports.
- `audit.py`: Query immutable audit logs.
- `websocket.py`: Connection manager for real-time alert broadcasts.

---

### 3. Completed Capabilities

| Capability Area | Implemented Components | Verified Baseline |
| :--- | :--- | :---: |
| **Feed Ingestion** | 6 dynamic public feeds (URLhaus, ThreatFox, Feodo, MalwareBazaar, CISA KEV, OTX) | Phase 3 |
| **Deduplication & Provenance** | Canonical upsert, sightings increment, `IndicatorSource` provenance tracking | Phase 3 |
| **Enrichment Engine** | Abstract provider architecture, async dispatch, VirusTotal, AbuseIPDB, OTX, TTL cache | Phase 4B |
| **Threat Scoring** | Mathematical 4-factor scoring (0–100), aggregate enrichment verdict scoring | Phase 4B |
| **Correlation & Incidents** | Multi-signal correlation (IOC, host, MITRE, source, 15m window), incident clustering | Phase 4A |
| **Incident Lifecycle** | Status state-machine transitions, severity escalation, chronological forensic timeline | Phase 4A |
| **Real-time Pipeline** | Redis Pub/Sub channel `threatlens:events:alerts`, WebSocket fan-out, JWT auth | Phase 3 |
| **Security Architecture** | Argon2id hashing, server-side RBAC, immutable DB engine audit triggers | Phase 1B, 2 |
| **Threat Analytics** | Board KPIs (Risk Score, MTTD, MTTR), zero-filled trend velocity, MITRE/geo aggregation | Phase 4C |
| **Export Formats** | STIX 2.1 JSON bundle, CSV indicator export | Phase 4C |

---

### 4. REAL / PARTIAL / MOCK / BROKEN / MISSING Matrix

Forensic classification of all 23 core platform capabilities:

| # | Capability Area | Status | Evidence / Notes |
| :-: | :--- | :---: | :--- |
| **A** | Threat hunting | **PARTIAL** | `/dashboard/hunting` renders MITRE techniques and filters local IOCs, but lacks interactive query execution or saved hunts. |
| **B** | Advanced search | **PARTIAL** | Backend `/api/v1/search/indicators` exists with ES/DB queries; Navbar search bar is unconnected to API. |
| **C** | Detection engineering | **PARTIAL** | Alerts generated during ingestion and event correlation, but no rule authoring or testing interface exists. |
| **D** | Detection rules | **MISSING** | Alert logic is hardcoded in Python; no `detection_rules` table or rule management CRUD API exists (FR-17). |
| **E** | Detection pipelines | **REAL** | Ingest → Score → Alert → Correlate → Incident → Redis Pub/Sub → WebSocket pipeline is fully operational. |
| **F** | Threat scoring | **REAL** | Pure mathematical deterministic models implemented across indicators (0–100), enrichments, and risk score. |
| **G** | IOC lifecycle | **PARTIAL** | Status transition (`PATCH /status`) exists, but automated TTL aging-out worker (FR-08) and relationships (FR-09) are missing. |
| **H** | Investigation workflows | **PARTIAL** | Analyst drawer inspects enrichments; incident cockpit shows timeline; free-text notes and tagging modals are absent. |
| **I** | Analyst workflows | **REAL** | Queue triage, single-click enrichment, alert acknowledgement, and incident lifecycle transitions are functional. |
| **J** | Case management | **PARTIAL** | Correlated incidents cluster alerts and track timeline; formal case tasks, evidence files, and SLA tracking are absent. |
| **K** | Playbooks | **MISSING** | No incident response playbook engine, task runbooks, or workflow automation exists. |
| **L** | Automated response | **MISSING** | Active containment actions (IP block, firewall rule push, host isolation) do not exist. |
| **M** | External integrations | **REAL** | VirusTotal, AbuseIPDB, AlienVault OTX integrated via modular provider interface with health checks. |
| **N** | SIEM | **PARTIAL** | `/api/v1/incidents/correlate-event` ingests generic SIEM telemetry payloads; native SIEM connectors do not exist. |
| **O** | EDR | **MISSING** | Affected host tracking exists; direct EDR sensors (CrowdStrike, Defender) or isolation actions do not exist. |
| **P** | SOAR | **MISSING** | Event fan-out exists, but bidirectional orchestration and ticketing synchronization (Jira/ServiceNow) do not exist. |
| **Q** | STIX / TAXII | **PARTIAL** | STIX 2.1 JSON bundle export is operational (FR-24); TAXII 2.1 client/server polling is completely absent (FR-04). |
| **R** | Threat-intelligence feeds | **REAL** | 6 live feeds dynamically ingested with per-source provenance, manual triggers, and toggle endpoints. |
| **S** | Evidence management | **PARTIAL** | Correlated alerts and timeline events are preserved; arbitrary file attachments, PCAPs, and evidence hashes are absent. |
| **T** | Export / reporting | **PARTIAL** | STIX 2.1 and CSV exports are operational; automated executive PDF report generation (FR-23) is completely absent. |
| **U** | API integrations | **REAL** | Full REST API with OpenAPI documentation, JWT authentication, and server-side RBAC across all resources. |
| **V** | Webhooks | **MISSING** | Outbound WebSockets operational; inbound external webhooks (FR-29) and outbound notification webhooks do not exist. |
| **W** | Notifications | **PARTIAL** | Real-time WebSocket toast notifications active in UI; email, SMS, and webhook alerting are absent. |

---

### 5. PRD Traceability

Traceability against Product Requirements Document (PRD v1.0) and `THREATLENS_IMPLEMENTATION_AUDIT.md`:

#### 1. Completed Requirements (REAL):
- **FR-01:** Multi-source feed ingestion across >= 6 configured sources (`feed_service.py`).
- **FR-03:** Canonical indicator deduplication with provenance tracking (`IndicatorSource`).
- **FR-10:** IP reputation analysis with abuse confidence aggregation (`AbuseIPDBProvider`, `VirusTotalProvider`).
- **FR-11:** Malicious domain detection and categorization (`VirusTotalProvider`, `OTXProvider`).
- **FR-12:** Malware hash lookup and detection engine ratios (`VirusTotalProvider`, `OTXProvider`).
- **FR-13:** Pure mathematical 0–100 severity scoring model (`scoring_service.py`).
- **FR-15:** Real-time threat alert streaming via Redis Pub/Sub and authenticated WebSockets (`ws_manager`).
- **FR-16:** Multi-dimensional threat correlation and automated incident clustering (`correlation_service.py`).
- **FR-19:** Ordered immutable incident forensic timeline (`IncidentTimeline`).
- **FR-20:** Global geographic threat density visualization (`analytics/geography`, `GlobalHeatmap.tsx`).
- **FR-21:** Time-series threat velocity and severity breakdown charts (`analytics/trends`, `AnalyticsCharts.tsx`).
- **FR-24:** STIX 2.1 JSON bundle and CSV export (`export.py`).
- **FR-26:** Server-side RBAC enforcement (`require_authenticated_user`, `RoleChecker`).
- **FR-27:** Database engine immutable audit logging (`AuditLog`, engine event listeners).
- **FR-28:** Authenticated REST and WebSocket APIs (`/api/v1/`).
- **NFR-02:** Sub-second alert propagation via Redis and WebSockets.
- **NFR-04:** Operational liveness and readiness probes (`/health`, `/health/ready`).
- **NFR-11:** Orchestrated production stack (`docker-compose.yml`).

#### 2. Partially Implemented Requirements (PARTIAL):
- **FR-02:** Canonical normalization (JSON dict parsing implemented; lacks STIX 2.1 / CSV ingestion normalizers).
- **FR-06:** IOC CRUD lifecycle (`GET /`, `POST /create`, `PATCH /status` active; lacks `GET /{id}`, `PUT /{id}`, `DELETE /{id}`, and email/MD5 handling).
- **FR-07:** Metadata tagging (columns `tags`, `tlp`, `mitre_technique` exist; lacks `analyst_notes` column and analyst editing modal).
- **FR-14:** Geolocation & ASN enrichment (backend endpoints active; frontend inspector partially visualizes).
- **FR-18:** Alert lifecycle management (backend `PATCH /alerts/{id}` active with audit logs; UI lacks dedicated alert action drawer).
- **FR-25:** Full-text and faceted search (backend `search_service.py` active; frontend search bar not connected).
- **NFR-01:** High-scale performance benchmarking under 100k+ indicators.
- **NFR-07:** Persistent named volumes and idempotent upsert constraints.
- **NFR-09:** Rapid analyst triage <= 4 clicks.

#### 3. Missing Requirements (MISSING):
- **FR-04:** TAXII 2.1 collections ingestion transport.
- **FR-05:** Dynamic feed management UI (backend endpoints exist; frontend lacks management screen).
- **FR-08:** Configurable IOC time-to-live (TTL) and automated background expiration worker.
- **FR-09:** Indicator relationship graph (`indicator_relationships` model, graph API, and visual explorer).
- **FR-17:** Configurable alert rule engine (`alert_rules` model, threshold, category, routing).
- **FR-22:** Custom dashboard widget builder and user layout storage.
- **FR-23:** Automated executive PDF report generation (`POST /api/v1/reports`).
- **FR-29:** Inbound SIEM/EDR integration hooks (`/api/v1/integrations/inbound`).

---

### 6. Threat Hunting Review

Forensic inspection of `/dashboard/hunting` and hunting services:
- **IOC Search:** Backend endpoint `GET /api/v1/search/indicators` supports full-text search, type filtering, severity filtering, and faceted aggregations. However, `/dashboard/hunting` does not make any requests to `/api/v1/search/indicators`.
- **Advanced Filtering:** Hunting page only filters by clicking a MITRE technique card. There is no filter for date range, threat score, source, or confidence.
- **Indicator Investigation:** Clicking an IOC on the hunting page does not open an indicator details drawer or trigger enrichment.
- **Enrichment Inspection:** Isolated to `/dashboard/analyst`; unavailable inside the hunting cockpit.
- **Incident Linkage:** When an IOC is associated with an active incident, there is no visual indicator or link navigating the hunter to `/dashboard/incidents`.
- **Saved Searches:** The hunting page has 2 static cards labeled "Active Threat Hunting Queries" (`type:ip severity:CRITICAL`, `type:cve mitre:T1190`), but they are hardcoded UI elements with no execution handler or database persistence.
- **Investigation Notes & Evidence:** No mechanism exists for threat hunters to record findings, hypothesis notes, or bookmark IOCs during a hunt.

---

### 7. Investigation Workflow Review

- **Alert Triage:** SOC analysts on `/dashboard/analyst` can view ingested indicators, sort by severity, view confidence/TLP, and trigger external enrichment via `/api/v1/indicators/{id}/enrich`.
- **Incident Response:** Incident responders on `/dashboard/incidents` view active incidents, correlated alerts count, correlation score, affected host, and chronological forensic timeline (`GET /api/v1/incidents/{id}/timeline`).
- **Workflow Gaps:**
  1. Incidents cannot have analyst notes appended directly to their timeline via the UI.
  2. Indicators cannot have tags or TLP updated from the UI drawer.
  3. No relationship graph exists to pivot from an IP to associated domains or file hashes.

---

### 8. Detection Engineering Review

- **Current Mechanism:**
  1. During ingestion, `evaluate_ioc_for_alerts(db, ioc)` evaluates whether `ioc.threat_score >= 80` or `ioc.severity == "CRITICAL"`. If matched, an `Alert` is created with hardcoded `rule_name="Known Malicious IP Ingress"` or `"High Severity IoC Match"`.
  2. When security events arrive at `/api/v1/incidents/correlate-event`, `correlate_and_create_incident` evaluates multi-dimensional signals against existing indicators and alerts.
- **Gaps:**
  1. Zero user-configurable detection rules exist in the database.
  2. Security engineers cannot define custom rules (e.g., "Alert when source is CISA KEV and type is CVE", or "Alert when confidence >= 90 and tags contain 'ransomware'").
  3. No alert suppression, deduplication windows, or routing rules exist.

---

### 9. Integration Review

- **Threat Intel Feeds:** 6 public feeds operational with periodic polling and error isolation.
- **Threat Intel Providers:** VirusTotal, AbuseIPDB, and AlienVault OTX operational with abstract interface, health checks, and caching.
- **SIEM/EDR Ingestion:** `/api/v1/incidents/correlate-event` accepts event payloads, but requires session JWT authentication rather than system-to-system API keys, and has no webhook signature verification.
- **Notifications:** WebSocket real-time alerts active; no Slack, Teams, email, or webhook notifications.
- **Downstream Export:** STIX 2.1 JSON and CSV export operational; no TAXII 2.1 server or PDF executive reports.

---

### 10. Backend Gap Analysis

1. **Search Integration:** `backend/app/services/search_service.py` is implemented and functional, but lacks integration with the frontend navigation and hunting pages.
2. **Missing Rule Engine:** No models or service exist for configurable detection rules.
3. **Missing Relationship Engine:** No service or database model exists to represent IOC-to-IOC relationships (`resolves-to`, `communicates-with`, `downloads`).
4. **Missing Expiration Worker:** No scheduled background task ages out indicators past their TTL.
5. **Missing Inbound Webhooks:** No webhook endpoint exists for unauthenticated/API-key authenticated external systems.

---

### 11. Database Gap Analysis

The database currently maintains 8 core tables (`users`, `indicators`, `indicator_sources`, `indicator_enrichments`, `alerts`, `incidents`, `incident_alerts`, `incident_timelines`, `feeds`, `audit_logs`). 

Data models needed to support future requirements:
- **Detection Rules:** Missing `detection_rules` table (`id`, `name`, `severity`, `rule_type`, `conditions`, `action`, `enabled`, `author_id`, `created_at`).
- **Indicator Relationships:** Missing `indicator_relationships` table (`id`, `source_indicator_id`, `target_indicator_id`, `relationship_type`, `confidence`, `created_at`).
- **Analyst Notes & TTL:** Missing columns on `indicators`: `analyst_notes` (TEXT), `expires_at` (TIMESTAMP), `ttl_days` (INTEGER).
- **Saved Hunting Queries:** Missing `saved_queries` table (`id`, `name`, `query_string`, `filters`, `user_id`, `created_at`).
- **Inbound Integrations:** Missing `integrations` / `api_keys` table (`id`, `name`, `key_hash`, `system_type`, `is_active`, `created_at`).

---

### 12. Frontend Gap Analysis

1. **Navbar Search:** `<input>` in `Navbar.tsx` updates local state `searchVal` but triggers no search action, page navigation, or API call.
2. **Hunting Query Execution:** `/dashboard/hunting` contains static query filter cards with no execution handler.
3. **Feed Management Screen:** Backend supports listing, fetching, and toggling feeds (`/api/v1/feeds/*`), but no UI exists for security engineers to manage feeds.
4. **Interactive Pivot Drawer:** Selecting an indicator in Hunting or Incidents does not open a detailed investigation drawer.
5. **PDF Export Action:** Executive dashboard contains a "Generate PDF Briefing" button that currently only toggles a local timer string.

---

### 13. Security Gap Analysis

1. **System-to-System Authentication:** Inbound event ingestion currently requires a user JWT token; there is no API key or webhook HMAC verification for machine-to-machine integrations.
2. **Detection Rule Injection:** If dynamic rule conditions are implemented, rule definitions must be strictly validated against an AST or Pydantic schema to prevent Python `eval()` or SQL injection vulnerabilities.
3. **Graph Traversal Limits:** If IOC relationships are implemented, graph traversal depth must be strictly bounded to prevent Denial of Service via circular references.
4. **Analyst Notes Sanitization:** If analyst notes are implemented, markdown or HTML content must be sanitized server-side and client-side to prevent XSS.

---

### 14. Performance Considerations

- **Elasticsearch Query Latency:** Full-text queries must maintain sub-second response times (< 800ms at p95) with proper pagination (`skip`, `limit <= 100`).
- **Recursive Graph Queries:** Graph relationship queries in PostgreSQL must use indexed foreign keys and recursion depth limits (`depth <= 3`).
- **Rule Engine Overhead:** Detection rule evaluation must execute asynchronously or during ingestion without blocking WebSocket event broadcast.

---

### 15. Phase 4D Candidate Scope

Based strictly on PRD requirements, implementation audit, and architecture gaps, the following five legitimate candidate areas are identified. **They are listed separately with equal technical depth, without ranking, preference, or declaration of a "best" option.**

---

#### Candidate Area 1: Advanced Threat Hunting & Adversary Infrastructure Graph (FR-09, FR-25)

- **Problem:** Threat hunters lack an interactive query interface, cannot query the full-text search backend from the UI, and cannot pivot across linked adversary infrastructure (e.g. domain resolves-to IP, hash communicates-with domain).
- **Current State:** Backend has `/api/v1/search/indicators` and Elasticsearch service, but hunting UI uses local client-side filtering. No relationship model exists.
- **Affected Modules:**
  - Backend: `backend/app/models/relationship.py` (new), `backend/app/api/v1/endpoints/search.py`, `backend/app/services/graph_service.py` (new).
  - Database: New `indicator_relationships` table (`source_id`, `target_id`, `relationship_type`, `confidence`).
  - Frontend: `frontend/src/app/dashboard/hunting/page.tsx`, `frontend/src/components/Navbar.tsx` (active search routing), interactive relationship visualization.
- **Required Backend Work:** Expose graph traversal endpoint (`GET /api/v1/indicators/{id}/relationships`), wire `/api/v1/search/indicators` to return related nodes, implement relationship creation API.
- **Required Database Work:** Alembic migration for `indicator_relationships` with foreign keys and composite indexes on `(source_indicator_id, relationship_type)`.
- **Required Frontend Work:** Build search query bar with typeahead suggestions, display query results with pagination, render relationship node graph or linked table, wire Navbar search input to hunting search.
- **Security Implications:** Input sanitization on search queries, cycle detection and depth caps on graph queries, RBAC on relationship modifications.
- **Testing Requirements:** Graph traversal unit tests, cycle detection tests, search integration tests, performance tests under multi-hop queries.
- **Dependencies:** `Indicator` model, `search_service.py`.
- **Risks:** High-connectivity nodes (e.g. cloud IPs) causing visual clutter or query timeouts if not bounded.

---

#### Candidate Area 2: Configurable Detection Rule Engine & Alert Routing (FR-17, FR-18)

- **Problem:** Security engineers cannot define custom detection rules or adjust alert sensitivity. Alert generation is hardcoded in Python ingestion logic. Alerts cannot be routed to specific SOC analysts or groups.
- **Current State:** Alerts store a static `rule_name`. Ingestion checks `severity >= 80`. No rule definitions, thresholds, or routing tables exist in the database.
- **Affected Modules:**
  - Backend: `backend/app/models/detection_rule.py` (new), `backend/app/api/v1/endpoints/rules.py` (new), `backend/app/services/rule_service.py` (new), `backend/app/services/alert_service.py`.
  - Database: New `detection_rules` table (`name`, `description`, `severity`, `threshold_score`, `conditions_json`, `assignee_role`, `enabled`).
  - Frontend: Detection rule management interface (list, create, edit, toggle), alert routing and assignment drawer.
- **Required Backend Work:** Build rule matching engine evaluating indicators against active rules, trigger alerts matching rule thresholds and tags, expose CRUD endpoints under `/api/v1/rules`.
- **Required Database Work:** Alembic migration for `detection_rules` with audit logging foreign keys.
- **Required Frontend Work:** Build Rule Management tab/modal with condition builder (threshold, indicator type, source feed, MITRE technique), wire alert assignment actions to backend.
- **Security Implications:** Safe evaluation of rule conditions without `eval()`, RBAC restricting rule creation to `require_engineer`, audit logging of all rule mutations.
- **Testing Requirements:** Rule evaluation unit tests, threshold matching tests, alert routing tests, invalid condition validation tests.
- **Dependencies:** `Alert` model, `Indicator` model, `alert_service.py`.
- **Risks:** Misconfigured broad rules generating alert floods; ingestion latency if rule matching is unindexed.

---

#### Candidate Area 3: IOC Lifecycle Management, TTL Expiration & Feed Management UI (FR-05, FR-06, FR-07, FR-08)

- **Problem:** Indicators remain active indefinitely with no automated aging or TTL decay. Analysts cannot edit tags, TLP, or attach investigation notes to IOCs. Security engineers have no frontend interface to manage or re-poll feeds.
- **Current State:** `Indicator` model lacks `analyst_notes` and `expires_at`. `Feed` model and `/api/v1/feeds` endpoints exist on backend, but frontend has zero UI for feed administration.
- **Affected Modules:**
  - Backend: `backend/app/models/indicator.py`, `backend/app/api/v1/endpoints/indicators.py`, `backend/app/services/expiration_service.py` (new).
  - Database: Add columns `analyst_notes` (TEXT), `expires_at` (TIMESTAMP), `ttl_days` (INTEGER) to `indicators` table.
  - Frontend: Feed Management screen/tab (`/dashboard/feeds` or settings modal), IOC detail drawer with note editing, tagging, and status dropdown.
  - Required Backend Work: Implement periodic or on-demand indicator expiration job, implement `PUT /api/v1/indicators/{id}` for notes/tags/TLP updates, implement full IOC CRUD lifecycle.
- **Required Database Work:** Alembic migration adding columns to `indicators` with index on `(status, expires_at)`.
- **Required Frontend Work:** Build Feed Management console with feed list, toggle switches, and "Poll Now" triggers; build IOC detail drawer with interactive notes editor and tag manager.
- **Security Implications:** Sanitization of analyst notes against XSS, RBAC enforcement (`require_analyst` for notes, `require_engineer` for feeds), audit logging for IOC modifications.
- **Testing Requirements:** Expiration worker unit tests, IOC update endpoint tests, feed toggle tests, notes sanitization tests.
- **Dependencies:** `Indicator` model, `Feed` model, `feed_service.py`.
- **Risks:** Large batch updates during expiration causing database locks if not chunked.

---

#### Candidate Area 4: Inbound Security Integrations & Automated Response Webhooks (FR-29, FR-04)

- **Problem:** External security tools (SIEMs, EDRs, ticketing systems) cannot send telemetry to ThreatLens via standard webhooks or API keys. ThreatLens cannot push automated alerts or containment notifications to external systems.
- **Current State:** `/api/v1/incidents/correlate-event` exists but requires analyst session JWT authentication. No API key infrastructure, inbound webhook endpoints, or outbound webhook dispatchers exist.
- **Affected Modules:**
  - Backend: `backend/app/models/integration.py` (new), `backend/app/api/v1/endpoints/integrations.py` (new), `backend/app/services/webhook_service.py` (new).
  - Database: New `integrations` table (`id`, `name`, `system_type`, `api_key_hash`, `webhook_url`, `is_active`, `created_at`).
  - Frontend: Integrations settings tab with API key generation, webhook URL configuration, and test dispatch button.
- **Required Backend Work:** Build API key authentication dependency (`X-API-Key` header with Argon2/SHA-256 verification), build `/api/v1/integrations/inbound` webhook handler, build outbound webhook dispatcher on critical incident creation.
- **Required Database Work:** Alembic migration for `integrations` table with encrypted or hashed credential storage.
- **Required Frontend Work:** Integrations management UI with key generation modal (copy once), webhook status indicators, and delivery logs.
- **Security Implications:** Secure API key generation and hashing, rate limiting on webhook endpoints to prevent DoS, SSRF protection on outbound webhook URLs (blocking private IP ranges).
- **Testing Requirements:** API key authentication tests, inbound webhook schema validation tests, rate limit tests, SSRF validation tests.
- **Dependencies:** `correlation_service.py`, `alert_service.py`.
- **Risks:** External webhook failures blocking internal pipeline if dispatch is synchronous (must be async background task).

---

#### Candidate Area 5: Automated Forensic Case Management & Executive PDF Reporting (FR-23)

- **Problem:** CISOs cannot generate downloadable, board-ready executive PDF briefing summaries. Incident responders cannot generate exportable forensic case dossiers with complete evidence packages.
- **Current State:** STIX 2.1 JSON and CSV exports are operational. Executive PDF button on `/dashboard/executive` is a non-functional UI placeholder.
- **Affected Modules:**
  - Backend: `backend/app/services/pdf_report_service.py` (new), `backend/app/api/v1/endpoints/reports.py` (new).
  - Database: New `reports` table (`id`, `report_type`, `title`, `parameters`, `file_path`, `generated_by`, `created_at`).
  - Frontend: Report generation modal on Executive and Incidents dashboards with date range picker, format options, and download history.
- **Required Backend Work:** Integrate PDF generation engine (e.g. WeasyPrint or ReportLab), design HTML/CSS report templates (Executive CISO Brief, Incident Forensic Dossier), expose `POST /api/v1/reports/generate` and `GET /api/v1/reports/{id}/download`.
- **Required Database Work:** Alembic migration for `reports` table.
- **Required Frontend Work:** Connect "Generate PDF Briefing" button to backend report API, display progress indicator, handle file download.
- **Security Implications:** Template injection prevention (strict Jinja2 escaping), authorization check ensuring users can only download reports matching their role/TLP clearance.
- **Testing Requirements:** PDF generation unit tests, template rendering tests, file download authentication tests.
- **Dependencies:** `analytics_service.py`, `correlation_service.py`, PDF engine library.
- **Risks:** Memory and CPU spikes during high-resolution PDF rendering; PDF library dependencies on OS-level fonts/Cairo.

---

### 16. Dependencies

Any subsequent Phase 4D implementation will depend on:
1. **Existing Persistent Baseline:** PostgreSQL 16 schema (`3f89a12c4b5e`, `4a1c0rre1at1`, `4b2enr1chment`), Alembic migration framework, and SQLAlchemy ORM models.
2. **Security Infrastructure:** `app.core.rbac.RoleChecker`, `require_authenticated_user`, `get_current_user`, Argon2id password hashing, and JWT secret verification.
3. **Event Backbone:** Redis 7 Pub/Sub broker (`threatlens:events:alerts`, `threatlens:events:incidents`, `threatlens:events:enrichment`) and WebSocket manager.
4. **Authoritative Entities:** Canonical models for `Indicator`, `Alert`, `Incident`, `IndicatorEnrichment`, and `AuditLog`.

---

### 17. Risks

1. **Scope Bloat:** Attempting to implement multiple candidate areas simultaneously in a single phase risks architectural fragmentation and regression of verified Phase 4A–4C functionality.
2. **Third-Party Service Limits:** External feed APIs and threat intelligence providers enforce strict rate limits; integration designs must rely on caching and asynchronous dispatch.
3. **Database Migration Safety:** Any new tables or columns must use explicit Alembic migration scripts with reversible `downgrade()` functions and foreign key constraints.

---

### 18. Explicit Out-of-Scope Items

To preserve architecture integrity, the following items are strictly out-of-scope for the baseline and any initial Phase 4D scope:
- Full commercial SIEM / EDR platform replication (ThreatLens is a CTI & SOC correlation platform, not an endpoint sensor or log collector).
- Automated active endpoint isolation or network firewall reconfiguration.
- Complete redesign of existing UI themes, branding, color systems, or navigation architecture.
- Deprecation or modification of existing verified Phase 1–4C endpoints or tests.

---

### 19. Exact Files / Modules Likely to Change (by Candidate Area)

Depending on which candidate area is authorized for Phase 4D:

| Candidate Area | Backend Modules | Database Migrations | Frontend Modules |
| :--- | :--- | :--- | :--- |
| **Candidate 1: Hunting & Graph** | `api/v1/endpoints/search.py`, `services/search_service.py`, `models/relationship.py`, `services/graph_service.py` | `alembic/versions/4d_indicator_relationships.py` | `dashboard/hunting/page.tsx`, `components/Navbar.tsx`, `lib/api.ts` |
| **Candidate 2: Detection Rules** | `api/v1/endpoints/rules.py`, `models/detection_rule.py`, `services/rule_service.py`, `services/alert_service.py` | `alembic/versions/4d_detection_rules.py` | `dashboard/analyst/page.tsx`, new rule modal, `lib/api.ts` |
| **Candidate 3: IOC Lifecycle & Feeds** | `models/indicator.py`, `api/v1/endpoints/indicators.py`, `services/expiration_service.py`, `api/v1/endpoints/feeds.py` | `alembic/versions/4d_ioc_lifecycle_columns.py` | `dashboard/analyst/page.tsx`, new feed tab, `lib/api.ts` |
| **Candidate 4: Inbound Webhooks** | `models/integration.py`, `api/v1/endpoints/integrations.py`, `services/webhook_service.py`, `core/security.py` | `alembic/versions/4d_integrations.py` | Settings/integrations modal, `lib/api.ts` |
| **Candidate 5: PDF Reporting** | `services/pdf_report_service.py`, `api/v1/endpoints/reports.py`, `models/report.py` | `alembic/versions/4d_reports.py` | `dashboard/executive/page.tsx`, `dashboard/incidents/page.tsx`, `lib/api.ts` |

---

### 20. Test Baseline

- **Test Framework:** pytest 9.1.1 (Python 3.14.6)
- **Execution Command:** `python -m pytest -v` (run in `backend/`)
- **Total Tests:** 96
- **Passed:** 96
- **Failed:** 0
- **Skipped:** 0
- **Errors:** 0
- **Execution Duration:** 8.03 seconds

---

### 21. Runtime Baseline

- **FastAPI Backend:** Fully operational with Uvicorn. Operational endpoints verified:
  - `GET /health`: HTTP 200 (healthy)
  - `GET /health/ready`: HTTP 200 (database, redis, and elasticsearch connectivity checks active)
  - `GET /api/v1/analytics/*`: HTTP 200 across all 9 canonical analytics endpoints with real database aggregations.
- **Next.js Frontend:** Fully operational on Next.js 16 Turbopack. Production build (`npm run build`) verifies:
  - TypeScript compilation: 0 errors
  - Static route generation: 8/8 routes prerendered (`/`, `/_not-found`, `/dashboard/analyst`, `/dashboard/executive`, `/dashboard/hunting`, `/dashboard/incidents`).
- **Data Integrity:** 0 occurrences of `Math.random()`, fake coordinates, synthetic percentages, or static mock arrays in production code.

---

### 22. Phase 4D Readiness

The ThreatLens platform is in a **STABLE, FULLY TESTED, AND VERIFIED BASELINE STATE**. 
- Architecture is clean, decoupled, and authenticated.
- Regression suite has 100% pass rate.
- Gaps and candidate scopes are comprehensively analyzed and documented.
- **Phase 4D is READY TO BE SCOPED AND AUTHORIZED BY ENGINEERING STAKEHOLDERS.**
