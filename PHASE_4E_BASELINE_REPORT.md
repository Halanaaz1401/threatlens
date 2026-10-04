# THREATLENS — PHASE 4E: BASELINE AUDIT & IMPLEMENTATION BLUEPRINT
**Scope:** Automated Forensic Case Management & Executive PDF Reporting  
**PRD Alignment:** ThreatLens PRD v1.0 (Sentinova Security Systems) — FR-19 (Timeline/Evidence), FR-23 (Executive PDF Reporting), FR-26 (RBAC), FR-27 (Immutable Audit), FR-28 (REST/WebSocket APIs)  
**Date:** October 2026  
**Auditor/Engineer Mode:** Autonomous Full Implementation & Verification  
**Initial Safe Checkpoint Commit:** `1bd99a0` (branch: `main`)  
**Target Repository:** `Halanaaz1401/threatlens`  

---

## 1. Executive Summary & Objective

ThreatLens has successfully completed and verified Phases 1A through 4D-D:
- **Phase 1A/1B:** Unified canonical router tree (`/api/v1`), Argon2id password hashing, JWT authentication, server-side RBAC (`RoleChecker`), and CORS protection.
- **Phase 2:** PostgreSQL 16 persistence, Redis 7 token revocation, Elasticsearch 8.x search fallback, and database-level immutable audit logging (`audit_log`).
- **Phase 3:** Real-time feed ingestion across 6 public threat feeds, canonical indicator deduplication, alert generation, and authenticated WebSocket streaming via Redis Pub/Sub.
- **Phase 4A:** Deterministic multi-dimensional threat correlation, canonical incident clustering, incident lifecycle, and chronological incident timeline.
- **Phase 4B:** Multi-provider threat intelligence enrichment (VirusTotal, AbuseIPDB, AlienVault OTX) with in-memory TTL caching and PostgreSQL storage.
- **Phase 4C:** Enterprise threat analytics engine under `/api/v1/analytics` (`overview`, `kpis`, `trends`, `severity`, `mitre`, `geography`), zero mock data.
- **Phase 4D-A:** Indicator relationship graph (`IndicatorRelationship`) with BFS traversal, cycle detection, and SVG hunting graph.
- **Phase 4D-B:** Declarative detection rule engine with 11 safe operators, team/queue alert routing, and automated correlation handoff.
- **Phase 4D-C:** Threat feed management cockpit and IOC lifecycle (active, expired, revoked, under_review, whitelisted) with deterministic UTC TTL background expiration.
- **Phase 4D-D:** Inbound SIEM/EDR webhook receivers (Splunk, QRadar, Sentinel, CrowdStrike, Elastic) and TAXII 2.1 STIX collection polling.

**Phase 4E Objective:**  
Elevate ThreatLens from an alert/incident correlation and threat-intelligence platform into a complete, enterprise-grade forensic case management and executive reporting system:
1. **Part A–J: Automated Forensic Case Management:**
   - Multi-incident and multi-indicator investigation cases with strict lifecycle (`OPEN`, `IN_PROGRESS`, `CONTAINED`, `RESOLVED`, `CLOSED`).
   - Forensic evidence tracking (what, source entity, provider, observed/collected timestamps, collector, confidence, hash).
   - Investigator notes with append-only forensic integrity.
   - Unified chronological forensic timeline synthesizing case events, incident correlations, evidence, notes, and containment steps.
   - Automated Incident -> Case clustering workflow avoiding case explosion and preserving source traceability.
   - Strict server-side RBAC (Viewer read-only, Analyst case workflow, Admin full access).
   - Dedicated Next.js SOC case workspace at `/dashboard/cases` with real-time telemetry and zero mock data.
2. **Part K–O: Executive PDF Reporting (FR-23):**
   - Server-side generated Executive Security Reports in PDF format suitable for CISOs and board review.
   - Grounded exclusively in real PostgreSQL operational data (incidents, alerts, indicators, enrichments, cases, detection rules, MITRE ATT&CK, geographic distribution).
   - High-fidelity PDF generation engine with cover sheet, executive summary, posture metrics, severity breakdown, top threats, findings, recommendations, and forensic report generation metadata.
   - Safe empty-state handling ("No data available for the selected reporting period") with zero fabricated numbers.
   - REST API under `/api/v1/reports` with RBAC, UUID report tokens, path traversal prevention, and secure file downloads.
3. **Part P–Q: Audit & Event Integration:**
   - Full immutable audit logging for all case and report lifecycle events.
   - Redis Pub/Sub events on `threatlens:events:cases` and `threatlens:events:reports`.

---

## 2. Current Architecture & Baseline Inventory

### 2.1 Persistence & Models (`backend/app/models/`)
- `User` (`user.py`): UUIDv4 string PK, roles (`admin`, `security_engineer`, `analyst`, `soc_analyst`, `incident_responder`, `threat_hunter`, `viewer`, `executive`).
- `Indicator` (`indicator.py`): Canonical indicators, lifecycle status, TTL, tags, TLP, analyst notes.
- `Alert` (`alert.py`): Severity, status (`NEW`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`), rule links, routing queues.
- `Incident` & `IncidentTimeline` (`incident.py`): Correlated incident clustering, severity, correlation score, status transitions, timeline entries.
- `SecurityEvent` (`incident.py`): Inbound SIEM/EDR normalized telemetry.
- `IndicatorEnrichment` (`enrichment.py`): Multi-provider reputation scores, verdicts, and raw responses.
- `IndicatorRelationship` (`relationship.py`): Graph edges with relationship types and confidence.
- `Feed` & `WebhookConfig` (`feed.py`, `integration.py`): Threat feeds and webhook secrets.
- `AuditLog` (`audit.py`): Database-level immutable audit records with trigger-enforced append-only guarantees.

### 2.2 API Router Namespace (`backend/app/api/v1/api.py`)
- Mounted under `/api/v1` in `backend/app/main.py`:
  - `/auth`, `/indicators`, `/alerts`, `/incidents`, `/feeds`, `/integrations`, `/search`, `/enrichment`, `/hunting`, `/detection-rules`, `/analytics`, `/export`, `/audit`, `/ws`.

### 2.3 Analytics Engine (`backend/app/services/analytics_service.py`)
- Real PostgreSQL aggregations: `get_executive_kpis`, `get_trends`, `get_severity_breakdown`, `get_indicator_types`, `get_incident_analytics`, `get_mitre_analytics`, `get_geographic_density`, `get_feed_source_contributions`.
- Provides authoritative metrics across 24h, 7d, 30d, 90d intervals.

---

## 3. Gap Analysis: Missing Functionality for Phase 4E

| Requirement | Current State | Required Phase 4E Implementation |
| :--- | :--- | :--- |
| **Case Model & Persistence** | None. Incidents are clustered, but cannot be grouped into multi-incident investigation cases. | Canonical `Case` model with unique case numbers (`CASE-2026-XXXX`), title, description, severity, priority, status, assignee, owner, dates. |
| **Case Relationships** | None. | Relational link tables: `CaseIncident`, `CaseAlert`, `CaseIndicator` preserving foreign keys, source provenance, and cascade rules. |
| **Forensic Evidence Model** | None. Evidence is unstructured inside raw alert contexts. | Canonical `CaseEvidence` table recording evidence type, source entity, provider, confidence, hashes, collector, and observed timestamps. |
| **Investigator Notes** | None. | Canonical `CaseNote` table with author attribution, immutable timestamps, and safe text validation. |
| **Unified Forensic Timeline** | Only `IncidentTimeline` exists for single incidents. | Unified `CaseTimeline` table auto-capturing case creation, status changes, incident attachments, alert links, evidence additions, and notes. |
| **Incident -> Case Automation** | Incident correlation stops at `Incident`. | Deterministic hook attaching high-severity or high-score incidents to matching active cases or creating a new case without explosion. |
| **Case Management API** | None. `/api/v1/cases` is unassigned. | Full REST API at `/api/v1/cases` with search, filtering, pagination, evidence, notes, status transitions, and RBAC. |
| **Executive PDF Reporting (FR-23)** | None. Export only supports STIX 2.1 JSON and CSV indicator dumps. | Server-side PDF generation engine compiling authoritative ThreatLens metrics into a publication-grade CISO executive report. |
| **Reporting API** | None. | Canonical endpoints at `/api/v1/reports` (`/executive`, list, detail, secure download). |
| **Report Security** | N/A | Strict path traversal prevention, IDOR protection, safe sanitized filenames, and restricted storage directories. |
| **Frontend Case Workspace** | Absent. No `/dashboard/cases` route. | Next.js 16 SOC Case cockpit matching ThreatLens dark aesthetics, filtering, detail drawer, evidence manager, notes, and timeline. |
| **Frontend Reporting Action** | Missing in `/dashboard/executive`. | Interactive PDF generation trigger, status indicator, and direct authenticated download button. |

---

## 4. Required Database Models & Migrations

### 4.1 New Canonical Models (`backend/app/models/case.py` & `backend/app/models/report.py`)

1. **`Case` (`cases`):**
   - `id`: `String(36)` UUID primary key
   - `case_number`: `String(50)`, unique, indexed (`CASE-2026-XXXX`)
   - `title`: `String(255)`, not null
   - `description`: `Text`, nullable
   - `severity`: `String(50)`, default `"MEDIUM"`, indexed (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
   - `priority`: `String(50)`, default `"P2"`, indexed (`P1`, `P2`, `P3`, `P4`)
   - `status`: `String(50)`, default `"OPEN"`, indexed (`OPEN`, `IN_PROGRESS`, `CONTAINED`, `RESOLVED`, `CLOSED`)
   - `owner`: `String(100)`, nullable
   - `assignee`: `String(100)`, nullable
   - `source`: `String(100)`, default `"Manual"`
   - `tags`: `SafeJSONOrList`, default list
   - `created_by`: `String(100)`, nullable
   - `closed_by`: `String(100)`, nullable
   - `closed_at`: `DateTime`, nullable
   - `created_at`: `DateTime`, default `datetime.utcnow`, indexed
   - `updated_at`: `DateTime`, default `datetime.utcnow`, onupdate `datetime.utcnow`

2. **`CaseIncident` (`case_incidents`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `incident_id`: `String(36)` FK `incidents.id` ON DELETE CASCADE, indexed
   - `linked_at`: `DateTime`, default `datetime.utcnow`
   - `linked_by`: `String(100)`, nullable
   - UniqueConstraint(`case_id`, `incident_id`)

3. **`CaseAlert` (`case_alerts`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `alert_id`: `String(36)` FK `alerts.id` ON DELETE CASCADE, indexed
   - `linked_at`: `DateTime`, default `datetime.utcnow`
   - `linked_by`: `String(100)`, nullable
   - UniqueConstraint(`case_id`, `alert_id`)

4. **`CaseIndicator` (`case_indicators`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `indicator_id`: `String(36)` FK `indicators.id` ON DELETE CASCADE, indexed
   - `linked_at`: `DateTime`, default `datetime.utcnow`
   - `linked_by`: `String(100)`, nullable
   - UniqueConstraint(`case_id`, `indicator_id`)

5. **`CaseEvidence` (`case_evidence`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `evidence_type`: `String(100)`, not null (`INDICATOR`, `ALERT`, `INCIDENT`, `LOG`, `ENRICHMENT`, `PCAP`, `FILE_HASH`, `RULE_MATCH`)
   - `title`: `String(255)`, not null
   - `description`: `Text`, nullable
   - `source_entity`: `String(100)`, nullable
   - `source_provider`: `String(100)`, nullable
   - `reference_hash`: `String(128)`, nullable
   - `confidence`: `Integer`, default 80
   - `data`: `SafeJSONOrList`, default dict
   - `observed_at`: `DateTime`, nullable
   - `collected_at`: `DateTime`, default `datetime.utcnow`
   - `collected_by`: `String(100)`, not null
   - `created_at`: `DateTime`, default `datetime.utcnow`

6. **`CaseNote` (`case_notes`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `author`: `String(100)`, not null
   - `author_id`: `String(36)`, nullable
   - `content`: `Text`, not null
   - `created_at`: `DateTime`, default `datetime.utcnow`, indexed

7. **`CaseTimeline` (`case_timeline`):**
   - `id`: `String(36)` UUID PK
   - `case_id`: `String(36)` FK `cases.id` ON DELETE CASCADE, indexed
   - `event_type`: `String(100)`, not null
   - `title`: `String(255)`, not null
   - `details`: `Text`, nullable
   - `actor`: `String(100)`, default `"System"`
   - `created_at`: `DateTime`, default `datetime.utcnow`, indexed

8. **`Report` (`reports`):**
   - `id`: `String(36)` UUID PK
   - `report_code`: `String(50)`, unique, indexed (`RPT-2026-XXXX`)
   - `title`: `String(255)`, not null
   - `report_type`: `String(50)`, default `"EXECUTIVE_SECURITY_SUMMARY"`
   - `time_range`: `String(20)`, default `"30d"`
   - `status`: `String(50)`, default `"COMPLETED"`
   - `file_path`: `String(500)`, nullable
   - `file_name`: `String(255)`, not null
   - `file_size_bytes`: `Integer`, default 0
   - `content_hash`: `String(64)`, nullable (SHA-256)
   - `created_by`: `String(100)`, not null
   - `created_by_role`: `String(50)`, nullable
   - `generation_duration_ms`: `Integer`, default 0
   - `created_at`: `DateTime`, default `datetime.utcnow`, indexed
   - `parameters`: `SafeJSONOrList`, default dict

### 4.2 Alembic Migration
- New revision: `4e1casemgmt`
- Down revision: `4d4integrat10ns`
- Creates all 8 tables with proper foreign key cascades, unique constraints, and indexes.

---

## 5. Required API Specifications

### 5.1 Case Management API (`/api/v1/cases`)
- `GET /api/v1/cases`: List cases with filtering (`status`, `severity`, `priority`, `assignee`, `search`, `start_date`, `end_date`), pagination (`skip`, `limit`), and deterministic sorting.
- `POST /api/v1/cases`: Create a new case (Analyst+).
- `GET /api/v1/cases/{case_id}`: Retrieve case details with linked counts, incidents, alerts, indicators, evidence, notes, timeline.
- `PATCH /api/v1/cases/{case_id}`: Update mutable case fields (title, description, severity, priority, status, assignee, tags).
- `PATCH /api/v1/cases/{case_id}/status`: Validate and transition lifecycle (`OPEN -> IN_PROGRESS -> CONTAINED -> RESOLVED -> CLOSED`).
- `PATCH /api/v1/cases/{case_id}/assign`: Reassign case owner or assignee.
- `POST /api/v1/cases/{case_id}/incidents`: Link incident to case.
- `DELETE /api/v1/cases/{case_id}/incidents/{incident_id}`: Unlink incident from case.
- `POST /api/v1/cases/{case_id}/alerts`: Link alert to case.
- `DELETE /api/v1/cases/{case_id}/alerts/{alert_id}`: Unlink alert from case.
- `POST /api/v1/cases/{case_id}/indicators`: Link indicator to case.
- `DELETE /api/v1/cases/{case_id}/indicators/{indicator_id}`: Unlink indicator from case.
- `GET /api/v1/cases/{case_id}/evidence`: List forensic evidence items.
- `POST /api/v1/cases/{case_id}/evidence`: Add evidence item with provenance metadata.
- `GET /api/v1/cases/{case_id}/notes`: List append-only investigation notes.
- `POST /api/v1/cases/{case_id}/notes`: Add investigator note with author attribution.
- `GET /api/v1/cases/{case_id}/timeline`: Retrieve unified forensic chronological timeline.
- `GET /api/v1/cases/{case_id}/audit`: Retrieve case-specific immutable audit records.

### 5.2 Reporting API (`/api/v1/reports`)
- `POST /api/v1/reports/executive`: Generate an Executive Security Report PDF for a specified time range (`24h`, `7d`, `30d`, `90d`).
- `GET /api/v1/reports`: List generated reports with metadata (title, report_code, status, size, author, timestamp).
- `GET /api/v1/reports/{report_id}`: Retrieve single report metadata.
- `GET /api/v1/reports/{report_id}/download`: Download PDF binary safely (Content-Disposition attachment, application/pdf).

---

## 6. Executive PDF Reporting Engine Architecture

The PDF report generator is implemented server-side in Python (`backend/app/services/pdf_report_service.py`):
1. **Data Aggregation:** Direct reuse of `analytics_service.py` methods and authoritative queries from `Indicator`, `Alert`, `Incident`, `Case`, `DetectionRule`, `IndicatorEnrichment`.
2. **Dual PDF Rendering Engine:**
   - Primary: `reportlab` (Platypus flowables, ParagraphStyle, Table, TableStyle, PageBreak).
   - Secondary / Standalone Fallback: High-precision pure-Python compliant PDF generator producing valid PDF 1.4 syntax with binary streams, catalog dictionary, font mappings, and vector layout.
3. **Structured Content & Sections:**
   - 1. Title / Metadata Banner (TLP:AMBER, Report Reference, Generation Date, Author)
   - 2. Executive Summary (Grounded synthesis of exposure and risk)
   - 3. Reporting Period (Explicit UTC interval)
   - 4. Overall Security Posture (Risk index, active indicators, feeds)
   - 5. Incident Overview (Volume, open vs closed, MTTR)
   - 6. Severity Distribution (Severity tier breakdown table)
   - 7. Critical and High Severity Incidents (Table of active critical/high incidents)
   - 8. Case Overview (Investigation cases, active investigations)
   - 9. Top Threat Indicators (Authoritative high-score IOCs)
   - 10. Detection Rule Activity (Rules matched and routing queues)
   - 11. Alert Summary (Alerts by status and destination queue)
   - 12. MITRE ATT&CK Summary (Top techniques observed in real alerts/incidents)
   - 13. Threat Intelligence / Enrichment Summary (Provider breakdown and verdicts)
   - 14. Geographic Threat Summary (Country code threat distribution)
   - 15. Major Findings (Concrete operational findings from active data)
   - 16. Recommended Actions (Prescriptive mitigations)
   - 17. Report Generation Metadata (SHA-256 fingerprint, execution duration, audit trail)
4. **Honest Empty States:** Sections with no telemetry render `"No data available for the selected reporting period."` Zero synthetic counts or mock names.

---

## 7. Security & Governance Architecture

1. **Server-Side RBAC (`RoleChecker`):**
   - `Viewer`: Read-only for cases (`GET /cases`), read-only for report metadata. Cannot create/modify cases or generate reports (returns `403 Forbidden`).
   - `Analyst` / `Incident Responder` / `Threat Hunter`: Full investigation permissions, case creation, status transition, evidence attachment, note addition, and report generation.
   - `Administrator`: SuperSet permissions, full case management, hard deletion if ever needed.
2. **Path Traversal & Storage Isolation:**
   - Reports stored in strict, isolated local directory: `backend/app/reports_storage/`.
   - File retrieval validates filename using strict regex and verifies that the canonical resolved path (`os.path.realpath`) resides within the designated storage directory. Rejection of `..`, `/`, `\`.
3. **IDOR Defense:**
   - All report and case references use UUID4 identifiers or deterministic indexed codes.
   - Authorization checked on every download and detail endpoint.
4. **Audit Immutability:**
   - State-changing actions (`CASE_CREATED`, `CASE_STATUS_CHANGED`, `CASE_ASSIGNED`, `EVIDENCE_ADDED`, `NOTE_ADDED`, `INCIDENT_LINKED`, `REPORT_GENERATED`, `REPORT_DOWNLOADED`) write immediately to `AuditLog`.
5. **Redis Pub/Sub Events:**
   - Events emitted to `threatlens:events:cases` and `threatlens:events:reports`.

---

## 8. Frontend Implementation Architecture

1. **New Route `/dashboard/cases` (`frontend/src/app/dashboard/cases/page.tsx`):**
   - High-density SOC Case Cockpit matching ThreatLens design system (`#0b1220`, `#080d19`, border-slate-800, cyan/purple/amber badges).
   - Filter bar: Status tabs, Severity dropdown, Priority filter, Assignee filter, Text search.
   - Case Cards / Table: Case number, Title, Severity, Priority, Status, Assignee, Linked counts, Timestamps.
   - "New Case" modal with validation.
   - Comprehensive Case Detail Drawer:
     - Header with status transition buttons.
     - Tabs: Overview, Linked Incidents, Linked Alerts, Indicators, Evidence, Notes, Timeline, Audit.
     - Evidence submission form & Notes submission form.
2. **Executive Reporting Integration (`frontend/src/app/dashboard/executive/page.tsx`):**
   - Executive PDF Briefing card with time range selection (`24h`, `7d`, `30d`, `90d`).
   - "Generate Executive Report (PDF)" button.
   - Real-time generation feedback and one-click direct PDF download.
3. **Navigation Integration (`Navbar.tsx` & `RoleContext.tsx`):**
   - Add "Cases" (`/dashboard/cases`, icon `📁`) to navigation and persona tabs.

---

## 9. Implementation Plan

1. **Database Models & Alembic Migration:**
   - Create `backend/app/models/case.py` and `backend/app/models/report.py`.
   - Update `backend/app/models/__init__.py`.
   - Create migration `4e1casemgmt_phase4e_case_management_and_reporting.py`.
2. **Services & Core Logic:**
   - `backend/app/services/case_service.py` (case CRUD, lifecycle, evidence, notes, timeline, automated incident clustering).
   - `backend/app/services/pdf_report_service.py` (authoritative metrics compilation and PDF generation).
   - Update `backend/app/core/redis.py` with case and report event helpers.
   - Update `backend/app/core/config.py` with case and report channels.
3. **API Endpoints:**
   - `backend/app/api/v1/endpoints/cases.py` (`/api/v1/cases`).
   - `backend/app/api/v1/endpoints/reports.py` (`/api/v1/reports`).
   - Register in `backend/app/api/v1/api.py`.
4. **Automated Incident -> Case Workflow:**
   - Integrate `link_or_create_case_for_incident` in `correlation_service.py`.
5. **Frontend Implementation:**
   - Add case and report methods in `frontend/src/lib/api.ts`.
   - Create `frontend/src/app/dashboard/cases/page.tsx`.
   - Update `frontend/src/app/dashboard/executive/page.tsx`.
   - Update `frontend/src/components/Navbar.tsx` and `frontend/src/context/RoleContext.tsx`.
6. **Testing & QA:**
   - Create comprehensive test suite `backend/tests/test_phase4e_cases_and_reports.py`.
   - Verify RBAC, security, path traversal, IDOR, empty data, large data, timeline.
   - Run full regression.
7. **Documentation & Checkpoints:**
   - `PHASE_4E_IMPLEMENTATION_REPORT.md`
   - `PHASE_4E_QA_REPORT.md`
   - Update `THREATLENS_IMPLEMENTATION_AUDIT.md`.
   - Final Git checkpoint and commit.

---
**Status:** AUDIT & BASELINE COMPLETE. PROCEEDING TO IMPLEMENTATION AUTOMATICALLY.
