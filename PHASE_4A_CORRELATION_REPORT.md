# THREATLENS — PHASE 4A: ADVANCED THREAT CORRELATION & INCIDENT ENGINE REPORT

**Target Repository:** `Halanaaz1401/threatlens`  
**Execution Date:** October 2026  
**Status:** COMPLETE  
**Correlation Engine:** PASS  
**Incident Engine:** PASS  
**Incident Timeline:** PASS  
**Redis Incident Events:** PASS  
**Security:** PASS  
**Database Migration:** PASS  
**Tests:** 63 passed / 0 failed  
**Runtime E2E:** PASS  

---

## 1. Baseline Findings

Prior to Phase 4A implementation, a forensic audit of the ThreatLens system was conducted (documented in `PHASE_4A_BASELINE_REPORT.md`):
- **Incident & Alert Models:** An initial `Incident` model existed in `backend/app/models/incident.py`, and `Alert` existed in `backend/app/models/alert.py`. However, alerts were not linked to incidents (`incident_id` foreign key was missing), incidents lacked deterministic clustering columns (`incident_code`, `correlation_score`, `primary_indicator`, `primary_source`, `mitre_techniques`, `affected_host`, `first_seen`, `last_seen`), and PostgreSQL enums caused database transaction failures on new lifecycle statuses (`ACKNOWLEDGED`, `IN_PROGRESS`).
- **Correlation Service:** An unmounted prototype in `backend/app/services/correlation_service.py` attempted to compare internal `SecurityEvent` models against indicators with broken imports (`ThreatSeverity`), lacking explainable multi-dimensional scoring and integration with incoming alert streams.
- **Alert Generation Pipeline:** `AlertService.evaluate_and_alert()` persisted alerts to PostgreSQL and published them to Redis Pub/Sub (`threatlens:events:alerts`), but treated every alert in isolation without clustering or incident creation.
- **Frontend Dashboard:** `frontend/src/app/dashboard/incidents/page.tsx` rendered static markup and hardcoded data for `INC-2026-0815` rather than consuming live backend APIs.

---

## 2. Architecture

Phase 4A introduces an automated, explainable, deterministic correlation and incident management architecture:

```
REAL THREAT FEED (URLhaus, ThreatFox, Feodo, MalwareBazaar, CISA KEV, AlienVault OTX)
        ↓
INGESTION & CANONICAL NORMALIZATION
        ↓
INDICATOR DEDUPLICATION & PROVENANCE (PostgreSQL)
        ↓
THREAT SCORING (scoring.py)
        ↓
ALERT GENERATION (AlertService)
        ↓
DETERMINISTIC CORRELATION ENGINE (CorrelationService)
  ├── Search Open Incidents within Window (CORRELATION_WINDOW_MINUTES = 15)
  ├── Multi-Dimensional Signal Evaluation & Explainable Scoring
  ├── Concurrency Control: PostgreSQL SELECT ... FOR UPDATE (Row-Locking)
  └── Cluster into Existing Incident OR Create Canonical Incident
        ↓
SEVERITY PROPAGATION & FORENSIC TIMELINE CREATION (IncidentTimeline)
        ↓
IMMUTABLE AUDIT LOG (AuditLog)
        ↓
REDIS PUB/SUB EVENT BROADCAST (`threatlens:events:incidents`, `threatlens:events:alerts`)
        ↓
AUTHENTICATED WEBSOCKET (`/api/v1/ws/alerts`)
        ↓
NEXT.JS SOC INCIDENT WORKSPACE (`/dashboard/incidents`)
```

---

## 3. Correlation Rules

The correlation engine evaluates alerts across 6 deterministic, explainable dimensions:

1. **Indicator Exact Match (`same_indicator_value`):**
   Matches alert IOC value with the incident's primary indicator or any previously correlated alert in the incident.
2. **Normalized IOC Value Match (`same_normalized_ioc`):**
   Matches normalized representations (e.g. lowercase stripped URLs, domains, stripped IP port representations).
3. **Internal Host / Asset Match (`same_host`):**
   Matches `internal_host` or internal network asset targets across alerts and incidents.
4. **MITRE ATT&CK Technique Match (`same_mitre_technique`):**
   Matches MITRE technique identifiers (e.g., `T1059`, `T1566`, `T1190`) between incoming alert and existing incidents.
5. **Threat Source Match (`same_source`):**
   Matches threat feed origin or detection engine provenance (e.g., `urlhaus`, `threatfox`, `cisa_kev`).
6. **Temporal Proximity:**
   Enforces a configurable sliding time window (`CORRELATION_WINDOW_MINUTES = 15`, default) from the incident's `last_seen` timestamp. Alerts occurring beyond this boundary spawn a new distinct incident cluster.

Every correlation decision produces an explicit, human-readable forensic explanation array, e.g.:
```
[
  "Same indicator: 198.51.100.22",
  "Same MITRE ATT&CK technique: T1059",
  "Temporal proximity: alert within 15-minute window"
]
```

---

## 4. Correlation Scoring

Correlation confidence is calculated using weighted deterministic signals:

| Correlation Signal | Weight | Justification |
| :--- | :---: | :--- |
| **Exact Indicator Match** | `+40` | Strongest evidence of identical adversary infrastructure. |
| **Internal Asset / Host Match** | `+30` | Strong evidence of same internal endpoint under targeted attack. |
| **MITRE ATT&CK Technique Match** | `+20` | Demonstrates shared tactic, technique, or procedural fingerprint. |
| **Temporal Proximity** | `+15` | Rapid succession of alerts indicates coordinated threat wave. |
| **Threat Source Match** | `+10` | Identical detection feed or telemetry source context. |

- **Clustering Threshold:** `50` points minimum. Alerts scoring $\ge 50$ are clustered into the existing incident. Alerts scoring $< 50$ instantiate a new canonical incident.
- **Score Cap:** Deterministically clamped to $[0, 100]$.
- **Explainability:** Transparent mathematical calculation without non-deterministic black-box heuristics or opaque LLM hallucinations.

---

## 5. Incident Model

The `Incident` model in `backend/app/models/incident.py` has been consolidated and mapped with:

- `id`: Native UUID (Postgres) / String(36) UUID (SQLite) primary key.
- `incident_code`: Sequential human-readable SOC identifier (e.g. `INC-2026-0001`).
- `title`: Descriptive SOC summary title.
- `description`: Structured narrative detailing the correlated attack vectors.
- `severity`: Standardized string enum (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `status`: Standardized string enum (`OPEN`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`).
- `correlation_score`: Integer $[0, 100]$ tracking correlation confidence.
- `first_seen`: Datetime of the earliest associated telemetry alert.
- `last_seen`: Datetime of the most recent associated telemetry alert.
- `primary_indicator`: Canonical IOC initiating or dominating the incident.
- `primary_source`: Primary feed or engine providing telemetry.
- `mitre_techniques`: JSON array of all MITRE techniques observed across alerts.
- `affected_host`: Internal host or endpoint asset associated with the incident.
- `assigned_to_id`: Foreign key reference to investigating user.
- `alerts`: One-to-many relationship linking `Alert` records via `Alert.incident_id`.
- `timeline`: One-to-many relationship linking `IncidentTimeline` entries.

---

## 6. Incident Lifecycle

A strict server-side state machine validates all incident status transitions via `is_valid_status_transition()`:

| Current Status | Allowed Target Statuses |
| :--- | :--- |
| **OPEN** | `ACKNOWLEDGED`, `IN_PROGRESS`, `CLOSED` |
| **ACKNOWLEDGED** | `IN_PROGRESS`, `RESOLVED`, `CLOSED` |
| **IN_PROGRESS** | `RESOLVED`, `CLOSED` |
| **RESOLVED** | `CLOSED`, `IN_PROGRESS` (reopened on new escalation) |
| **CLOSED** | *(Terminal; cannot transition directly)* |

Invalid status mutations (e.g. client attempting `CLOSED -> OPEN` or `OPEN -> RESOLVED` without acknowledgment) are rejected server-side with HTTP 400 Bad Request.

---

## 7. Timeline Architecture

The `IncidentTimeline` model (`backend/app/models/incident.py`) records real forensic progression events:
- **`INCIDENT_CREATED`**: Logged immediately upon initial incident synthesis.
- **`ALERT_CORRELATED`**: Logged when a subsequent alert is attached, recording the alert ID, indicator, and correlation score.
- **`SEVERITY_ESCALATED`**: Logged when incoming evidence triggers automatic severity increase.
- **`STATUS_CHANGED`**: Logged when an analyst changes incident status.
- **`INCIDENT_RESOLVED`**: Logged when investigation is marked resolved.

Every timeline record originates strictly from database operations and immutable audit events, completely eliminating fabricated or synthetic timeline entries.

---

## 8. Severity / Risk Propagation

Incident severity is dynamically computed from cumulative correlated evidence via `derive_incident_severity()`:
- $\ge 2$ `HIGH` alerts $\implies$ Incident elevated to `CRITICAL`.
- $\ge 1$ `CRITICAL` alert $\implies$ Incident elevated to `CRITICAL`.
- $\ge 2$ `MEDIUM` alerts $\implies$ Incident elevated to `HIGH`.
- 1 `HIGH` alert $\implies$ Incident set to `HIGH`.
- 1 `MEDIUM` alert $\implies$ Incident set to `MEDIUM`.
- Otherwise: `LOW`.

**Non-Downgrade Invariant:** An incident's severity is never automatically downgraded when a subsequent alert with lower severity is correlated.

---

## 9. API Changes

Canonical REST endpoints in `backend/app/api/v1/endpoints/incidents.py`:
- `GET /api/v1/incidents`: Supports rich SOC filtering (`status`, `severity`, `mitre_technique`, `source`, `affected_host`, `min_score`, `time_from`, `time_to`, pagination).
- `GET /api/v1/incidents/{incident_id}`: Retrieves single incident with full metadata and alert count.
- `GET /api/v1/incidents/{incident_id}/timeline`: Retrieves ordered forensic timeline.
- `GET /api/v1/incidents/{incident_id}/alerts`: Retrieves all alerts clustered under this incident.
- `PATCH /api/v1/incidents/{incident_id}/status`: Updates status with state machine validation, timeline logging, and audit tracking (requires `analyst` or `admin` role).
- `PATCH /api/v1/incidents/{incident_id}/severity`: Updates severity with audit logging and timeline tracking (requires `analyst` or `admin` role).

---

## 10. Redis Events

Structured incident events are published to Redis channels `threatlens:events:incidents` and `threatlens:events:alerts`:
- **`INCIDENT_CREATED`**: Broadcasts new incident code, title, severity, score, and initial alert ID.
- **`INCIDENT_UPDATED`**: Broadcasts updated alert list, last_seen, and correlation score.
- **`INCIDENT_SEVERITY_CHANGED`**: Broadcasts severity elevation with underlying evidence.
- **`INCIDENT_RESOLVED`**: Broadcasts resolution timestamp and status.

---

## 11. Database Migration

Alembic migration `4a1c0rre1at1_phase4a_correlation_and_incidents.py` (`Revises: 3f89a12c4b5e`):
- Added `incident_id` foreign key to `alerts` table.
- Added correlation and forensic columns to `incidents` table.
- Converted PostgreSQL enum columns `status` and `severity` to `VARCHAR(50)` for flexibility and cross-database stability.
- Verified both `alembic upgrade head` and `alembic downgrade -1` clean execution against PostgreSQL 16 container.

---

## 12. Security Controls

- **Authentication & RBAC:** All endpoints require valid JWT authentication. State mutations require `analyst` or `admin` roles via `require_analyst`.
- **Database Row-Level Locking:** Candidate search uses PostgreSQL `SELECT ... FOR UPDATE` to prevent race conditions during high-volume ingestion.
- **Audit Immutability:** All incident state mutations are recorded via `log_action()` to PostgreSQL with engine-level triggers preventing modification.
- **Input Validation:** Pydantic schemas enforce type safety and reject invalid statuses or arbitrary parameters.

---

## 13. Test Results

Created `backend/tests/test_phase4a_correlation.py` covering all 20 required test scenarios:
1. `test_same_ioc_correlates`: PASS
2. `test_different_ioc_does_not_incorrectly_correlate`: PASS
3. `test_same_host_correlation`: PASS
4. `test_same_mitre_technique_correlation`: PASS
5. `test_temporal_correlation`: PASS
6. `test_correlation_window_boundary`: PASS
7. `test_correlation_score_calculation`: PASS
8. `test_new_incident_creation`: PASS
9. `test_existing_incident_reuse`: PASS
10. `test_multiple_alerts_attach_to_one_incident`: PASS
11. `test_incident_severity_propagation`: PASS
12. `test_incident_status_transitions`: PASS
13. `test_invalid_status_transition_rejected`: PASS
14. `test_incident_timeline_contains_real_events`: PASS
15. `test_redis_incident_created_event`: PASS
16. `test_redis_incident_updated_event`: PASS
17. `test_rbac_enforcement`: PASS
18. `test_unauthorized_incident_access_rejected`: PASS
19. `test_no_duplicate_incidents_under_repeated_ingestion`: PASS
20. `test_full_end_to_end_ioc_to_incident`: PASS

**Full Backend Test Suite Execution:**
```
============================== 63 passed in 10.42s ==============================
```
(43 previous tests from Phases 1A–3 + 20 Phase 4A tests; 0 failed, 0 skipped).

---

## 14. Runtime Verification

Executed end-to-end verification script `backend/scripts/verify_runtime_phase4a.py` against live running Docker stack:
- **Authentication:** Admin login succeeded with valid JWT access token.
- **WebSocket Gateway:** Authenticated connection to `/api/v1/ws/alerts` established.
- **Ingestion Alert 1:** First IOC (`93.184.216.34`, score 90) ingested $\implies$ Triggered `NEW_ALERT` + `INCIDENT_CREATED` (`INC-2026-0001`).
- **Ingestion Alert 2:** Related IOC URL with same host (`hxxp://93.184.216.34/beacon.bin`) ingested within 15-minute window $\implies$ Correlated to `INC-2026-0001` (Score: 73, Alerts: 2).
- **Severity Escalation:** Correlated evidence escalated incident severity to `CRITICAL` $\implies$ Redis emitted `INCIDENT_SEVERITY_CHANGED`.
- **Status Lifecycle:** Transitioned from `OPEN` to `ACKNOWLEDGED` $\implies$ API returned HTTP 200, timeline updated.
- **Concurrency & Idempotency:** Verified exactly 1 incident created for the cluster, 0 duplicates.

---

## 15. Known Limitations

- Multi-tenant enterprise scoping (organization partitioning) is deferred to future enterprise hardening.
- Graph visualization of correlated IOC relationships (`FR-09`) is deferred to Phase 4C.
- Third-party enrichment APIs (VirusTotal, AbuseIPDB) are excluded per explicit Phase 4A instructions.

---

## 16. Files Changed & Git Commit

### Modified Files:
- `backend/app/core/config.py`: Added `CORRELATION_WINDOW_MINUTES = 15`.
- `backend/app/core/redis.py`: Added `publish_incident_event()`.
- `backend/app/core/websocket.py`: Fixed local vs Redis subscriber race condition.
- `backend/app/models/alert.py`: Added `incident_id` foreign key and relation; removed default internal host.
- `backend/app/models/incident.py`: Added forensic clustering columns, timeline model, and lifecycle validator.
- `backend/app/services/alert_service.py`: Integrated `correlate_alert_to_incident()`.
- `backend/app/services/correlation_service.py`: Implemented deterministic scoring and clustering engine.
- `backend/app/api/v1/endpoints/incidents.py`: Updated endpoints with RBAC and SOC filtering.
- `backend/alembic/env.py`: Included `incident` model in autogenerate metadata.
- `frontend/src/lib/api.ts`: Added `safeFetchIncidents()` and `safeFetchIncidentTimeline()`.
- `frontend/src/app/dashboard/incidents/page.tsx`: Connected UI to live backend API.
- `THREATLENS_IMPLEMENTATION_AUDIT.md`: Updated FR-16 and FR-19 status to REAL.

### Created Files:
- `PHASE_4A_BASELINE_REPORT.md`: Baseline forensic assessment.
- `backend/alembic/versions/4a1c0rre1at1_phase4a_correlation_and_incidents.py`: Database migration.
- `backend/tests/test_phase4a_correlation.py`: 20 unit and integration tests.
- `backend/scripts/verify_runtime_phase4a.py`: Live runtime verification script.
- `PHASE_4A_CORRELATION_REPORT.md`: This comprehensive report.

**Git Checkpoint Commit:** `557a422 checkpoint: ThreatLens before Phase 4A correlation engine`  
**Phase 4A Feature Commit:** `feat: implement Phase 4A threat correlation and incident engine`
