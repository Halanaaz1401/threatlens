# ThreatLens — Phase 4A Forensic Baseline & Architecture Plan
**Phase 4A: Advanced Threat Correlation & Incident Engine**
**Timestamp:** 2026-10-01T18:52:00Z
**Git Head:** `557a422 checkpoint: ThreatLens before Phase 4A correlation engine`

---

## 1. Existing Incident Architecture
- **Model Location:** `backend/app/models/incident.py`
- **Existing Entities:**
  - `Incident`: `id`, `title`, `description`, `severity` (Enum: LOW, MEDIUM, HIGH, CRITICAL), `status` (Enum: OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED), `assignee`, `indicator_id`, `matched_ioc_value`, `created_at`, `updated_at`.
  - `IncidentTimeline`: `id`, `incident_id`, `action`, `details`, `actor`, `created_at`.
  - `SecurityEvent`: raw internal telemetry log entity (`source_ip`, `destination_ip`, `domain`, `file_hash`, `event_type`, `raw_log`, `timestamp`).
- **Gaps identified:**
  - Lacks `incident_code` (e.g. `INC-2026-XXXX`).
  - Lacks `correlation_score` (SmallInteger).
  - Lacks temporal boundary tracking: `first_seen`, `last_seen`.
  - Lacks metadata: `primary_indicator`, `primary_source`, `mitre_techniques` (JSON/list), `affected_host`.
  - Lacks direct foreign key or association model to `Alert`.
  - Status enum lacks `ACKNOWLEDGED` and `IN_PROGRESS` (currently has `INVESTIGATING` and `CONTAINED`). Status model must support `OPEN`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `CLOSED` with backward-compatible aliases for `INVESTIGATING` and `CONTAINED`.

## 2. Existing Alert Architecture
- **Model Location:** `backend/app/models/alert.py`
- **Fields:** `id`, `alert_code`, `title`, `description`, `severity`, `severity_score`, `status`, `indicator_id`, `indicator_value`, `rule_name`, `assignee`, `source`, `mitre_technique`, `internal_sightings_count`, `internal_host`, `context`, `created_at`, `updated_at`.
- **Alert Generation:** `backend/app/services/alert_service.py` evaluates indicators with `threat_score >= 60` or severity HIGH/CRITICAL. Deduplicates against open alerts for the same indicator. Publishes to Redis `threatlens:events:alerts`.
- **Gaps identified:**
  - `Alert` has no reference to `incident_id`.
  - `AlertService` does not trigger correlation or incident creation/updating.

## 3. Existing IOC Architecture
- **Model Location:** `backend/app/models/indicator.py`
- **Fields:** `id`, `value`, `type`, `threat_score`, `severity_score`, `severity`, `confidence`, `source`, `sightings`, `tlp`, `status`, `tags`, `context`, `mitre_technique`, `first_seen`, `last_seen`, `created_at`, `updated_at`.
- **Provenance:** `IndicatorSource` entity records multi-feed sources and confidence levels.

## 4. Existing Relationships
- `Indicator` 1-to-many `Alert` (`Alert.indicator_id` -> `Indicator.id`).
- `Indicator` 1-to-many `IndicatorSource` (`IndicatorSource.indicator_id` -> `Indicator.id`).
- `Incident` 1-to-many `IncidentTimeline` (`IncidentTimeline.incident_id` -> `Incident.id`).
- **Missing:**
  - `Incident` 1-to-many `Alert` (`Alert.incident_id` -> `Incident.id`), and `incident_alerts` table for explicit audit linkage.

## 5. Existing API Endpoints
- `GET /api/v1/incidents/`: List incidents with status filtering and pagination.
- `GET /api/v1/incidents/{incident_id}/timeline`: Retrieve incident timeline.
- `PATCH /api/v1/incidents/{incident_id}`: Generic status update.
- `POST /api/v1/incidents/correlate-event`: Legacy raw event correlation stub.
- **Missing Endpoints Required by Step 11:**
  - `GET /api/v1/incidents/{incident_id}`: Detailed single incident view.
  - `GET /api/v1/incidents/{incident_id}/alerts`: List all alerts linked to the incident.
  - `PATCH /api/v1/incidents/{incident_id}/status`: Controlled status transition with strict validation.
  - `PATCH /api/v1/incidents/{incident_id}/severity`: Manual or analyst-adjusted severity update with audit.
  - Rich filtering: `severity`, `status`, `mitre_technique`, `source`, `affected_host`, `min_score`, `time range`.

## 6. Existing Redis Events
- `REDIS_ALERT_CHANNEL = "threatlens:events:alerts"`
- Emits `NEW_ALERT` / `NEW_CRITICAL_ALERT`.
- **Missing Events Required by Step 10:**
  - `INCIDENT_CREATED`
  - `INCIDENT_UPDATED`
  - `INCIDENT_SEVERITY_CHANGED`
  - `INCIDENT_RESOLVED`
  - Published to `threatlens:events:incidents` and also forwarded to WebSocket alert/incident subscribers.

## 7. Existing Gaps Summary
1. No explainable, multi-dimensional correlation engine.
2. No configurable correlation window (`CORRELATION_WINDOW_MINUTES=15`).
3. No weighted correlation scoring model.
4. No automated incident clustering from new alerts.
5. Incomplete incident columns and status model.
6. No Alert -> Incident foreign key.
7. No timeline generation from real correlation events.
8. No severity/risk propagation rules.
9. No concurrency locks for race condition prevention on concurrent alert ingestion.
10. Missing Alembic migration for new columns and relations.

---

## 8. Exact Phase 4A Implementation Plan

### Phase 4A.1: Core Configuration & Schema Extensions
1. Add `CORRELATION_WINDOW_MINUTES: int = 15` and `REDIS_INCIDENT_CHANNEL: str = "threatlens:events:incidents"` in `backend/app/core/config.py`.
2. Extend `Incident` in `backend/app/models/incident.py`:
   - `incident_code` (e.g. `INC-2026-XXXX`, unique, indexed)
   - `correlation_score` (SmallInteger, default 0)
   - `first_seen` (DateTime, default utcnow)
   - `last_seen` (DateTime, default utcnow)
   - `primary_indicator` (String 500)
   - `primary_source` (String 100)
   - `mitre_techniques` (SafeJSONOrList)
   - `affected_host` (String 100)
   - Status model: `OPEN`, `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `CLOSED` (with `INVESTIGATING` and `CONTAINED` mapped as valid aliases).
3. Extend `Alert` in `backend/app/models/alert.py`:
   - Add `incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)`.
   - Add relationship `incident = relationship("Incident", back_populates="alerts")`.
   - Add relationship `Incident.alerts = relationship("Alert", back_populates="incident", order_by="Alert.created_at.desc()")`.
4. Create Alembic Migration:
   - Generate revision `4a1c0rre1at1_phase4a_correlation_and_incidents.py`.
   - Apply columns cleanly to PostgreSQL.

### Phase 4A.2: Correlation Engine (`backend/app/services/correlation_service.py`)
1. Multi-dimensional deterministic correlation evaluation:
   - Dimension 1: Exact IOC match (`indicator_id` or `indicator_value`).
   - Dimension 2: Normalized IOC match (domain/IP/hash canonical form).
   - Dimension 3: Affected host / internal asset match (`internal_host`).
   - Dimension 4: MITRE ATT&CK technique match (`mitre_technique`).
   - Dimension 5: Source feed match (`source`).
   - Dimension 6: Temporal proximity (within `CORRELATION_WINDOW_MINUTES`).
2. Scoring:
   - Same IOC / Normalized IOC: +40 points.
   - Same Affected Host: +30 points.
   - Same MITRE Technique: +20 points.
   - Same Threat Source: +10 points.
   - Temporal Proximity (decay within window): +15 points.
   - Threshold for clustering into existing active incident: `correlation_score >= 50` AND within time window.
3. Explicit explanation generation:
   - E.g.: `"Correlated because: same IOC (185.220.101.4); same MITRE technique (T1071); activity within 12-minute window"`
4. Concurrency & Idempotency:
   - Use database-level row locking (`with_for_update`) on candidate incidents during evaluation to prevent concurrent alerts from creating duplicate incidents.

### Phase 4A.3: Incident Lifecycle & Timeline Management
1. Status transition validator:
   - `OPEN` -> `ACKNOWLEDGED`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`.
   - `ACKNOWLEDGED` -> `IN_PROGRESS`, `RESOLVED`, `CLOSED`.
   - `IN_PROGRESS` -> `RESOLVED`, `CLOSED`, `ACKNOWLEDGED`.
   - `RESOLVED` -> `CLOSED`, `OPEN` (re-opened).
   - `CLOSED` -> `OPEN` (re-opened).
   - Reject invalid transitions with 400 Bad Request.
2. Severity propagation:
   - Calculate maximum severity among attached alerts and threat scores.
   - If multiple HIGH alerts (>= 2) or any CRITICAL alert or affected host match + high score, promote incident to `CRITICAL`.
   - Never downgrade incident severity automatically if a lower severity alert attaches.
3. Timeline recorder:
   - Record `INCIDENT_CREATED`, `ALERT_ATTACHED`, `SEVERITY_ESCALATED`, `STATUS_CHANGED`, `NOTE_ADDED`.
   - Record immutable audit logs for all transitions.

### Phase 4A.4: Alert Integration & Redis Event Fan-out
1. In `alert_service.py`:
   - After `new_alert` is persisted, invoke `correlate_alert_to_incident(db, new_alert)`.
   - Attach alert to existing matching open incident or create new incident.
   - Emit Redis events:
     - `INCIDENT_CREATED` when new incident is formed.
     - `INCIDENT_UPDATED` when alert is attached.
     - `INCIDENT_SEVERITY_CHANGED` when severity increases.
     - `INCIDENT_RESOLVED` on resolution.
   - Broadcast events across `threatlens:events:incidents` and `threatlens:events:alerts`.

### Phase 4A.5: API Endpoints
1. Implement full suite in `backend/app/api/v1/endpoints/incidents.py`:
   - `GET /api/v1/incidents`: filtering by `severity`, `status`, `mitre_technique`, `source`, `affected_host`, `min_score`, `start_time`, `end_time`.
   - `GET /api/v1/incidents/{incident_id}`: single incident with alert counts and summary.
   - `GET /api/v1/incidents/{incident_id}/timeline`: sorted chronological timeline.
   - `GET /api/v1/incidents/{incident_id}/alerts`: alerts attached to this incident.
   - `PATCH /api/v1/incidents/{incident_id}/status`: strict status transition endpoint.
   - `PATCH /api/v1/incidents/{incident_id}/severity`: manual severity update.

### Phase 4A.6: Testing & Verification
1. `backend/tests/test_phase4a_correlation.py`: all 20 specified test scenarios.
2. Full pytest suite run (`pytest -v`).
3. Live Docker runtime verification with PostgreSQL, Redis, Elasticsearch, Backend, Frontend.
