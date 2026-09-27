# THREATLENS — PHASE 3: REAL-TIME TELEMETRY, INGESTION & REDIS EVENT FAN-OUT
## FORENSIC BASELINE AUDIT REPORT

**Date:** September 2026  
**Auditor:** ThreatLens Senior Security & Infrastructure Engineering  
**Target Repository:** `Halanaaz1401/threatlens`  
**Git Working Tree:** `C:\Users\Hala\Downloads\Project Files\threatlens-main\threatlens-main-git`  
**Baseline Git Checkpoint:** `afd7f5e` (`checkpoint: ThreatLens before Phase 3 realtime telemetry`)  
**Prerequisites:** Phase 0 (Audit), Phase 1A (Consolidation), Phase 1B (Security Hardening), Phase 2 (Infrastructure & Persistence) verified.

---

## 1. Executive Summary

Phase 2 established the containerized multi-tier backing persistence and infrastructure:
- PostgreSQL 16 persistence with SQLAlchemy connection pooling (`QueuePool`).
- Database-level audit log immutability triggers on PostgreSQL and SQLite.
- Redis 7 integration for JWT revocation (`jti` claim).
- Elasticsearch 8.x index mappings and full-text search with database fallback.
- Unified `/health` and `/health/ready` operational health probes.
- 35/35 passing pytest tests and 12/12 passing security verifications.

However, the **telemetry and ingestion pipelines remain partially decoupled and simulated**:
1. Ingestion of threat feeds in `backend/app/services/ingestion.py` relies on hardcoded static lists for AlienVault OTX and CISA KEV feeds, and does not record multi-source provenance (`IndicatorSource`).
2. While `backend/app/services/feed_service.py` fetches 4 real feeds (URLhaus, ThreatFox, Feodo, MalwareBazaar) and calls `evaluate_ioc_for_alerts()`, alerts are only broadcast via an in-memory FastAPI WebSocket list in `ConnectionManager`—completely bypassing the Redis message broker.
3. The WebSocket endpoints (`/ws/alerts` and `/api/v1/ws/alerts`) are secured with JWTs (rejecting unauthorized handshakes with code 1008), but their event loops are idle listeners (`while True: await websocket.receive_text()`) that do not subscribe to Redis channels or fan out broker events.
4. On the frontend, `frontend/src/app/dashboard/analyst/page.tsx` connects to `ws://127.0.0.1:8000/ws/alerts` without passing the authentication token (`?token=...`), causing legitimate connections to be rejected with 1008; it also falls back to a 6-item `defaultFallbackIOCs` array upon fetch failure. `AlertQueue.tsx` contains static `mockAlerts` and is currently unmounted.

**Phase 3 Objective:** Eliminate all simulations in the production path, connect a robust 6-source ingestion pipeline to PostgreSQL, generate real alerts based on deterministic threat threshold rules, publish alerts to Redis Pub/Sub channel `threatlens:events:alerts`, subscribe WebSocket workers to Redis to fan out real-time alerts to authenticated clients, and connect the frontend to the authenticated live stream.

---

## 2. Current Architecture Forensic Analysis

### 2.1 Ingestion Architecture
- **Active Files:**
  - `backend/app/services/ingestion.py`: Defines 6 feeds, but AlienVault OTX (`fetch_alienvault_otx`) and CISA KEV (`fetch_cisa_kev`) are hardcoded static lists.
  - `backend/app/services/feed_service.py`: Defines 4 feeds (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar) using `httpx.AsyncClient`. Includes helper `_save_and_index_ioc()` that upserts into `Indicator` and calls `evaluate_ioc_for_alerts()`.
  - `backend/app/api/v1/endpoints/feeds.py`: Exposes `GET /api/v1/feeds/` and `POST /api/v1/feeds/fetch` (restricted to Security Engineer+).
- **Gaps & Defects:**
  - AlienVault OTX and CISA KEV are not included in `feed_service.py`. CISA KEV can be pulled from the real CISA official JSON catalog (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
  - No `IndicatorSource` provenance records are saved when an indicator is sighted across multiple feeds.
  - Ingestion errors in individual feed entries must not abort the remaining feed processing.
  - Lack of structured logging for feed ingestion batches.

### 2.2 Alert Generation Architecture
- **Active Files:**
  - `backend/app/services/alert_service.py`: `evaluate_ioc_for_alerts(db, indicator)`.
- **Logic:**
  - Triggers an alert if `indicator.severity in [HIGH, CRITICAL]` or `indicator.threat_score >= 60`.
  - Creates an `Alert` record in PostgreSQL (`status=NEW`, `rule_name="SEVERITY_THRESHOLD_RULE"`).
  - Broadcasts payload directly to in-process memory `ws_manager.broadcast_alert(alert_payload)`.
- **Gaps & Defects:**
  - Does NOT check for deduplication: Re-ingesting the same indicator can generate duplicate active alerts.
  - Does NOT publish events to Redis Pub/Sub.
  - Does NOT create an audit log record for automated alert generation.

### 2.3 Redis Architecture
- **Active Files:**
  - `backend/app/core/redis.py`: Implements `RedisManager` for token revocation (`revoke_token`, `is_token_revoked`) and connectivity check (`ping`).
- **Gaps & Defects:**
  - No Pub/Sub publisher method exists (`publish_event(channel, payload)`).
  - No async Pub/Sub subscriber generator or listener for WebSocket workers.
  - No in-memory Pub/Sub broadcast fallback when Redis is offline in local dev/testing.

### 2.4 WebSocket Architecture
- **Active Files:**
  - `backend/app/core/websocket.py`: `ConnectionManager` with `self.active_connections: List[WebSocket]`.
  - `backend/app/api/v1/endpoints/websocket.py`: Protected route `/api/v1/ws/alerts`.
  - `backend/app/main.py`: Protected alias `/ws/alerts`.
- **Gaps & Defects:**
  - The endpoints accept connections, but their loop only does `await websocket.receive_text()`. They never receive or forward events from Redis.
  - If a client disconnects, `ws_manager.disconnect()` is called, but no Redis subscription teardown occurs.

### 2.5 Frontend Telemetry & Alert Queue
- **Active Files:**
  - `frontend/src/hooks/useAlertStream.ts`: WebSocket hook with token query param, listens for `payload.type === "NEW_ALERT"`. Currently orphaned.
  - `frontend/src/components/analyst/AlertQueue.tsx`: UI table with mock alerts array. Currently orphaned.
  - `frontend/src/app/dashboard/analyst/page.tsx`: Embedded raw WebSocket to `ws://127.0.0.1:8000/ws/alerts` without auth token (blocked by Phase 1B security). Uses `defaultFallbackIOCs` array upon API failure.
- **Gaps & Defects:**
  - Analyst dashboard WebSocket fails authentication because no JWT is appended to the connection string.
  - Simulated fallback IOC arrays mask network or backend failures.

---

## 3. Inventory of Mock / Simulated / Fake Telemetry in Codebase

| File | Type | Description | Classification | Planned Phase 3 Action |
| :--- | :--- | :--- | :--- | :--- |
| `backend/app/services/ingestion.py:135-157` | Mock Feed | Static list for AlienVault OTX | **MUST REMOVE** | Unify in `feed_service.py` with real/resilient fetcher |
| `backend/app/services/ingestion.py:160-182` | Mock Feed | Static list for CISA KEV vulnerabilities | **MUST REMOVE** | Replace with official CISA KEV JSON feed ingestion |
| `backend/app/routers/alerts.py:14-38` | Mock Seed | `_seed_mock_alerts()` seeds synthetic alerts into SQLite | **DEPRECATED** | Router is deprecated; ensure production path does not call it |
| `frontend/src/components/analyst/AlertQueue.tsx:22-53` | Mock Array | `mockAlerts` array (ALT-9042, etc.) | **MUST REMOVE** | Refactor component to accept real alerts or live props |
| `frontend/src/app/dashboard/analyst/page.tsx:31-70` | Mock Array | `defaultFallbackIOCs` 6-item synthetic array | **MUST REMOVE** | Replace with explicit empty/error state; remove fake data |
| `frontend/src/app/dashboard/analyst/page.tsx:128` | Missing Auth | `new WebSocket("ws://127.0.0.1:8000/ws/alerts")` | **BROKEN** | Update to use `getAuthToken()` and `/api/v1/ws/alerts?token=...` |

---

## 4. Phase 3 Target Architecture

```
                      +---------------------------------------+
                      |       Threat Intelligence Sources      |
                      | (URLhaus, ThreatFox, Feodo, Malware,  |
                      |        CISA KEV, AlienVault OTX)      |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Ingestion & Validation Engine     |
                      |       (app/services/feed_service.py)   |
                      +-------------------+-------------------+
                                          |
                        [Deduplication & Provenance]
                                          |
                                          v
                      +---------------------------------------+
                      |       Scoring & Persistence Tier       |
                      |  - Indicator / IndicatorSource (PG)   |
                      |  - Elasticsearch Document Index       |
                      +-------------------+-------------------+
                                          |
                          [Threat Score >= 60 or HIGH/CRIT]
                                          |
                                          v
                      +---------------------------------------+
                      |       Alert Evaluation Engine         |
                      |       (app/services/alert_service.py) |
                      |  - Deduplicate active alerts          |
                      |  - Persist Alert in PostgreSQL        |
                      |  - Log Audit Event                    |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |          Redis Event Publisher        |
                      | Channel: 'threatlens:events:alerts'   |
                      +-------------------+-------------------+
                                          |
                                          | (Redis Pub/Sub)
                                          v
                      +---------------------------------------+
                      |     WebSocket Fan-Out Subscribers     |
                      |      (app/core/websocket.py)          |
                      |  - Async Redis channel listener       |
                      |  - Broadcast to Authenticated Clients |
                      +-------------------+-------------------+
                                          |
                                          | (Authenticated WS)
                                          v
                      +---------------------------------------+
                      |     Next.js Frontend (SOC Cockpit)    |
                      |  - Live Alert Queue / Toasts          |
                      |  - Zero fake / synthetic fallback     |
                      +---------------------------------------+
```

---

## 5. Files Requiring Modification & Creation

### Files to Modify:
1. `backend/app/core/config.py` — Add `REDIS_ALERT_CHANNEL: str = "threatlens:events:alerts"`.
2. `backend/app/core/redis.py` — Add synchronous and asynchronous Pub/Sub methods (`publish_event`, `subscribe_channel`, in-memory fallback bus).
3. `backend/app/core/websocket.py` — Connect `ConnectionManager` to Redis Pub/Sub listener with proper subscription lifecycle, deduplication, and client cleanup.
4. `backend/app/services/feed_service.py` — Add CISA KEV and AlienVault OTX public/fallback fetchers; record multi-source provenance in `indicator_sources`; validate and sanitize records; trigger alert evaluation.
5. `backend/app/services/alert_service.py` — Check for existing active alerts for the indicator (avoid duplicate alerts), persist Alert, log audit record, and publish structured JSON to Redis Pub/Sub.
6. `backend/app/api/v1/endpoints/websocket.py` & `backend/app/main.py` — Ensure WebSocket routes cleanly manage connection lifecycle and dispatch Redis events.
7. `frontend/src/hooks/useAlertStream.ts` — Align event payload structure with backend Redis alert format (`NEW_ALERT` / `NEW_CRITICAL_ALERT`).
8. `frontend/src/app/dashboard/analyst/page.tsx` — Connect to authenticated WebSocket with `getAuthToken()`, remove `defaultFallbackIOCs` synthetic substitution, handle legitimate empty/error states.
9. `frontend/src/components/analyst/AlertQueue.tsx` — Remove `mockAlerts` fallback and accept dynamic live alerts.

### Files to Create:
1. `backend/tests/test_phase3_telemetry.py` — Comprehensive unit and integration test suite:
   - Feed ingestion normalization and deduplication.
   - Malformed feed record resilience.
   - Alert evaluation and deduplication.
   - Redis Pub/Sub publish and fallback behavior.
   - WebSocket authenticated connection and event fan-out.
   - End-to-end ingestion -> scoring -> alert -> Redis -> WebSocket pipeline.
2. `PHASE_3_VERIFICATION_REPORT.md` — Live verification results.

---

## 6. Execution Plan

- [x] **Step 3A**: Forensic Baseline completed and documented in `PHASE_3_BASELINE_REPORT.md`.
- [ ] **Step 3B**: Implement Real Ingestion Pipeline in `feed_service.py` (6 sources, schema normalization, `IndicatorSource` provenance, safe error handling).
- [ ] **Step 3C**: Implement Real Alert Generation in `alert_service.py` (alert deduplication, DB persistence, audit logging, trigger Redis publication).
- [ ] **Step 3D**: Implement Redis Pub/Sub in `redis.py` (channel namespace, structured JSON payloads, async subscriber, offline dev bus fallback).
- [ ] **Step 3E**: Implement WebSocket Fan-Out in `websocket.py` (listening to Redis Pub/Sub, broadcasting to authenticated clients, clean disconnects).
- [ ] **Step 3F**: Update Frontend Telemetry Hook and Analyst View (authenticate WebSocket with JWT, remove fake fallback arrays).
- [ ] **Step 3G**: Security, input validation, and reliability audit.
- [ ] **Step 3H**: Create comprehensive Phase 3 test suite (`test_phase3_telemetry.py`) and run full pytest regression suite.
- [ ] **Step 3I**: Perform live end-to-end verification and compile `PHASE_3_VERIFICATION_REPORT.md`.
- [ ] **Step 3J**: Complete simulated telemetry removal from production paths.
- [ ] **Step 3K**: Git commit and Phase 3 completion report.
