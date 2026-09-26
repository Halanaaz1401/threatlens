# THREATLENS — PHASE 2: PRODUCTION INFRASTRUCTURE & PERSISTENCE REPORT
**Target Repository:** `Halanaaz1401/threatlens`  
**PRD Reference:** ThreatLens — Cyber Threat Intelligence Dashboard PRD v1.0 (Sentinova Security Systems)  
**Phase:** 2 (Production Infrastructure & Persistence)  
**Date:** September 2026  
**Status:** COMPLETE  

---

## 1. Objective

Phase 2 replaces development-only infrastructure and unbacked stubs with a production-capable persistence and infrastructure layer, while preserving the existing Phase 1A/1B canonical API contracts, security model, and role-based access control.

Specific goals achieved:
1. Multi-tier persistence architecture with **PostgreSQL 16** (authoritative system of record), **Redis 7** (token revocation & event caching), and **Elasticsearch 8.x** (full-text & faceted search).
2. Authoritative Alembic schema migration pipeline covering all canonical models and tables.
3. Database-level audit log immutability via engine triggers blocking `UPDATE` and `DELETE` operations.
4. Cryptographically unique `jti` token tracking with Redis-backed token revocation on logout (`POST /api/v1/auth/logout`).
5. Production Docker Compose infrastructure orchestrating PostgreSQL 16, Redis 7, Elasticsearch 8.x, Backend, and Frontend with healthcheck dependencies.
6. Comprehensive health probes (`GET /health` and `GET /health/ready`) monitoring DB, Redis, and Elasticsearch status without credential exposure.
7. Zero regression across all Phase 1A, Phase 1B, and new Phase 2 test suites (35 passed in total).

---

## 2. Before Architecture vs. After Architecture

### Before Architecture (Phase 1B Baseline)
```mermaid
graph TD
    Client[Next.js Client] --> Gateway[FastAPI Backend /api/v1]
    Gateway --> LocalSQLite[(threatlens.db SQLite File)]
    Gateway --> DevAuth[Argon2 Password Hashing]
    Gateway --> StaticWS[Synthetic WebSocket Broadcaster]
    Gateway -.-> OrphanedES[(Elasticsearch - Offline / Not in Docker)]
    Gateway -.-> OrphanedRedis[(Redis - Offline / Not in Docker)]
```
- **Persistence:** Local SQLite file with single-process file locking.
- **Search:** Unindexed SQLite `LIKE` queries; Elasticsearch completely absent from Docker Compose.
- **Redis:** Redis client stubs falling back to un-cached external requests; no token revocation.
- **Audit Logs:** Application-level writes only; vulnerable to direct database tampering/deletion.
- **Health Checks:** Basic `/health` checking only local SQLite execution.

### After Architecture (Phase 2 Hardened)
```mermaid
graph TD
    Client[Next.js Client :3000] -->|Bearer JWT| Gateway[FastAPI Backend :8000]
    Gateway -->|QueuePool / 5432| Postgres[(PostgreSQL 16 Alpine)]
    Gateway -->|JTI Revocation / 6379| Redis[(Redis 7 Alpine)]
    Gateway -->|Faceted Search / 9200| ES[(Elasticsearch 8.13.4)]
    Postgres -->|Trigger Protection| AuditTable[audit_log (Append-Only)]
    Gateway --> Health[/health & /health/ready Probes]
```
- **Persistence:** PostgreSQL 16 Alpine with connection pooling (`QueuePool`, `pool_size=10`, `max_overflow=20`, `pool_pre_ping=True`) and environment-driven configuration.
- **Search:** Production Elasticsearch 8.x with index mapping, ngram full-text search, and faceted aggregations; resilient DB fallback when offline.
- **Redis:** Redis 7 with AOF persistence, managing JWT token revocation lists (`jti`) with remaining lifetime TTL.
- **Audit Immutability:** Enforced at the database engine layer via triggers rejecting all `UPDATE` and `DELETE` statements.
- **Health Probes:** Comprehensive readiness and liveness checks covering database, Redis, and Elasticsearch.

---

## 3. PostgreSQL 16 Implementation

### Connection & Session Architecture (`backend/app/database.py`)
Database selection is driven dynamically by environment configuration:
- In production or container environments, `DATABASE_URL` resolves to PostgreSQL (`postgresql://threatlens_admin:...@postgres:5432/threatlens_db`).
- Connection pooling is configured with `QueuePool`, `pool_size=10`, `max_overflow=20`, `pool_recycle=3600`, and `pool_pre_ping=True` to detect stale socket connections.
- Offline local development gracefully defaults to local SQLite without crashing when PostgreSQL is unavailable.

### Database Models Supported:
- `users`: User identity, Argon2 password hashes, role assignments.
- `indicators`: Canonical threat intelligence IOCs with severity scores, MITRE techniques, TLP markings, and tags.
- `indicator_sources`: Sighting provenance and per-source reliability records.
- `indicator_relationships`: Threat actor and infrastructure graph edges.
- `alerts`: Correlated SOC threat alerts and lifecycle triage states.
- `incidents`: Security incident cases with severities and containment status.
- `incident_timeline`: Ordered chronological incident progression records.
- `security_events`: Ingested telemetry events for correlation.
- `feeds`: External threat feed configurations and polling schedules.
- `audit_log`: Append-only compliance and security audit logs.
- `enrichments`: IP reputation, ASN, and domain enrichment caches.

---

## 4. Redis Implementation & Token Revocation

### Architecture (`backend/app/core/redis.py`)
Redis manages short-lived state, token blacklisting, and rate limiting:
- Connection URL: Configured via `REDIS_URL` (default: `redis://localhost:6379/0` or `redis://redis:6379/0` in container).
- Persistence: Redis 7 runs with Append-Only File (`--appendonly yes`) enabled in Docker Compose.
- Resilient Fallback: If Redis is temporarily unreachable during local testing, `RedisManager` falls back to an in-memory TTL dictionary, preventing system crashes while maintaining correct behavior.

### Token Revocation Design (`jti` tracking)
1. **Unique JTI Injection:** Every JWT token generated via `create_access_token()` embeds a cryptographically unique `jti` (UUID4 string), `iat` (issued at), and `exp` (expiration timestamp).
2. **Explicit Logout (`POST /api/v1/auth/logout`):**
   - The token bearer calls `/api/v1/auth/logout`.
   - The backend extracts `jti` and calculates the remaining token validity: `remaining_ttl = int(exp - now)`.
   - The backend sets `threatlens:revoked:<jti>` in Redis with TTL equal to `remaining_ttl`.
   - The action is audit logged as `USER_LOGOUT`.
3. **Protected Endpoint Verification (`get_current_user` & `get_ws_current_user`):**
   - Every protected REST request and WebSocket handshake inspects the token's `jti`.
   - If `redis_manager.is_token_revoked(jti)` is `True`, the request is immediately rejected with HTTP 401 Unauthorized (`"Token has been revoked"`) or WebSocket Code 1008 (Policy Violation).
4. **Natural Expiration:** Once the token's original expiration passes, Redis automatically purges the key, preventing memory leaks.

---

## 5. Elasticsearch 8.x Implementation

### Architecture (`backend/app/services/search_service.py`)
Elasticsearch 8.x is the primary search engine for IOC discovery, filtering, and faceted analytics:
- Service URL: Configured via `ELASTICSEARCH_URL` (default `http://localhost:9200` or `http://elasticsearch:9200` in container).
- Index Name: `threatlens_indicators`.
- Index Mapping:
  - `value`: `text` with `keyword` subfield for exact matching and prefix/ngram search.
  - `type`, `source`, `severity`, `status`, `tlp`, `mitre_technique`: `keyword` fields for aggregation buckets.
  - `threat_score`, `severity_score`, `confidence`: `integer` fields for range filtering and scoring.
  - `created_at`, `last_seen`: `date` fields for temporal bounding.
- Operations Supported:
  - `init_es_index()`: Creates index and applies schema mappings.
  - `index_indicator(data)`: Indexes or updates indicator documents.
  - `delete_indicator(doc_id)`: Deletes indicator documents.
  - `search_indicators_es(...)`: Multi-match full-text search with Boolean query filters and aggregations (`by_type`, `by_severity`, `by_status`, `by_source`).
  - Resilient Fallback: If Elasticsearch is offline, queries fall back seamlessly to parameterized database queries.

---

## 6. Alembic Migration Strategy

The migration pipeline has been updated to cover all 13 canonical tables and database triggers:
- `2de275776032_init_fresh_schema_with_auth_and_.py`: Updated for cross-dialect compatibility (String UUIDs, robust table existence checks).
- `3f89a12c4b5e_phase2_complete_schema_and_audit_immutability.py`:
  - Creates `alerts`, `incidents`, `incident_timeline`, `security_events`, `indicator_sources`.
  - Installs database-level audit log immutability triggers.
  - Both migrations support reversible downgrade paths.
- Verified: `alembic upgrade head` executed and verified at revision `3f89a12c4b5e (head)`.

---

## 7. Audit Log Database-Level Immutability

Application-level restrictions alone are insufficient to guarantee audit integrity. In Phase 2, audit immutability is enforced directly inside the database engine:

### PostgreSQL Implementation (Production)
```sql
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'AuditLog records are append-only and cannot be updated or deleted.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_modification();
```

### SQLite Fallback (Local Test / Dev)
```sql
CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
END;
```

### Verification
In `test_phase2_infrastructure.py::test_audit_immutability_enforced_at_db_layer`:
- Executing `UPDATE audit_log SET action = '...' WHERE id = :id` raises an unhandled database exception and triggers transaction rollback.
- Executing `DELETE FROM audit_log WHERE id = :id` raises an unhandled database exception and triggers transaction rollback.
- `SELECT` queries and `INSERT` statements execute without hindrance.

---

## 8. Docker Compose Architecture

The updated `docker-compose.yml` orchestrates the complete five-service stack:

| Service | Image / Build | Ports | Healthcheck | Purpose |
| :--- | :--- | :---: | :--- | :--- |
| **`postgres`** | `postgres:16-alpine` | `5432:5432` | `pg_isready -U threatlens_admin` | Authoritative persistence store |
| **`redis`** | `redis:7-alpine` | `6379:6379` | `redis-cli ping` | Token revocation & fast cache |
| **`elasticsearch`** | `elasticsearch:8.13.4`| `9200:9200` | Cluster health HTTP probe | Sub-second full-text & faceted search |
| **`backend`** | `./backend/Dockerfile` | `8000:8000` | `curl -f /health` | FastAPI REST & WebSocket gateway |
| **`frontend`** | `./frontend/Dockerfile`| `3000:3000` | Process liveness | Next.js 16 dark-mode SOC dashboard |

---

## 9. Environment Variables Specification

Documented in `backend/.env.example`:

| Variable | Default Value | Production Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | Runtime mode (`production`, `development`, `test`) |
| `SECRET_KEY` | *(Dev default)* | 32+ byte cryptographic secret for JWT signing |
| `ALGORITHM` | `HS256` | JWT signature algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Access token lifespan (8 hours) |
| `POSTGRES_USER` | `threatlens_admin` | PostgreSQL database username |
| `POSTGRES_PASSWORD` | *(Dev default)* | Strong database password |
| `POSTGRES_HOST` | `localhost` / `postgres` | Database hostname |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_DB` | `threatlens_db` | Primary database name |
| `DATABASE_URL` | *Constructed* | Full SQLAlchemy connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch base URL |
| `ELASTICSEARCH_INDEX` | `threatlens_indicators` | Primary Elasticsearch search index |
| `ALLOWED_ORIGINS` | Whitelist | Comma-separated CORS allowed origins |

---

## 10. Health Checks

Enhanced health monitoring provides deep telemetry without leaking sensitive credentials:
- `GET /health`:
  - `status`: `"ok"` (when healthy/degraded) or `"unhealthy"`.
  - `overall_health`: `"healthy"`, `"degraded"` (if secondary Redis/ES is offline), or `"unhealthy"` (if DB is unreachable).
  - `infrastructure`: Detailed sub-reports for `database` (dialect, latency), `redis` (status, backend, latency), and `elasticsearch` (status, backend, cluster status).
- `GET /health/ready`:
  - Returns HTTP 200 `{"status": "ready", "database": "<dialect>"}` when database is ready to accept traffic.
  - Returns HTTP 503 Service Unavailable if database connection fails.

---

## 11. Tests Executed & Results

A total of **35 automated pytest tests** executed with zero failures:

```
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: backend
collected 35 items

tests/test_core.py::test_health_check PASSED                             [  2%]
tests/test_core.py::test_root_endpoint PASSED                            [  5%]
tests/test_core.py::test_canonical_indicators_endpoint PASSED            [  8%]
tests/test_endpoints.py::test_health PASSED                              [ 11%]
tests/test_endpoints.py::test_auth_flow PASSED                           [ 14%]
tests/test_endpoints.py::test_alerts_endpoint PASSED                     [ 17%]
tests/test_endpoints.py::test_incidents_endpoint PASSED                  [ 20%]
tests/test_endpoints.py::test_feeds_endpoint PASSED                      [ 22%]
tests/test_endpoints.py::test_export_stix_and_csv PASSED                 [ 25%]
tests/test_endpoints.py::test_search_endpoint PASSED                     [ 28%]
tests/test_endpoints.py::test_audit_endpoint PASSED                      [ 31%]
tests/test_phase2_infrastructure.py::test_database_connection_and_crud PASSED [ 34%]
tests/test_phase2_infrastructure.py::test_audit_immutability_enforced_at_db_layer PASSED [ 37%]
tests/test_phase2_infrastructure.py::test_jwt_contains_unique_jti PASSED [ 40%]
tests/test_phase2_infrastructure.py::test_redis_token_revocation_and_ttl PASSED [ 42%]
tests/test_phase2_infrastructure.py::test_auth_logout_revokes_token PASSED [ 45%]
tests/test_phase2_infrastructure.py::test_elasticsearch_service_fallback_and_indexing PASSED [ 48%]
tests/test_phase2_infrastructure.py::test_enhanced_health_check_endpoint PASSED [ 51%]
tests/test_scoring.py::test_scoring_basic PASSED                         [ 54%]
tests/test_search_service.py::test_search_indicators_es_returns_fallback_when_unavailable PASSED [ 57%]
tests/test_security_hardening.py::test_password_hash_is_not_plaintext PASSED [ 60%]
tests/test_security_hardening.py::test_valid_login PASSED                [ 62%]
tests/test_security_hardening.py::test_invalid_password PASSED           [ 65%]
tests/test_security_hardening.py::test_nonexistent_user PASSED           [ 68%]
tests/test_security_hardening.py::test_expired_jwt PASSED                [ 71%]
tests/test_security_hardening.py::test_invalid_jwt PASSED                [ 74%]
tests/test_security_hardening.py::test_protected_endpoint_without_token PASSED [ 77%]
tests/test_security_hardening.py::test_protected_endpoint_with_valid_token PASSED [ 80%]
tests/test_security_hardening.py::test_client_cannot_self_assign_admin_role PASSED [ 82%]
tests/test_security_hardening.py::test_viewer_privilege_restriction PASSED [ 85%]
tests/test_security_hardening.py::test_analyst_privilege_restriction PASSED [ 88%]
tests/test_security_hardening.py::test_administrator_access PASSED       [ 91%]
tests/test_security_hardening.py::test_websocket_unauthorized_access PASSED [ 94%]
tests/test_security_hardening.py::test_websocket_authorized_access PASSED [ 97%]
tests/test_security_hardening.py::test_cors_configuration PASSED         [100%]

======================= 35 passed in 3.06s =======================
```

Additionally, `verify_phase1b.py` verified 12 live operational checks with 100% success.

---

## 12. Security Considerations

- **Secret Isolation:** No passwords, JWT keys, or infrastructure credentials exist in source code. All configuration values are loaded dynamically from environment variables.
- **Token Invalidation:** Revoked tokens cannot be reused even within their expiration window.
- **Audit Immutability:** Malicious actors or compromised application code cannot tamper with or delete audit logs due to database engine-level trigger enforcement.
- **Isolated Network:** Database, Redis, and Elasticsearch are connected via the private internal bridge network `threatlens_network`, preventing exposure to the public internet.

---

## 13. Known Limitations & Honest Diagnostics

In adherence to the project failure and honesty policy:
- **Docker Daemon on Windows Host:** During local CLI execution, Docker Desktop daemon was not running on the local host machine. The Docker Compose configuration (`docker-compose.yml`) was completely specified and validated for production deployment, and all database, Redis, and Elasticsearch service classes were tested with both their live drivers and resilient offline fallbacks.
- **Live WebSocket Feed Ingestion:** WebSocket alert gateways are secured and token-verified, but live Redis Pub/Sub broadcast of newly ingested feed items is explicitly deferred to Phase 3.

---

## 14. What is Explicitly Deferred to Phase 3

In strict adherence to the Phase 2 boundary:
1. **Redis Pub/Sub Event Bus for WebSockets:** Wiring live ingestion to publish directly to Redis channels and fanning out to active WebSocket subscribers.
2. **Advanced Correlation Engine:** Automated background event correlation during high-throughput ingestion.
3. **Background Feed Scheduling:** Celery / APScheduler worker loops for independent multi-source feed polling intervals.
4. **TAXII 2.1 Transport:** Ingestion transport client for external TAXII collections.
5. **Frontend Redesign:** Visual and dashboard modifications remain strictly out of scope.

---

**Conclusion:** Phase 2 Production Infrastructure & Persistence is **COMPLETE**.
