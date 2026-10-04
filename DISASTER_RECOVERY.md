# THREATLENS V1.0 — DISASTER RECOVERY & BACKUP RUNBOOK

**Target System:** ThreatLens Enterprise Cyber Threat Intelligence & Incident Correlation Platform  
**Target Release:** v1.0.0 (Production Release)  
**Classification:** Operational Security & Business Continuity Guide  

---

## 1. Overview & Service Objectives

ThreatLens relies on three core data stores:
1. **PostgreSQL 16:** Authoritative relational store for indicators, relationships, alerts, incidents, cases, evidence, audit logs, feeds, and detection rules.
2. **Redis 7:** High-speed in-memory message broker, real-time alert fan-out bus, token revocation blocklist, and threat intel cache.
3. **Elasticsearch 8.13.4:** Full-text and faceted search index over threat indicators and telemetry.

### Business Continuity Targets
- **Recovery Point Objective (RPO):** < 1 hour (via hourly automated database snapshots).
- **Recovery Time Objective (RTO):** < 15 minutes (via automated container redeployment and state restoration).

---

## 2. PostgreSQL Backup Procedures

### 2.1 Storage Volumes
PostgreSQL data is persisted in Docker named volume `postgres_data` mapped to `/var/lib/postgresql/data`.

### 2.2 Automated Snapshot Script (`scripts/backup.sh`)
The repository includes an environment-driven backup script:
```bash
./scripts/backup.sh
```

**Environment Configuration:**
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `BACKUP_DIR` | `./backups` | Host or volume directory where compressed backups are saved |
| `POSTGRES_CONTAINER` | `threatlens_postgres` | Name of the active PostgreSQL Docker container |
| `POSTGRES_USER` | `threatlens_admin` | Database administrative username |
| `POSTGRES_DB` | `threatlens_db` | Target database name |
| `RETENTION_DAYS` | `7` | Days to retain backup archives before automatic pruning |

### 2.3 Scheduling Backups via Cron
On the production host, add the following cron entry to schedule hourly snapshots:
```bash
0 * * * * cd /opt/threatlens && BACKUP_DIR=/var/backups/threatlens ./scripts/backup.sh >> /var/log/threatlens_backup.log 2>&1
```

---

## 3. Database Restoration Procedure

### 3.1 Interactive or Automated Restore (`scripts/restore.sh`)
To restore an existing database snapshot into a running PostgreSQL container:
```bash
# Interactive mode (prompts for confirmation)
./scripts/restore.sh ./backups/threatlens_db_20261004_150000.sql.gz

# Automated / CI mode
./scripts/restore.sh ./backups/threatlens_db_20261004_150000.sql.gz --force
```

### 3.2 Cold Node Recovery (Disaster Recovery onto Fresh Host)
If the primary host fails completely:
1. Provision a clean VM/host with Docker and Docker Compose installed.
2. Clone the repository and configure `.env` with production secrets (`POSTGRES_PASSWORD`, `SECRET_KEY`).
3. Start the datastores:
   ```bash
   docker compose up -d postgres redis elasticsearch
   ```
4. Wait for PostgreSQL to report healthy:
   ```bash
   docker compose ps postgres
   ```
5. Restore the latest backup:
   ```bash
   ./scripts/restore.sh /path/to/latest_backup.sql.gz --force
   ```
6. Start the backend and frontend:
   ```bash
   docker compose up -d backend frontend
   ```
7. Verify system health:
   ```bash
   curl -f http://localhost:8000/health
   curl -f http://localhost:8000/health/ready
   curl -f http://localhost:8000/metrics
   ```

---

## 4. Redis Persistence & Recovery

- **Durability Mode:** Configured with Append-Only File (`AOF`) logging via `["redis-server", "--appendonly", "yes"]` in `docker-compose.yml`.
- **Storage Volume:** Mapped to persistent volume `redis_data:/data`.
- **Restart Recovery:** Upon container restart, Redis automatically replays `appendonly.aof` to reconstruct session state and the JTI token revocation blocklist.
- **Fail-Safe Behavior:** If Redis state is cleared, user sessions are re-validated against PostgreSQL active accounts.

---

## 5. Elasticsearch Index Recovery

- **Persistence:** Indices are persisted in volume `es_data:/usr/share/elasticsearch/data`.
- **Re-indexing from PostgreSQL:** Because PostgreSQL is the authoritative system of record, Elasticsearch indices can be reconstructed at any time without data loss. If Elasticsearch is ever re-initialized or corrupted:
  1. Ensure Elasticsearch is healthy: `curl http://localhost:9200/_cluster/health`
  2. The backend startup routines and query endpoints automatically fall back to PostgreSQL queries if index sync is in progress.

---

## 6. Audit Trail Immutability Compliance

- The `audit_log` table enforces append-only guarantees at the database engine level via PostgreSQL trigger `trg_audit_log_immutable`.
- **Tamper Protection:** In the event of an investigation, all authentication attempts, role updates, indicator lifecycle changes, case creation, and report generation events are immutably preserved in the database.
