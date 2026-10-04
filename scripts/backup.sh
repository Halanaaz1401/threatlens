#!/usr/bin/env bash
# ==============================================================================
# ThreatLens Production PostgreSQL Backup Script
# Creates a compressed, timestamped database snapshot for disaster recovery.
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-threatlens_postgres}"
POSTGRES_USER="${POSTGRES_USER:-threatlens_admin}"
POSTGRES_DB="${POSTGRES_DB:-threatlens_db}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/threatlens_db_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[INFO] Starting ThreatLens PostgreSQL backup..."
echo "[INFO] Container: ${POSTGRES_CONTAINER} | Database: ${POSTGRES_DB} | User: ${POSTGRES_USER}"

# Execute pg_dump inside container and pipe through gzip
if docker exec -t "${POSTGRES_CONTAINER}" pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" --clean --if-exists | gzip > "${BACKUP_FILE}"; then
    FILE_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
    echo "[SUCCESS] Backup completed successfully: ${BACKUP_FILE} (${FILE_SIZE})"
else
    echo "[ERROR] Backup failed. Removing incomplete file..."
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# Prune backups older than retention window
echo "[INFO] Pruning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "threatlens_db_*.sql.gz" -type f -mtime +"${RETENTION_DAYS}" -exec rm -f {} \; || true
echo "[INFO] Backup routine finished cleanly."
