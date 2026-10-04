#!/usr/bin/env bash
# ==============================================================================
# ThreatLens Production PostgreSQL Restore Script
# Restores a compressed SQL dump into the active PostgreSQL container.
# CAUTION: This operation replaces existing data in the target database.
# ==============================================================================
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path_to_backup.sql.gz> [--force]"
    exit 1
fi

BACKUP_FILE="$1"
FORCE_FLAG="${2:-}"

POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-threatlens_postgres}"
POSTGRES_USER="${POSTGRES_USER:-threatlens_admin}"
POSTGRES_DB="${POSTGRES_DB:-threatlens_db}"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "[ERROR] Backup file not found: ${BACKUP_FILE}"
    exit 1
fi

echo "======================================================================"
echo "THREATLENS DATABASE RESTORE"
echo "======================================================================"
echo "Target Container: ${POSTGRES_CONTAINER}"
echo "Database:         ${POSTGRES_DB}"
echo "User:             ${POSTGRES_USER}"
echo "Source File:      ${BACKUP_FILE}"
echo "======================================================================"

if [ "${FORCE_FLAG}" != "--force" ]; then
    read -p "Are you sure you want to restore? This will overwrite data. (y/N): " -r CONFIRM
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        echo "[INFO] Restore aborted by user."
        exit 0
    fi
fi

echo "[INFO] Streaming decompressed SQL into PostgreSQL..."
gunzip -c "${BACKUP_FILE}" | docker exec -i "${POSTGRES_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"

echo "[SUCCESS] Database restored successfully from ${BACKUP_FILE}."
echo "[INFO] Verifying database connection..."
docker exec -t "${POSTGRES_CONTAINER}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"
echo "[INFO] Restore verification complete."
