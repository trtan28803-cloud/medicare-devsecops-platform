#!/usr/bin/env bash
# Automated SQLite Online Backup + AES-256-CBC Encryption
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/medicare-ehr}"
DATA_DIR="${DATA_DIR:-${APP_DIR}/data_vault}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/medicare-ehr}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PASSPHRASE_FILE="${PASSPHRASE_FILE:-${DATA_DIR}/.vault.key}"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

if [[ ! -f "${DATA_DIR}/ehr.db" ]]; then
    echo "[ERROR] Database not found at ${DATA_DIR}/ehr.db" >&2
    exit 1
fi

if [[ ! -f "${PASSPHRASE_FILE}" ]]; then
    openssl rand -hex 32 > "${PASSPHRASE_FILE}"
    chmod 600 "${PASSPHRASE_FILE}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Online atomic SQLite backup (WAL-safe via Python native sqlite3 backup API)
python3 -c "import sqlite3; src=sqlite3.connect('${DATA_DIR}/ehr.db'); dst=sqlite3.connect('${TMP_DIR}/ehr.db'); src.backup(dst); dst.close(); src.close()"
cp -p "${PASSPHRASE_FILE}" "${TMP_DIR}/.vault.key"

for f in users.json audit.jsonl; do
    if [[ -f "${DATA_DIR}/${f}" ]]; then
        cp -p "${DATA_DIR}/${f}" "${TMP_DIR}/${f}"
    fi
done

ARCHIVE_FILE="${BACKUP_DIR}/medicare-ehr-${TIMESTAMP}.tar.gz.enc"
tar -czf - -C "${TMP_DIR}" . | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -pass "file:${PASSPHRASE_FILE}" -out "${ARCHIVE_FILE}"

chmod 600 "${ARCHIVE_FILE}"
sha256sum "${ARCHIVE_FILE}" > "${ARCHIVE_FILE}.sha256"

# Prune backups older than RETENTION_DAYS
find "${BACKUP_DIR}" -name "medicare-ehr-*.tar.gz.enc*" -mtime +"${RETENTION_DAYS}" -delete

echo "[OK] Encrypted backup created: ${ARCHIVE_FILE}"
