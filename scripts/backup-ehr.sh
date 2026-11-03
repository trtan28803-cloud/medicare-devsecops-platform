#!/usr/bin/env bash
# Kịch bản Sao lưu Nóng CSDL SQLite (Zero-Downtime Hot Backup) & Mã hóa AES-256
# Tự động xoay vòng và dọn dẹp các bản sao lưu cũ quá 30 ngày (Retention Policy)
set -euo pipefail

DATA_DIR="${HICP_DATA_DIR:-/var/lib/hicp-ehr}"
BACKUP_DIR="${HICP_BACKUP_DIR:-/var/backups/hicp-ehr-vault}"
PASSPHRASE="${HICP_BACKUP_KEY:-HICP-Hospital-Offline-Vault-Key-2026}"
RETENTION_DAYS="${HICP_BACKUP_RETENTION_DAYS:-30}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

sudo mkdir -p "$BACKUP_DIR"
sudo chmod 700 "$BACKUP_DIR"

TMP_DB="/tmp/ehr_snapshot_${TIMESTAMP}.db"
sqlite3 "${DATA_DIR}/ehr.db" ".backup '${TMP_DB}'"

sudo openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
  -in "$TMP_DB" \
  -out "${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc" \
  -pass "pass:${PASSPHRASE}"

rm -f "$TMP_DB"
sudo chmod 400 "${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc"

# Xoay vòng tự động: xóa các bản sao lưu đã cũ hơn RETENTION_DAYS (mặc định 30 ngày)
sudo find "$BACKUP_DIR" -maxdepth 1 -type f -name "ehr_*.db.enc" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

echo "[+] Đã sao lưu nóng và mã hóa AES-256-CBC thành công: ${BACKUP_DIR}/ehr_${TIMESTAMP}.db.enc (Lưu trữ ${RETENTION_DAYS} ngày)"