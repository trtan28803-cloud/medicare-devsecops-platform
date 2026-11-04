#!/usr/bin/env python3
"""Hệ thống Quản lý Bệnh viện MediCare (HICP & Zero Trust v2.2)."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import ssl
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.environ.get("HICP_DATA_DIR", os.environ.get("HICP_DATA", "/var/lib/hicp-ehr")))
DB_PATH = DATA_DIR / "ehr.db"
USERS_PATH = DATA_DIR / "users.json"
AUDIT_JSONL_PATH = DATA_DIR / "audit.jsonl"

HOST = os.environ.get("HICP_HOST", os.environ.get("HOST", "127.0.0.1"))
PORT = int(os.environ.get("HICP_PORT", os.environ.get("PORT", "80")))
TRUST_LOCAL_PROXY = os.environ.get("TRUST_LOCAL_PROXY", "0") == "1"
TLS_ENABLED = os.environ.get("HICP_TLS_ENABLED", "0") == "1"
TLS_CERT_PATH = os.environ.get("HICP_TLS_CERT", "").strip()
TLS_KEY_PATH = os.environ.get("HICP_TLS_KEY", "").strip()

# Tham số bảo mật theo chuẩn HICP
REQUIRE_MFA = os.environ.get("REQUIRE_MFA", "0") == "1"
MFA_SHARED_SECRET = os.environ.get("HICP_MFA_SECRET", "JBSWY3DPEHPK3PXP")
IOMT_DEVICE_KEY = os.environ.get("HICP_IOMT_KEY", "HICP-ICU-MON-2026-KEY")

SESSION_TIMEOUT_SECONDS = int(os.environ.get("HICP_SESSION_TIMEOUT", "900"))
# Tham số IDS / IPS theo địa chỉ MAC
IDS_WARN_WINDOW_SECONDS = int(os.environ.get("HICP_IDS_WARN_WINDOW", "300"))          
IDS_WARN_THRESHOLD = int(os.environ.get("HICP_IDS_WARN_THRESHOLD", "2"))              
IPS_FAIL_WINDOW_SECONDS = int(os.environ.get("HICP_IPS_FAIL_WINDOW", "600"))          
IPS_FAIL_THRESHOLD = int(os.environ.get("HICP_IPS_FAIL_THRESHOLD", "5"))              
IPS_BASE_BLOCK_SECONDS = int(os.environ.get("HICP_IPS_BASE_BLOCK", "300"))            
IPS_RECIDIVISM_WINDOW_SECONDS = int(os.environ.get("HICP_IPS_RECIDIVISM_WINDOW", "600"))  
EXPORT_WINDOW_SECONDS = 300
EXPORT_MAX_COUNT = 2
OTP_EXPIRY_SECONDS = 180

# Chính sách lưu trữ & cân bằng tải Hồ sơ bệnh án
SAVE_COOLDOWN_SECONDS = float(os.environ.get("HICP_SAVE_COOLDOWN_SECONDS", "60"))
REVISION_RETENTION_DAYS = int(os.environ.get("HICP_REVISION_RETENTION_DAYS", "15"))
REVISION_MIN_KEEP_COUNT = int(os.environ.get("HICP_REVISION_MIN_KEEP_COUNT", "2"))

# Cấu hình khung giờ đặt lịch khám
APPOINTMENT_START_MINUTE = 7 * 60   
APPOINTMENT_END_MINUTE = 15 * 60    
APPOINTMENT_MIN_LEAD_MINUTES = int(os.environ.get("HICP_APPOINTMENT_LEAD_MINUTES", "30"))
ENFORCE_REALTIME_BOOKING_CLOCK = os.environ.get("HICP_ENFORCE_BOOKING_CLOCK", "0") == "1"

VALID_ROLES = ("admin", "doctor", "nurse", "patient")
DEPARTMENTS = (
    "Nội tổng quát",
    "Tim mạch",
    "Nội tiết",
    "Tai Mũi Họng",
    "Khám sức khỏe định kỳ",
)
CLINICAL_PHI_FIELDS = ("diagnosis", "treatment_plan", "care_note", "note")

LOCK = threading.RLock()
SESSIONS: dict[str, dict] = {}
FAILURES: dict[str, list[float]] = {}
MAC_AUTH_TRACKER: dict[str, list[tuple[float, str, str]]] = {}
MAC_BLACKLIST: dict[str, dict] = {}
EXPORT_TRACKER: dict[str, list[float]] = {}
USER_SAVE_TRACKER: dict[str, float] = {}
RESET_OTPS: dict[str, dict] = {}
LAST_MEM_PRUNE_EPOCH: float = 0.0

# Dữ liệu hồ sơ bệnh án mặc định
SYNTHETIC_PATIENTS = [
    ("DEMO-001", "Nguyễn An (giả lập)", 1985, "0901000001", "Quận 1, TP.HCM (giả lập)", "HQ", "Tăng huyết áp độ 1 (giả lập)", "Kiểm soát huyết áp bằng Amlodipin 5mg", "Theo dõi huyết áp định kỳ tại HQ.", "BS.CKI Trần Minh Quân"),
    ("DEMO-002", "Trần Bình (giả lập)", 1992, "0901000002", "Quận 3, TP.HCM (giả lập)", "Branch", "Viêm mũi dị ứng (giả lập)", "Xịt mũi corticosteroid tại chỗ", "Khám ban đầu tại chi nhánh Branch.", "BS.CKI Vũ Đức Anh"),
    ("DEMO-003", "Lê Chi (giả lập)", 1978, "0901000003", "Quận 5, TP.HCM (giả lập)", "HQ", "Đái tháo đường type 2 (giả lập)", "Metformin 500mg ngày 2 lần", "Kiểm tra HbA1c mỗi 3 tháng (giả lập).", "BS.CKII Phạm Thu Hà"),
    ("DEMO-004", "Phạm Dũng (giả lập)", 2001, "0901000004", "Quận 7, TP.HCM (giả lập)", "Branch", "Cúm mùa lành tính (giả lập)", "Hạ sốt Paracetamol, bù điện giải", "Hướng dẫn nghỉ ngơi, bù nước (giả lập).", "BS.CKI Trần Minh Quân"),
    ("DEMO-005", "Hoàng Em (giả lập)", 1969, "0901000005", "Tân Bình, TP.HCM (giả lập)", "HQ", "Rối loạn lipid máu (giả lập)", "Atorvastatin 10mg buổi tối", "Điều chỉnh chế độ ăn (giả lập).", "ThS.BS Lê Hoàng Nam"),
    ("DEMO-006", "Vũ Phương (giả lập)", 1995, "0901000006", "Bình Thạnh, TP.HCM (giả lập)", "Branch", "Khám sức khỏe tổng quát (giả lập)", "Không dùng thuốc", "Các chỉ số sinh hiệu ổn định (giả lập).", "BS.CKI Trần Minh Quân"),
    ("DEMO-007", "Đỗ Gia Bảo (giả lập)", 1988, "0901000007", "Phú Nhuận, TP.HCM (giả lập)", "HQ", "Viêm dạ dày tá tràng (giả lập)", "Esomeprazol 40mg trước ăn sáng", "Hạn chế đồ cay nóng, nội soi định kỳ.", "BS.CKI Trần Minh Quân"),
    ("DEMO-008", "Ngô Hải Yến (giả lập)", 2003, "0901000008", "Thủ Đức, TP.HCM (giả lập)", "Branch", "Thiếu máu nhẹ do thiếu sắt (giả lập)", "Viên sắt + Acid Folic mỗi ngày", "Bổ sung viên sắt và dinh dưỡng.", "BS.CKII Phạm Thu Hà"),
    ("DEMO-009", "Bùi Khắc Huy (giả lập)", 1972, "0901000009", "Quận 10, TP.HCM (giả lập)", "HQ", "Bệnh mạch vành ổn định (giả lập)", "Aspirin 81mg + Bisoprolol 2.5mg", "Tuân thủ đơn thuốc tim mạch, tái khám tháng tới.", "ThS.BS Lê Hoàng Nam"),
    ("DEMO-010", "Đặng Linh Đan (giả lập)", 1998, "0901000010", "Quận 4, TP.HCM (giả lập)", "Branch", "Viêm họng cấp (giả lập)", "Súc họng nước muối sinh lý, giảm đau", "Kê kháng sinh và hạ sốt 5 ngày.", "BS.CKI Vũ Đức Anh"),
    ("DEMO-011", "Mai Nhật Minh (giả lập)", 1981, "0901000011", "Quận 6, TP.HCM (giả lập)", "HQ", "Gan nhiễm mỡ độ 1 (giả lập)", "Chế độ ăn Địa Trung Hải, tập thể dục", "Tăng cường vận động thể lực, giảm tinh bột.", "BS.CKI Trần Minh Quân"),
    ("DEMO-012", "Trịnh Oanh Kiều (giả lập)", 1990, "0901000012", "Quận 8, TP.HCM (giả lập)", "Branch", "Rối loạn tiền đình (giả lập)", "Betahistin 16mg ngày 2 lần", "Nghỉ ngơi hợp lý, tránh thức khuya.", "BS.CKI Vũ Đức Anh"),
    ("DEMO-013", "Cao Phúc Lâm (giả lập)", 1965, "0901000013", "Quận 11, TP.HCM (giả lập)", "HQ", "Thoái hóa cột sống thắt lưng (giả lập)", "Vật lý trị liệu kéo giãn cột sống", "Vật lý trị liệu kết hợp giảm đau.", "BS.CKI Trần Minh Quân"),
    ("DEMO-014", "Phan Quỳnh Nga (giả lập)", 2000, "0901000014", "Quận 12, TP.HCM (giả lập)", "Branch", "Dị ứng thức ăn nhẹ (giả lập)", "Loratadin 10mg khi có triệu chứng", "Dừng thực phẩm gây dị ứng, theo dõi tại nhà.", "BS.CKII Phạm Thu Hà"),
    ("DEMO-015", "Lương Tấn Phát (giả lập)", 1975, "0901000015", "Gò Vấp, TP.HCM (giả lập)", "HQ", "Tăng acid uric máu / Gout (giả lập)", "Allopurinol 300mg sau ăn", "Hạn chế đạm động vật và bia rượu.", "BS.CKII Phạm Thu Hà"),
    ("DEMO-016", "Dương Uyên Thư (giả lập)", 1993, "0901000016", "Tân Phú, TP.HCM (giả lập)", "Branch", "Viêm kết mạc dị ứng (giả lập)", "Olopatadin 0.1% nhỏ mắt", "Nhỏ mắt kháng histamine theo đơn.", "BS.CKI Vũ Đức Anh"),
]


def utc_now_iso(epoch: float | None = None) -> str:
    dt = datetime.fromtimestamp(epoch if epoch is not None else time.time(), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()
    return salt.hex(), derived


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    try:
        _, derived = hash_password(password, salt_hex)
        return hmac.compare_digest(derived, expected_hash_hex)
    except Exception:
        return False


def validate_password_complexity(pw: str) -> tuple[bool, str]:
    if len(pw) < 10:
        return False, "Mật khẩu phải có độ dài tối thiểu 10 ký tự."
    if not re.search(r"[A-Z]", pw):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ cái in hoa (A-Z)."
    if not re.search(r"[a-z]", pw):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ cái thường (a-z)."
    if not re.search(r"[0-9]", pw):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ số (0-9)."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return False, "Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt (!@#$%^&*...)."
    return True, ""


def generate_totp(secret_b32: str, time_step: int = 30, offset: int = 0) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int(time.time() // time_step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[pos : pos + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def verify_totp(token: str) -> bool:
    token = (token or "").strip()
    if not token.isdigit() or len(token) != 6:
        return False
    return any(hmac.compare_digest(token, generate_totp(MFA_SHARED_SECRET, offset=o)) for o in (-1, 0, 1))


def ensure_column(conn: sqlite3.Connection, table: str, column: str, col_def: str) -> None:
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def init_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    now_epoch = time.time()
    now_iso = utc_now_iso(now_epoch)

    with sqlite3.connect(DB_PATH, timeout=15) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        # 1. Bảng users
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL DEFAULT '',
                department TEXT NOT NULL DEFAULT '',
                birth_year INTEGER NOT NULL DEFAULT 1990,
                phone TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                linked_patient_id TEXT DEFAULT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_column(conn, "users", "department", "TEXT NOT NULL DEFAULT ''")

        # 2. Bảng medical_records
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS medical_records (
                id TEXT PRIMARY KEY,
                patient_user_id INTEGER DEFAULT NULL,
                full_name TEXT NOT NULL,
                birth_year INTEGER NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                site TEXT NOT NULL DEFAULT 'HQ',
                diagnosis TEXT NOT NULL,
                treatment_plan TEXT NOT NULL DEFAULT '',
                care_note TEXT NOT NULL DEFAULT '',
                attending_doctor TEXT NOT NULL DEFAULT 'BS.CKI Trần Minh Quân',
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL DEFAULT 'system',
                last_saved_epoch REAL NOT NULL DEFAULT 0
            )
            """
        )
        ensure_column(conn, "medical_records", "attending_doctor", "TEXT NOT NULL DEFAULT 'BS.CKI Trần Minh Quân'")

        # 3. Bảng record_revisions
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS record_revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                changed_fields TEXT NOT NULL,
                old_values_json TEXT NOT NULL,
                new_values_json TEXT NOT NULL,
                diff_summary TEXT NOT NULL,
                edited_at TEXT NOT NULL,
                edited_epoch REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_revisions_record_epoch ON record_revisions(record_id, edited_epoch DESC)")

        # 4. Bảng audit_logs
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER DEFAULT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event TEXT NOT NULL,
                target TEXT NOT NULL,
                status INTEGER NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            )
            """
        )

        # 5. Bảng mac_blacklist
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mac_blacklist (
                mac_address TEXT PRIMARY KEY,
                last_ip TEXT NOT NULL DEFAULT '',
                last_username TEXT NOT NULL DEFAULT '',
                strike_count INTEGER NOT NULL DEFAULT 1,
                fail_count INTEGER NOT NULL DEFAULT 0,
                blocked_until_epoch REAL NOT NULL DEFAULT 0,
                last_unlocked_epoch REAL NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )

        # 6. Bảng appointments
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                patient_id TEXT DEFAULT NULL,
                patient_name TEXT NOT NULL,
                branch TEXT NOT NULL DEFAULT 'HQ',
                department TEXT NOT NULL DEFAULT 'Nội tổng quát',
                doctor_username TEXT NOT NULL DEFAULT '',
                doctor_name TEXT NOT NULL DEFAULT '',
                appointment_date TEXT NOT NULL,
                appointment_time TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                source_ip TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, appointment_date)
            )
            """
        )
        ensure_column(conn, "appointments", "doctor_username", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "appointments", "doctor_name", "TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_appointments_doc_date ON appointments(doctor_username, appointment_date, appointment_time, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_appointments_status_date ON appointments(status, appointment_date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_patient_uid ON medical_records(patient_user_id)")

        # Tài khoản mặc định
        default_profiles = {
            "admin": ("Quản trị viên Hệ thống", "Quản trị hệ thống", 1988, "0909000111", "Phòng CNTT - Trụ sở HQ", None),
            "doctor": ("BS.CKI Trần Minh Quân", "Nội tổng quát", 1980, "0909000222", "Khoa Nội tổng quát - HQ", None),
            "doctor_timmach": ("ThS.BS Lê Hoàng Nam", "Tim mạch", 1979, "0909000223", "Khoa Tim mạch - HQ", None),
            "doctor_noitiet": ("BS.CKII Phạm Thu Hà", "Nội tiết", 1982, "0909000224", "Khoa Nội tiết - HQ", None),
            "doctor_tmh": ("BS.CKI Vũ Đức Anh", "Tai Mũi Họng", 1984, "0909000225", "Khoa Tai Mũi Họng - Branch", None),
            "nurse": ("ĐD. Nguyễn Thị Mai Hương", "Nội tổng quát", 1994, "0909000333", "Khoa Nội tổng quát - HQ", None),
            "patient": ("Nguyễn An (giả lập)", "", 1985, "0901000001", "Quận 1, TP.HCM (giả lập)", "DEMO-001"),
        }

        loaded_users: dict[str, dict] = {}
        if USERS_PATH.is_file():
            try:
                loaded_users = json.loads(USERS_PATH.read_text(encoding="utf-8"))
            except Exception:
                loaded_users = {}

        for uname, udata in loaded_users.items():
            role = udata.get("role", "patient")
            if role == "viewer":
                role = "patient"
            prof = default_profiles.get(uname, (f"Người dùng {uname}", "", 1990, "0900000000", "TP.HCM", None))
            conn.execute(
                """
                INSERT OR IGNORE INTO users
                (username, role, password_salt, password_hash, full_name, department, birth_year, phone, address, linked_patient_id, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    uname,
                    role,
                    udata["salt"],
                    udata["hash"],
                    udata.get("full_name", prof[0]),
                    udata.get("department", prof[1]),
                    int(udata.get("birth_year", prof[2])),
                    udata.get("phone", prof[3]),
                    udata.get("address", prof[4]),
                    udata.get("linked_patient_id", prof[5]),
                    now_iso,
                    now_iso,
                ),
            )

        default_pw_map = {
            "admin": os.environ.get("HICP_PASS_ADMIN", "Admin@Hicp2026!"),
            "doctor": os.environ.get("HICP_PASS_DOCTOR", "Doctor@Hicp2026!"),
            "doctor_timmach": os.environ.get("HICP_PASS_DOCTOR", "Doctor@Hicp2026!"),
            "doctor_noitiet": os.environ.get("HICP_PASS_DOCTOR", "Doctor@Hicp2026!"),
            "doctor_tmh": os.environ.get("HICP_PASS_DOCTOR", "Doctor@Hicp2026!"),
            "nurse": os.environ.get("HICP_PASS_NURSE", "Nurse@Hicp2026!"),
            "patient": os.environ.get("HICP_PASS_PATIENT", "Patient@Hicp2026!"),
        }
        seed_accounts = [
            ("admin", "admin"),
            ("doctor", "doctor"),
            ("doctor_timmach", "doctor"),
            ("doctor_noitiet", "doctor"),
            ("doctor_tmh", "doctor"),
            ("nurse", "nurse"),
            ("patient", "patient"),
        ]
        for uname, role in seed_accounts:
            cur = conn.execute("SELECT id, department, phone FROM users WHERE username = ?", (uname,)).fetchone()
            prof = default_profiles[uname]
            if not cur:
                salt_hex, hash_hex = hash_password(default_pw_map[uname])
                conn.execute(
                    """
                    INSERT INTO users
                    (username, role, password_salt, password_hash, full_name, department, birth_year, phone, address, linked_patient_id, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (uname, role, salt_hex, hash_hex, prof[0], prof[1], prof[2], prof[3], prof[4], prof[5], now_iso, now_iso),
                )
            else:
                if not cur[1] and prof[1]:
                    conn.execute("UPDATE users SET department = ? WHERE username = ?", (prof[1], uname))
                if not cur[2] and prof[3]:
                    conn.execute("UPDATE users SET phone = ? WHERE username = ?", (prof[3], uname))

        pat_row = conn.execute("SELECT id FROM users WHERE username = 'patient'").fetchone()
        patient_uid = pat_row[0] if pat_row else None

        # Khởi tạo 16 hồ sơ bệnh án
        for p in SYNTHETIC_PATIENTS:
            pid, fname, byear, phone, addr, site, diag, treat, cnote, att_doc = p
            linked_uid = patient_uid if pid == "DEMO-001" else None
            conn.execute(
                """
                INSERT OR IGNORE INTO medical_records
                (id, patient_user_id, full_name, birth_year, phone, address, site, diagnosis, treatment_plan, care_note, attending_doctor, updated_at, updated_by, last_saved_epoch)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'system', 0)
                """,
                (pid, linked_uid, fname, byear, phone, addr, site, diag, treat, cnote, att_doc, now_iso),
            )
            conn.execute(
                "UPDATE medical_records SET attending_doctor = ? WHERE id = ? AND (attending_doctor = 'doctor' OR attending_doctor = '')",
                (att_doc, pid),
            )

        # Lịch trình mẫu
        appt_count = conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0]
        if appt_count == 0:
            today = datetime.now().date()
            monday = today - timedelta(days=today.weekday())
            doc_row = conn.execute("SELECT id FROM users WHERE username = 'doctor'").fetchone()
            doc_tm_row = conn.execute("SELECT id FROM users WHERE username = 'doctor_timmach'").fetchone()
            doc_nt_row = conn.execute("SELECT id FROM users WHERE username = 'doctor_noitiet'").fetchone()
            if doc_row and doc_tm_row and doc_nt_row:
                sample_appts = [
                    (doc_row[0], "DEMO-004", "DEMO-004", "Phạm Dũng (giả lập)", "HQ", "Nội tổng quát", "doctor", "BS.CKI Trần Minh Quân", (monday + timedelta(days=0)).isoformat(), "09:15", "Khám nội tổng quát định kỳ", "confirmed"),
                    (doc_row[0], "DEMO-006", "DEMO-006", "Vũ Phương (giả lập)", "HQ", "Nội tổng quát", "doctor", "BS.CKI Trần Minh Quân", (monday + timedelta(days=2)).isoformat(), "08:30", "Theo dõi sức khỏe tổng quát", "confirmed"),
                    (doc_tm_row[0], "DEMO-009", "DEMO-009", "Bùi Khắc Huy (giả lập)", "HQ", "Tim mạch", "doctor_timmach", "ThS.BS Lê Hoàng Nam", (monday + timedelta(days=4)).isoformat(), "10:00", "Tái khám tim mạch", "confirmed"),
                    (doc_nt_row[0], "DEMO-003", "DEMO-003", "Lê Chi (giả lập)", "HQ", "Nội tiết", "doctor_noitiet", "BS.CKII Phạm Thu Hà", (monday + timedelta(days=5)).isoformat(), "07:30", "Kiểm tra đường huyết", "cancelled"),
                ]
                for sa in sample_appts:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO appointments
                        (user_id, username, patient_id, patient_name, branch, department, doctor_username, doctor_name, appointment_date, appointment_time, reason, status, source_ip, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '10.20.10.50', ?)
                        """,
                        (*sa, now_iso),
                    )

        conn.commit()
        conn.row_factory = sqlite3.Row
        for mb in conn.execute("SELECT * FROM mac_blacklist").fetchall():
            MAC_BLACKLIST[mb["mac_address"]] = dict(mb)
    sync_users_json()


def sync_users_json() -> None:
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM users WHERE is_active = 1").fetchall()
    export_map = {}
    for r in rows:
        export_map[r["username"]] = {
            "id": r["id"],
            "role": r["role"],
            "salt": r["password_salt"],
            "hash": r["password_hash"],
            "full_name": r["full_name"],
            "department": r["department"],
            "phone": r["phone"],
            "linked_patient_id": r["linked_patient_id"],
        }
    USERS_PATH.write_text(json.dumps(export_map, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(USERS_PATH, 0o640)
    except OSError:
        pass


def resolve_client_mac(ip: str, header_mac: str = "") -> str:
    cand = (header_mac or "").strip().upper().replace("-", ":")
    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", cand):
        return cand
    try:
        arp_path = Path("/proc/net/arp")
        if arp_path.is_file():
            for line in arp_path.read_text(encoding="utf-8").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    mac = parts[3].upper()
                    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                        return mac
    except Exception:
        pass
    digest = hashlib.sha256(f"medicare-l2-mac:{ip}".encode("utf-8")).digest()
    return f"02:{digest[0]:02X}:{digest[1]:02X}:{digest[2]:02X}:{digest[3]:02X}:{digest[4]:02X}"


def check_mac_ips_block(mac: str, now: float | None = None) -> tuple[bool, int, dict | None]:
    if now is None:
        now = time.time()
    with LOCK:
        entry = MAC_BLACKLIST.get(mac)
        if not entry:
            return False, 0, None
        blocked_until = float(entry.get("blocked_until_epoch") or 0.0)
        if now < blocked_until:
            rem = int(blocked_until - now) + 1
            return True, rem, dict(entry)
        return False, 0, dict(entry)


def record_mac_auth_failure(mac: str, ip: str, username: str, role: str = "none", user_id: int | None = None, now: float | None = None) -> dict:
    if now is None:
        now = time.time()
    with LOCK:
        history = [item for item in MAC_AUTH_TRACKER.get(mac, []) if now - item[0] <= IPS_FAIL_WINDOW_SECONDS]
        history.append((now, username, ip))
        MAC_AUTH_TRACKER[mac] = history

        fails_5m = [item for item in history if now - item[0] <= IDS_WARN_WINDOW_SECONDS]
        fails_10m = history
        count_5m = len(fails_5m)
        count_10m = len(fails_10m)

        ids_warn_triggered = count_5m >= IDS_WARN_THRESHOLD
        ips_block_triggered = count_10m >= IPS_FAIL_THRESHOLD

        block_duration = 0
        strike_count = 0
        blocked_until = 0.0

        if ips_block_triggered:
            prev = MAC_BLACKLIST.get(mac)
            prev_unlocked = float(prev["last_unlocked_epoch"]) if prev else 0.0
            prev_strikes = int(prev["strike_count"]) if prev else 0

            if prev and prev_strikes >= 1 and (now - prev_unlocked) <= IPS_RECIDIVISM_WINDOW_SECONDS:
                strike_count = prev_strikes + 1
            else:
                strike_count = 1

            block_duration = IPS_BASE_BLOCK_SECONDS * (2 ** (strike_count - 1))
            blocked_until = now + block_duration
            now_iso = utc_now_iso(now)
            reason_str = (
                f"Nhập sai mật khẩu {count_10m} lần trong 10 phút từ thiết bị MAC {mac} "
                f"(Tài khoản thử cuối: {username}, Lần phạt #{strike_count}, Khóa {block_duration}s)"
            )
            entry_data = {
                "mac_address": mac,
                "last_ip": ip,
                "last_username": username,
                "strike_count": strike_count,
                "fail_count": count_10m,
                "blocked_until_epoch": blocked_until,
                "last_unlocked_epoch": blocked_until,
                "reason": reason_str,
                "updated_at": now_iso,
            }
            MAC_BLACKLIST[mac] = entry_data
            MAC_AUTH_TRACKER[mac] = []

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.execute(
                    """
                    INSERT INTO mac_blacklist
                    (mac_address, last_ip, last_username, strike_count, fail_count, blocked_until_epoch, last_unlocked_epoch, reason, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        last_ip = excluded.last_ip,
                        last_username = excluded.last_username,
                        strike_count = excluded.strike_count,
                        fail_count = excluded.fail_count,
                        blocked_until_epoch = excluded.blocked_until_epoch,
                        last_unlocked_epoch = excluded.last_unlocked_epoch,
                        reason = excluded.reason,
                        updated_at = excluded.updated_at
                    """,
                    (mac, ip, username, strike_count, count_10m, blocked_until, blocked_until, reason_str, now_iso),
                )
                conn.commit()

    if ips_block_triggered:
        write_audit(
            username or "anonymous",
            role,
            ip,
            "ips_mac_temp_blocked",
            f"MAC:{mac}",
            HTTPStatus.TOO_MANY_REQUESTS,
            user_id=user_id,
            detail=f"IPS Blocked MAC {mac} for {block_duration}s (strike #{strike_count}, {count_10m} fails in 10m; account {username} NOT locked)",
            mac_address=mac,
        )
    elif ids_warn_triggered:
        write_audit(
            username or "anonymous",
            role,
            ip,
            "ids_bruteforce_warning",
            f"MAC:{mac}",
            HTTPStatus.UNAUTHORIZED,
            user_id=user_id,
            detail=f"IDS Alert: {count_5m} failed password attempts in 5m from MAC {mac} (account: {username})",
            mac_address=mac,
        )

    return {
        "mac_address": mac,
        "count_5m": count_5m,
        "count_10m": count_10m,
        "ids_warning": ids_warn_triggered,
        "ips_blocked": ips_block_triggered,
        "block_duration": block_duration,
        "strike_count": strike_count,
        "blocked_until_epoch": blocked_until,
    }


def write_audit(
    username: str,
    role: str,
    source_ip: str,
    event: str,
    target: str,
    status: int,
    user_id: int | None = None,
    detail: str = "",
    mac_address: str = "",
) -> None:
    record = {
        "timestamp": utc_now_iso(),
        "app": "hicp_ehr",
        "user_id": user_id,
        "username": username or "anonymous",
        "role": role or "none",
        "source_ip": source_ip,
        "mac_address": mac_address or resolve_client_mac(source_ip),
        "event": event,
        "target": target,
        "status": int(status),
        "detail": detail,
    }
    with LOCK:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (timestamp, user_id, username, role, source_ip, event, target, status, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    record["user_id"],
                    record["username"],
                    record["role"],
                    record["source_ip"],
                    record["event"],
                    record["target"],
                    record["status"],
                    record["detail"],
                ),
            )
            conn.commit()
        with open(AUDIT_JSONL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def prune_record_revisions(conn: sqlite3.Connection, record_id: str, now_epoch: float | None = None) -> int:
    if now_epoch is None:
        now_epoch = time.time()
    cutoff_seconds = REVISION_RETENTION_DAYS * 86400.0
    rows = conn.execute(
        "SELECT id, edited_epoch FROM record_revisions WHERE record_id = ? ORDER BY edited_epoch DESC, id DESC",
        (record_id,),
    ).fetchall()

    ids_to_delete = []
    for idx, (rev_id, edited_epoch) in enumerate(rows):
        age_seconds = now_epoch - float(edited_epoch)
        if idx >= REVISION_MIN_KEEP_COUNT and age_seconds > cutoff_seconds:
            ids_to_delete.append(rev_id)

    if ids_to_delete:
        conn.executemany(
            "DELETE FROM record_revisions WHERE id = ?",
            [(rev_id,) for rev_id in ids_to_delete],
        )
    return len(ids_to_delete)


def record_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["name"] = d["full_name"]
    d["birth"] = d["birth_year"]
    d["branch"] = d["site"]
    d["note"] = d["care_note"]
    d["updated"] = d["updated_at"]
    return d


def compute_diff_and_log_revision(
    conn: sqlite3.Connection,
    record_id: str,
    sess: dict,
    source_ip: str,
    action: str,
    old_obj: dict,
    new_obj: dict,
    now_epoch: float | None = None,
) -> dict:
    if now_epoch is None:
        now_epoch = time.time()
    now_iso = utc_now_iso(now_epoch)

    tracked_keys = ["full_name", "birth_year", "phone", "address", "site", "diagnosis", "treatment_plan", "care_note", "attending_doctor"]
    changed_fields = []
    old_filtered = {}
    new_filtered = {}
    summary_parts = []

    for k in tracked_keys:
        ov = old_obj.get(k)
        nv = new_obj.get(k)
        if ov != nv:
            changed_fields.append(k)
            old_filtered[k] = ov
            new_filtered[k] = nv
            summary_parts.append(f"{k}: '{ov}' -> '{nv}'")

    if not changed_fields and action == "UPDATE":
        changed_fields = ["no_change"]

    diff_summary = "; ".join(summary_parts) if summary_parts else f"Thao tác {action} trên hồ sơ {record_id}"

    conn.execute(
        """
        INSERT INTO record_revisions
        (record_id, user_id, username, role, source_ip, action, changed_fields, old_values_json, new_values_json, diff_summary, edited_at, edited_epoch)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record_id,
            int(sess.get("user_id") or 0),
            sess["username"],
            sess["role"],
            source_ip,
            action,
            json.dumps(changed_fields, ensure_ascii=False),
            json.dumps(old_filtered, ensure_ascii=False),
            json.dumps(new_filtered, ensure_ascii=False),
            diff_summary,
            now_iso,
            now_epoch,
        ),
    )
    pruned_count = prune_record_revisions(conn, record_id, now_epoch=now_epoch)
    return {
        "changed_fields": changed_fields,
        "old_values": old_filtered,
        "new_values": new_filtered,
        "pruned_revisions": pruned_count,
        "edited_at": now_iso,
    }


def mask_revision_for_role(rev_row: sqlite3.Row, viewer_role: str) -> dict:
    item = dict(rev_row)
    changed_fields = json.loads(item.pop("changed_fields", "[]"))
    old_vals = json.loads(item.pop("old_values_json", "{}"))
    new_vals = json.loads(item.pop("new_values_json", "{}"))
    item["changed_fields"] = changed_fields
    item["old_values"] = old_vals
    item["new_values"] = new_vals
    return item


def validate_appointment_time_window(time_str: str, date_str: str | None = None) -> tuple[bool, str]:
    m = re.match(r"^(\d{2}):(\d{2})$", (time_str or "").strip())
    if not m:
        return False, "Định dạng giờ khám không hợp lệ (cần nhập HH:MM, ví dụ 08:30)."
    hh, mm = int(m.group(1)), int(m.group(2))
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        return False, "Giờ hoặc phút không hợp lệ."
    total_minutes = hh * 60 + mm
    if not (APPOINTMENT_START_MINUTE <= total_minutes <= APPOINTMENT_END_MINUTE):
        return False, "Giới hạn thời gian: Hệ thống chỉ cho phép đặt lịch khám trong khung giờ từ 07:00 đến 15:00."

    now_local = datetime.now()
    if date_str:
        try:
            appt_dt = datetime.strptime(f"{date_str.strip()} {hh:02d}:{mm:02d}", "%Y-%m-%d %H:%M")
        except ValueError:
            return False, "Ngày khám hoặc giờ khám không hợp lệ."
        earliest_dt = now_local.replace(second=0, microsecond=0) + timedelta(minutes=APPOINTMENT_MIN_LEAD_MINUTES)
        if appt_dt < earliest_dt:
            earliest_str = earliest_dt.strftime("%H:%M ngày %Y-%m-%d")
            return (
                False,
                f"Giới hạn thời gian: Lịch khám phải cách thời điểm hiện tại tối thiểu {APPOINTMENT_MIN_LEAD_MINUTES} phút (Sớm nhất có thể đặt là từ {earliest_str}).",
            )

    if ENFORCE_REALTIME_BOOKING_CLOCK:
        now_min = now_local.hour * 60 + now_local.minute
        if not (APPOINTMENT_START_MINUTE <= now_min <= APPOINTMENT_END_MINUTE):
            return False, "Ngoài khung giờ tiếp nhận đặt lịch trực tuyến (07:00 - 15:00)."
    return True, ""


def prune_expired_memory_state(now: float | None = None) -> None:
    global LAST_MEM_PRUNE_EPOCH
    if now is None:
        now = time.time()
    if now - LAST_MEM_PRUNE_EPOCH < 60.0:
        return
    with LOCK:
        if now - LAST_MEM_PRUNE_EPOCH < 60.0:
            return
        LAST_MEM_PRUNE_EPOCH = now
        expired_sids = [sid for sid, s in SESSIONS.items() if now - float(s.get("last_seen", 0)) > SESSION_TIMEOUT_SECONDS]
        for sid in expired_sids:
            SESSIONS.pop(sid, None)
        expired_otps = [u for u, o in RESET_OTPS.items() if float(o.get("expires_at", 0)) < now]
        for u in expired_otps:
            RESET_OTPS.pop(u, None)
        for mac_k in list(MAC_AUTH_TRACKER.keys()):
            kept = [item for item in MAC_AUTH_TRACKER[mac_k] if now - item[0] <= IPS_FAIL_WINDOW_SECONDS]
            if kept:
                MAC_AUTH_TRACKER[mac_k] = kept
            else:
                MAC_AUTH_TRACKER.pop(mac_k, None)
        for ip_k in list(EXPORT_TRACKER.keys()):
            kept_ex = [t for t in EXPORT_TRACKER[ip_k] if now - t < EXPORT_WINDOW_SECONDS]
            if kept_ex:
                EXPORT_TRACKER[ip_k] = kept_ex
            else:
                EXPORT_TRACKER.pop(ip_k, None)


class HICPRequestHandler(BaseHTTPRequestHandler):
    server_version = "MediCareEHR/2.2"

    def log_message(self, fmt: str, *args) -> None:
        return

    def client_ip(self) -> str:
        raw_ip = self.client_address[0]
        if TRUST_LOCAL_PROXY and raw_ip in ("127.0.0.1", "::1"):
            cf_ip = self.headers.get("CF-Connecting-IP", "").strip()
            if cf_ip:
                return cf_ip
            xff = self.headers.get("X-Forwarded-For", "").strip()
            if xff:
                first_ip = xff.split(",")[0].strip()
                if first_ip:
                    return first_ip
            forwarded = self.headers.get("X-Real-IP", "").strip()
            if forwarded:
                return forwarded
        return raw_ip

    def is_https_request(self) -> bool:
        if TLS_ENABLED:
            return True
        if TRUST_LOCAL_PROXY and self.client_address[0] in ("127.0.0.1", "::1"):
            proto = self.headers.get("X-Forwarded-Proto", "").strip().lower()
            if proto == "https":
                return True
            cf_visitor = self.headers.get("CF-Visitor", "").strip().lower().replace(" ", "")
            if '"scheme":"https"' in cf_visitor:
                return True
        return False

    def client_mac(self) -> str:
        hdr_mac = self.headers.get("X-Client-MAC", "") or self.headers.get("X-Device-MAC", "")
        return resolve_client_mac(self.client_ip(), hdr_mac)

    def send_security_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if self.is_https_request():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def send_json(self, status: int, payload: dict | list, extra_headers: list[tuple[str, str]] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def current_session(self) -> dict | None:
        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        morsel = cookie.get("hicp_session")
        if not morsel:
            return None
        sid = morsel.value
        now = time.time()
        prune_expired_memory_state(now)
        with LOCK:
            sess = SESSIONS.get(sid)
            if not sess:
                return None
            if now - sess["last_seen"] > SESSION_TIMEOUT_SECONDS:
                del SESSIONS[sid]
                return None
            sess["last_seen"] = now
            return sess

    def verify_csrf(self, sess: dict) -> bool:
        csrf_hdr = self.headers.get("X-CSRF-Token", "")
        return bool(csrf_hdr and hmac.compare_digest(csrf_hdr, sess["csrf"]))

    def read_json_body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 32768:
                return None
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    # GET ENDPOINTS
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        ip = self.client_ip()

        if path in ("/health", "/healthz"):
            self.send_json(HTTPStatus.OK, {"status": "ok", "service": "hicp_ehr", "version": "2.2"})
            return

        if path in ("/ready", "/readyz"):
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                conn.execute("SELECT 1").fetchone()
            self.send_json(HTTPStatus.OK, {"status": "ready", "database": "wal_ok", "version": "2.2"})
            return

        if path == "/metrics":
            now_m = time.time()
            with LOCK:
                active_sess = sum(1 for s in SESSIONS.values() if now_m - float(s.get("last_seen", 0)) <= SESSION_TIMEOUT_SECONDS)
                blocked_macs = sum(1 for b in MAC_BLACKLIST.values() if float(b.get("blocked_until_epoch", 0)) > now_m)
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                u_cnt = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
                r_cnt = conn.execute("SELECT COUNT(*) FROM medical_records").fetchone()[0]
                rev_cnt = conn.execute("SELECT COUNT(*) FROM record_revisions").fetchone()[0]
                aud_cnt = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
                ap_pending = conn.execute("SELECT COUNT(*) FROM appointments WHERE status = 'pending'").fetchone()[0]
                ap_confirmed = conn.execute("SELECT COUNT(*) FROM appointments WHERE status = 'confirmed'").fetchone()[0]
                ap_cancelled = conn.execute("SELECT COUNT(*) FROM appointments WHERE status = 'cancelled'").fetchone()[0]
                sec_cnt = conn.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE status >= 400 OR event IN ('ids_probe','iomt_alert','dlp_export_blocked','admin_phi_access_blocked','rbac_medical_record_violation','record_save_cooldown_blocked','ids_bruteforce_warning','ips_mac_temp_blocked')"
                ).fetchone()[0]
            prom_lines = [
                "# HELP medicare_up Trạng thái hoạt động của dịch vụ MediCare EHR (1 = online).",
                "# TYPE medicare_up gauge",
                "medicare_up 1",
                "# HELP medicare_active_sessions_total Số phiên đăng nhập đang hoạt động.",
                "# TYPE medicare_active_sessions_total gauge",
                f"medicare_active_sessions_total {active_sess}",
                "# HELP medicare_ips_blocked_macs_total Số thiết bị MAC đang bị khóa tạm thời bởi IPS.",
                "# TYPE medicare_ips_blocked_macs_total gauge",
                f"medicare_ips_blocked_macs_total {blocked_macs}",
                "# HELP medicare_users_total Tổng số tài khoản đang hoạt động.",
                "# TYPE medicare_users_total gauge",
                f"medicare_users_total {u_cnt}",
                "# HELP medicare_records_total Tổng số hồ sơ bệnh án trong CSDL.",
                "# TYPE medicare_records_total gauge",
                f"medicare_records_total {r_cnt}",
                "# HELP medicare_revisions_total Tổng số bản ghi lịch sử chỉnh sửa (Audit Diff).",
                "# TYPE medicare_revisions_total gauge",
                f"medicare_revisions_total {rev_cnt}",
                "# HELP medicare_appointments_total Số lượng lịch khám theo trạng thái.",
                "# TYPE medicare_appointments_total gauge",
                f'medicare_appointments_total{{status="pending"}} {ap_pending}',
                f'medicare_appointments_total{{status="confirmed"}} {ap_confirmed}',
                f'medicare_appointments_total{{status="cancelled"}} {ap_cancelled}',
                "# HELP medicare_audit_events_total Tổng số sự kiện kiểm toán đã ghi nhận.",
                "# TYPE medicare_audit_events_total counter",
                f"medicare_audit_events_total {aud_cnt}",
                "# HELP medicare_security_alerts_total Tổng số cảnh báo an ninh (IDS/IPS/RBAC/DLP/IoMT).",
                "# TYPE medicare_security_alerts_total counter",
                f"medicare_security_alerts_total {sec_cnt}",
                "",
            ]
            prom_bytes = "\n".join(prom_lines).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_security_headers()
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(prom_bytes)))
            self.end_headers()
            self.wfile.write(prom_bytes)
            return

        if path == "/demo/ids-probe":
            sess = self.current_session()
            write_audit(
                sess["username"] if sess else "anonymous",
                sess["role"] if sess else "none",
                ip,
                "ids_probe",
                "/demo/ids-probe",
                HTTPStatus.OK,
                user_id=sess["user_id"] if sess else None,
            )
            self.send_json(HTTPStatus.OK, {"message": "HICP IDS test marker only. Check actual Suricata/Wazuh logs."})
            return

        if path == "/api/me":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            self.send_json(
                HTTPStatus.OK,
                {
                    "user_id": sess["user_id"],
                    "username": sess["username"],
                    "role": sess["role"],
                    "full_name": sess.get("full_name", ""),
                    "department": sess.get("department", ""),
                    "linked_patient_id": sess.get("linked_patient_id"),
                    "csrf": sess["csrf"],
                    "source_ip": ip,
                    "mfa_enabled": REQUIRE_MFA,
                    "save_cooldown_seconds": SAVE_COOLDOWN_SECONDS,
                    "revision_retention_days": REVISION_RETENTION_DAYS,
                },
            )
            return

        # Danh bạ Khoa & Bác sĩ (/api/doctors)
        if path == "/api/doctors":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, username, full_name, department FROM users WHERE role = 'doctor' AND is_active = 1 ORDER BY department ASC, full_name ASC"
                ).fetchall()
            doctors = [dict(r) for r in rows]
            depts = list(DEPARTMENTS)
            for d in doctors:
                if d["department"] and d["department"] not in depts:
                    depts.append(d["department"])
            self.send_json(HTTPStatus.OK, {"departments": depts, "doctors": doctors})
            return

        # 1. Hồ sơ bệnh án (GET /api/patients)
        if path == "/api/patients":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return

            if sess["role"] == "admin":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "admin_phi_access_blocked",
                    "medical_records_list",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail="System Admin attempted to view clinical medical records",
                )
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Vi phạm chính sách HICP & Zero Trust: Admin hệ thống không được phép xem hoặc can thiệp nội dung hồ sơ bệnh án!"
                    },
                )
                return

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                if sess["role"] in ("doctor", "nurse"):
                    rows = conn.execute("SELECT * FROM medical_records ORDER BY id ASC").fetchall()
                elif sess["role"] == "patient":
                    linked_id = sess.get("linked_patient_id")
                    rows = conn.execute(
                        "SELECT * FROM medical_records WHERE patient_user_id = ? OR id = ? ORDER BY id ASC",
                        (sess["user_id"], linked_id or ""),
                    ).fetchall()
                else:
                    rows = []

            records = [record_to_dict(r) for r in rows]
            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "view_records",
                "patients_list",
                HTTPStatus.OK,
                user_id=sess["user_id"],
                detail=f"Returned {len(records)} record(s)",
            )
            self.send_json(HTTPStatus.OK, records)
            return

        # 2. Lịch sử chỉnh sửa hồ sơ (GET /api/revisions)
        if path == "/api/revisions" or (path.startswith("/api/patients/") and path.endswith("/revisions")):
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] != "admin":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "access_denied",
                    "record_revisions",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                )
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Quản trị viên hệ thống (Admin) mới có quyền xem lịch sử chỉnh sửa."})
                return

            record_filter = None
            if path.startswith("/api/patients/"):
                parts = path.strip("/").split("/")
                if len(parts) >= 3:
                    record_filter = parts[2]
            elif "record_id" in query:
                record_filter = query["record_id"][0]

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                if record_filter:
                    prune_record_revisions(conn, record_filter)
                    conn.commit()
                    rows = conn.execute(
                        "SELECT * FROM record_revisions WHERE record_id = ? ORDER BY edited_epoch DESC, id DESC LIMIT 100",
                        (record_filter,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM record_revisions ORDER BY edited_epoch DESC, id DESC LIMIT 200"
                    ).fetchall()

            result = [mask_revision_for_role(r, sess["role"]) for r in rows]
            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "view_revisions",
                record_filter or "all_revisions",
                HTTPStatus.OK,
                user_id=sess["user_id"],
            )
            self.send_json(HTTPStatus.OK, result)
            return

        # 3. Thông tin cá nhân (GET /api/profile)
        if path == "/api/profile":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                u = conn.execute(
                    "SELECT id, username, role, full_name, department, birth_year, phone, address, linked_patient_id, created_at, updated_at FROM users WHERE id = ?",
                    (sess["user_id"],),
                ).fetchone()
            if not u:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy hồ sơ tài khoản."})
                return
            self.send_json(HTTPStatus.OK, dict(u))
            return

        # 4. Lịch khám & Lịch trình bác sĩ (GET /api/appointments)
        if path == "/api/appointments":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Bắt buộc phải đăng nhập mới được xem hoặc đặt lịch khám."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                if sess["role"] == "patient":
                    rows = conn.execute(
                        "SELECT * FROM appointments WHERE user_id = ? ORDER BY appointment_date DESC, appointment_time ASC",
                        (sess["user_id"],),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM appointments ORDER BY appointment_date ASC, appointment_time ASC LIMIT 300"
                    ).fetchall()
            self.send_json(HTTPStatus.OK, [dict(r) for r in rows])
            return

        # 5. Danh sách tài khoản (GET /api/users)
        if path == "/api/users":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "users_management", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền quản lý và phân quyền tài khoản."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, username, role, full_name, department, birth_year, phone, address, linked_patient_id, is_active, created_at, updated_at FROM users ORDER BY id ASC"
                ).fetchall()
            self.send_json(HTTPStatus.OK, [dict(r) for r in rows])
            return

        # 6. Danh sách thiết bị bị khóa (GET /api/mac-blacklist)
        if path == "/api/mac-blacklist":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] != "admin":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền xem danh sách thiết bị bị hạn chế."})
                return
            now = time.time()
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM mac_blacklist ORDER BY updated_at DESC").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                rem = max(0, int(float(d["blocked_until_epoch"]) - now))
                d["remaining_seconds"] = rem
                d["status"] = "blocked" if rem > 0 else "expired_watching_recidivism"
                items.append(d)
            self.send_json(HTTPStatus.OK, items)
            return

        # 7. Trạng thái hệ thống (GET /api/system/status)
        if path == "/api/system/status":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "system_status", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền giám sát hạ tầng & SIEM."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                record_count = conn.execute("SELECT COUNT(*) FROM medical_records").fetchone()[0]
                revision_count = conn.execute("SELECT COUNT(*) FROM record_revisions").fetchone()[0]
                audit_count = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
                appt_count = conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0]
                security_alerts = conn.execute(
                    "SELECT COUNT(*) FROM audit_logs WHERE status >= 400 OR event IN ('ids_probe', 'iomt_alert', 'dlp_export_blocked', 'admin_phi_access_blocked', 'record_save_cooldown_blocked')"
                ).fetchone()[0]

            self.send_json(
                HTTPStatus.OK,
                {
                    "server_ip": "10.20.10.50",
                    "vlan": "VLAN 20 Server (10.20.10.0/24)",
                    "vpn_topology": "Site-to-Site WireGuard / IPsec (HQ 192.168.226.133 <-> Branch 192.168.226.134)",
                    "siem_agent": "Wazuh Manager & Localfile JSON Collector (/var/lib/hicp-ehr/audit.jsonl)",
                    "ids_engine": "Suricata NIDS/IPS Ready (/var/log/suricata/eve.json)",
                    "metrics": {
                        "total_users": user_count,
                        "total_records_metadata": record_count,
                        "total_revisions": revision_count,
                        "total_audit_events": audit_count,
                        "total_appointments": appt_count,
                        "security_alerts_count": security_alerts,
                    },
                },
            )
            return

        # 8. Xuất dữ liệu CSV (GET /api/export)
        if path == "/api/export":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] == "admin":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "admin_phi_access_blocked",
                    "export_csv",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                )
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "Admin hệ thống không được phép trích xuất nội dung hồ sơ bệnh án (Tuân thủ HICP Least Privilege)."},
                )
                return
            if sess["role"] != "doctor":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "export_csv", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Bác sĩ điều trị mới có quyền kết xuất hồ sơ chuyên môn."})
                return

            now = time.time()
            with LOCK:
                history = [t for t in EXPORT_TRACKER.get(ip, []) if now - t < EXPORT_WINDOW_SECONDS]
                if len(history) >= EXPORT_MAX_COUNT:
                    EXPORT_TRACKER[ip] = history
                    write_audit(
                        sess["username"],
                        sess["role"],
                        ip,
                        "dlp_export_blocked",
                        "all_synthetic_patients",
                        HTTPStatus.TOO_MANY_REQUESTS,
                        user_id=sess["user_id"],
                    )
                    self.send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {"error": "Cảnh báo Active DLP: Vượt ngưỡng xuất dữ liệu CSV cho phép (tối đa 2 lần/5 phút)."},
                    )
                    return
                history.append(now)
                EXPORT_TRACKER[ip] = history

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                rows = conn.execute(
                    "SELECT id, full_name, birth_year, site, diagnosis, treatment_plan, care_note, attending_doctor, updated_at, updated_by FROM medical_records ORDER BY id ASC"
                ).fetchall()

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["id", "full_name", "birth_year", "site", "diagnosis", "treatment_plan", "care_note", "attending_doctor", "updated_at", "updated_by"])
            writer.writerows(rows)
            csv_bytes = buf.getvalue().encode("utf-8")

            write_audit(sess["username"], sess["role"], ip, "export_records", "all_synthetic_patients", HTTPStatus.OK, user_id=sess["user_id"])
            self.send_response(HTTPStatus.OK)
            self.send_security_headers()
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="medicare_records.csv"')
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        # 9. Nhật ký hệ thống (GET /api/audit)
        if path == "/api/audit":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "audit_log", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Tài khoản không có quyền xem nhật ký kiểm toán hệ thống."})
                return
            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, timestamp, user_id, username, role, source_ip, event, target, status, detail FROM audit_logs ORDER BY id DESC LIMIT 250"
                ).fetchall()
            self.send_json(HTTPStatus.OK, [dict(r) for r in rows])
            return

        # Phục vụ Static Files
        rel = "index.html" if path == "/" else path.lstrip("/")
        target_file = (STATIC_DIR / rel).resolve()
        if not str(target_file).startswith(str(STATIC_DIR.resolve())) or not target_file.is_file():
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy tài nguyên."})
            return

        ext_map = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }
        ctype = ext_map.get(target_file.suffix, "application/octet-stream")
        content = target_file.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_security_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # POST ENDPOINTS
    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_ip()

        # 1. ĐĂNG NHẬP (/api/login)
        if path == "/api/login":
            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu đăng nhập không hợp lệ."})
                return
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            otp_code = str(data.get("otp", "")).strip()
            mac = self.client_mac()

            now = time.time()
            is_blocked, wait_sec, blk_info = check_mac_ips_block(mac, now)
            if is_blocked:
                strike_no = blk_info["strike_count"] if blk_info else 1
                write_audit(
                    username or "anonymous",
                    "none",
                    ip,
                    "login_throttled",
                    f"MAC:{mac}",
                    HTTPStatus.TOO_MANY_REQUESTS,
                    detail=f"Blocked login attempt from blacklisted MAC {mac} ({wait_sec}s remaining, strike #{strike_no})",
                    mac_address=mac,
                )
                self.send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {
                        "error": f"Thiết bị bị tạm khoá {wait_sec} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                        "ips_blocked": True,
                        "retry_after_seconds": wait_sec,
                        "strike_count": strike_no,
                    },
                )
                return

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                uinfo = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)).fetchone()

            if not uinfo or not verify_password(password, uinfo["password_salt"], uinfo["password_hash"]):
                write_audit(
                    username or "anonymous",
                    uinfo["role"] if uinfo else "none",
                    ip,
                    "login_failed",
                    f"login:{mac}",
                    HTTPStatus.UNAUTHORIZED,
                    user_id=uinfo["id"] if uinfo else None,
                    detail=f"Failed password from MAC {mac}",
                    mac_address=mac,
                )
                sec_res = record_mac_auth_failure(
                    mac,
                    ip,
                    username or "anonymous",
                    role=uinfo["role"] if uinfo else "none",
                    user_id=uinfo["id"] if uinfo else None,
                    now=now,
                )
                if sec_res["ips_blocked"]:
                    self.send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {
                            "error": f"Thiết bị bị tạm khoá {sec_res['block_duration']} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                            "ips_blocked": True,
                            "block_duration": sec_res["block_duration"],
                            "retry_after_seconds": sec_res["block_duration"],
                            "strike_count": sec_res["strike_count"],
                        },
                    )
                    return
                if sec_res["ids_warning"]:
                    self.send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {
                            "error": "Nhập sai mật khẩu 5 lần thiết bị sẽ bị tạm khoá đăng nhập",
                            "ids_warning": True,
                            "fail_count_5m": sec_res["count_5m"],
                        },
                    )
                    return
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Sai tên đăng nhập hoặc mật khẩu."})
                return

            if REQUIRE_MFA and not verify_totp(otp_code):
                write_audit(username, uinfo["role"], ip, "mfa_failed", f"login:{mac}", HTTPStatus.UNAUTHORIZED, user_id=uinfo["id"], mac_address=mac)
                sec_mfa = record_mac_auth_failure(mac, ip, username, role=uinfo["role"], user_id=uinfo["id"], now=now)
                if sec_mfa["ips_blocked"]:
                    self.send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {
                            "error": f"Thiết bị bị tạm khoá {sec_mfa['block_duration']} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                            "ips_blocked": True,
                            "block_duration": sec_mfa["block_duration"],
                            "retry_after_seconds": sec_mfa["block_duration"],
                            "strike_count": sec_mfa["strike_count"],
                        },
                    )
                    return
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Mã xác thực đa yếu tố (MFA/OTP) không hợp lệ."})
                return

            sid = secrets.token_urlsafe(32)
            csrf = secrets.token_hex(16)
            with LOCK:
                MAC_AUTH_TRACKER.pop(mac, None)
                SESSIONS[sid] = {
                    "user_id": uinfo["id"],
                    "username": username,
                    "role": uinfo["role"],
                    "full_name": uinfo["full_name"],
                    "department": uinfo["department"],
                    "linked_patient_id": uinfo["linked_patient_id"],
                    "csrf": csrf,
                    "last_seen": now,
                }

            write_audit(username, uinfo["role"], ip, "login_success", "login", HTTPStatus.OK, user_id=uinfo["id"])
            cookie_header = f"hicp_session={sid}; HttpOnly; Path=/; SameSite=Strict"
            if self.is_https_request():
                cookie_header += "; Secure"
            self.send_json(
                HTTPStatus.OK,
                {
                    "user_id": uinfo["id"],
                    "username": username,
                    "role": uinfo["role"],
                    "full_name": uinfo["full_name"],
                    "department": uinfo["department"],
                    "linked_patient_id": uinfo["linked_patient_id"],
                    "csrf": csrf,
                    "source_ip": ip,
                },
                extra_headers=[("Set-Cookie", cookie_header)],
            )
            return

        # 1B. Khôi phục mật khẩu qua SĐT (/api/forgot-password/*)
        if path == "/api/forgot-password/request-otp":
            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return
            username = str(data.get("username", "")).strip()
            phone = str(data.get("phone", "")).strip()
            if not username or not phone:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Vui lòng nhập đầy đủ Tên tài khoản và Số điện thoại đã đăng ký."})
                return

            now = time.time()
            mac = self.client_mac()
            is_blk, wait_s, _ = check_mac_ips_block(mac, now)
            if is_blk:
                self.send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {
                        "error": f"Thiết bị bị tạm khoá {wait_s} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                        "ips_blocked": True,
                        "retry_after_seconds": wait_s,
                    },
                )
                return

            with sqlite3.connect(DB_PATH, timeout=10) as conn:
                conn.row_factory = sqlite3.Row
                uinfo = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)).fetchone()

            if not uinfo or uinfo["role"] != "patient" or not uinfo["phone"] or uinfo["phone"].strip() != phone:
                sec_fp = record_mac_auth_failure(mac, ip, username or "anonymous", now=now)
                write_audit(
                    username or "anonymous",
                    uinfo["role"] if uinfo else "none",
                    ip,
                    "password_reset_failed",
                    "forgot_password_otp",
                    HTTPStatus.BAD_REQUEST,
                    user_id=uinfo["id"] if uinfo else None,
                    detail="Invalid patient username or phone mismatch",
                )
                if sec_fp["ips_blocked"]:
                    self.send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {
                            "error": f"Thiết bị bị tạm khoá {sec_fp['block_duration']} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                            "ips_blocked": True,
                            "block_duration": sec_fp["block_duration"],
                        },
                    )
                    return
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Thông tin tài khoản bệnh nhân hoặc số điện thoại xác nhận không chính xác."},
                )
                return

            otp_code = f"{secrets.randbelow(900000) + 100000:06d}"
            with LOCK:
                RESET_OTPS[username] = {
                    "otp": otp_code,
                    "phone": phone,
                    "expires_at": now + OTP_EXPIRY_SECONDS,
                    "attempts": 0,
                }

            write_audit(
                username,
                "patient",
                ip,
                "password_reset_otp_sent",
                f"phone:{phone[-4:]}",
                HTTPStatus.OK,
                user_id=uinfo["id"],
                detail="Generated 6-digit SMS OTP for patient password reset",
            )
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "otp_code": otp_code,
                    "expires_in": OTP_EXPIRY_SECONDS,
                    "message": f"Mã xác nhận OTP đã được gửi tới số điện thoại {phone}.",
                },
            )
            return

        if path == "/api/forgot-password/reset":
            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return
            username = str(data.get("username", "")).strip()
            phone = str(data.get("phone", "")).strip()
            otp_input = str(data.get("otp", "")).strip()
            new_password = str(data.get("new_password", ""))

            now = time.time()
            mac = self.client_mac()
            is_blk, wait_s, _ = check_mac_ips_block(mac, now)
            if is_blk:
                self.send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {
                        "error": f"Thiết bị bị tạm khoá {wait_s} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác",
                        "ips_blocked": True,
                        "retry_after_seconds": wait_s,
                    },
                )
                return
            with LOCK:
                otp_entry = RESET_OTPS.get(username)
                if not otp_entry or otp_entry["expires_at"] < now or otp_entry["phone"] != phone:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Mã xác nhận OTP không tồn tại hoặc đã hết hạn (3 phút)."})
                    return
                otp_entry["attempts"] += 1
                if otp_entry["attempts"] > 5:
                    RESET_OTPS.pop(username, None)
                    self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Nhập sai OTP quá 5 lần. Vui lòng yêu cầu mã mới."})
                    return
                if not hmac.compare_digest(otp_entry["otp"], otp_input):
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Mã xác nhận OTP không chính xác."})
                    return

                ok_pw, pw_msg = validate_password_complexity(new_password)
                if not ok_pw:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": pw_msg})
                    return

                salt_hex, hash_hex = hash_password(new_password)
                now_iso = utc_now_iso(now)
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    cur = conn.execute(
                        "UPDATE users SET password_salt = ?, password_hash = ?, updated_at = ? WHERE username = ? AND role = 'patient'",
                        (salt_hex, hash_hex, now_iso, username),
                    )
                    conn.commit()
                    if cur.rowcount == 0:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Không thể cập nhật mật khẩu cho tài khoản này."})
                        return
                RESET_OTPS.pop(username, None)
                sync_users_json()

            write_audit(username, "patient", ip, "password_reset_success", "forgot_password", HTTPStatus.OK, detail="Patient reset password via phone OTP")
            self.send_json(HTTPStatus.OK, {"ok": True, "message": "Đổi mật khẩu thành công. Vui lòng đăng nhập bằng mật khẩu mới."})
            return

        # 2. ĐĂNG XUẤT (/api/logout)
        if path == "/api/logout":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if not self.verify_csrf(sess):
                write_audit(sess["username"], sess["role"], ip, "access_denied", "csrf_logout", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
                return
            raw_cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = raw_cookie.get("hicp_session")
            if morsel:
                with LOCK:
                    SESSIONS.pop(morsel.value, None)
            write_audit(sess["username"], sess["role"], ip, "logout", "logout", HTTPStatus.OK, user_id=sess["user_id"])
            logout_cookie = "hicp_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict"
            if self.is_https_request():
                logout_cookie += "; Secure"
            self.send_json(
                HTTPStatus.OK,
                {"ok": True},
                extra_headers=[("Set-Cookie", logout_cookie)],
            )
            return

        # 3. Thêm hồ sơ bệnh án (POST /api/patients)
        if path == "/api/patients":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if not self.verify_csrf(sess):
                write_audit(sess["username"], sess["role"], ip, "access_denied", "csrf_create_record", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
                return

            if sess["role"] == "admin":
                write_audit(sess["username"], sess["role"], ip, "admin_phi_access_blocked", "create_record", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin hệ thống tuyệt đối không được tạo hoặc can thiệp hồ sơ bệnh án."})
                return
            if sess["role"] != "doctor":
                write_audit(sess["username"], sess["role"], ip, "rbac_medical_record_violation", "create_record", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Bác sĩ điều trị mới có quyền thêm hoặc chỉnh sửa hồ sơ bệnh án."})
                return

            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu hồ sơ không hợp lệ."})
                return

            record_id = str(data.get("id", "")).strip().upper()
            full_name = str(data.get("full_name", "")).strip()
            birth_year = int(data.get("birth_year", 0) or 0)
            phone = str(data.get("phone", "")).strip()
            address = str(data.get("address", "")).strip()
            site = str(data.get("site", "HQ")).strip()
            diagnosis = str(data.get("diagnosis", "")).strip()
            treatment_plan = str(data.get("treatment_plan", "")).strip()
            care_note = str(data.get("note", data.get("care_note", ""))).strip()
            attending_doctor = str(data.get("attending_doctor", sess.get("full_name") or sess["username"])).strip()

            if not re.match(r"^[A-Z0-9\-]{4,24}$", record_id):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Mã hồ sơ không hợp lệ (ví dụ: DEMO-017)."})
                return
            if not full_name or not (1900 <= birth_year <= 2026) or not diagnosis:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Vui lòng nhập đầy đủ Họ tên, Năm sinh hợp lệ và Chẩn đoán."})
                return
            if site not in ("HQ", "Branch"):
                site = "HQ"

            now_epoch = time.time()
            with LOCK:
                last_user_save = USER_SAVE_TRACKER.get(sess["username"], 0.0)
                if now_epoch - last_user_save < SAVE_COOLDOWN_SECONDS:
                    wait_sec = int(SAVE_COOLDOWN_SECONDS - (now_epoch - last_user_save)) + 1
                    write_audit(
                        sess["username"],
                        sess["role"],
                        ip,
                        "record_save_cooldown_blocked",
                        record_id,
                        HTTPStatus.TOO_MANY_REQUESTS,
                        user_id=sess["user_id"],
                        detail=f"Cooldown active ({wait_sec}s remaining)",
                    )
                    self.send_json(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        {"error": f"Để cân bằng tải, mỗi lần lưu dữ liệu bệnh án cần cách nhau tối thiểu 1 phút (60 giây). Vui lòng đợi {wait_sec} giây nữa."},
                    )
                    return

                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    existing = conn.execute("SELECT id FROM medical_records WHERE id = ?", (record_id,)).fetchone()
                    if existing:
                        self.send_json(HTTPStatus.CONFLICT, {"error": f"Mã hồ sơ {record_id} đã tồn tại."})
                        return

                    now_iso = utc_now_iso(now_epoch)
                    new_obj = {
                        "id": record_id,
                        "full_name": full_name,
                        "birth_year": birth_year,
                        "phone": phone,
                        "address": address,
                        "site": site,
                        "diagnosis": diagnosis,
                        "treatment_plan": treatment_plan,
                        "care_note": care_note,
                        "attending_doctor": attending_doctor,
                    }
                    conn.execute(
                        """
                        INSERT INTO medical_records
                        (id, patient_user_id, full_name, birth_year, phone, address, site, diagnosis, treatment_plan, care_note, attending_doctor, updated_at, updated_by, last_saved_epoch)
                        VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_id,
                            full_name,
                            birth_year,
                            phone,
                            address,
                            site,
                            diagnosis,
                            treatment_plan,
                            care_note,
                            attending_doctor,
                            now_iso,
                            sess["username"],
                            now_epoch,
                        ),
                    )
                    diff_meta = compute_diff_and_log_revision(
                        conn,
                        record_id,
                        sess,
                        ip,
                        "CREATE",
                        {},
                        new_obj,
                        now_epoch=now_epoch,
                    )
                    conn.commit()
                    USER_SAVE_TRACKER[sess["username"]] = now_epoch

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "create_record",
                record_id,
                HTTPStatus.CREATED,
                user_id=sess["user_id"],
                detail=f"Created record {record_id} ({site})",
            )
            self.send_json(HTTPStatus.CREATED, {"ok": True, "id": record_id, "attending_doctor": attending_doctor, "revision": diff_meta})
            return

        # 4. Đặt lịch khám trực tuyến (POST /api/appointments)
        if path == "/api/appointments":
            sess = self.current_session()
            if not sess:
                write_audit("anonymous", "none", ip, "access_denied", "book_appointment_unauth", HTTPStatus.UNAUTHORIZED)
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Bắt buộc phải đăng nhập mới được quyền đặt lịch khám."})
                return
            if not self.verify_csrf(sess):
                write_audit(sess["username"], sess["role"], ip, "access_denied", "csrf_appointment", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
                return

            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu đặt lịch không hợp lệ."})
                return

            appointment_date = str(data.get("appointment_date", "")).strip()
            appointment_time = str(data.get("appointment_time", "")).strip()
            branch = str(data.get("branch", "HQ")).strip()
            department = str(data.get("department", "")).strip()
            doctor_username = str(data.get("doctor_username", "")).strip()
            reason = str(data.get("reason", "")).strip()
            patient_name = str(data.get("patient_name", sess.get("full_name") or sess["username"])).strip()

            if not department:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Vui lòng chọn Khoa đăng ký khám bệnh."})
                return
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", appointment_date):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Ngày khám phải có định dạng YYYY-MM-DD."})
                return
            if not reason or len(reason) > 500:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Vui lòng nhập lý do khám / triệu chứng (tối đa 500 ký tự)."})
                return

            ok_time, time_err = validate_appointment_time_window(appointment_time, appointment_date)
            if not ok_time:
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "appointment_rejected_time_window",
                    f"{appointment_date} {appointment_time}",
                    HTTPStatus.BAD_REQUEST,
                    user_id=sess["user_id"],
                    detail=time_err,
                )
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": time_err})
                return

            now_iso = utc_now_iso()
            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row

                    doctor_name = ""
                    if doctor_username:
                        doc_row = conn.execute(
                            "SELECT username, full_name, department FROM users WHERE username = ? AND role = 'doctor' AND is_active = 1",
                            (doctor_username,),
                        ).fetchone()
                        if not doc_row:
                            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Bác sĩ được chọn không tồn tại trong hệ thống."})
                            return
                        if doc_row["department"] and doc_row["department"] != department:
                            self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"Bác sĩ {doc_row['full_name']} không thuộc khoa {department}."})
                            return
                        doctor_name = doc_row["full_name"]

                    existing = conn.execute(
                        "SELECT id, appointment_time FROM appointments WHERE user_id = ? AND appointment_date = ?",
                        (sess["user_id"], appointment_date),
                    ).fetchone()
                    if existing:
                        write_audit(
                            sess["username"],
                            sess["role"],
                            ip,
                            "appointment_rejected_daily_limit",
                            appointment_date,
                            HTTPStatus.TOO_MANY_REQUESTS,
                            user_id=sess["user_id"],
                            detail=f"User already booked appointment #{existing['id']} on {appointment_date}",
                        )
                        self.send_json(
                            HTTPStatus.TOO_MANY_REQUESTS,
                            {
                                "error": f"Giới hạn tần suất: Mỗi tài khoản cá nhân chỉ được phép đặt tối đa 01 lịch khám trong 01 ngày (Đã có lịch khám lúc {existing['appointment_time']} ngày {appointment_date})."
                            },
                        )
                        return

                    cur = conn.execute(
                        """
                        INSERT INTO appointments
                        (user_id, username, patient_id, patient_name, branch, department, doctor_username, doctor_name, appointment_date, appointment_time, reason, status, source_ip, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                        """,
                        (
                            sess["user_id"],
                            sess["username"],
                            sess.get("linked_patient_id"),
                            patient_name,
                            branch if branch in ("HQ", "Branch") else "HQ",
                            department,
                            doctor_username,
                            doctor_name,
                            appointment_date,
                            appointment_time,
                            reason,
                            ip,
                            now_iso,
                        ),
                    )
                    appt_id = cur.lastrowid
                    conn.commit()

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "appointment_booked",
                f"APPT-{appt_id}:{appointment_date}_{appointment_time}",
                HTTPStatus.CREATED,
                user_id=sess["user_id"],
                detail=f"Booked {department} (doctor={doctor_username or 'unassigned'}) on {appointment_date} {appointment_time} [status=pending]",
            )
            self.send_json(
                HTTPStatus.CREATED,
                {
                    "ok": True,
                    "id": appt_id,
                    "appointment_date": appointment_date,
                    "appointment_time": appointment_time,
                    "branch": branch,
                    "department": department,
                    "doctor_username": doctor_username,
                    "doctor_name": doctor_name,
                    "status": "pending",
                },
            )
            return

        # 5. Tạo tài khoản mới (POST /api/users)
        if path == "/api/users":
            sess = self.current_session()
            if not sess:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
                return
            if not self.verify_csrf(sess):
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
                return
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "create_user", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền thêm tài khoản."})
                return

            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return
            new_username = str(data.get("username", "")).strip()
            new_role = str(data.get("role", "")).strip()
            new_password = str(data.get("password", ""))
            full_name = str(data.get("full_name", new_username)).strip()
            department = str(data.get("department", "")).strip()
            birth_year = int(data.get("birth_year", 1990) or 1990)
            phone = str(data.get("phone", "")).strip()
            address = str(data.get("address", "")).strip()
            linked_patient_id = str(data.get("linked_patient_id", "")).strip() or None

            if not re.match(r"^[a-zA-Z0-9_.\-]{3,32}$", new_username):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Tên tài khoản không hợp lệ (3-32 ký tự chữ, số, gạch dưới)."})
                return
            if new_role not in VALID_ROLES:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"Vai trò phải thuộc: {', '.join(VALID_ROLES)}."})
                return
            ok_pw, pw_msg = validate_password_complexity(new_password)
            if not ok_pw:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": pw_msg})
                return

            salt_hex, hash_hex = hash_password(new_password)
            now_iso = utc_now_iso()
            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    exists = conn.execute("SELECT id FROM users WHERE username = ?", (new_username,)).fetchone()
                    if exists:
                        self.send_json(HTTPStatus.CONFLICT, {"error": "Tài khoản đã tồn tại."})
                        return
                    cur = conn.execute(
                        """
                        INSERT INTO users
                        (username, role, password_salt, password_hash, full_name, department, birth_year, phone, address, linked_patient_id, is_active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (new_username, new_role, salt_hex, hash_hex, full_name, department, birth_year, phone, address, linked_patient_id, now_iso, now_iso),
                    )
                    new_uid = cur.lastrowid
                    conn.commit()
                sync_users_json()

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "user_created",
                f"{new_username}({new_role})",
                HTTPStatus.CREATED,
                user_id=sess["user_id"],
                detail=f"Created user id={new_uid} role={new_role} dept={department}",
            )
            self.send_json(HTTPStatus.CREATED, {"ok": True, "id": new_uid, "username": new_username, "role": new_role, "department": department})
            return

        # 6. Cổng dữ liệu thiết bị IoMT (POST /api/iomt/telemetry)
        if path == "/api/iomt/telemetry":
            dev_key = self.headers.get("X-Medical-Device-Key", "")
            data = self.read_json_body() or {}
            device_id = str(data.get("device_id", "UNKNOWN-DEVICE")).strip()
            patient_id = str(data.get("patient_id", "DEMO-001")).strip()
            heart_rate = data.get("heart_rate", 0)
            spo2 = data.get("spo2", 0)

            if not hmac.compare_digest(dev_key, IOMT_DEVICE_KEY):
                write_audit(device_id, "iomt_device", ip, "iomt_alert", f"unauth_device:{device_id}", HTTPStatus.FORBIDDEN)
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Thiết bị y tế IoMT không có khóa xác thực hợp lệ."})
                return

            if not isinstance(heart_rate, int) or not isinstance(spo2, int) or not (20 <= heart_rate <= 250) or not (50 <= spo2 <= 100):
                write_audit(device_id, "iomt_device", ip, "iomt_alert", f"spoofed_vitals:{patient_id}", HTTPStatus.BAD_REQUEST)
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Phát hiện bất thường dữ liệu sinh hiệu IoMT (Data Tampering)."})
                return

            write_audit(device_id, "iomt_device", ip, "iomt_telemetry_ok", patient_id, HTTPStatus.OK)
            self.send_json(HTTPStatus.OK, {"status": "recorded", "device_id": device_id, "patient_id": patient_id})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy API."})

    # PUT ENDPOINTS
    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_ip()

        sess = self.current_session()
        if not sess:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
            return
        if not self.verify_csrf(sess):
            write_audit(sess["username"], sess["role"], ip, "access_denied", "csrf_put", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
            return

        # 1. Cập nhật thông tin cá nhân (PUT /api/profile)
        if path == "/api/profile":
            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return

            if sess["role"] == "patient" and any(k in data for k in ("diagnosis", "treatment_plan", "care_note", "note")):
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "rbac_medical_record_violation",
                    "profile_phi_tamper",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail="Patient attempted to modify clinical PHI via profile endpoint",
                )
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "Bệnh nhân chỉ được phép chỉnh sửa thông tin cá nhân, không được phép can thiệp hồ sơ bệnh án!"},
                )
                return

            full_name = str(data.get("full_name", "")).strip()
            birth_year = int(data.get("birth_year", 1990) or 1990)
            phone = str(data.get("phone", "")).strip()
            address = str(data.get("address", "")).strip()

            if not full_name or not (1900 <= birth_year <= 2026):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Họ tên và năm sinh không hợp lệ."})
                return

            now_iso = utc_now_iso()
            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.execute(
                        "UPDATE users SET full_name = ?, birth_year = ?, phone = ?, address = ?, updated_at = ? WHERE id = ?",
                        (full_name, birth_year, phone, address, now_iso, sess["user_id"]),
                    )
                    if sess.get("linked_patient_id"):
                        conn.execute(
                            "UPDATE medical_records SET full_name = ?, birth_year = ?, phone = ?, address = ? WHERE id = ?",
                            (full_name, birth_year, phone, address, sess["linked_patient_id"]),
                        )
                    conn.commit()
                sess["full_name"] = full_name
                sync_users_json()

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "update_personal_profile",
                sess["username"],
                HTTPStatus.OK,
                user_id=sess["user_id"],
            )
            self.send_json(HTTPStatus.OK, {"ok": True, "full_name": full_name, "birth_year": birth_year, "phone": phone, "address": address})
            return

        # 2. Xác nhận / Báo hủy lịch hẹn (PUT /api/appointments/<id>/status)
        if path.startswith("/api/appointments/") and path.endswith("/status"):
            parts = path.strip("/").split("/")
            if len(parts) != 4 or not parts[2].isdigit():
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Mã lịch hẹn không hợp lệ."})
                return
            appt_id = int(parts[2])

            if sess["role"] != "doctor":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "access_denied",
                    f"appointment_status:{appt_id}",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail=f"Role {sess['role']} attempted to modify appointment schedule",
                )
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Bác sĩ mới có quyền xác nhận hoặc báo huỷ lịch khám."})
                return

            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return
            new_status = str(data.get("status", "")).strip()
            if new_status not in ("confirmed", "cancelled"):
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Trạng thái lịch hẹn chỉ nhận 'confirmed' hoặc 'cancelled'."})
                return

            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    appt = conn.execute("SELECT * FROM appointments WHERE id = ?", (appt_id,)).fetchone()
                    if not appt:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy lịch hẹn."})
                        return

                    if appt["doctor_username"] and appt["doctor_username"] != sess["username"]:
                        self.send_json(
                            HTTPStatus.FORBIDDEN,
                            {"error": f"Lịch hẹn này thuộc phụ trách của {appt['doctor_name'] or appt['doctor_username']}."},
                        )
                        return

                    assigned_doc_user = appt["doctor_username"] or sess["username"]
                    assigned_doc_name = appt["doctor_name"] or sess.get("full_name") or sess["username"]

                    if new_status == "confirmed":
                        conflict = conn.execute(
                            """
                            SELECT id, patient_name FROM appointments
                            WHERE doctor_username = ? AND appointment_date = ? AND appointment_time = ?
                              AND status = 'confirmed' AND id != ?
                            """,
                            (assigned_doc_user, appt["appointment_date"], appt["appointment_time"], appt_id),
                        ).fetchone()
                        if conflict:
                            self.send_json(
                                HTTPStatus.CONFLICT,
                                {
                                    "error": f"Trùng lịch trình: Bạn đã có lịch khám được xác nhận cho bệnh nhân {conflict['patient_name']} vào lúc {appt['appointment_time']} ngày {appt['appointment_date']}."
                                },
                            )
                            return

                    conn.execute(
                        "UPDATE appointments SET status = ?, doctor_username = ?, doctor_name = ? WHERE id = ?",
                        (new_status, assigned_doc_user, assigned_doc_name, appt_id),
                    )
                    conn.commit()

            ev_name = "appointment_confirmed" if new_status == "confirmed" else "appointment_cancelled"
            write_audit(
                sess["username"],
                sess["role"],
                ip,
                ev_name,
                f"APPT-{appt_id}",
                HTTPStatus.OK,
                user_id=sess["user_id"],
                detail=f"Doctor {assigned_doc_user} set status={new_status} on {appt['appointment_date']} {appt['appointment_time']}",
            )
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "id": appt_id,
                    "status": new_status,
                    "doctor_username": assigned_doc_user,
                    "doctor_name": assigned_doc_name,
                },
            )
            return

        # 3. Cập nhật hồ sơ bệnh án (PUT /api/patients/<id>)
        if path.startswith("/api/patients/"):
            patient_id = path.split("/")[-1].strip()
            if sess["role"] == "admin":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "admin_phi_access_blocked",
                    patient_id,
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail="System Admin attempted to modify medical record",
                )
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "Vi phạm chính sách HICP: Admin hệ thống tuyệt đối không được chỉnh sửa nội dung hồ sơ bệnh án!"},
                )
                return

            if sess["role"] != "doctor":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "rbac_medical_record_violation",
                    patient_id,
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail=f"Role {sess['role']} attempted to modify medical record {patient_id}",
                )
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Bác sĩ điều trị mới có quyền chỉnh sửa hồ sơ bệnh án."})
                return

            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return

            diagnosis = str(data.get("diagnosis", "")).strip()
            care_note = str(data.get("note", data.get("care_note", ""))).strip()
            treatment_plan = str(data.get("treatment_plan", "")).strip()

            if not diagnosis or len(diagnosis) > 500 or len(care_note) > 2000:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Chẩn đoán không được để trống hoặc vượt quá độ dài cho phép."})
                return

            now_epoch = time.time()
            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    old_row = conn.execute("SELECT * FROM medical_records WHERE id = ?", (patient_id,)).fetchone()
                    if not old_row:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy hồ sơ bệnh nhân."})
                        return

                    last_rec_save = float(old_row["last_saved_epoch"] or 0.0)
                    last_usr_save = USER_SAVE_TRACKER.get(sess["username"], 0.0)
                    most_recent_save = max(last_rec_save, last_usr_save)

                    if most_recent_save > 0 and (now_epoch - most_recent_save) < SAVE_COOLDOWN_SECONDS:
                        wait_sec = int(SAVE_COOLDOWN_SECONDS - (now_epoch - most_recent_save)) + 1
                        write_audit(
                            sess["username"],
                            sess["role"],
                            ip,
                            "record_save_cooldown_blocked",
                            patient_id,
                            HTTPStatus.TOO_MANY_REQUESTS,
                            user_id=sess["user_id"],
                            detail=f"Save cooldown triggered ({wait_sec}s left)",
                        )
                        self.send_json(
                            HTTPStatus.TOO_MANY_REQUESTS,
                            {
                                "error": f"Để cân bằng tải, mỗi lần lưu dữ liệu bệnh án cần cách nhau tối thiểu 1 phút (60 giây). Vui lòng đợi {wait_sec} giây nữa."
                            },
                        )
                        return

                    old_obj = dict(old_row)
                    full_name = str(data.get("full_name", old_obj["full_name"])).strip()
                    birth_year = int(data.get("birth_year", old_obj["birth_year"]) or old_obj["birth_year"])
                    phone = str(data.get("phone", old_obj["phone"])).strip()
                    address = str(data.get("address", old_obj["address"])).strip()
                    site = str(data.get("site", old_obj["site"])).strip()
                    attending_doctor = str(data.get("attending_doctor", old_obj.get("attending_doctor") or sess.get("full_name") or sess["username"])).strip()
                    if not treatment_plan:
                        treatment_plan = old_obj["treatment_plan"]

                    now_iso = utc_now_iso(now_epoch)
                    new_obj = {
                        "full_name": full_name,
                        "birth_year": birth_year,
                        "phone": phone,
                        "address": address,
                        "site": site,
                        "diagnosis": diagnosis,
                        "treatment_plan": treatment_plan,
                        "care_note": care_note,
                        "attending_doctor": attending_doctor,
                    }

                    conn.execute(
                        """
                        UPDATE medical_records
                        SET full_name = ?, birth_year = ?, phone = ?, address = ?, site = ?,
                            diagnosis = ?, treatment_plan = ?, care_note = ?, attending_doctor = ?,
                            updated_at = ?, updated_by = ?, last_saved_epoch = ?
                        WHERE id = ?
                        """,
                        (
                            full_name,
                            birth_year,
                            phone,
                            address,
                            site,
                            diagnosis,
                            treatment_plan,
                            care_note,
                            attending_doctor,
                            now_iso,
                            sess["username"],
                            now_epoch,
                            patient_id,
                        ),
                    )
                    diff_meta = compute_diff_and_log_revision(
                        conn,
                        patient_id,
                        sess,
                        ip,
                        "UPDATE",
                        old_obj,
                        new_obj,
                        now_epoch=now_epoch,
                    )
                    conn.commit()
                    USER_SAVE_TRACKER[sess["username"]] = now_epoch

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "update_record",
                patient_id,
                HTTPStatus.OK,
                user_id=sess["user_id"],
                detail=f"Changed fields: {','.join(diff_meta['changed_fields'])}",
            )
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "id": patient_id,
                    "updated_at": now_iso,
                    "updated_by": sess["username"],
                    "attending_doctor": attending_doctor,
                    "revision": diff_meta,
                },
            )
            return

        # 4. Cập nhật tài khoản (PUT /api/users/<username>)
        if path.startswith("/api/users/"):
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "update_user", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền sửa phân quyền tài khoản."})
                return
            target_uname = path.split("/")[-1].strip()
            data = self.read_json_body()
            if not data:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Dữ liệu không hợp lệ."})
                return

            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    u = conn.execute("SELECT * FROM users WHERE username = ?", (target_uname,)).fetchone()
                    if not u:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy tài khoản."})
                        return

                    new_role = str(data.get("role", u["role"])).strip()
                    if new_role not in VALID_ROLES:
                        self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Vai trò không hợp lệ."})
                        return
                    full_name = str(data.get("full_name", u["full_name"])).strip()
                    department = str(data.get("department", u["department"])).strip()
                    is_active = int(data.get("is_active", u["is_active"]))
                    linked_pid = data.get("linked_patient_id", u["linked_patient_id"])

                    salt_hex, hash_hex = u["password_salt"], u["password_hash"]
                    if data.get("password"):
                        ok_pw, pw_msg = validate_password_complexity(str(data["password"]))
                        if not ok_pw:
                            self.send_json(HTTPStatus.BAD_REQUEST, {"error": pw_msg})
                            return
                        salt_hex, hash_hex = hash_password(str(data["password"]))

                    now_iso = utc_now_iso()
                    conn.execute(
                        """
                        UPDATE users
                        SET role = ?, password_salt = ?, password_hash = ?, full_name = ?, department = ?, linked_patient_id = ?, is_active = ?, updated_at = ?
                        WHERE username = ?
                        """,
                        (new_role, salt_hex, hash_hex, full_name, department, linked_pid, is_active, now_iso, target_uname),
                    )
                    conn.commit()
                sync_users_json()

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "user_updated",
                f"{target_uname}->role:{new_role}",
                HTTPStatus.OK,
                user_id=sess["user_id"],
            )
            self.send_json(HTTPStatus.OK, {"ok": True, "username": target_uname, "role": new_role, "department": department})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy API."})

    # DELETE ENDPOINTS
    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_ip()

        sess = self.current_session()
        if not sess:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Chưa đăng nhập."})
            return
        if not self.verify_csrf(sess):
            write_audit(sess["username"], sess["role"], ip, "access_denied", "csrf_delete", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF token không hợp lệ."})
            return

        # 1. Xóa hồ sơ bệnh án (DELETE /api/patients/<id>)
        if path.startswith("/api/patients/"):
            patient_id = path.split("/")[-1].strip()
            if sess["role"] == "admin":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "admin_phi_access_blocked",
                    f"delete:{patient_id}",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                )
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin hệ thống tuyệt đối không được xóa hồ sơ bệnh án!"})
                return
            if sess["role"] != "doctor":
                write_audit(
                    sess["username"],
                    sess["role"],
                    ip,
                    "rbac_medical_record_violation",
                    f"delete:{patient_id}",
                    HTTPStatus.FORBIDDEN,
                    user_id=sess["user_id"],
                    detail=f"Role {sess['role']} attempted to delete record {patient_id}",
                )
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Bác sĩ (Doctor) mới có quyền xóa hồ sơ bệnh án."})
                return

            now_epoch = time.time()
            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    old_row = conn.execute("SELECT * FROM medical_records WHERE id = ?", (patient_id,)).fetchone()
                    if not old_row:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy hồ sơ bệnh án."})
                        return
                    old_obj = dict(old_row)
                    conn.execute("DELETE FROM medical_records WHERE id = ?", (patient_id,))
                    diff_meta = compute_diff_and_log_revision(
                        conn,
                        patient_id,
                        sess,
                        ip,
                        "DELETE",
                        old_obj,
                        {},
                        now_epoch=now_epoch,
                    )
                    conn.commit()

            write_audit(
                sess["username"],
                sess["role"],
                ip,
                "delete_record",
                patient_id,
                HTTPStatus.OK,
                user_id=sess["user_id"],
                detail=f"Deleted medical record {patient_id}",
            )
            self.send_json(HTTPStatus.OK, {"ok": True, "deleted_id": patient_id, "revision": diff_meta})
            return

        # 2. Xóa tài khoản (DELETE /api/users/<username>)
        if path.startswith("/api/users/"):
            if sess["role"] != "admin":
                write_audit(sess["username"], sess["role"], ip, "access_denied", "delete_user", HTTPStatus.FORBIDDEN, user_id=sess["user_id"])
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Chỉ Admin hệ thống mới có quyền xóa tài khoản."})
                return
            target_uname = path.split("/")[-1].strip()
            if target_uname == sess["username"]:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Không thể tự xóa tài khoản Admin đang đăng nhập."})
                return

            with LOCK:
                with sqlite3.connect(DB_PATH, timeout=10) as conn:
                    cur = conn.execute("DELETE FROM users WHERE username = ?", (target_uname,))
                    conn.commit()
                    if cur.rowcount == 0:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy tài khoản."})
                        return
                sync_users_json()

            write_audit(sess["username"], sess["role"], ip, "user_deleted", target_uname, HTTPStatus.OK, user_id=sess["user_id"])
            self.send_json(HTTPStatus.OK, {"ok": True, "deleted_username": target_uname})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy API."})


if __name__ == "__main__":
    init_storage()
    server = ThreadingHTTPServer((HOST, PORT), HICPRequestHandler)
    scheme = "http"
    if TLS_CERT_PATH and TLS_KEY_PATH and Path(TLS_CERT_PATH).is_file() and Path(TLS_KEY_PATH).is_file():
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
        TLS_ENABLED = True
        scheme = "https"
    print(f"Hệ thống MediCare listening on {scheme}://{HOST}:{PORT}")
    server.serve_forever()
