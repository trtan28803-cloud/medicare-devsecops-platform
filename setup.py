#!/usr/bin/env python3
"""Khởi tạo tài khoản RBAC 4 vai trò (admin, doctor, nurse, patient) kèm Khoa khám & điều trị theo chuẩn HICP Practice #3."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

DATA_DIR = Path(os.environ.get("HICP_DATA_DIR", os.environ.get("HICP_DATA", "/var/lib/hicp-ehr")))
USERS_PATH = DATA_DIR / "users.json"
ROLES = [
    ("admin", "admin", "Quản trị viên Hệ thống (IT/SOC)", None, None),
    ("doctor", "doctor", "BS.CKI Trần Minh Quân", None, "Nội tổng quát"),
    ("doctor_timmach", "doctor", "ThS.BS Lê Hoàng Nam", None, "Tim mạch"),
    ("doctor_noitiet", "doctor", "BS.CKII Phạm Thu Hà", None, "Nội tiết"),
    ("doctor_tmh", "doctor", "BS.CKI Vũ Đức Anh", None, "Tai Mũi Họng"),
    ("nurse", "nurse", "ĐD. Nguyễn Thị Mai Hương", None, "Nội tổng quát"),
    ("patient", "patient", "Nguyễn An (giả lập)", "DEMO-001", None),
]


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


def hash_password(password: str) -> dict[str, str]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return {"salt": salt.hex(), "hash": digest.hex()}


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    users = {}
    defaults = {
        "admin": "Admin@Hicp2026!",
        "doctor": "Doctor@Hicp2026!",
        "doctor_timmach": "Doctor@Hicp2026!",
        "doctor_noitiet": "Doctor@Hicp2026!",
        "doctor_tmh": "Doctor@Hicp2026!",
        "nurse": "Nurse@Hicp2026!",
        "patient": "Patient@Hicp2026!",
    }
    non_interactive = os.environ.get("HICP_NONINTERACTIVE", "0") == "1"

    for username, role, full_name, linked_pid, department in ROLES:
        env_key = f"HICP_PASS_{username.upper()}"
        pw = os.environ.get(env_key, "")
        if not pw and role == "doctor" and username != "doctor":
            pw = os.environ.get("HICP_PASS_DOCTOR", "")
        if not pw and non_interactive:
            pw = defaults[username]
        while True:
            if not pw:
                pw = getpass.getpass(
                    f"Nhập mật khẩu cho '{username}' (role={role}, Enter để dùng mặc định '{defaults[username]}'): "
                ) or defaults[username]
            ok, msg = validate_password_complexity(pw)
            if ok:
                break
            print(f"[!] Không đạt chuẩn HICP: {msg}")
            pw = ""
        users[username] = {
            "role": role,
            "full_name": full_name,
            "department": department,
            "linked_patient_id": linked_pid,
            **hash_password(pw),
        }

    USERS_PATH.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(USERS_PATH, 0o640)
    print(f"[+] Đã lưu thông tin xác thực các tài khoản Hệ thống MediCare (PBKDF2-SHA256 200,000 vòng) tại {USERS_PATH}")


if __name__ == "__main__":
    main()
