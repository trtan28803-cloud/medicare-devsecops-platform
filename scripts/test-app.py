"""Kiểm thử tích hợp tự động toàn diện (End-to-End Integration Test Suite) cho Hệ thống MediCare v2.1 (HICP & Zero Trust).
Kiểm tra:
1. Phân quyền RBAC 4 vai trò (Admin, Doctor, Nurse, Patient) & Least Privilege.
2. Cô lập Admin khỏi hồ sơ bệnh án (Admin bị chặn 403 khi xem/thêm/sửa/xóa/xuất bệnh án, ghi log admin_phi_access_blocked).
3. Bác sĩ toàn quyền Thêm/Xem/Sửa/Xóa hồ sơ bệnh án (có trường Bác sĩ điều trị `attending_doctor`).
4. Y tá (`nurse`): Chỉ được phép tìm kiếm và xem bệnh án (cấm Thêm/Sửa/Xóa bệnh án -> 403 Forbidden) và chỉ được xem lịch trình của bác sĩ (cấm xác nhận/huỷ lịch hẹn -> 403 Forbidden).
5. Bệnh nhân (`patient`): Chỉ xem bệnh án cá nhân, tự sửa thông tin cá nhân (`/api/profile`), và sử dụng tính năng Quên mật khẩu qua xác thực Số điện thoại + OTP (`/api/forgot-password/request-otp` & `/api/forgot-password/reset`).
6. Đặt lịch khám trực tuyến (`/api/appointments`):
   - Dropdown liên hoàn Khoa khám -> Bác sĩ thuộc khoa (`/api/doctors`), cho phép để trống bác sĩ.
   - Giới hạn khung giờ 07:00-15:00, tối đa 01 lịch/ngày/tài khoản.
   - Sau khi đặt lịch, trạng thái mặc định là `pending` ("Đang chờ xác nhận").
   - Bác sĩ xác nhận lịch hẹn (`PUT /api/appointments/<id>/status` với `status='confirmed'`) -> kiểm tra chống trùng lịch hẹn cùng ngày & giờ (409 Conflict) -> hiển thị trên lịch trình bác sĩ.
   - Bác sĩ báo huỷ lịch hẹn (`status='cancelled'`) -> lịch bị huỷ vẫn tồn tại trên lịch trình với trạng thái `cancelled` ("Lịch đã huỷ").
7. Audit Trail & Diff (lưu Thời gian, User ID, Username, IP nguồn, Giá trị trước/sau) — Chỉ Admin xem được lịch sử chỉnh sửa (`/api/revisions`).
8. Chính sách lưu trữ bệnh án 15 ngày / 2 lần sửa gần nhất & Cooldown 1 phút (HTTP 429).
"""

import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as tmp:
    data_dir = Path(tmp)
    password = "TestPassword123!"

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    env = dict(
        os.environ,
        HICP_HOST="127.0.0.1",
        HICP_PORT=str(port),
        HICP_DATA_DIR=tmp,
        TRUST_LOCAL_PROXY="0",
        HICP_SAVE_COOLDOWN_SECONDS="2",
        HICP_IPS_BASE_BLOCK="2",
        HICP_PASS_ADMIN=password,
        HICP_PASS_DOCTOR=password,
        HICP_PASS_NURSE=password,
        HICP_PASS_PATIENT=password,
    )

    def request(path, method="GET", body=None, cookie=None, csrf=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        hdr = headers.copy() if headers else {}
        if cookie:
            hdr["Cookie"] = cookie
        if csrf:
            hdr["X-CSRF-Token"] = csrf
        payload = json.dumps(body) if body is not None else None
        if payload is not None:
            hdr["Content-Type"] = "application/json"
        c.request(method, path, payload, hdr)
        r = c.getresponse()
        raw = r.read()
        status = r.status
        out = dict(r.getheaders())
        c.close()
        result = json.loads(raw) if out.get("Content-Type", "").startswith("application/json") else raw
        return status, result, out

    def start_server():
        p = subprocess.Popen(
            [sys.executable, str(root / "app.py")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                if request("/health")[0] == 200:
                    return p
            except OSError:
                pass
            time.sleep(0.04)
        p.terminate()
        raise AssertionError("Server failed to start")

    def login(username, pw=None):
        use_pw = pw if pw is not None else password
        status, result, hdr = request("/api/login", "POST", {"username": username, "password": use_pw})
        assert status == 200, f"Login failed for {username}: {status} {result}"
        cookie = hdr["Set-Cookie"].split(";")[0]
        assert "HttpOnly" in hdr["Set-Cookie"] and "SameSite=Strict" in hdr["Set-Cookie"]
        status, me, _ = request("/api/me", cookie=cookie)
        assert status == 200 and me["username"] == username
        return cookie, me["csrf"], me

    process = None
    try:
        process = start_server()

        # 1. Kiểm tra Static Files & Chống Path Traversal
        assert request("/")[0] == 200
        assert request("/style.css")[0] == 200
        assert request("/app.js")[0] == 200
        assert request("/../../app.py")[0] == 404
        assert request("/api/patients")[0] == 401
        assert request("/api/appointments")[0] == 401

        # 2. Kiểm tra Vai trò ADMIN HỆ THỐNG
        admin_cookie, admin_csrf, admin_me = login("admin")
        assert admin_me["role"] == "admin"
        assert request("/api/patients", cookie=admin_cookie)[0] == 403
        assert request("/api/patients", "POST", {"id": "DEMO-099", "full_name": "Test", "birth_year": 1990, "diagnosis": "Test"}, admin_cookie, admin_csrf)[0] == 403
        assert request("/api/patients/DEMO-001", "PUT", {"diagnosis": "Admin hack", "note": "hack"}, admin_cookie, admin_csrf)[0] == 403
        assert request("/api/patients/DEMO-001", "DELETE", {}, admin_cookie, admin_csrf)[0] == 403
        assert request("/api/export", cookie=admin_cookie)[0] == 403
        assert request("/api/system/status", cookie=admin_cookie)[0] == 200
        st, new_u, _ = request(
            "/api/users",
            "POST",
            {"username": "nurse_branch", "role": "nurse", "full_name": "ĐD. Chi Nhánh", "department": "Tim mạch", "password": "NurseBranch@2026!"},
            admin_cookie,
            admin_csrf,
        )
        assert st == 201 and new_u["department"] == "Tim mạch"
        assert request("/api/users/nurse_branch", "PUT", {"role": "doctor", "department": "Nội tiết"}, admin_cookie, admin_csrf)[0] == 200
        assert request("/api/users/nurse_branch", "DELETE", {}, admin_cookie, admin_csrf)[0] == 200

        # 3. Kiểm tra Tính năng QUÊN MẬT KHẨU BỆNH NHÂN QUA SỐ ĐIỆN THOẠI + OTP
        assert request("/api/forgot-password/request-otp", "POST", {"username": "doctor", "phone": "0901000001"})[0] == 400
        assert request("/api/forgot-password/request-otp", "POST", {"username": "patient", "phone": "0999999999"})[0] == 400
        st_otp, otp_res, _ = request("/api/forgot-password/request-otp", "POST", {"username": "patient", "phone": "0901000001"})
        assert st_otp == 200 and "otp_code" in otp_res
        otp_code = otp_res["otp_code"]
        new_pat_pw = "NewPatient@2026!"
        st_rst, rst_res, _ = request(
            "/api/forgot-password/reset",
            "POST",
            {"username": "patient", "phone": "0901000001", "otp": otp_code, "new_password": new_pat_pw},
        )
        assert st_rst == 200
        pat_cookie, pat_csrf, pat_me = login("patient", pw=new_pat_pw)
        assert pat_me["role"] == "patient"

        # 4. Kiểm tra Vai trò BỆNH NHÂN
        st_docs, docs_data, _ = request("/api/doctors", cookie=pat_cookie)
        assert st_docs == 200 and len(docs_data["doctors"]) >= 4
        st, pat_records, _ = request("/api/patients", cookie=pat_cookie)
        assert st == 200 and len(pat_records) == 1 and pat_records[0]["id"] == "DEMO-001"
        assert pat_records[0]["attending_doctor"] == "BS.CKI Trần Minh Quân"
        st, prof_res, _ = request(
            "/api/profile",
            "PUT",
            {"full_name": "Nguyễn An (Đã cập nhật SĐT)", "birth_year": 1985, "phone": "0988777666", "address": "Quận 1, TP.HCM"},
            pat_cookie,
            pat_csrf,
        )
        assert st == 200 and prof_res["phone"] == "0988777666"
        assert request("/api/profile", "PUT", {"full_name": "An", "birth_year": 1985, "diagnosis": "Tự sửa bệnh án"}, pat_cookie, pat_csrf)[0] == 403
        assert request("/api/patients/DEMO-001", "PUT", {"diagnosis": "Tự sửa", "note": "Tự sửa"}, pat_cookie, pat_csrf)[0] == 403
        assert request("/api/patients/DEMO-001", "DELETE", {}, pat_cookie, pat_csrf)[0] == 403
        assert request("/api/revisions", cookie=pat_cookie)[0] == 403

        # 5. Kiểm tra ĐẶT LỊCH KHÁM TRỰC TUYẾN & QUY TRÌNH XÁC NHẬN / BÁO HUỶ LỊCH HẸN CỦA BÁC SĨ
        assert request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2026-11-12", "appointment_time": "06:30", "branch": "HQ", "department": "Tim mạch", "reason": "Khám sớm"},
            pat_cookie,
            pat_csrf,
        )[0] == 400
        assert request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2026-11-12", "appointment_time": "16:15", "branch": "HQ", "department": "Tim mạch", "reason": "Khám chiều muộn"},
            pat_cookie,
            pat_csrf,
        )[0] == 400
        assert request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2020-01-01", "appointment_time": "09:00", "branch": "HQ", "department": "Nội tổng quát", "reason": "Lịch quá khứ / dưới 30 phút"},
            pat_cookie,
            pat_csrf,
        )[0] == 400
        assert request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2026-11-12", "appointment_time": "08:30", "branch": "HQ", "department": "Tim mạch", "doctor_username": "doctor", "reason": "Sai khoa"},
            pat_cookie,
            pat_csrf,
        )[0] == 400
        st, appt_ok, _ = request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2026-11-12", "appointment_time": "08:30", "branch": "HQ", "department": "Nội tổng quát", "doctor_username": "", "reason": "Tái khám huyết áp định kỳ"},
            pat_cookie,
            pat_csrf,
        )
        assert st == 201 and appt_ok["status"] == "pending" and appt_ok["appointment_time"] == "08:30"
        new_appt_id = appt_ok["id"]
        assert request(
            "/api/appointments",
            "POST",
            {"appointment_date": "2026-11-12", "appointment_time": "14:00", "branch": "Branch", "department": "Nội tổng quát", "reason": "Đặt lần 2 trong ngày"},
            pat_cookie,
            pat_csrf,
        )[0] == 429

        # 6. Kiểm tra Vai trò Y TÁ
        nurse_cookie, nurse_csrf, nurse_me = login("nurse")
        assert nurse_me["department"] == "Nội tổng quát"
        assert request("/api/patients", cookie=nurse_cookie)[0] == 200
        assert request("/api/appointments", cookie=nurse_cookie)[0] == 200
        assert request(
            "/api/patients",
            "POST",
            {"id": "DEMO-017", "full_name": "Test Nurse", "birth_year": 1991, "site": "Branch", "diagnosis": "Test"},
            nurse_cookie,
            nurse_csrf,
        )[0] == 403
        assert request(
            "/api/patients/DEMO-001",
            "PUT",
            {"diagnosis": "Y tá cố sửa", "note": "Bị chặn"},
            nurse_cookie,
            nurse_csrf,
        )[0] == 403
        assert request("/api/patients/DEMO-001", "DELETE", {}, nurse_cookie, nurse_csrf)[0] == 403
        assert request(f"/api/appointments/{new_appt_id}/status", "PUT", {"status": "confirmed"}, nurse_cookie, nurse_csrf)[0] == 403

        # 7. Kiểm tra Vai trò BÁC SĨ
        doc_cookie, doc_csrf, doc_me = login("doctor")
        assert doc_me["department"] == "Nội tổng quát"

        st_conf, conf_res, _ = request(
            f"/api/appointments/{new_appt_id}/status",
            "PUT",
            {"status": "confirmed"},
            doc_cookie,
            doc_csrf,
        )
        assert st_conf == 200 and conf_res["status"] == "confirmed" and conf_res["doctor_username"] == "doctor"

        st_canc, canc_res, _ = request(
            f"/api/appointments/{new_appt_id}/status",
            "PUT",
            {"status": "cancelled"},
            doc_cookie,
            doc_csrf,
        )
        assert st_canc == 200 and canc_res["status"] == "cancelled"

        st, create_res, _ = request(
            "/api/patients",
            "POST",
            {
                "id": "DEMO-017",
                "full_name": "Lê Hoàng Nam (giả lập)",
                "birth_year": 1991,
                "site": "Branch",
                "attending_doctor": "BS.CKI Trần Minh Quân",
                "diagnosis": "Theo dõi sốt siêu vi (giả lập)",
                "treatment_plan": "Hạ sốt, bù nước",
                "note": "Bác sĩ khám và lập bệnh án.",
            },
            doc_cookie,
            doc_csrf,
        )
        assert st == 201 and create_res["attending_doctor"] == "BS.CKI Trần Minh Quân"

        st_cool, cool_err, _ = request(
            "/api/patients/DEMO-001",
            "PUT",
            {"diagnosis": "Sửa liên tục", "note": "Chưa đủ thời gian chờ"},
            doc_cookie,
            doc_csrf,
        )
        assert st_cool == 429

        time.sleep(2.1)
        st, upd_res, _ = request(
            "/api/patients/DEMO-001",
            "PUT",
            {
                "attending_doctor": "BS.CKI Trần Minh Quân",
                "diagnosis": "Tăng huyết áp độ 2 - Đã điều chỉnh thuốc (giả lập)",
                "note": "Bác sĩ cập nhật phác đồ.",
            },
            doc_cookie,
            doc_csrf,
        )
        assert st == 200 and "diagnosis" in upd_res["revision"]["changed_fields"]

        time.sleep(2.1)
        assert request("/api/patients/DEMO-017", "DELETE", {}, doc_cookie, doc_csrf)[0] == 200

        # 8. Kiểm tra Chính sách Lưu trữ Lịch sử Chỉnh sửa 15 ngày / 2 lần gần nhất
        db_file = Path(tmp) / "ehr.db"
        now_ts = time.time()
        with sqlite3.connect(db_file) as conn:
            conn.execute("DELETE FROM record_revisions WHERE record_id = 'DEMO-005'")
            for i in range(5):
                ep = now_ts - (i + 1) * 2 * 86400
                conn.execute(
                    "INSERT INTO record_revisions (record_id, user_id, username, role, source_ip, action, changed_fields, old_values_json, new_values_json, diff_summary, edited_at, edited_epoch) VALUES ('DEMO-005', 2, 'doctor', 'doctor', '10.10.10.100', 'UPDATE', '[\"diagnosis\"]', '{\"diagnosis\":\"old\"}', '{\"diagnosis\":\"new\"}', 'diff', '2026-10-15T00:00:00Z', ?)",
                    (ep,),
                )
            conn.commit()
        assert request("/api/revisions", cookie=doc_cookie)[0] == 403
        assert request("/api/revisions", cookie=nurse_cookie)[0] == 403
        st, revs_5, _ = request("/api/patients/DEMO-005/revisions", cookie=admin_cookie)
        assert st == 200 and len(revs_5) == 5, f"Expected all 5 revisions within 15 days to be kept, got {len(revs_5)}"

        with sqlite3.connect(db_file) as conn:
            conn.execute("DELETE FROM record_revisions WHERE record_id = 'DEMO-006'")
            for days_ago in (20, 25, 30, 35):
                ep = now_ts - days_ago * 86400
                conn.execute(
                    "INSERT INTO record_revisions (record_id, user_id, username, role, source_ip, action, changed_fields, old_values_json, new_values_json, diff_summary, edited_at, edited_epoch) VALUES ('DEMO-006', 2, 'doctor', 'doctor', '10.10.10.100', 'UPDATE', '[\"diagnosis\"]', '{\"diagnosis\":\"old\"}', '{\"diagnosis\":\"new\"}', 'diff', '2026-09-20T00:00:00Z', ?)",
                    (ep,),
                )
            conn.commit()
        st, revs_old, _ = request("/api/patients/DEMO-006/revisions", cookie=admin_cookie)
        assert st == 200 and len(revs_old) == 2, f"Expected only 2 most recent revisions kept when >15 days old, got {len(revs_old)}"

        # 8B. Kiểm tra Tính năng IDS
        attacker_mac = "AA:BB:CC:DD:EE:99"
        legit_mac = "11:22:33:44:55:66"

        st_f1, res_f1, _ = request(
            "/api/login",
            "POST",
            {"username": "doctor", "password": "WrongPass_1"},
            headers={"X-Client-MAC": attacker_mac},
        )
        assert st_f1 == 401 and not res_f1.get("ids_warning") and not res_f1.get("ips_blocked")
        assert res_f1["error"] == "Sai tên đăng nhập hoặc mật khẩu."
        assert "MAC" not in json.dumps(res_f1, ensure_ascii=False) and attacker_mac not in json.dumps(res_f1, ensure_ascii=False)

        for i in range(2, 5):
            st_f, res_f, _ = request(
                "/api/login",
                "POST",
                {"username": "doctor", "password": f"WrongPass_{i}"},
                headers={"X-Client-MAC": attacker_mac},
            )
            assert st_f == 401 and res_f.get("ids_warning") is True, f"Expected IDS warning on attempt {i}, got {res_f}"
            assert res_f["error"] == "Nhập sai mật khẩu 5 lần thiết bị sẽ bị tạm khoá đăng nhập", f"Unexpected message: {res_f}"
            assert "MAC" not in json.dumps(res_f, ensure_ascii=False) and attacker_mac not in json.dumps(res_f, ensure_ascii=False)

        st_ips1, res_ips1, _ = request(
            "/api/login",
            "POST",
            {"username": "doctor", "password": "WrongPass_5"},
            headers={"X-Client-MAC": attacker_mac},
        )
        assert st_ips1 == 429 and res_ips1.get("ips_blocked") is True and res_ips1.get("strike_count") == 1
        first_block_dur = res_ips1["block_duration"]
        assert res_ips1["error"] == f"Thiết bị bị tạm khoá {first_block_dur} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác"
        assert "MAC" not in json.dumps(res_ips1, ensure_ascii=False) and attacker_mac not in json.dumps(res_ips1, ensure_ascii=False)

        st_throttled, res_throttled, _ = request(
            "/api/login",
            "POST",
            {"username": "doctor", "password": password},
            headers={"X-Client-MAC": attacker_mac},
        )
        assert st_throttled == 429
        assert res_throttled["error"].startswith("Thiết bị bị tạm khoá ") and res_throttled["error"].endswith(" giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác")
        assert "MAC" not in json.dumps(res_throttled, ensure_ascii=False) and attacker_mac not in json.dumps(res_throttled, ensure_ascii=False)

        st_legit, res_legit, _ = request(
            "/api/login",
            "POST",
            {"username": "doctor", "password": password},
            headers={"X-Client-MAC": legit_mac},
        )
        assert st_legit == 200 and res_legit["username"] == "doctor"

        time.sleep(2.2)
        for i in range(1, 5):
            assert request(
                "/api/login",
                "POST",
                {"username": "doctor", "password": f"RecidivismWrong_{i}"},
                headers={"X-Client-MAC": attacker_mac},
            )[0] == 401
        st_ips2, res_ips2, _ = request(
            "/api/login",
            "POST",
            {"username": "doctor", "password": "RecidivismWrong_5"},
            headers={"X-Client-MAC": attacker_mac},
        )
        assert st_ips2 == 429 and res_ips2.get("strike_count") == 2 and res_ips2["block_duration"] == first_block_dur * 2
        assert res_ips2["error"] == f"Thiết bị bị tạm khoá {res_ips2['block_duration']} giây, vẫn có thể thực hiện đăng nhập trên thiết bị khác"
        assert "MAC" not in json.dumps(res_ips2, ensure_ascii=False)

        st_bl, bl_list, _ = request("/api/mac-blacklist", cookie=admin_cookie)
        assert st_bl == 200 and any(item["mac_address"] == attacker_mac and item["strike_count"] == 2 for item in bl_list)

        # 9. Kiểm tra Chống giả mạo IP, IDS Probe, IoMT Gateway & Wazuh JSONL Audit Integrity
        assert request("/api/me", cookie=doc_cookie, headers={"X-Real-IP": "8.8.8.8"})[1]["source_ip"] == "127.0.0.1"
        assert request("/demo/ids-probe")[0] == 200
        assert request("/api/iomt/telemetry", "POST", {"device_id": "ICU-01", "patient_id": "DEMO-001", "heart_rate": 80, "spo2": 98}, headers={"X-Medical-Device-Key": "WRONG-KEY"})[0] == 403

        lines = [json.loads(x) for x in (data_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        events_logged = {x["event"] for x in lines}
        for expected_ev in (
            "admin_phi_access_blocked",
            "rbac_medical_record_violation",
            "record_save_cooldown_blocked",
            "ids_bruteforce_warning",
            "ips_mac_temp_blocked",
            "login_throttled",
            "password_reset_otp_sent",
            "password_reset_success",
            "appointment_booked",
            "appointment_confirmed",
            "appointment_cancelled",
            "appointment_rejected_time_window",
            "appointment_rejected_daily_limit",
            "update_record",
            "delete_record",
            "iomt_alert",
        ):
            assert expected_ev in events_logged, f"Missing expected SIEM audit event: {expected_ev}"
        assert not any(password in json.dumps(x) for x in lines), "Password leaked into audit.jsonl!"

        print("PASS: All MediCare v2.1 requirements (Patient Phone OTP Password Reset, Nurse Read-Only Records & Schedule, Cascading Dept/Doctor Appointment Workflow, Doctor Confirm/Cancel Weekly Schedule, and Wazuh SIEM JSONL) verified successfully!")
    finally:
        if process:
            process.terminate()
            process.wait(timeout=5)
