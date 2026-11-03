-- HỆ THỐNG QUẢN LÝ BỆNH VIỆN MEDICARE (HICP & ZERO TRUST V2.2)

-- 1. Bảng users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(64) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'patient')),
    password_salt VARCHAR(64) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    full_name VARCHAR(120) NOT NULL DEFAULT '',
    department VARCHAR(80) NOT NULL DEFAULT '',
    birth_year INTEGER NOT NULL DEFAULT 1990,
    phone VARCHAR(32) NOT NULL DEFAULT '',
    address VARCHAR(255) NOT NULL DEFAULT '',
    linked_patient_id VARCHAR(32) DEFAULT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(32) NOT NULL,
    updated_at VARCHAR(32) NOT NULL
);

-- 2. Bảng medical_records
CREATE TABLE IF NOT EXISTS medical_records (
    id VARCHAR(32) PRIMARY KEY,
    patient_user_id INTEGER DEFAULT NULL,
    full_name VARCHAR(120) NOT NULL,
    birth_year INTEGER NOT NULL,
    phone VARCHAR(32) NOT NULL DEFAULT '',
    address VARCHAR(255) NOT NULL DEFAULT '',
    site VARCHAR(32) NOT NULL DEFAULT 'HQ',
    diagnosis TEXT NOT NULL,
    treatment_plan TEXT NOT NULL DEFAULT '',
    care_note TEXT NOT NULL DEFAULT '',
    attending_doctor VARCHAR(120) NOT NULL DEFAULT 'BS.CKI Trần Minh Quân',
    updated_at VARCHAR(32) NOT NULL,
    updated_by VARCHAR(64) NOT NULL,
    last_saved_epoch REAL NOT NULL DEFAULT 0,
    FOREIGN KEY (patient_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_records_patient_uid ON medical_records(patient_user_id);

-- 3. Bảng record_revisions
CREATE TABLE IF NOT EXISTS record_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id VARCHAR(32) NOT NULL,
    user_id INTEGER NOT NULL,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    action VARCHAR(32) NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'DELETE')),
    changed_fields TEXT NOT NULL,
    old_values_json TEXT NOT NULL,
    new_values_json TEXT NOT NULL,
    diff_summary TEXT NOT NULL,
    edited_at VARCHAR(32) NOT NULL,
    edited_epoch REAL NOT NULL,
    FOREIGN KEY (record_id) REFERENCES medical_records(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_revisions_record_epoch ON record_revisions(record_id, edited_epoch DESC);

-- 4. Bảng audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp VARCHAR(32) NOT NULL,
    user_id INTEGER DEFAULT NULL,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    event VARCHAR(64) NOT NULL,
    target VARCHAR(128) NOT NULL,
    status INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_source_ip ON audit_logs(source_ip);

-- 5. Bảng appointments
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username VARCHAR(64) NOT NULL,
    patient_id VARCHAR(32) DEFAULT NULL,
    patient_name VARCHAR(120) NOT NULL,
    branch VARCHAR(32) NOT NULL DEFAULT 'HQ',
    department VARCHAR(80) NOT NULL DEFAULT 'Nội tổng quát',
    doctor_username VARCHAR(64) NOT NULL DEFAULT '',
    doctor_name VARCHAR(120) NOT NULL DEFAULT '',
    appointment_date VARCHAR(10) NOT NULL,
    appointment_time VARCHAR(5) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    source_ip VARCHAR(45) NOT NULL,
    created_at VARCHAR(32) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, appointment_date)
);

CREATE INDEX IF NOT EXISTS idx_appointments_user_date ON appointments(user_id, appointment_date);
CREATE INDEX IF NOT EXISTS idx_appointments_doc_date ON appointments(doctor_username, appointment_date, appointment_time, status);
CREATE INDEX IF NOT EXISTS idx_appointments_status_date ON appointments(status, appointment_date);

-- 6. Bảng mac_blacklist
CREATE TABLE IF NOT EXISTS mac_blacklist (
    mac_address VARCHAR(32) PRIMARY KEY,
    last_ip VARCHAR(45) NOT NULL DEFAULT '',
    last_username VARCHAR(64) NOT NULL DEFAULT '',
    strike_count INTEGER NOT NULL DEFAULT 1,
    fail_count INTEGER NOT NULL DEFAULT 0,
    blocked_until_epoch REAL NOT NULL DEFAULT 0,
    last_unlocked_epoch REAL NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    updated_at VARCHAR(32) NOT NULL
);
