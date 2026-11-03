# MediCare EHR (v2.2) — Multi-Branch Zero-Trust Healthcare Platform & DevSecOps Pipeline

**Capstone Project:** Secure Multi-Branch Healthcare Network Architecture Using Site-to-Site VPN, IDS/IPS, and Data Loss Prevention (DLP/SIEM) Monitoring.  
**Compliance & Architecture Standards:** **HHS 405(d) HICP (Health Industry Cybersecurity Practices)**, **Zero Trust (Least Privilege & Micro-Segmentation)**, and **Cloud-Native DevSecOps**.

---

## 1. Project Architecture & Repository Structure (`hicp-demo/`)

```text
hicp-demo/
├── app.py                              # Core Full-Stack Server (PBKDF2 Auth, MAC IDS/IPS, 4-Role RBAC, Phone OTP, Audit Diff, 60s Cooldown, Weekly Schedule, Prometheus /metrics)
├── Dockerfile                          # Hardened production container image (python:3.11-slim, non-root user hicp-ehr, native HEALTHCHECK)
├── docker-compose.yml                  # Multi-container orchestration (medicare-ehr + prometheus, resource limits, persistent volumes)
├── Makefile                            # Standardized DevOps automation targets (setup, lint, test, run, docker-up, backup, deploy-lab-https)
├── README.md                           # Project overview, architecture, RBAC matrix, and deployment guide (English)
├── HICP_SECURITY_FEATURES_DEEP_DIVE.md # Deep-dive engineering specification of all 12 security controls & DevSecOps stack
├── .github/
│   └── workflows/
│       └── ci-cd.yml                   # 4-Stage GitHub Actions DevSecOps Pipeline (Syntax Lint -> Bandit SAST -> 12 E2E Tests -> Docker Smoke Test)
├── static/                             # Frontend Web Application (HTML5, Responsive CSS3 Container Queries, XSS-safe Vanilla JS)
│   ├── index.html                      # Role-adaptive UI panels, collapsible sidebar, unified .table-card containers & search groups
│   ├── app.js                          # REST API client with X-CSRF-Token, 7-day weekly doctor schedule, OTP password reset & instant search
│   └── style.css                       # Zero-horizontal-scroll wrapping tables, uniform 38px controls, and responsive container queries
├── deploy/                             # Security Configs, Infrastructure as Code (K8s, Terraform, Ansible), SIEM, IDS/IPS, Prometheus & Proxy
│   ├── k8s-deployment.yaml             # Kubernetes manifests (Namespace, ConfigMap, PVC, RollingUpdate Deployment, Probes, Service, HPA 2–6 Pods)
│   ├── ansible-playbook.yml            # Idempotent Ansible Playbook for automated Ubuntu provisioning, Systemd hardening & Wazuh rule deployment
│   ├── prometheus.yml                  # Prometheus scrape configuration targeting /metrics
│   ├── terraform/
│   │   └── main.tf                     # AWS Terraform IaC (VPC 10.20.0.0/16, VLAN20 Server Subnet, Zero-Trust Security Group)
│   ├── schema_postgres_mysql.sql       # Relational DB schema (6 tables & composite indexes: users, medical_records, record_revisions, audit_logs, mac_blacklist, appointments)
│   ├── wazuh-lab-rules.xml             # Custom Wazuh SIEM rules (Rules 100510–100522: MAC IDS/IPS, Admin PHI isolation, RBAC, DLP, DNS Tunneling)
│   ├── wazuh-localfile.xml             # Wazuh localfile collector for audit.jsonl and Suricata eve.json
│   ├── suricata-lab.rules              # Suricata IDS signatures (SID 1001001–1001003: HTTP Probe, TCP SYN Burst, DNS Tunneling)
│   ├── suricata-ips.rules              # Suricata Inline IPS drop rules
│   ├── wazuh-active-response-ips.sh    # Automated Host IPS script blocking attacker MAC/IP via Linux iptables (-m mac)
│   ├── hicp-ehr.service                # Hardened Systemd service unit (User=hicp-ehr, ProtectSystem=strict, CAP_NET_BIND_SERVICE, UMask=0027)
│   ├── nginx-http.conf                 # Optional HTTP reverse proxy configuration
│   └── nginx-https.conf                # TLS 1.2/1.3 reverse proxy for MediCare EHR & Wazuh SIEM Dashboard (preserving HTTP /demo/ids-probe)
├── scripts/                            # Provisioning, Automated E2E Testing, Domain/HTTPS Orchestration & Encrypted Backup Scripts
│   ├── setup.py                        # Initializes 7 default accounts across 4 RBAC roles and clinical departments (PBKDF2 200,000 iterations)
│   ├── test-app.py                     # Automated End-to-End integration & security test suite (12 test scenarios + Prometheus /metrics)
│   ├── deploy-domain-https.sh          # Automated script for Lab HTTPS, Cloudflare Zero-Trust Tunnel, and Let's Encrypt SSL deployment
│   ├── dns-lab.py                      # DNS Tunneling traffic generator (60 queries to .hicp-demo.invalid) for DLP verification
│   ├── backup-ehr.sh                   # Zero-downtime SQLite hot backup (.backup) with OpenSSL AES-256-CBC encryption & 30-day rotation
│   └── install-ubuntu.sh               # One-command automated installer for Ubuntu Server (10.20.10.50)
├── docs/                               # Documentation, Security Deep-Dive, Test Reports & Defense Checklists
│   ├── DEMO_CHECKLIST.md               # 11-step live demonstration checklist
│   ├── TEST_REPORT.md                  # Automated E2E test execution report with exact line mappings
│   ├── SECURITY_FEATURES_DEEP_DIVE.md  # Under-the-hood code analysis of all 12 security features & DevSecOps components
│   ├── HICP_MASTER_DOCUMENT_V2.md      # Comprehensive thesis master reference & defense Q&A
│   └── CAM_NANG_JUNIOR_DEVOPS_FPT_SOFTWARE_7_NGAY.md # 7-day Junior DevOps interview & CV preparation handbook
└── data_vault/                         # Pre-seeded SQLite database and credential store (ehr.db, users.json, audit.jsonl)
```

---

## 2. Default Accounts & 4-Role RBAC Matrix (HICP Least Privilege)

| Username | Role | Department | Default Password | Authorized Capabilities & Zero-Trust Restrictions |
| :--- | :--- | :--- | :--- | :--- |
| `admin` | **System Admin (`admin`)** | IT / SOC | `Admin@Hicp2026!` | Manages user accounts (`/api/users`), views Audit Diff history (`/api/revisions`), inspects MAC Blacklist (`/api/mac-blacklist`) and system logs (`/api/audit`); **STRICTLY BLOCKED from accessing or modifying clinical PHI (`HTTP 403` — Wazuh Rule `100517`)**. |
| `doctor` | **Attending Doctor (`doctor`)** | Internal Medicine (`Nội tổng quát`) | `Doctor@Hicp2026!` | Full **Create, Read, Update, Delete (CRUD)** access to medical records, CSV export, weekly schedule view, and **Confirm (`confirmed`) / Cancel (`cancelled`)** patient appointments; blocked from viewing audit revision logs (`HTTP 403`). |
| `doctor_timmach` | **Attending Doctor (`doctor`)** | Cardiology (`Tim mạch`) | `Doctor@Hicp2026!` | Specialist physician account (ThS.BS Lê Hoàng Nam). |
| `doctor_noitiet` | **Attending Doctor (`doctor`)** | Endocrinology (`Nội tiết`) | `Doctor@Hicp2026!` | Specialist physician account (BS.CKII Phạm Thu Hà). |
| `doctor_tmh` | **Attending Doctor (`doctor`)** | ENT (`Tai Mũi Họng`) | `Doctor@Hicp2026!` | Specialist physician account (BS.CKI Vũ Đức Anh). |
| `nurse` | **Clinical Nurse (`nurse`)** | Internal Medicine (`Nội tổng quát`) | `Nurse@Hicp2026!` | **Read-only search and view** of medical records (`GET /api/patients`) and doctor schedules (`GET /api/appointments`); **blocked from creating, editing, or deleting records or modifying schedules (`HTTP 403` — Wazuh Rule `100518`)**. |
| `patient` | **Patient (`patient`)** | — (`DEMO-001`) | `Patient@Hicp2026!` | Views own medical record (`DEMO-001`), updates personal contact info (`/api/profile`), **books online appointments** (cascading Department ➔ Doctor selection, $\ge$ 30-minute lead time), and performs **self-service password reset via registered phone (`0901000001`) + 6-digit OTP**. |

---

## 3. Core Security & DevSecOps Capabilities

1. **MAC-Based IDS/IPS Brute-Force & DDoS Protection (Zero Account Lockout DoS):**
   * **IDS Alert (`>= 2` failed logins within 5 minutes):** Returns a clean user warning (`"Nhập sai mật khẩu 5 lần thiết bị sẽ bị tạm khoá đăng nhập"`) while emitting `ids_bruteforce_warning` with full device MAC telemetry to Wazuh SIEM (`Rule 100514` - Level 8).
   * **IPS Device Lock (`>= 5` failed logins within 10 minutes):** Temporarily locks the offending device by MAC address for **300 seconds (5 minutes)** using $O(1)$ pre-authentication RAM lookup (bypassing 200,000-iteration PBKDF2 hashing to prevent CPU exhaustion) and doubles the lock duration progressively (`300s ➔ 600s ➔ 1200s...`) upon recidivism within the next 10 minutes (`Rule 100515` - Level 11). Legitimate doctors and patients can still log into their accounts from other devices without interruption.
2. **Audit Trail (Before/After JSON Diff), 15-Day / Top-2 Retention & 60-Second Save Cooldown:**
   * Automatically records field-level JSON diffs on every `CREATE`, `UPDATE`, and `DELETE` operation, enforces a 60-second cooldown between consecutive saves (`HTTP 429`), retains all revisions within 15 days, and prunes revisions older than 15 days beyond the 2 most recent snapshots.
3. **Active Data Loss Prevention (CSV Rate-Limiting & Suricata DNS Tunneling Detection):**
   * Restricts CSV exports to attending doctors (`max 2 exports / 5 minutes` — `dlp_export_blocked`) and inspects network traffic via Suricata DPI (`SID 1001003` / Wazuh `Rule 100522`) to detect covert DNS exfiltration.
4. **Cloud-Native Observability & DevSecOps Automation:**
   * Exposes real-time operational and security metrics at `GET /metrics` in **Prometheus Exposition Format**, ships with a 4-stage **GitHub Actions CI/CD pipeline**, hardened non-root **Docker / Kubernetes** manifests, and **Terraform / Ansible** Infrastructure-as-Code templates.

---

## 4. Quickstart & Deployment Commands

```bash
# 1. Automated Installation on Ubuntu Server (10.20.10.50 - Port 80)
unzip -o hicp-demo-live-v2.zip
cd hicp-demo
sudo bash scripts/install-ubuntu.sh

# 2. Run Syntax Linting & Full Automated E2E Security Test Suite
make test
# Or run directly: python3 scripts/test-app.py

# 3. Run Locally on Port 8080
make run

# 4. Build & Launch with Docker Compose (MediCare EHR :8080 + Prometheus :9090)
make docker-up

# 5. Deploy to Kubernetes Cluster (K3s / Minikube / EKS / AKS)
kubectl apply -f deploy/k8s-deployment.yaml

# 6. Enable HTTPS Reverse Proxy (Lab Self-Signed SAN TLS or Real Domain via Cloudflare Tunnel)
sudo bash scripts/deploy-domain-https.sh --lab-https
# Or with a real domain:
sudo bash scripts/deploy-domain-https.sh --cloudflare-domain <your-domain> [TUNNEL_TOKEN]
```
