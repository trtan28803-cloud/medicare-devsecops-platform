# Makefile Chuẩn hóa Vận hành DevOps / DevSecOps - Hệ thống MediCare v2.2
.PHONY: help setup test lint run docker-build docker-up docker-down backup deploy-lab-https

help:
	@echo "Các lệnh vận hành DevOps chuẩn cho Hệ thống MediCare v2.2:"
	@echo "  make setup            - Khởi tạo CSDL SQLite và 7 tài khoản RBAC mặc định"
	@echo "  make lint             - Kiểm tra cú pháp Python, JavaScript và Bash scripts"
	@echo "  make test             - Chạy bộ kiểm thử tự động E2E (12 kịch bản bảo mật & nghiệp vụ)"
	@echo "  make run              - Chạy máy chủ MediCare trên cổng 8080 (Local)"
	@echo "  make docker-build     - Đóng gói Docker Image (medicare-hicp-ehr:v2.2)"
	@echo "  make docker-up        - Khởi chạy cụm Container (MediCare + Prometheus)"
	@echo "  make docker-down      - Dừng cụm Container"
	@echo "  make backup           - Sao lưu nóng CSDL SQLite mã hóa AES-256"
	@echo "  make deploy-lab-https - Bật Nginx HTTPS Reverse Proxy & tách cổng Wazuh 5601"

setup:
	HICP_DATA_DIR=./data_vault HICP_NONINTERACTIVE=1 python3 scripts/setup.py

lint:
	python3 -m py_compile app.py scripts/setup.py scripts/test-app.py scripts/dns-lab.py
	node --check static/app.js
	bash -n scripts/install-ubuntu.sh scripts/deploy-domain-https.sh scripts/backup-ehr.sh deploy/wazuh-active-response-ips.sh

test: lint
	python3 scripts/test-app.py

run:
	HICP_DATA_DIR=./data_vault HICP_PORT=8080 python3 app.py

docker-build:
	docker build -t medicare-hicp-ehr:v2.2 .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

backup:
	sudo bash scripts/backup-ehr.sh

deploy-lab-https:
	sudo bash scripts/deploy-domain-https.sh --lab-https
