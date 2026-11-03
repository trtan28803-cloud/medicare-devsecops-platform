#!/usr/bin/env bash
# Kịch bản triển khai HTTPS & Tên miền thật (Hệ thống MediCare v2.2)
set -euo pipefail

PROJECT_DIR="/home/trtan/hicp-demo"
if [ ! -d "$PROJECT_DIR" ]; then
  PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
fi

TLS_DIR="/etc/hicp-tls"
WAZUH_DASHBOARD_CFG="/etc/wazuh-dashboard/opensearch_dashboards.yml"
SYSTEMD_UNIT="/etc/systemd/system/hicp-ehr.service"
NGINX_SITE_AVAIL="/etc/nginx/sites-available/medicare-https.conf"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/medicare-https.conf"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Vui lòng chạy script với quyền root (sudo):"
    echo "    sudo bash $0 $*"
    exit 1
  fi
}

usage() {
  cat <<'EOF'
==============================================================================
HƯỚNG DẪN SỬ DỤNG: deploy-domain-https.sh (Hệ thống MediCare v2.2)
==============================================================================
1. Bật HTTPS nội bộ trên máy Lab:
   sudo bash scripts/deploy-domain-https.sh --lab-https

2. Triển khai với Tên miền thật qua Cloudflare Tunnel:
   sudo bash scripts/deploy-domain-https.sh --cloudflare-domain <ten-mien> [TUNNEL_TOKEN]

3. Triển khai trên VPS có IP Public tĩnh (Nginx + Let's Encrypt):
   sudo bash scripts/deploy-domain-https.sh --letsencrypt-domain <ten-mien> <email>

4. Khôi phục về cấu hình HTTP cổng 80:
   sudo bash scripts/deploy-domain-https.sh --rollback-http
==============================================================================
EOF
}

# 1. Chuyển cổng Wazuh Dashboard sang 127.0.0.1:5601
move_wazuh_dashboard_to_5601() {
  echo "[*] Kiểm tra cấu hình Wazuh Dashboard tại $WAZUH_DASHBOARD_CFG..."
  if [ -f "$WAZUH_DASHBOARD_CFG" ]; then
    cp -a "$WAZUH_DASHBOARD_CFG" "${WAZUH_DASHBOARD_CFG}.bak.$(date +%s)"
    if grep -qE '^\s*server\.port:' "$WAZUH_DASHBOARD_CFG"; then
      sed -i 's/^\s*server\.port:.*/server.port: 5601/' "$WAZUH_DASHBOARD_CFG"
    else
      echo "server.port: 5601" >> "$WAZUH_DASHBOARD_CFG"
    fi
    if grep -qE '^\s*server\.host:' "$WAZUH_DASHBOARD_CFG"; then
      sed -i 's/^\s*server\.host:.*/server.host: "127.0.0.1"/' "$WAZUH_DASHBOARD_CFG"
    else
      echo 'server.host: "127.0.0.1"' >> "$WAZUH_DASHBOARD_CFG"
    fi
    echo "[+] Đã chuyển Wazuh Dashboard sang https://127.0.0.1:5601"
    systemctl restart wazuh-dashboard 2>/dev/null || true
  else
    echo "[i] Không tìm thấy $WAZUH_DASHBOARD_CFG (bỏ qua)."
  fi
}

# 2. Cấu hình dịch vụ hicp-ehr lắng nghe tại 127.0.0.1:8080
configure_backend_proxy_mode() {
  echo "[*] Cấu hình dịch vụ hicp-ehr tại 127.0.0.1:8080 (TRUST_LOCAL_PROXY=1)..."
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Hệ thống Bệnh viện MediCare (HICP EHR Backend - Proxy Mode)
After=network.target

[Service]
Type=simple
User=hicp-ehr
Group=hicp-ehr
WorkingDirectory=${PROJECT_DIR}
Environment="HICP_HOST=127.0.0.1"
Environment="HICP_PORT=8080"
Environment="TRUST_LOCAL_PROXY=1"
ExecStart=/usr/bin/python3 ${PROJECT_DIR}/app.py
Restart=always
RestartSec=3

ProtectSystem=strict
ProtectHome=false
PrivateTmp=true
ReadWritePaths=/var/lib/hicp-ehr
NoNewPrivileges=true
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now hicp-ehr
  systemctl restart hicp-ehr
  echo "[+] Dịch vụ hicp-ehr đã chạy tại http://127.0.0.1:8080."
}

# 3. Khởi tạo chứng chỉ SSL/TLS (Self-Signed SAN)
generate_self_signed_tls() {
  local domain_extra="${1:-medicare.local}"
  echo "[*] Khởi tạo chứng chỉ TLS tại $TLS_DIR..."
  mkdir -p "$TLS_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$TLS_DIR/server.key" \
    -out "$TLS_DIR/server.crt" \
    -subj "/C=VN/ST=HCMC/L=HCMC/O=MediCare-HICP/CN=10.20.10.50" \
    -addext "subjectAltName=IP:10.20.10.50,DNS:localhost,DNS:medicare.local,DNS:siem.medicare.local,DNS:medicare.${domain_extra},DNS:siem.${domain_extra}"
  chmod 600 "$TLS_DIR/server.key"
  chmod 644 "$TLS_DIR/server.crt"
  echo "[+] Đã tạo chứng chỉ TLS: $TLS_DIR/server.crt & $TLS_DIR/server.key"
}

# 4. Cấu hình Nginx Reverse Proxy
configure_nginx_reverse_proxy() {
  local base_domain="${1:-medicare.local}"
  local medicare_host="medicare.${base_domain}"
  local siem_host="siem.${base_domain}"
  if [ "$base_domain" = "medicare.local" ]; then
    medicare_host="10.20.10.50 medicare.local"
    siem_host="siem.medicare.local"
  fi

  if ! command -v nginx >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y nginx
  fi

  cat > "$NGINX_SITE_AVAIL" <<EOF
server {
    listen 80;
    server_name 10.20.10.50 ${medicare_host} _;

    location = /demo/ids-probe {
        proxy_pass http://127.0.0.1:8080/demo/ids-probe;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
    }

    location = /health {
        proxy_pass http://127.0.0.1:8080/health;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name 10.20.10.50 ${medicare_host};

    ssl_certificate     ${TLS_DIR}/server.crt;
    ssl_certificate_key ${TLS_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    client_max_body_size 32k;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header X-Client-MAC \$http_x_client_mac;
    }
}

server {
    listen 443 ssl http2;
    listen 8443 ssl http2;
    server_name ${siem_host};

    ssl_certificate     ${TLS_DIR}/server.crt;
    ssl_certificate_key ${TLS_DIR}/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

  rm -f /etc/nginx/sites-enabled/default
  ln -sf "$NGINX_SITE_AVAIL" "$NGINX_SITE_ENABLED"
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
  echo "[+] Đã kích hoạt Nginx Reverse Proxy trên cổng 80, 443 và 8443."
}

# 5. Cài đặt & Cấu hình Cloudflare Tunnel
setup_cloudflare_tunnel() {
  local domain="$1"
  local token="${2:-}"

  if ! command -v cloudflared >/dev/null 2>&1; then
    curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb
    rm -f /tmp/cloudflared.deb
  fi

  mkdir -p /etc/cloudflared
  cat > /etc/cloudflared/config.yml.example <<EOF
tunnel: <TUNNEL_UUID_CUA_BAN>
credentials-file: /root/.cloudflared/<TUNNEL_UUID_CUA_BAN>.json

ingress:
  - hostname: medicare.${domain}
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true

  - hostname: siem.${domain}
    service: https://127.0.0.1:5601
    originRequest:
      noTLSVerify: true

  - service: http_status:404
EOF

  if [ -n "$token" ]; then
    cloudflared service install "$token" || true
    systemctl enable --now cloudflared
    echo "[+] Đã kích hoạt dịch vụ cloudflared thành công!"
  else
    echo "[+] Đã tạo cấu hình mẫu tại /etc/cloudflared/config.yml.example cho tên miền ${domain}."
  fi
}

# 6. Khôi phục về cấu hình HTTP cổng 80
rollback_to_http() {
  systemctl stop nginx 2>/dev/null || true
  rm -f "$NGINX_SITE_ENABLED"
  install -m 644 "$PROJECT_DIR/deploy/hicp-ehr.service" "$SYSTEMD_UNIT"
  systemctl daemon-reload
  systemctl restart hicp-ehr
  echo "[+] Đã khôi phục dịch vụ hicp-ehr trên cổng 80 (HTTP)."
}

# Điều phối tham số dòng lệnh
MODE="${1:-}"
case "$MODE" in
  --lab-https)
    require_root "$@"
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "medicare.local"
    configure_nginx_reverse_proxy "medicare.local"
    echo "[+] Hoàn tất bật HTTPS Lab: https://10.20.10.50 & Wazuh: https://10.20.10.50:8443"
    ;;

  --cloudflare-domain)
    require_root "$@"
    DOMAIN="${2:-}"
    CF_TOKEN="${3:-}"
    if [ -z "$DOMAIN" ]; then
      echo "[!] Thiếu tên miền. Ví dụ: sudo bash $0 --cloudflare-domain medicare-hicp.id.vn"
      exit 1
    fi
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "$DOMAIN"
    configure_nginx_reverse_proxy "$DOMAIN"
    setup_cloudflare_tunnel "$DOMAIN" "$CF_TOKEN"
    ;;

  --letsencrypt-domain)
    require_root "$@"
    DOMAIN="${2:-}"
    EMAIL="${3:-}"
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
      echo "[!] Thiếu tên miền hoặc email. Ví dụ: sudo bash $0 --letsencrypt-domain medicare-hicp.id.vn admin@gmail.com"
      exit 1
    fi
    move_wazuh_dashboard_to_5601
    configure_backend_proxy_mode
    generate_self_signed_tls "$DOMAIN"
    configure_nginx_reverse_proxy "$DOMAIN"
    apt-get update -y && apt-get install -y certbot python3-certbot-nginx
    certbot --nginx -d "medicare.${DOMAIN}" -d "siem.${DOMAIN}" --non-interactive --agree-tos -m "$EMAIL" --redirect
    ;;

  --rollback-http)
    require_root "$@"
    rollback_to_http
    ;;

  *)
    usage
    exit 0
    ;;
esac
