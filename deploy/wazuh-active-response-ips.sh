#!/usr/bin/env bash
# Wazuh Active Response / Host IPS Script (MAC & IP Filtering)
set -euo pipefail

read -r INPUT_JSON
ACTION=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))")
SRC_IP=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('alert',{}).get('data',{}).get('source_ip') or d.get('parameters',{}).get('alert',{}).get('data',{}).get('src_ip',''))")
MAC_ADDR=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('alert',{}).get('data',{}).get('mac_address',''))")

LOG_FILE="/var/ossec/logs/active-responses.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 1. Chặn thiết bị theo địa chỉ MAC (Layer 2)
if [ -n "$MAC_ADDR" ] && [[ "$MAC_ADDR" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
  if [ "$ACTION" = "add" ]; then
    iptables -I INPUT -m mac --mac-source "$MAC_ADDR" -j DROP 2>/dev/null || true
    echo "${TIMESTAMP} HICP-IPS [MAC-BLOCK] Blocked device MAC ${MAC_ADDR} (IP: ${SRC_IP}) via iptables -m mac" >> "$LOG_FILE"
    exit 0
  elif [ "$ACTION" = "delete" ]; then
    iptables -D INPUT -m mac --mac-source "$MAC_ADDR" -j DROP 2>/dev/null || true
    echo "${TIMESTAMP} HICP-IPS [MAC-UNBLOCK] Removed block for device MAC ${MAC_ADDR}" >> "$LOG_FILE"
    exit 0
  fi
fi

# 2. Chặn theo địa chỉ IP (Layer 3)
if [ -z "$SRC_IP" ] || [ "$SRC_IP" = "127.0.0.1" ] || [ "$SRC_IP" = "10.20.10.50" ]; then
  exit 0
fi

if [ "$ACTION" = "add" ]; then
  iptables -I INPUT -s "$SRC_IP" -j DROP
  echo "${TIMESTAMP} HICP-IPS [IP-BLOCK] Blocked attacker IP ${SRC_IP} via iptables" >> "$LOG_FILE"
elif [ "$ACTION" = "delete" ]; then
  iptables -D INPUT -s "$SRC_IP" -j DROP 2>/dev/null || true
  echo "${TIMESTAMP} HICP-IPS [IP-UNBLOCK] Removed block for IP ${SRC_IP}" >> "$LOG_FILE"
fi
