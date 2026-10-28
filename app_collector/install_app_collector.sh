#!/bin/bash
# ==============================================================================
# SecurePulse Application-Level SIEM Collector Installer (securepulse-app)
# ==============================================================================
# Strictly Read-Only. Never modifies application code or databases.
# Runs as an isolated systemd service with capped resources (10% CPU / 200MB RAM).
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[ERROR] Please run this onboarding script as root (e.g. using sudo bash)."
  exit 1
fi

SOC_URL="__SOC_URL__"
TOKEN="__TOKEN__"
APP_ID="__APP_ID__"
ROLE="__ROLE__"
NODE_NAME="__NODE_NAME__"
TARGET_PORT="__TARGET_PORT__"
TARGET_DB="__TARGET_DB__"

echo "======================================================================"
echo "    SecurePulse Application-Level SIEM Collector Setup (v1.6.0)       "
echo "======================================================================"
echo "Application ID:  $APP_ID"
echo "Node Name:       $NODE_NAME"
echo "Role:            $ROLE"
echo "Target Port:     ${TARGET_PORT:-auto-detect}"
echo "Target Database: ${TARGET_DB:-all}"
echo "SOC Server:      $SOC_URL"
echo "======================================================================"

# 1. Onboarding Approval Check (Aligned with Server Asset Security Architecture)
echo ""
echo "======================================================================"
echo "[*] Submitting Application Collector Onboarding Request to SOC..."
echo "======================================================================"
HOST_IP=$(curl -s --connect-timeout 2 ifconfig.me || hostname -I | awk '{print $1}')
if [ -z "$HOST_IP" ]; then HOST_IP="127.0.0.1"; fi

REQ_RES=$(curl -s -X POST "${SOC_URL}/api/approvals/request" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"${NODE_NAME}\",\"ip\":\"${HOST_IP}\",\"token\":\"${TOKEN}\",\"app_id\":${APP_ID},\"role\":\"${ROLE}\"}" || echo '{"ok":false}')

echo "[PENDING] Collector onboarding request submitted to SOC Command Center!"
echo "[PENDING] Waiting for SOC Administrator approval in Dashboard... (Token: $TOKEN)"
STATUS="pending"
MAX_WAIT=300
WAITED=0
while [ "$STATUS" = "pending" ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 5
    WAITED=$((WAITED+5))
    CHECK_RES=$(curl -s -G "${SOC_URL}/api/agent/status" --data-urlencode "token=${TOKEN}" --data-urlencode "hostname=${NODE_NAME}" || echo '{"status":"pending"}')
    STATUS=$(echo "$CHECK_RES" | grep -o '"status":"[^"]*' | cut -d'"' -f4 || echo "pending")
    if [ "$STATUS" = "pending" ]; then
        echo -n "."
    fi
done

if [ "$STATUS" != "approved" ]; then
    echo ""
    echo "❌ [TIMED OUT] Approval not received within $MAX_WAIT seconds."
    echo "   Please approve under 'SERVER APPROVALS' in SOC Dashboard and re-run."
    exit 1
fi
echo ""
echo "✅ [SUCCESS] Approval Granted by SOC Administrator!"

# 2. Check Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required. Installing python3..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3
    else
        echo "[ERROR] python3 could not be installed automatically. Please install python3 and re-run."
        exit 1
    fi
fi

# 2. Create directories
mkdir -p /opt/securepulse-app /etc/securepulse-app

# 3. Write configuration file
cat << EOF > /etc/securepulse-app/collector.env
SOC_URL="$SOC_URL"
ENROLLMENT_TOKEN="$TOKEN"
APP_ID="$APP_ID"
COMPONENT_ROLE="$ROLE"
NODE_NAME="$NODE_NAME"
TARGET_PORT="$TARGET_PORT"
TARGET_DB_NAME="$TARGET_DB"
POLL_INTERVAL_SEC=0.5
BATCH_MAX_LINES=50
BATCH_MAX_WAIT_SEC=2.0
HEARTBEAT_INTERVAL_SEC=30.0
EOF
chmod 600 /etc/securepulse-app/collector.env

# 4. Fetch collector script from SOC server
echo "[+] Downloading SecurePulse Application Collector..."
curl -sSL "${SOC_URL}/api/app/collector.py?token=${TOKEN}" -o /opt/securepulse-app/app_collector.py
chmod 755 /opt/securepulse-app/app_collector.py

# 5. Install systemd service
cat << 'EOF' > /etc/systemd/system/securepulse-app.service
[Unit]
Description=SecurePulse Application-Level SIEM Collector
Documentation=https://github.com/aladdiinn/sec-app
After=network.target tomcat.service postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/securepulse-app
EnvironmentFile=/etc/securepulse-app/collector.env
ExecStart=/usr/bin/python3 /opt/securepulse-app/app_collector.py
Restart=always
RestartSec=5s

# Hard Resource Limits (Zero impact on business applications)
CPUQuota=10%
MemoryMax=200M
TasksMax=50

# Security Hardening
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and restart service
echo "[+] Starting securepulse-app service..."
systemctl daemon-reload
systemctl enable securepulse-app.service
systemctl restart securepulse-app.service

# 7. Verification check
sleep 2
if systemctl is-active --quiet securepulse-app.service; then
    echo "======================================================================"
    echo "[SUCCESS] SecurePulse Application Collector is ACTIVE and RUNNING!"
    echo "Logs: journalctl -u securepulse-app -f"
    echo "Check your BSmart SOC dashboard; the status badge will turn to 'RECEIVING'."
    echo "======================================================================"
else
    echo "[WARN] Service started but status is not active. Check logs:"
    journalctl -u securepulse-app -n 20 --no-pager
fi
