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
echo "    SecurePulse Application-Level SIEM Collector Setup (v1.7.3)       "
echo "======================================================================"
echo "Application ID:  $APP_ID"
echo "Node Name:       $NODE_NAME"
echo "Role:            $ROLE"
echo "Target Port:     ${TARGET_PORT:-auto-detect}"
echo "Target Database: ${TARGET_DB:-all}"
echo "SOC Server:      $SOC_URL"
echo "======================================================================"

# 1. Onboarding Approval Check (Aligned with Server Asset Security Architecture)
# Bypass local environment proxies for SOC communication
SOC_HOST=$(echo "$SOC_URL" | sed -e 's|^[^/]*//||' -e 's|[:/].*$||')
export no_proxy="$no_proxy,*,${SOC_HOST},localhost,127.0.0.1"
export NO_PROXY="$NO_PROXY,*,${SOC_HOST},localhost,127.0.0.1"

echo ""
echo "======================================================================"
echo "[*] Submitting Application Collector Onboarding Request to SOC..."
echo "======================================================================"
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$HOST_IP" ] || [ "$HOST_IP" = "127.0.0.1" ]; then
    HOST_IP=$(curl -s --connect-timeout 2 --noproxy "*" ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "127.0.0.1")
fi

REQ_RES=$(curl -s --noproxy "*" -X POST "${SOC_URL}/api/approvals/request" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"${NODE_NAME}\",\"ip\":\"${HOST_IP}\",\"token\":\"${TOKEN}\",\"app_id\":${APP_ID},\"role\":\"${ROLE}\"}" || echo '{"ok":false}')

if echo "$REQ_RES" | grep -q "<!DOCTYPE"; then
    echo "⚠️  [WARNING] Received HTTP proxy response instead of SOC server JSON."
    echo "   Ensure your network proxy allows traffic to $SOC_URL on port 8000"
fi

STATUS="pending"
# Check if already approved (e.g. re-run or pre-approved)
CHECK_RES=$(curl -s --noproxy "*" -G "${SOC_URL}/api/agent/status" --data-urlencode "token=${TOKEN}" --data-urlencode "hostname=${NODE_NAME}" || echo '{"status":"pending"}')
STATUS=$(echo "$CHECK_RES" | grep -o '"status":"[^"]*' | cut -d'"' -f4 || echo "pending")

if [ "$STATUS" = "approved" ]; then
    echo "✅ [SUCCESS] Component already approved by SOC Administrator!"
else
    echo "[PENDING] Collector onboarding request submitted to SOC Command Center!"
    echo "[PENDING] Waiting for SOC Administrator approval in Dashboard... (Token: $TOKEN)"
    MAX_WAIT=300
    WAITED=0
    while [ "$STATUS" = "pending" ] && [ $WAITED -lt $MAX_WAIT ]; do
        sleep 5
        WAITED=$((WAITED+5))
        CHECK_RES=$(curl -s --noproxy "*" -G "${SOC_URL}/api/agent/status" --data-urlencode "token=${TOKEN}" --data-urlencode "hostname=${NODE_NAME}" || echo '{"status":"pending"}')
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
fi

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

PYTHON_BIN=$(command -v python3 || echo "/usr/bin/python3")

# 3. Create directories & determine instance-safe service name
mkdir -p /opt/securepulse-app /etc/securepulse-app
INSTANCE_ID="${APP_ID}-${ROLE}"
ENV_FILE="/etc/securepulse-app/collector-${INSTANCE_ID}.env"
SERVICE_NAME="securepulse-app-${INSTANCE_ID}.service"

# 4. Write instance-specific configuration file
cat << EOF > "$ENV_FILE"
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
no_proxy="*"
NO_PROXY="*"
EOF
chmod 600 "$ENV_FILE"

# Maintain default fallback configuration for standalone manual debugging
cp -f "$ENV_FILE" /etc/securepulse-app/collector.env 2>/dev/null || true

# 5. Fetch collector script from SOC server
echo "[+] Downloading SecurePulse Application Collector..."
curl -sSL --noproxy "*" "${SOC_URL}/api/app/collector.py?token=${TOKEN}" -o /opt/securepulse-app/app_collector.py
chmod 755 /opt/securepulse-app/app_collector.py

# 6. Install isolated instance systemd service (allows multiple apps/roles on same node)
cat << EOF > /etc/systemd/system/${SERVICE_NAME}
[Unit]
Description=SecurePulse Application SIEM Collector (App ${APP_ID} - ${ROLE} - ${NODE_NAME})
Documentation=https://github.com/aladdiinn/sec-app
After=network.target tomcat.service postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/securepulse-app
Environment="COLLECTOR_ENV_FILE=${ENV_FILE}"
EnvironmentFile=${ENV_FILE}
ExecStart=${PYTHON_BIN} /opt/securepulse-app/app_collector.py
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

# Clean migration: if single generic service was running for this exact App ID, stop and disable it
if [ -f /etc/systemd/system/securepulse-app.service ]; then
    systemctl stop securepulse-app.service 2>/dev/null || true
    systemctl disable securepulse-app.service 2>/dev/null || true
fi

# 7. Enable and restart service
echo "[+] Starting ${SERVICE_NAME} service..."
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

# 8. Verification check
sleep 2
if systemctl is-active --quiet ${SERVICE_NAME}; then
    echo "======================================================================"
    echo "✅ [SUCCESS] SecurePulse Collector (${SERVICE_NAME}) is ACTIVE and RUNNING!"
    echo "======================================================================"
    echo "Recent collector telemetry:"
    journalctl -u ${SERVICE_NAME} -n 6 --no-pager || true
    echo "======================================================================"
    echo "Check your BSmart SOC dashboard; the status badge will turn to 'RECEIVING' / 'NORMAL'."
    echo "======================================================================"
else
    echo "[WARN] Service started but status is not active. Check logs:"
    journalctl -u ${SERVICE_NAME} -n 20 --no-pager
fi
