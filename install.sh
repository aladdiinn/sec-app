#!/usr/bin/env bash
# =============================================================
# install.sh — SecurePulse Agent Installer
# Run on the TARGET Linux server you want to monitor.
#
# Usage:
#   sudo bash install.sh \
#     --backend-url http://YOUR_DASHBOARD_IP:5000 \
#     --api-key     YOUR_AGENT_API_KEY
#
# What this does:
#   1. Installs Python 3, pip, psutil
#   2. Copies agent files to /opt/securepulse-agent/
#   3. Registers the server with the backend → gets agent_token
#   4. Writes /etc/securepulse-agent.conf
#   5. Creates and enables systemd service
# =============================================================

set -euo pipefail

# ── Defaults (override via flags) ────────────────────────────
BACKEND_URL=""
API_KEY=""
INSTALL_DIR="/opt/securepulse-agent"
SERVICE_NAME="securepulse-agent"
CONFIG_FILE="/etc/securepulse-agent.conf"
LOG_FILE="/var/log/securepulse-agent.log"

# ── Color helpers ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-url) BACKEND_URL="$2"; shift 2 ;;
    --api-key)     API_KEY="$2";     shift 2 ;;
    *) error "Unknown argument: $1" ;;
  esac
done

[[ -z "$BACKEND_URL" ]] && error "--backend-url is required (e.g. http://192.168.1.10:5000)"
[[ -z "$API_KEY"     ]] && error "--api-key is required (from your .env AGENT_API_KEY)"
[[ "$EUID" -ne 0     ]] && error "Please run as root (sudo)"

info "Starting SecurePulse Agent installation"
info "Backend: $BACKEND_URL"

# ── 1. System packages ────────────────────────────────────────
info "Installing Python3 and pip…"
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip curl
elif command -v yum &>/dev/null; then
  yum install -y python3 python3-pip curl
elif command -v dnf &>/dev/null; then
  dnf install -y python3 python3-pip curl
else
  error "Unsupported package manager. Install Python3 manually."
fi

info "Installing psutil…"
pip3 install psutil --quiet

# ── 2. Copy agent files ───────────────────────────────────────
info "Installing agent to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$SCRIPT_DIR/agent"

if [[ ! -d "$AGENT_SRC" ]]; then
  error "agent/ directory not found next to install.sh. Run from project root."
fi

cp -r "$AGENT_SRC/"*.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/agent.py"

# ── 3. Register with backend ──────────────────────────────────
info "Registering server with SecurePulse backend…"
HOSTNAME_VAL="$(hostname -f 2>/dev/null || hostname)"
IP_VAL="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'unknown')"
OS_INFO="$(uname -s) $(uname -r)"

REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "$BACKEND_URL/agents/register" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "{\"hostname\":\"$HOSTNAME_VAL\",\"ip_address\":\"$IP_VAL\",\"os_info\":\"$OS_INFO\"}" \
  2>/dev/null) || error "curl failed. Is the backend reachable at $BACKEND_URL?"

HTTP_BODY="$(echo "$REGISTER_RESPONSE" | head -n -1)"
HTTP_CODE="$(echo "$REGISTER_RESPONSE" | tail -n 1)"

if [[ "$HTTP_CODE" != "201" ]]; then
  error "Registration failed (HTTP $HTTP_CODE): $HTTP_BODY"
fi

AGENT_TOKEN="$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_token'])")"
SERVER_ID="$(echo "$HTTP_BODY"   | python3 -c "import sys,json; print(json.load(sys.stdin)['server_id'])")"

info "Registered! Server ID: $SERVER_ID"

# ── 4. Write config ───────────────────────────────────────────
info "Writing config to $CONFIG_FILE…"
cat > "$CONFIG_FILE" <<EOF
[agent]
backend_url        = $BACKEND_URL
agent_token        = $AGENT_TOKEN
poll_interval      = 5
log_level          = INFO
EOF
chmod 600 "$CONFIG_FILE"

# ── 5. Create log file ────────────────────────────────────────
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# ── 6. Create systemd service ─────────────────────────────────
info "Creating systemd service: $SERVICE_NAME"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SecurePulse Security Monitoring Agent
Documentation=https://github.com/your-org/securepulse
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securepulse-agent
Environment="SP_CONFIG_FILE=$CONFIG_FILE"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ── 7. Enable and start ───────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 2
STATUS="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo 'unknown')"
if [[ "$STATUS" == "active" ]]; then
  info "✅ Service is RUNNING"
else
  warn "Service status: $STATUS. Check: journalctl -u $SERVICE_NAME -f"
fi

info "============================================"
info " SecurePulse Agent installed successfully!"
info " Server ID    : $SERVER_ID"
info " Config       : $CONFIG_FILE"
info " Logs         : journalctl -u $SERVICE_NAME -f"
info " Dashboard    : $BACKEND_URL/servers"
info "============================================"
