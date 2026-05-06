#!/bin/bash
# =============================================================================
# SecurePulse — Full Update & Restart Script (Run on Ubuntu server as root/sudo)
# =============================================================================
# This script:
#   1. Installs eventlet for WebSocket support
#   2. Copies updated app files from this repo
#   3. Restarts the backend with the correct gunicorn config
#   4. Updates and restarts the agent with the new heartbeat monitor
#
# Usage:
#   cd /home/ubuntu/sec-app
#   bash deploy_update.sh

set -euo pipefail

APP_DIR="/home/ubuntu/sec-app"
AGENT_DIR="/opt/securepulse-agent"
VENV="/home/ubuntu/venv"
PYTHON="$VENV/bin/python3"
PIP="$VENV/bin/pip"
GUNICORN="$VENV/bin/gunicorn"
LOG_DIR="$APP_DIR/logs"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 1. Ensure log dir exists ───────────────────────────────────────────────
info "Creating log directory..."
mkdir -p "$LOG_DIR"

# ── 2. Install eventlet (required for WebSocket support) ───────────────────
info "Installing/upgrading eventlet..."
$PIP install --quiet --upgrade eventlet

# ── 3. Verify eventlet is installed ────────────────────────────────────────
$PYTHON -c "import eventlet; print('eventlet version:', eventlet.__version__)"
info "eventlet OK"

# ── 4. Create systemd service for gunicorn with eventlet ──────────────────
info "Writing systemd service file..."
cat > /etc/systemd/system/securepulse.service <<'EOF'
[Unit]
Description=SecurePulse SOC Dashboard (Gunicorn + Eventlet)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/sec-app
Environment="PATH=/home/ubuntu/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/home/ubuntu/venv/bin/gunicorn \
    --worker-class eventlet \
    --workers 1 \
    --bind 0.0.0.0:5000 \
    --timeout 120 \
    --keepalive 65 \
    --access-logfile /home/ubuntu/sec-app/logs/access.log \
    --error-logfile /home/ubuntu/sec-app/logs/error.log \
    --log-level info \
    app:app
Restart=always
RestartSec=5s
StandardOutput=append:/home/ubuntu/sec-app/app.log
StandardError=append:/home/ubuntu/sec-app/app.log

[Install]
WantedBy=multi-user.target
EOF

# ── 5. Reload systemd and restart app ─────────────────────────────────────
info "Reloading systemd and restarting SecurePulse backend..."
systemctl daemon-reload
systemctl enable securepulse
systemctl restart securepulse
sleep 3

# Check status
if systemctl is-active --quiet securepulse; then
    info "SecurePulse backend is RUNNING ✅"
else
    error "SecurePulse backend FAILED to start. Check: journalctl -u securepulse -n 50"
fi

# ── 6. Update agent with new heartbeat monitor ────────────────────────────
if [ -d "$AGENT_DIR" ]; then
    info "Updating agent files..."
    
    # Download fresh agent files from the running backend
    BACKEND_URL="http://localhost:5000"
    AGENT_DATA=$(curl -s "$BACKEND_URL/setup/agent-files")
    
    if echo "$AGENT_DATA" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        echo "$AGENT_DATA" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
for filename, content in data.items():
    path = os.path.join('$AGENT_DIR', filename)
    with open(path, 'w') as f:
        f.write(content)
    print(f'  -> Updated: {filename}')
"
        info "Agent files updated ✅"
        
        # Restart agent
        if systemctl is-active --quiet securepulse-agent 2>/dev/null; then
            info "Restarting securepulse-agent..."
            systemctl restart securepulse-agent
            sleep 2
            if systemctl is-active --quiet securepulse-agent; then
                info "Agent is RUNNING ✅"
            else
                warn "Agent may have an issue. Check: journalctl -u securepulse-agent -n 30"
            fi
        else
            warn "Agent service not found or not running. Start it manually."
        fi
    else
        warn "Could not fetch agent files from backend. Agent not updated."
    fi
else
    warn "Agent directory $AGENT_DIR not found. Skipping agent update."
fi

# ── 7. Quick connectivity test ────────────────────────────────────────────
info "Testing backend health..."
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    info "Backend health check: OK (HTTP 200) ✅"
else
    warn "Backend health check returned HTTP $HTTP_STATUS. Check app.log"
fi

echo ""
echo "========================================================"
echo "  SecurePulse Update Complete!"
echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo "  Logs:      tail -f $APP_DIR/app.log"
echo "  Status:    systemctl status securepulse"
echo "========================================================"
