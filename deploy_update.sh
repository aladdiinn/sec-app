#!/bin/bash
# =============================================================================
# SecurePulse — Full Update & Restart Script (Run on Ubuntu server as root/sudo)
# Python 3.14 compatible — uses gthread workers (no eventlet/gevent needed)
# =============================================================================
set -euo pipefail

APP_DIR="/home/ubuntu/sec-app"
AGENT_DIR="/opt/securepulse-agent"
VENV="$APP_DIR/venv"
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

# ── 2. Verify gunicorn is installed ───────────────────────────────────────
$GUNICORN --version || error "gunicorn not found at $GUNICORN"
info "Gunicorn OK: $($GUNICORN --version)"

# ── 3. Create systemd service using gthread (Python 3.14 compatible) ──────
info "Writing systemd service file..."
cat > /etc/systemd/system/securepulse.service <<EOF
[Unit]
Description=SecurePulse SOC Dashboard (Gunicorn gthread)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$GUNICORN \\
    --worker-class gthread \\
    --workers 1 \\
    --threads 8 \\
    --bind 0.0.0.0:5000 \\
    --timeout 300 \\
    --keepalive 75 \\
    --access-logfile $LOG_DIR/access.log \\
    --error-logfile $LOG_DIR/error.log \\
    --log-level info \\
    app:app
Restart=always
RestartSec=5s
StandardOutput=append:$APP_DIR/app.log
StandardError=append:$APP_DIR/app.log

[Install]
WantedBy=multi-user.target
EOF

# ── 4. Reload systemd and restart app ─────────────────────────────────────
info "Reloading systemd and restarting SecurePulse backend..."
systemctl daemon-reload
systemctl enable securepulse
systemctl restart securepulse
sleep 4

# Check status
if systemctl is-active --quiet securepulse; then
    info "SecurePulse backend is RUNNING ✅"
else
    error "SecurePulse backend FAILED to start. Check: journalctl -u securepulse -n 50"
fi

# ── 5. Update agent files ─────────────────────────────────────────────────
if [ -d "$AGENT_DIR" ]; then
    info "Updating agent files from backend..."
    sleep 2
    AGENT_DATA=$(curl -s --connect-timeout 5 "http://localhost:5000/setup/agent-files" || echo "")
    
    if [ -n "$AGENT_DATA" ] && echo "$AGENT_DATA" | $PYTHON -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        echo "$AGENT_DATA" | $PYTHON -c "
import sys, json, os
data = json.load(sys.stdin)
for filename, content in data.items():
    path = os.path.join('$AGENT_DIR', filename)
    with open(path, 'w') as f:
        f.write(content)
    print(f'  -> Updated: {filename}')
"
        info "Agent files updated ✅"
        
        if systemctl is-active --quiet securepulse-agent 2>/dev/null; then
            info "Restarting securepulse-agent..."
            systemctl restart securepulse-agent
            sleep 2
            systemctl is-active --quiet securepulse-agent && info "Agent is RUNNING ✅" || warn "Agent may have an issue. Check: journalctl -u securepulse-agent -n 30"
        else
            warn "Agent service not running. Start with: sudo systemctl start securepulse-agent"
        fi
    else
        warn "Could not fetch agent files. Skipping agent update."
    fi
else
    warn "Agent directory $AGENT_DIR not found. Skipping agent update."
fi

# ── 6. Quick health check ─────────────────────────────────────────────────
info "Testing backend health..."
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://localhost:5000/health || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    info "Health check: OK (HTTP 200) ✅"
else
    warn "Health check returned HTTP $HTTP_STATUS — check app.log"
fi

echo ""
echo "========================================================"
echo "  SecurePulse Update Complete!"
echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo "  App Logs:  tail -f $APP_DIR/app.log"
echo "  Status:    systemctl status securepulse"
echo "========================================================"
