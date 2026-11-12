#!/bin/bash
set -e

echo "============================================================"
echo " BSMART SOC - Host Agent & Container Live Reload"
echo "============================================================"

cd /application/Soc

# 1. Force recreate the SOC container so docker-compose.yml mounts take effect
echo "[1/4] Recreating Docker container with live mounts..."
docker rm -f bsmart-soc-app 2>/dev/null || true
docker compose up -d

# 2. Wait for SOC API container to become healthy and responding on loopback port 8001
echo "[2/4] Waiting for SOC API container to become live on http://127.0.0.1:8001..."
API_READY=0
for i in $(seq 1 30); do
    if curl -s -f http://127.0.0.1:8001/api/version >/dev/null 2>&1; then
        echo "[INFO] SOC API container is live and responding (attempt $i/30)!"
        API_READY=1
        break
    fi
    sleep 1
done

if [ "$API_READY" -ne 1 ]; then
    echo "[WARNING] SOC API container did not report ready within 30s, proceeding with deployment..."
fi

# 3. Generate the verified v1.7.0 host agent directly from local repo code
echo "[3/4] Deploying verified v1.7.0 Node Agent daemon..."
python3 /application/Soc/generate_agent.py

# Configure systemd unit with unbuffered output and proper environment
cat << 'UNIT_EOF' > /etc/systemd/system/securepulse.service
[Unit]
Description=BSMART SOC Node Agent Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/securepulse
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -u /opt/securepulse/node_push_agent.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/securepulse_agent.log
StandardError=append:/var/log/securepulse_agent.log

[Install]
WantedBy=multi-user.target
UNIT_EOF

# 4. Clear old log file and restart service cleanly
echo "[4/4] Truncating old log and restarting securepulse.service..."
> /var/log/securepulse_agent.log
pkill -9 -f node_push_agent.py 2>/dev/null || true
systemctl daemon-reload
systemctl restart securepulse

# Verification
sleep 3
systemctl status securepulse --no-pager

echo ""
echo "--- Live Agent Startup Log (/var/log/securepulse_agent.log) ---"
cat /var/log/securepulse_agent.log
echo "----------------------------------------------------------------"

echo "============================================================"
echo " [SUCCESS] Agent is active & ready for service restarts!"
echo "============================================================"
