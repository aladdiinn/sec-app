#!/bin/bash
set -e

echo "============================================================"
echo " BSMART SOC — Host Agent & Container Live Reload"
echo "============================================================"

cd /application/Soc

# 1. Force recreate the SOC container so docker-compose.yml mounts take effect
echo "[1/4] Recreating Docker container with live mounts..."
docker rm -f bsmart-soc-app 2>/dev/null || true
docker compose up -d

# 2. Generate the verified v1.7.0 host agent directly from local repo code
echo "[2/4] Deploying verified v1.7.0 Node Agent daemon..."
python3 /application/Soc/generate_agent.py

# 3. Stop any stray background processes and restart securepulse service
echo "[3/4] Restarting securepulse.service daemon..."
pkill -9 -f node_push_agent.py 2>/dev/null || true
systemctl daemon-reload
systemctl restart securepulse

# 4. Verification
echo "[4/4] Verifying agent status..."
sleep 2
systemctl status securepulse --no-pager

echo "============================================================"
echo " [SUCCESS] Deployment complete! Check live logs with:"
echo " tail -n 25 -f /var/log/securepulse_agent.log"
echo "============================================================"
