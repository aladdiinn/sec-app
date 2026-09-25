#!/bin/bash
set -e

echo "=========================================================="
echo "  SecurePulse SOC - Startup Script"
echo "=========================================================="

echo "[1/3] Checking Database (PostgreSQL)..."
if systemctl is-active --quiet postgresql; then
    echo "  [OK] PostgreSQL is already running."
else
    echo "  [INFO] PostgreSQL is not running. Attempting to start..."
    sudo systemctl start postgresql || {
        echo "  [ERROR] Failed to start PostgreSQL. Check journalctl -xeu postgresql"
        exit 1
    }
    echo "  [OK] PostgreSQL started successfully."
fi

echo "[2/3] Checking and Installing Dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    echo "  [WARN] requirements.txt not found. Skipping dependency installation."
fi

echo "[3/3] Starting Application (app.py)..."
# Kill existing uvicorn instances for this app to prevent port conflicts
pkill -f "uvicorn app:app" || true

# Start the application in the background
nohup uvicorn app:app --host 0.0.0.0 --port 8000 > app_backend.log 2>&1 &
APP_PID=$!

echo "=========================================================="
echo "  [SUCCESS] Application started!"
echo "  - Process ID (PID) : $APP_PID"
echo "  - Logs are output  : app_backend.log"
echo "  - Port             : 8000"
echo ""
echo "To view live logs, run: tail -f app_backend.log"
echo "=========================================================="
