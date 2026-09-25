#!/bin/bash
set -e

# Always ensure we are in the correct directory
cd "$(dirname "$0")"

echo "=========================================================="
echo "  SecurePulse SOC - Restart/Startup Script"
echo "=========================================================="

echo "[1/4] Checking Database (PostgreSQL)..."
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

echo "[2/4] Activating Virtual Environment..."
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "  [OK] Virtual environment 'venv' activated."
else
    echo "  [INFO] No venv found. Creating virtual environment 'venv'..."
    python3 -m venv venv
    source venv/bin/activate
    echo "  [OK] Virtual environment created and activated."
fi

echo "[3/4] Checking and Installing Dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "  [WARN] requirements.txt not found. Skipping dependency installation."
fi

echo "[4/4] Starting Application..."
echo "  Stopping any running app processes..."
pkill -f "uvicorn app:app" 2>/dev/null || true
pkill -f "python.*app.py" 2>/dev/null || true

# Give the port a moment to unbind
sleep 1

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
