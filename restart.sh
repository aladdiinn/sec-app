#!/bin/bash
# =============================================================
# EC2 Security Monitor — Restart Script
# Restarts the server on port 8000
# =============================================================

echo "Stopping any running app processes..."
pkill -f "app:app" 2>/dev/null || pkill -f "python.*app.py" 2>/dev/null

echo "Starting EC2 Security Monitor backend on http://localhost:8000 ..."
export PORT=8000
python3 app.py
