#!/bin/bash
# Startup script for Security Dash (Production Mode)
# Runs FastAPI with 4 independent workers for high concurrency.

echo "Starting Security Dashboard with 4 workers..."
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
