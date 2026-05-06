# gunicorn.conf.py — SecurePulse Production Config
# 
# IMPORTANT: Flask-SocketIO with WebSockets requires an async worker.
# Use eventlet or geventwebsocket, NOT the default sync worker.
#
# Run with:
#   gunicorn --config gunicorn.conf.py app:app

import multiprocessing

# ── Worker class: MUST be eventlet for SocketIO/WebSocket support ──
worker_class = "eventlet"
workers = 1          # eventlet handles concurrency internally; >1 causes issues
threads = 1

# ── Bind ───────────────────────────────────────────────────────────
bind = "0.0.0.0:5000"

# ── Timeouts ───────────────────────────────────────────────────────
# WebSocket connections are long-lived; increase timeout significantly
timeout = 120
keepalive = 65
graceful_timeout = 30

# ── Logging ────────────────────────────────────────────────────────
accesslog = "/home/ubuntu/sec-app/logs/access.log"
errorlog  = "/home/ubuntu/sec-app/logs/error.log"
loglevel  = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s'

# ── Misc ───────────────────────────────────────────────────────────
preload_app = False   # Disable preload — SocketIO needs per-worker init
daemon = False
