# gunicorn.conf.py — SecurePulse Production Config
#
# Python 3.14 does NOT support eventlet or gevent yet.
# Use gthread worker which handles WebSocket via threading (Flask-SocketIO threading mode).
#
# Run with:
#   gunicorn --config gunicorn.conf.py app:app
#
# Or directly:
#   gunicorn --worker-class gthread --workers 1 --threads 8 --bind 0.0.0.0:5000 --timeout 120 app:app

# ── Worker class: gthread for Python 3.14 + Flask-SocketIO threading mode ──
worker_class = "gthread"
workers = 1        # Must be 1 for SocketIO session consistency
threads = 8        # 8 threads handle concurrent requests + WebSocket connections

# ── Bind ───────────────────────────────────────────────────────────
bind = "0.0.0.0:5000"

# ── Timeouts ───────────────────────────────────────────────────────
# WebSocket connections are long-lived; must be high
timeout = 300
keepalive = 75
graceful_timeout = 30

# ── Logging ────────────────────────────────────────────────────────
accesslog = "/home/ubuntu/sec-app/logs/access.log"
errorlog  = "/home/ubuntu/sec-app/logs/error.log"
loglevel  = "info"

# ── Misc ───────────────────────────────────────────────────────────
preload_app = True
daemon = False
