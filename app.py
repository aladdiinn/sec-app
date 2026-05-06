"""
SecurePulse — Server Security Monitoring Platform
Main application entry point (Flask + PostgreSQL + WebSocket)
"""

import os
import json
import logging
import secrets
import time
import requests
import io
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except ImportError:
    pass
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, g, send_file
)
from flask_socketio import SocketIO, emit, join_room # type: ignore
import jwt # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from database import db, init_db
from models import User, Server, Event, Alert, AuditLog, AlertRule
from sqlalchemy import func # type: ignore
from sqlalchemy.exc import IntegrityError # type: ignore

load_dotenv()

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log"),
    ],
)
logger = logging.getLogger("securepulse")

# ─── App factory ─────────────────────────────────────────────────────────────
base_dir = os.path.abspath(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(base_dir, "templets"),
    static_folder=os.path.join(base_dir, "static"),
    static_url_path='/static'
)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://securepulse:securepulse_pass@localhost:5432/securepulse_db",
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": 10,
    "max_overflow": 20,
}
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_EXPIRE_HOURS"] = 24
app.config["AGENT_API_KEY"] = os.getenv("AGENT_API_KEY", "change-me-secret-key")

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ─── Page Routes ─────────────────────────────────────────────────────────────

# ─── JWT helpers ─────────────────────────────────────────────────────────────

def create_jwt(user_id: int, email: str, is_admin: bool) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "is_admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(hours=app.config["JWT_EXPIRE_HOURS"]),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"])


def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        app.config["SECRET_KEY"],
        algorithms=[app.config["JWT_ALGORITHM"]],
    )


def jwt_required(f):
    """Decorator — validates Bearer token from Authorization header or session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif "token" in session:
            token = session["token"]

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            g.jwt_payload = decode_jwt(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated


def login_required(f):
    """Decorator — validates session token for frontend pages, redirects to login if missing."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "token" not in session:
            return redirect(url_for("login_page"))
        try:
            # We don't necessarily need to decode it here, just check if it exists and is valid
            decode_jwt(session["token"])
        except:
            session.clear()
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def agent_key_required(f):
    """Decorator — validates X-API-Key header for agent endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != app.config["AGENT_API_KEY"]:
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated


def audit_log_action(action_name):
    """Decorator to log actions to AuditLog."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the actual function
            response = f(*args, **kwargs)
            
            # Extract status code
            status_code = 200
            if isinstance(response, tuple):
                status_code = response[1] if len(response) > 1 else 200
            elif hasattr(response, 'status_code'):
                status_code = response.status_code

            # Only log if successful
            if 200 <= status_code < 300:
                user_id = None
                if getattr(g, "user", None):
                    user_id = g.user.id
                elif hasattr(g, "login_user_id"):
                    user_id = g.login_user_id

                if user_id:
                    target = request.path
                    if "target_override" in g:
                        target = g.target_override
                        
                    log = AuditLog(user_id=user_id, action=action_name, target=target)
                    db.session.add(log)
                    db.session.commit()
            return response
        return decorated_function
    return decorator



# ─── Bootstrap DB ────────────────────────────────────────────────────────────

@app.before_request
def load_logged_in_user():
    token = session.get("token")
    if token:
        try:
            payload = decode_jwt(token)
            g.user = User.query.get(int(payload["sub"]))
        except:
            g.user = None
    else:
        g.user = None

# Proxy for current_user to maintain compatibility with my previous edits
class UserProxy:
    def __getattr__(self, name):
        if g.user:
            return getattr(g.user, name)
        return None
    def __bool__(self):
        return g.user is not None

current_user = UserProxy()


def seed_admin():
    """Create default admin user if not exists."""
    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@securepulse.local")
    admin_pass  = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@1234")

    # Check if admin already exists
    if not User.query.filter_by(email=admin_email).first():
        try:
            admin = User(
                email=admin_email,
                hashed_password=generate_password_hash(admin_pass),
                full_name="Default Admin",
                is_admin=True,
            )
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Default admin created: {admin_email}")
        except IntegrityError:
            db.session.rollback()
            logger.info(f"Admin already exists (handled IntegrityError): {admin_email}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error seeding admin: {str(e)}")


# ──────────────────────────────────────────────────────────────────────────────
# FRONTEND ROUTES (Server-side rendered pages)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    try:
        return render_template("login.html", active='login')
    except Exception as e:
        logger.error(f"DEBUG LOGIN ERROR: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return f"Error loading login page: {str(e)}", 500


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html", active='dashboard')


@app.route("/servers")
def servers_page():
    return render_template("servers.html", active='servers')


@app.route("/events")
def events_page():
    return render_template("events.html", active='events')


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", user=current_user)


@app.route("/logins")
def logins_page():
    return render_template("logins.html", user=current_user)


@app.route("/cron-jobs")
def cron_jobs_page():
    return render_template("cron_jobs.html", user=current_user)


@app.route("/processes")
def processes_page():
    return render_template("processes.html", user=current_user)


@app.route("/audit-log")
def audit_log_page():
    return render_template("audit_log.html", user=current_user)


@app.route("/settings")
def settings_page():
    return render_template("settings.html", user=current_user)


@app.route("/servers/<int:id>")
def server_detail_page(id):
    server = Server.query.get_or_404(id)
    return render_template("server_detail.html", user=current_user, server=server)



# ──────────────────────────────────────────────────────────────────────────────
# API — AUTH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/auth/login", methods=["POST"])
@audit_log_action("User Login")
def auth_login():
    data = request.get_json(force=True)
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.hashed_password, password):
        return jsonify({"error": "Invalid email or password"}), 401

    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    token = create_jwt(user.id, user.email, user.is_admin)
    session["token"] = token  # Store in session for server-side routes
    g.login_user_id = user.id  # For audit logging
    g.target_override = email
    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    })


@app.route("/auth/me", methods=["GET"])
@jwt_required
def auth_me():
    user_id = int(g.jwt_payload["sub"])
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — AGENT REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/agents/register", methods=["POST"])
@agent_key_required
def register_agent():
    data = request.get_json(force=True)
    hostname   = data.get("hostname", "unknown")
    ip_address = data.get("ip_address")
    os_info    = data.get("os_info")

    agent_token = secrets.token_urlsafe(48)
    server = Server(
        hostname=hostname,
        ip_address=ip_address,
        os_info=os_info,
        agent_token=agent_token,
        status="online",
        last_seen=datetime.now(timezone.utc),
    )
    db.session.add(server)
    db.session.commit()
    logger.info(f"New agent registered: {hostname} ({ip_address})")

    return jsonify({
        "server_id": server.id,
        "agent_token": agent_token,
        "message": "Agent registered successfully",
    }), 201


# ─── API — SETUP (One-liner installer) ────────────────────────────────────────

@app.route("/setup")
def setup_script():
    """Returns a dynamic bash script for one-liner installation."""
    base_url = request.url_root.rstrip("/")
    api_key  = app.config["AGENT_API_KEY"]
    
    script = f"""#!/bin/bash
# SecurePulse — Automated Agent Installer
# This script is dynamically generated.

set -euo pipefail

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'
info()  {{ echo -e "${{GREEN}}[INFO]${{NC}}  $*"; }}
error() {{ echo -e "${{RED}}[ERROR]${{NC}} $*"; exit 1; }}

[[ "$EUID" -ne 0 ]] && error "Please run as root (sudo bash)"

BACKEND_URL="{base_url}"
API_KEY="{api_key}"
INSTALL_DIR="/opt/securepulse-agent"

info "Starting SecurePulse Agent setup..."
mkdir -p "$INSTALL_DIR"

# 1. Download agent files
info "Fetching agent components from $BACKEND_URL..."
AGENT_DATA=$(curl -s "$BACKEND_URL/setup/agent-files")

# 2. Write files using python3
info "Installing files to $INSTALL_DIR..."
echo "$AGENT_DATA" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
for filename, content in data.items():
    path = os.path.join('$INSTALL_DIR', filename)
    with open(path, 'w') as f:
        f.write(content)
    print(f'  -> {{filename}}')
"

# 3. Run the installer logic
# Note: We reuse the registration and systemd logic here or just call agent.py
info "Registering server..."
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
IP_VAL=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo 'unknown')
OS_INFO="$(uname -s) $(uname -r)"

REG_RES=$(curl -s -X POST "$BACKEND_URL/api/agents/register" \
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $API_KEY" \\
  -d "{{\\"hostname\\":\\"$HOSTNAME_VAL\\",\\"ip_address\\":\\"$IP_VAL\\",\\"os_info\\":\\"$OS_INFO\\"}}")

AGENT_TOKEN=$(echo "$REG_RES" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_token'])")

info "Creating configuration..."
cat > "/etc/securepulse-agent.conf" <<EOF
[agent]
backend_url        = $BACKEND_URL
agent_token        = $AGENT_TOKEN
poll_interval      = 5
log_level          = INFO
EOF
chmod 600 "/etc/securepulse-agent.conf"

info "Setting up systemd service..."
cat > "/etc/systemd/system/securepulse-agent.service" <<EOF
[Unit]
Description=SecurePulse Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
WorkingDirectory=$INSTALL_DIR
Restart=always
Environment="SP_CONFIG_FILE=/etc/securepulse-agent.conf"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable securepulse-agent
systemctl restart securepulse-agent

info "✅ SecurePulse Agent installed and running!"
"""
    return script, 200, {"Content-Type": "text/plain"}


@app.route("/setup/agent-files")
def setup_agent_files():
    """Returns all files in the agent/ directory as a JSON object."""
    agent_dir = os.path.join(base_dir, "agent")
    files_data = {}
    
    if not os.path.exists(agent_dir):
        return jsonify({"error": "Agent directory not found"}), 500
        
    for filename in os.listdir(agent_dir):
        if filename.endswith(".py"):
            path = os.path.join(agent_dir, filename)
            with open(path, "r") as f:
                files_data[filename] = f.read()
                
    return jsonify(files_data)


# ──────────────────────────────────────────────────────────────────────────────
# API — EVENTS (agent ingest + dashboard query)
# ──────────────────────────────────────────────────────────────────────────────

ALERT_TRIGGERS = {"failed_login", "cron_change", "ssh_login", "file_change"}
CRITICAL_KEYWORDS = ["root", "sudo", "passwd", "/etc/shadow", "chmod 777"]

@app.route("/api/events", methods=["POST"])
def ingest_event():
    agent_token = request.headers.get("X-Agent-Token", "")
    if not agent_token:
        return jsonify({"error": "X-Agent-Token header required"}), 401

    server = Server.query.filter_by(agent_token=agent_token).first()
    if not server:
        return jsonify({"error": "Invalid agent token"}), 401

    data = request.get_json(force=True)
    event_type  = data.get("event_type", "")
    description = data.get("description", "")
    severity    = data.get("severity", "info")
    source      = data.get("source")
    raw_data    = data.get("raw_data")

    VALID_TYPES = {
        "login", "logout", "cron_change", "new_process",
        "process_ended", "ssh_login", "failed_login",
        "file_change",
    }
    if event_type not in VALID_TYPES:
        return jsonify({"error": f"Invalid event_type. Use one of: {VALID_TYPES}"}), 400

    for kw in CRITICAL_KEYWORDS:
        if kw in description.lower():
            severity = "critical"
            break

    event = Event(
        server_id=server.id,
        event_type=event_type,
        severity=severity,
        source=source,
        description=description,
        raw_data=raw_data,
    )
    db.session.add(event)
    db.session.flush()  # Ensure event.id is available

    # Update server heartbeat
    server.last_seen = datetime.now(timezone.utc)
    server.status = "online"

    # Auto-create alerts for suspicious events
    if event_type in ALERT_TRIGGERS or severity == "critical":
        alert_severity = "critical" if severity == "critical" else "warning"
        alert_titles = {
            "failed_login": "Failed Login Detected",
            "cron_change":  "Cron Job Modified",
            "ssh_login":    "SSH Login",
            "file_change":  "File Integrity Violation",
        }
        title = alert_titles.get(event_type, "Security Event") + f" on {server.hostname}"
        alert = Alert(
            server_id=server.id,
            event_id=event.id,  # Linked to event
            alert_type=event_type,
            severity=alert_severity,
            title=title,
            message=description,
        )
        db.session.add(alert)
        
    # Brute force detection logic
    if event_type == "failed_login":
        ip = raw_data.get("ip") if isinstance(raw_data, dict) else None
        if ip and ip not in ("127.0.0.1", "localhost", "::1"):
            now_ts = time.time()
            if ip not in brute_force_cache:
                brute_force_cache[ip] = []
            brute_force_cache[ip] = [t for t in brute_force_cache[ip] if now_ts - t < 60]
            brute_force_cache[ip].append(now_ts)
            
            if len(brute_force_cache[ip]) >= 5:
                active_brute_force_ips[ip] = {
                    "count": len(brute_force_cache[ip]),
                    "target": server.hostname,
                    "last_seen": now_ts
                }
                if len(brute_force_cache[ip]) == 5:
                    alert = Alert(
                        server_id=server.id,
                        event_id=event.id,
                        alert_type="brute_force",
                        severity="critical",
                        title=f"Brute-Force Attack from {ip}",
                        message=f"5+ failed logins within 60s from {ip}"
                    )
                    db.session.add(alert)

    db.session.commit()

    # Push real-time update to dashboard via WebSocket
    socketio.emit("new_event", {
        "id": event.id,
        "server_id": server.id,
        "hostname": server.hostname,
        "event_type": event_type,
        "severity": severity,
        "description": description,
        "created_at": event.created_at.isoformat(),
    }, room="dashboard")

    return jsonify({"id": event.id, "message": "Event recorded"}), 201


# Global caches for features
geoip_cache = {}
brute_force_cache = {} # IP -> [timestamps...]
active_brute_force_ips = {} # IP -> {"count": X, "target": Y, "last_seen": Z}



@app.route("/api/events", methods=["GET"])
@jwt_required
def get_events():
    server_id  = request.args.get("server_id", type=int)
    event_type = request.args.get("event_type")
    severity   = request.args.get("severity")
    days       = request.args.get("days", type=int)
    limit      = min(request.args.get("limit", 100, type=int), 500)
    offset     = request.args.get("offset", 0, type=int)

    query = Event.query
    if server_id:
        query = query.filter_by(server_id=server_id)
    if event_type:
        if "," in event_type:
            query = query.filter(Event.event_type.in_(event_type.split(",")))
        else:
            query = query.filter_by(event_type=event_type)
    if severity:
        query = query.filter_by(severity=severity)
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(Event.created_at >= cutoff)

    total = query.count()
    events = query.order_by(Event.created_at.desc()).limit(limit).offset(offset).all()

    # Get hostnames in one query
    server_ids = list({e.server_id for e in events})
    servers = {s.id: s.hostname for s in Server.query.filter(Server.id.in_(server_ids)).all()} if server_ids else {}

    return jsonify({
        "total": total,
        "items": [
            {
                "id": e.id,
                "server_id": e.server_id,
                "hostname": servers.get(e.server_id, "unknown"),
                "event_type": e.event_type,
                "severity": e.severity,
                "source": e.source,
                "description": e.description,
                "raw_data": e.raw_data,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — SERVERS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/servers", methods=["GET"])
@jwt_required
def get_servers():
    status_filter   = request.args.get("status")
    severity_filter = request.args.get("severity")

    servers = Server.query.all()
    timeout = datetime.now(timezone.utc) - timedelta(seconds=int(os.getenv("HEARTBEAT_TIMEOUT", 120)))

    result = []
    for s in servers:
        # 1. Calculate Status
        status = "offline"
        if s.last_seen:
            status = "online" if s.last_seen.replace(tzinfo=timezone.utc) >= timeout else "offline"

        if status_filter and status != status_filter:
            continue

        # 2. Calculate Server Severity (highest severity of unresolved alerts)
        unresolved_alerts = s.alerts.filter_by(is_resolved=False).all()
        max_sev_val = 0 # 0: info, 1: warning, 2: critical
        max_sev_name = "info"
        
        for a in unresolved_alerts:
            val = 2 if a.severity == "critical" else 1
            if val > max_sev_val:
                max_sev_val = val
                max_sev_name = a.severity
        
        if severity_filter and max_sev_name != severity_filter:
            continue

        result.append({
            "id": s.id,
            "hostname": s.hostname,
            "ip_address": s.ip_address,
            "os_info": s.os_info,
            "status": status,
            "severity": max_sev_name,
            "severity_val": max_sev_val,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            "registered_at": s.registered_at.isoformat(),
        })

    # Sort: Severity (Critical > Warning > Info)
    result.sort(key=lambda x: x["severity_val"], reverse=True)

    return jsonify(result)


@app.route("/api/servers/<int:server_id>/export-report")
@jwt_required
def export_report(server_id):
    server = Server.query.get_or_404(server_id)
    
    # 1. Gather stats for the report
    total_events = Event.query.filter_by(server_id=server_id).count()
    crit_alerts = Alert.query.filter_by(server_id=server_id, severity='critical', is_resolved=False).count()
    recent_events = Event.query.filter_by(server_id=server_id).order_by(Event.created_at.desc()).limit(10).all()
    
    # 2. Generate PDF using reportlab
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Header
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 50, f"SecurePulse Security Report — {server.hostname}")
    
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.line(50, height - 75, width - 50, height - 75)
    
    # Server Info
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 100, "Server Information")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 120, f"IP Address: {server.ip_address}")
    p.drawString(50, height - 135, f"OS: {server.os_info or 'Unknown'}")
    p.drawString(50, height - 150, f"Last Seen: {server.last_seen.strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else 'N/A'}")
    
    # Security Summary
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 180, "Security Summary (Last 24h)")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 200, f"Total Events Logged: {total_events}")
    p.drawString(50, height - 215, f"Unresolved Critical Alerts: {crit_alerts}")
    
    # Recent Events
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 245, "Recent Security Events")
    p.setFont("Helvetica", 9)
    y = height - 265
    for e in recent_events:
        time_str = e.created_at.strftime('%H:%M:%S')
        p.drawString(50, y, f"[{time_str}] {e.severity.upper()} — {e.event_type}: {e.description[:100]}")
        y -= 15
        if y < 50: break
        
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"report_{server.hostname}_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )


@app.route("/api/servers/stats", methods=["GET"])
@jwt_required
def server_stats():
    total = Server.query.count()
    timeout = datetime.now(timezone.utc) - timedelta(seconds=int(os.getenv("HEARTBEAT_TIMEOUT", 120)))
    online = Server.query.filter(Server.last_seen >= timeout).count()
    total_events = Event.query.count()
    open_alerts = Alert.query.filter_by(is_resolved=False).count()

    return jsonify({
        "total_servers": total,
        "online_servers": online,
        "offline_servers": total - online,
        "total_events": total_events,
        "open_alerts": open_alerts,
    })


@app.route("/api/dashboard/trend", methods=["GET"])
@jwt_required
def dashboard_trend():
    """Returns hourly event counts for the last 24 hours."""
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)
    
    # Query for events in the last 24h
    events = Event.query.filter(Event.created_at >= twenty_four_hours_ago).all()
    
    # Initialize buckets
    buckets = {}
    for i in range(25):
        dt = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        buckets[dt.isoformat()] = {"info": 0, "warning": 0, "critical": 0}
        
    for e in events:
        hour_dt = e.created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        if hour_dt in buckets:
            buckets[hour_dt][e.severity] += 1
            
    # Convert to sorted list
    sorted_keys = sorted(buckets.keys())
    result = {
        "labels": [datetime.fromisoformat(k).strftime("%H:%M") for k in sorted_keys],
        "info": [buckets[k]["info"] for k in sorted_keys],
        "warning": [buckets[k]["warning"] for k in sorted_keys],
        "critical": [buckets[k]["critical"] for k in sorted_keys],
    }
    return jsonify(result)


@app.route("/api/dashboard/active-servers", methods=["GET"])
@jwt_required
def active_servers():
    """Returns top 3 servers by event count in last 24h."""
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)
    
    stats = db.session.query(
        Event.server_id, func.count(Event.id).label("count")
    ).filter(Event.created_at >= twenty_four_hours_ago).group_by(Event.server_id).order_by(func.count(Event.id).desc()).limit(3).all()
    
    result = []
    for server_id, count in stats:
        server = Server.query.get(server_id)
        if server:
            result.append({
                "id": server.id,
                "hostname": server.hostname,
                "event_count": count
            })
    return jsonify(result)

@app.route("/api/dashboard/geoip", methods=["GET"])
@jwt_required
def get_geoip_data():
    events = Event.query.filter(Event.event_type.in_(["ssh_login", "failed_login"])).order_by(Event.created_at.desc()).limit(200).all()
    ips = {}
    for e in events:
        try:
            raw = json.loads(e.raw_data) if isinstance(e.raw_data, str) else e.raw_data
            ip = raw.get("ip") if raw else None
            if ip and ip not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
                if ip not in ips:
                    ips[ip] = { "count": 1, "last_seen": e.created_at, "status": e.event_type }
                else:
                    ips[ip]["count"] += 1
        except:
            pass

    results = []
    for ip, data in ips.items():
        if ip not in geoip_cache:
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,lat,lon", timeout=3)
                if res.status_code == 200:
                    geoip_cache[ip] = res.json()
            except Exception as ex:
                logger.error(f"GeoIP error for {ip}: {ex}")
                geoip_cache[ip] = {"status": "fail"}
                
        geo = geoip_cache.get(ip, {})
        if geo.get("status") == "success":
            results.append({
                "ip": ip,
                "count": data["count"],
                "event_type": data["status"],
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "country": geo.get("country"),
                "countryCode": geo.get("countryCode")
            })
            
    return jsonify(results)

@app.route("/api/dashboard/brute-force", methods=["GET"])
@jwt_required
def get_brute_force():
    now_ts = time.time()
    # Expire after 10 mins
    expired = [ip for ip, data in active_brute_force_ips.items() if now_ts - data["last_seen"] > 600]
    for ip in expired:
        del active_brute_force_ips[ip]
        
    return jsonify([{"ip": k, **v} for k, v in active_brute_force_ips.items()])

# ──────────────────────────────────────────────────────────────────────────────
# API — ALERTS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
@jwt_required
def get_alerts():
    server_id   = request.args.get("server_id", type=int)
    severity    = request.args.get("severity")
    is_resolved = request.args.get("is_resolved")
    limit       = min(request.args.get("limit", 100, type=int), 500)
    offset      = request.args.get("offset", 0, type=int)

    query = Alert.query
    if server_id:
        query = query.filter_by(server_id=server_id)
    if severity:
        query = query.filter_by(severity=severity)
    if is_resolved is not None:
        resolved_bool = is_resolved.lower() == "true"
        query = query.filter_by(is_resolved=resolved_bool)

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).offset(offset).all()

    server_ids = list({a.server_id for a in alerts})
    servers = {s.id: s.hostname for s in Server.query.filter(Server.id.in_(server_ids)).all()} if server_ids else {}

    return jsonify({
        "total": total,
        "items": [
            {
                "id": a.id,
                "server_id": a.server_id,
                "hostname": servers.get(a.server_id, "unknown"),
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "message": a.message,
                "is_resolved": a.is_resolved,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    })


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["PATCH"])
@jwt_required
@audit_log_action("Resolve Alert")
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.is_resolved:
        return jsonify({"error": "Already resolved"}), 400
    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    db.session.commit()

    socketio.emit("alert_resolved", {"alert_id": alert_id}, room="dashboard")
    g.target_override = f"Alert #{alert_id}: {alert.title}"
    
    return jsonify({
        "id": alert.id,
        "is_resolved": True
    })


@app.route("/api/audit-logs", methods=["GET"])
@jwt_required
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify({
        "items": [
            {
                "id": l.id,
                "user_email": l.user.email,
                "action": l.action,
                "target": l.target,
                "timestamp": l.timestamp.isoformat()
            }
            for l in logs
        ]
    })


# ──────────────────────────────────────────────────────────────────────────────
# WEBSOCKET
# ──────────────────────────────────────────────────────────────────────────────

@socketio.on("connect")
def ws_connect():
    logger.info(f"WebSocket client connected: {request.sid}")


@socketio.on("join_dashboard")
def ws_join_dashboard():
    join_room("dashboard")
    emit("joined", {"room": "dashboard"})


@socketio.on("disconnect")
def ws_disconnect():
    logger.info(f"WebSocket client disconnected: {request.sid}")


# ──────────────────────────────────────────────────────────────────────────────
# HEALTH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "securepulse"})


# ──────────────────────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ──────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/auth") or request.path.startswith("/events") \
            or request.path.startswith("/servers") or request.path.startswith("/alerts") \
            or request.path.startswith("/agents"):
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404



@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    # Log the full error to terminal so we can see it
    import traceback
    logger.error(f"Internal 500 Error: {e}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "Internal server error", "details": str(e)}), 500


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

# Initialize database on startup
with app.app_context():
    init_db(app)
    seed_admin()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    logger.info(f"Starting SecurePulse on port {port} (debug={debug})")
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, allow_unsafe_werkzeug=True)