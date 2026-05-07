"""
SecurePulse — Server Security Monitoring Platform
Main application entry point (Flask + PostgreSQL + WebSocket)
"""

import os
import json
import logging
import secrets
import time
import io
import yaml
import re
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
from models import User, Server, Event, Alert, AuditLog, AlertRule, Case, ThreatIndicator, Playbook
from sqlalchemy import func # type: ignore
from sqlalchemy.exc import IntegrityError # type: ignore

load_dotenv()

# ─── Logging ─────────────────────────────────────────────────────────────────
# Setup basic logging to both console and file
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
    template_folder=os.path.join(base_dir, "templates"), # Fixed typo: templets -> templates
    static_folder=os.path.join(base_dir, "static"),
    static_url_path='/static'
)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://securepulse:securepulse_pass@127.0.0.1:5432/securepulse_db",
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": 20,
    "max_overflow": 40,
    "pool_recycle": 1800,
    "pool_timeout": 30,
}
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_EXPIRE_HOURS"] = 24
app.config["AGENT_API_KEY"] = os.getenv("AGENT_API_KEY", "change-me-secret-key")

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

@app.route('/favicon.ico')
def favicon():
    return '', 204

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


def log_audit(action: str, target: str = None, user_id: int = None):
    """Logs an administrative action to the audit_logs table."""
    try:
        if user_id is None:
            user_id = getattr(g, "user_id", getattr(g, "login_user_id", None))
            
        remote_ip = request.remote_addr
        log = AuditLog(
            user_id=user_id,
            action=action,
            target=f"{target} (IP: {remote_ip})" if target else f"IP: {remote_ip}",
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log audit action: {e}")
        db.session.rollback()


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
            g.user_id = int(g.jwt_payload["sub"])
            g.user = User.query.get(g.user_id)
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
            payload = decode_jwt(session["token"])
            g.user_id = int(payload["sub"])
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
                        
                    log_audit(action_name, target)
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

# Proxy for current_user to maintain compatibility
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
    if "token" not in session:
        return redirect(url_for("login_page"))
    return redirect(url_for("dashboard_page"))


@app.route("/login")
def login_page():
    if "token" in session:
        return redirect(url_for("dashboard_page"))
    try:
        return render_template("login.html", hide_nav=True, active='login')
    except Exception as e:
        logger.error(f"DEBUG LOGIN ERROR: {str(e)}")
        return f"Error loading login page: {str(e)}", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/dashboard")
@login_required
def dashboard_page():
    # Fetch real-time stats for the SOC dashboard
    alert_count = Alert.query.count()
    case_count = Case.query.count()
    threat_count = ThreatIndicator.query.count()
    server_count = Server.query.count()
    
    return render_template("dashboard.html", 
                         active='dashboard',
                         alerts=alert_count, 
                         cases=case_count, 
                         threats=threat_count, 
                         servers=server_count)

@app.route("/incidents")
@login_required
def incidents_page():
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template("alerts.html", active='incidents', incidents=all_cases)

@app.route("/assets")
@login_required
def assets_page():
    all_servers = Server.query.all()
    return render_template("servers.html", active='assets', assets=all_servers)

@app.route("/audit-log")
@login_required
def audit_log_page():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template("audit_log.html", active='audit-log', logs=logs)


@app.route("/servers")
@login_required
def servers_legacy():
    return redirect(url_for("assets_page"))

@app.route("/events")
@login_required
def events_legacy():
    return redirect(url_for("incidents_page"))

@app.route("/alerts")
@login_required
def alerts_legacy():
    return redirect(url_for("incidents_page"))


@app.route("/logins")
@login_required
def logins_page():
    return render_template("logins.html", active='logins')

@app.route("/cron-jobs")
@login_required
def cron_jobs_page():
    return render_template("cron_jobs.html", active='cron-jobs')

@app.route("/processes")
@login_required
def processes_page():
    return render_template("processes.html", active='processes')

@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active='settings')


@app.route("/servers/<int:id>")
@login_required
def server_detail_page(id):
    server = Server.query.get_or_404(id)
    return render_template("server_detail.html", active='assets', user=current_user, server=server)


@app.route("/investigate/<int:case_id>")
@login_required
def investigation_page(case_id):
    case = Case.query.get_or_404(case_id)
    return render_template("investigation.html", active='incidents', case=case)


@app.route("/rules")
@login_required
def rules_page():
    return render_template("rules.html", active='rules')


@app.route("/threat-intel")
@login_required
def threat_intel_page():
    return render_template("threat_intel.html", active='threat-intel')


@app.route("/search")
@login_required
def search_page():
    return render_template("search.html", active='search')


@app.route("/playbooks")
@login_required
def playbooks_page():
    return render_template("playbooks.html", active='playbooks')


@app.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html", active='reports')


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
    session["token"] = token
    g.login_user_id = user.id
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
info "Registering server..."
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
IP_VAL=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo 'unknown')
OS_INFO="$(uname -s) $(uname -r)"

REG_RES=$(curl -s -X POST "$BACKEND_URL/api/agents/register" \\
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
# DETECTION ENGINE (Rule-based detection)
# ──────────────────────────────────────────────────────────────────────────────

class RuleManager:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()

    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                path = os.path.join(self.rules_dir, filename)
                try:
                    with open(path, "r") as f:
                        data = yaml.safe_load(f)
                        if data and "rules" in data:
                            self.rules.extend(data["rules"])
                    logger.info(f"Loaded {len(data.get('rules', []))} rules from {filename}")
                except Exception as e:
                    logger.error(f"Failed to load rules from {filename}: {e}")

    def evaluate(self, event_type, description, raw_data):
        triggered_rules = []
        for rule in self.rules:
            if rule.get("event_type") != event_type:
                continue

            condition = rule.get("condition", {})
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            # Resolve field value
            field_val = ""
            if field == "description":
                field_val = description
            elif isinstance(raw_data, dict) and field in raw_data:
                field_val = str(raw_data.get(field))
            
            # Evaluate condition
            match = False
            if operator == "contains":
                match = value.lower() in field_val.lower()
            elif operator == "equals":
                match = value.lower() == field_val.lower()
            elif operator == "regex":
                try:
                    match = re.search(value, field_val) is not None
                except:
                    pass

            if match:
                triggered_rules.append(rule)
        
        return triggered_rules

# Global Rule Manager instance
rule_manager = RuleManager()


def score_alert(severity: str, mitre_tactic: str = None, is_brute_force: bool = False) -> int:
    """Calculate a CVSS-style risk score (0-100) for an alert."""
    base = {"critical": 80, "warning": 50, "info": 20}.get(severity, 20)
    if mitre_tactic:
        base = min(base + 10, 100)
    if is_brute_force:
        base = min(base + 15, 100)
    return base



class PlaybookRunner:
    @staticmethod
    def run(playbook_id, alert_id):
        playbook = Playbook.query.get(playbook_id)
        alert = Alert.query.get(alert_id)
        if not playbook or not alert:
            return False
        
        try:
            actions = json.loads(playbook.actions) if isinstance(playbook.actions, str) else playbook.actions
            for action in actions:
                action_type = action.get("type")
                if action_type == "resolve_alert":
                    alert.is_resolved = True
                    alert.resolved_at = datetime.now(timezone.utc)
                elif action_type == "promote_to_case":
                    if not alert.case_id:
                        new_case = Case(
                            title=f"Auto-Promoted: {alert.title}",
                            priority=alert.severity,
                            summary=f"Automated promotion via playbook: {playbook.name}",
                            due_at=datetime.now(timezone.utc) + timedelta(hours=24)
                        )
                        db.session.add(new_case)
                        db.session.flush()
                        alert.case_id = new_case.id
                elif action_type == "isolate_host":
                    logger.warning(f"PLAYBOOK ACTION: Isolating host {alert.server.hostname}")
                    isolation_alert = Alert(
                        server_id=alert.server_id,
                        event_id=alert.event_id,
                        alert_type="isolation_triggered",
                        severity="critical",
                        title=f"HOST ISOLATED: {alert.server.hostname}",
                        message=f"Automated isolation triggered by playbook: {playbook.name}"
                    )
                    db.session.add(isolation_alert)
                    alert.server.status = "isolated"
            
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"Playbook execution error: {e}")
            db.session.rollback()
            return False

# ──────────────────────────────────────────────────────────────────────────────
# API — EVENTS (agent ingest + dashboard query)
# ──────────────────────────────────────────────────────────────────────────────

ALERT_TRIGGERS = {"failed_login", "cron_change", "ssh_login", "file_change"}
CRITICAL_KEYWORDS = ["root", "sudo", "passwd", "/etc/shadow", "chmod 777"]

# Global caches
geoip_cache = {}
brute_force_cache = {} 
active_brute_force_ips = {} 

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
        "file_change", "heartbeat",
    }
    if event_type not in VALID_TYPES:
        return jsonify({"error": f"Invalid event_type. Use one of: {VALID_TYPES}"}), 400

    # Heartbeat
    if event_type == "heartbeat":
        server.last_seen = datetime.now(timezone.utc)
        if server.status != "isolated":
            server.status = "online"
        db.session.commit()
        return jsonify({"message": "Heartbeat received"}), 200

    for kw in CRITICAL_KEYWORDS:
        if kw in description.lower():
            severity = "critical"
            break

    raw_data_str = json.dumps(raw_data) if raw_data is not None else None

    event = Event(
        server_id=server.id,
        event_type=event_type,
        severity=severity,
        source=source,
        description=description,
        raw_data=raw_data_str,
    )
    db.session.add(event)
    db.session.flush()

    server.last_seen = datetime.now(timezone.utc)
    server.status = "online"

    # --- 1. Custom Rule Detection ---
    triggered_rules = rule_manager.evaluate(event_type, description, raw_data)
    for rule in triggered_rules:
        sev = rule.get("severity", "warning")
        tactic = rule.get("mitre_tactic")
        alert = Alert(
            server_id=server.id,
            event_id=event.id,
            alert_type="custom_rule",
            severity=sev,
            title=rule.get("name", "Security Rule Triggered"),
            message=rule.get("message", description),
            mitre_tactic=tactic,
            mitre_technique=rule.get("mitre_technique"),
            score=score_alert(sev, tactic),
        )
        db.session.add(alert)
        logger.info(f"Rule triggered: {rule.get('name')} on {server.hostname}")

    # --- 2. Threat Intel Lookup ---
    # Check IP in raw_data or description against threat_indicators table
    potential_ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", description)
    if isinstance(raw_data, dict) and "ip" in raw_data:
        potential_ips.append(raw_data["ip"])
    
    for ip in set(potential_ips):
        if ip in ("127.0.0.1", "localhost", "::1"): continue
        ti = ThreatIndicator.query.filter_by(value=ip).first()
        if ti:
            alert = Alert(
                server_id=server.id,
                event_id=event.id,
                alert_type="threat_intel",
                severity="critical",
                title=f"Threat Intel Match: {ip}",
                message=f"Known malicious indicator detected. Source: {ti.source}. Severity: {ti.severity}",
            )
            db.session.add(alert)
            logger.info(f"Threat Intel Match: {ip} on {server.hostname}")

    # --- 3. UEBA (Anomaly Detection) ---
    # A. Unusual Login Time (2 AM - 5 AM)
    if event_type in ("ssh_login", "login"):
        hour = datetime.now(timezone.utc).hour
        if 2 <= hour <= 5:
            alert = Alert(
                server_id=server.id,
                event_id=event.id,
                alert_type="ueba_anomaly",
                severity="warning",
                title="Unusual Login Time",
                message=f"Login detected at unusual hour: {hour}:00 UTC",
            )
            db.session.add(alert)

    # --- 4. Hardcoded Security Triggers (Legacy) ---
    # Auto-create alerts
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
            event_id=event.id,
            alert_type=event_type,
            severity=alert_severity,
            title=title,
            message=description,
            score=score_alert(alert_severity),
        )
        db.session.add(alert)
        
    # Brute force detection
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
                    brute_alert = Alert(
                        server_id=server.id,
                        event_id=event.id,
                        alert_type="brute_force",
                        severity="critical",
                        title=f"Brute-Force Attack from {ip}",
                        message=f"5+ failed logins within 60s from {ip}",
                        score=score_alert("critical", is_brute_force=True),
                    )
                    db.session.add(brute_alert)

    db.session.commit()

    # --- 5. Auto-escalation: promote critical alerts with score >= 80 to cases ---
    new_alerts = db.session.query(Alert).filter(
        Alert.server_id == server.id,
        Alert.event_id == event.id,
        Alert.severity == "critical",
        Alert.score >= 80,
        Alert.case_id == None,
        Alert.auto_promoted == False,
    ).all()
    for na in new_alerts:
        auto_case = Case(
            title=f"[AUTO] {na.title}",
            priority="critical",
            summary=f"Auto-promoted by escalation engine. Score: {na.score}/100",
            due_at=datetime.now(timezone.utc) + timedelta(hours=4),  # High-severity SLA: 4h
        )
        db.session.add(auto_case)
        db.session.flush()
        na.case_id = auto_case.id
        na.auto_promoted = True
        logger.warning(f"Auto-escalated alert '{na.title}' to Case #{auto_case.id}")
    db.session.commit()

    # Push WebSocket update
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
        # Honor isolated status above all
        if s.status == "isolated":
            status = "isolated"
        elif s.last_seen:
            status = "online" if s.last_seen.replace(tzinfo=timezone.utc) >= timeout else "offline"
        else:
            status = "offline"

        if status_filter and status != status_filter:
            continue

        unresolved_alerts = s.alerts.filter_by(is_resolved=False).all()
        max_sev_val = 0 
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

    result.sort(key=lambda x: x["severity_val"], reverse=True)
    return jsonify(result)


@app.route("/api/servers/<int:server_id>/export-report")
@jwt_required
def export_report(server_id):
    server = Server.query.get_or_404(server_id)
    total_events = Event.query.filter_by(server_id=server_id).count()
    crit_alerts = Alert.query.filter_by(server_id=server_id, severity='critical', is_resolved=False).count()
    recent_events = Event.query.filter_by(server_id=server_id).order_by(Event.created_at.desc()).limit(10).all()
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 50, f"SecurePulse Security Report — {server.hostname}")
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.line(50, height - 75, width - 50, height - 75)
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 100, "Server Information")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 120, f"IP Address: {server.ip_address}")
    p.drawString(50, height - 135, f"OS: {server.os_info or 'Unknown'}")
    p.drawString(50, height - 150, f"Last Seen: {server.last_seen.strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else 'N/A'}")
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 180, "Security Summary (Last 24h)")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 200, f"Total Events Logged: {total_events}")
    p.drawString(50, height - 215, f"Unresolved Critical Alerts: {crit_alerts}")
    
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
@app.route("/api/servers/<int:server_id>/isolate", methods=["POST"])
@jwt_required
@audit_log_action("Isolate Server")
def isolate_server(server_id):
    server = Server.query.get_or_404(server_id)
    server.status = "isolated"
    
    # Create a critical containment alert
    isolation_alert = Alert(
        server_id=server.id,
        alert_type="manual_isolation",
        severity="critical",
        title=f"HOST ISOLATED: {server.hostname}",
        message=f"Manual containment triggered by administrator {g.user.email}"
    )
    db.session.add(isolation_alert)
    db.session.commit()
    
    socketio.emit("new_event", {
        "id": 0,
        "server_id": server.id,
        "hostname": server.hostname,
        "event_type": "isolation",
        "severity": "critical",
        "description": f"Host {server.hostname} has been isolated from the network.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, room="dashboard")
    
    return jsonify({"message": f"Server {server.hostname} isolated successfully", "status": "isolated"})


@app.route("/api/servers/<int:server_id>/reconnect", methods=["POST"])
@jwt_required
@audit_log_action("Reconnect Server")
def reconnect_server(server_id):
    server = Server.query.get_or_404(server_id)
    server.status = "online"
    reconnect_alert = Alert(
        server_id=server.id,
        alert_type="host_reconnected",
        severity="warning",
        title=f"HOST RECONNECTED: {server.hostname}",
        message=f"Network connectivity restored by administrator {g.user.email}",
        score=score_alert("warning"),
    )
    db.session.add(reconnect_alert)
    db.session.commit()
    socketio.emit("new_event", {
        "id": 0, "server_id": server.id, "hostname": server.hostname,
        "event_type": "reconnect", "severity": "warning",
        "description": f"Host {server.hostname} reconnected to network.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, room="dashboard")
    return jsonify({"message": f"Server {server.hostname} reconnected", "status": "online"})


@app.route("/api/search", methods=["GET"])
@jwt_required
def unified_search():
    """Search across events, alerts, and cases by a free-text query."""
    query = request.args.get("q", "").strip()
    limit = min(request.args.get("limit", 20, type=int), 100)
    scope = request.args.get("scope", "all")  # all | events | alerts | cases
    if not query:
        return jsonify({"events": [], "alerts": [], "cases": [], "total": 0})

    results = {"events": [], "alerts": [], "cases": [], "total": 0}

    if scope in ("all", "events"):
        events = Event.query.filter(
            (Event.description.ilike(f"%{query}%")) |
            (Event.event_type.ilike(f"%{query}%")) |
            (Event.source.ilike(f"%{query}%"))
        ).order_by(Event.created_at.desc()).limit(limit).all()
        server_map = {s.id: s.hostname for s in Server.query.all()}
        results["events"] = [
            {"id": e.id, "type": "event", "title": e.event_type,
             "description": e.description, "severity": e.severity,
             "hostname": server_map.get(e.server_id, "unknown"),
             "created_at": e.created_at.isoformat()}
            for e in events
        ]

    if scope in ("all", "alerts"):
        alerts = Alert.query.filter(
            (Alert.title.ilike(f"%{query}%")) |
            (Alert.message.ilike(f"%{query}%")) |
            (Alert.alert_type.ilike(f"%{query}%")) |
            (Alert.mitre_tactic.ilike(f"%{query}%"))
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        server_map = {s.id: s.hostname for s in Server.query.all()}
        results["alerts"] = [
            {"id": a.id, "type": "alert", "title": a.title,
             "description": a.message, "severity": a.severity,
             "hostname": server_map.get(a.server_id, "unknown"),
             "mitre_tactic": a.mitre_tactic, "score": a.score,
             "case_id": a.case_id, "created_at": a.created_at.isoformat()}
            for a in alerts
        ]

    if scope in ("all", "cases"):
        cases = Case.query.filter(
            (Case.title.ilike(f"%{query}%")) |
            (Case.summary.ilike(f"%{query}%"))
        ).order_by(Case.created_at.desc()).limit(limit).all()
        results["cases"] = [
            {"id": c.id, "type": "case", "title": c.title,
             "description": c.summary or "", "severity": c.priority,
             "status": c.status, "due_at": c.due_at.isoformat() if c.due_at else None,
             "created_at": c.created_at.isoformat() if c.created_at else None}
            for c in cases
        ]

    results["total"] = len(results["events"]) + len(results["alerts"]) + len(results["cases"])
    return jsonify(results)



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
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)
    events = Event.query.filter(Event.created_at >= twenty_four_hours_ago).all()
    
    buckets = {}
    for i in range(25):
        dt = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        buckets[dt.isoformat()] = {"info": 0, "warning": 0, "critical": 0}
        
    for e in events:
        hour_dt = e.created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        if hour_dt in buckets:
            buckets[hour_dt][e.severity] += 1
            
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
    
    case_id = request.args.get("case_id", type=int)
    if case_id:
        query = query.filter_by(case_id=case_id)

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
                "case_id": a.case_id,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique": a.mitre_technique,
                "score": a.score,
                "auto_promoted": a.auto_promoted,
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
    return jsonify({"id": alert.id, "is_resolved": True})


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
# API — CASES (Incident Management)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases", methods=["GET"])
@jwt_required
def get_cases():
    status = request.args.get("status")
    priority = request.args.get("priority")
    query = Case.query
    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)
    
    cases = query.order_by(Case.created_at.desc()).all()
    return jsonify([
        {
            "id": c.id,
            "title": c.title,
            "status": c.status,
            "priority": c.priority,
            "assignee_id": c.assignee_id,
            "summary": c.summary,
            "due_at": c.due_at.isoformat() if c.due_at else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        } for c in cases
    ])
@app.route("/api/cases/<int:case_id>/details", methods=["GET"])
@jwt_required
def get_case_details(case_id):
    case = Case.query.get_or_404(case_id)
    alerts = Alert.query.filter_by(case_id=case_id).all()
    
    nodes = [{"id": f"case_{case.id}", "label": case.title, "type": "case", "priority": case.priority}]
    links = []
    
    server_nodes = set()
    
    for a in alerts:
        alert_node_id = f"alert_{a.id}"
        nodes.append({
            "id": alert_node_id,
            "label": a.title,
            "type": "alert",
            "severity": a.severity,
            "mitre_tactic": a.mitre_tactic
        })
        links.append({"source": alert_node_id, "target": f"case_{case.id}"})
        
        if a.server_id:
            server_node_id = f"server_{a.server_id}"
            if server_node_id not in server_nodes:
                nodes.append({
                    "id": server_node_id,
                    "label": a.server.hostname,
                    "type": "server",
                    "status": a.server.status
                })
                server_nodes.add(server_node_id)
            links.append({"source": server_node_id, "target": alert_node_id})
            
        if a.event_id:
            event_node_id = f"event_{a.event_id}"
            nodes.append({
                "id": event_node_id,
                "label": a.event.event_type,
                "type": "event",
                "severity": a.event.severity
            })
            links.append({"source": event_node_id, "target": alert_node_id})

    return jsonify({"nodes": nodes, "links": links, "case": {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "due_at": case.due_at.isoformat() if case.due_at else None,
        "priority": case.priority
    }})


@app.route("/api/cases", methods=["POST"])
@jwt_required
@audit_log_action("Create Case")
def create_case():
    data = request.get_json(force=True)
    new_case = Case(
        title=data.get("title"),
        priority=data.get("priority", "medium"),
        summary=data.get("summary"),
        assignee_id=g.user.id
    )
    db.session.add(new_case)
    db.session.commit()
    g.target_override = f"Case: {new_case.title}"
    return jsonify({"id": new_case.id, "message": "Case created"}), 201

@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@jwt_required
@audit_log_action("Update Case")
def update_case(case_id):
    c = Case.query.get_or_404(case_id)
    data = request.get_json(force=True)
    
    if "status" in data:
        c.status = data["status"]
    if "priority" in data:
        c.priority = data["priority"]
    if "summary" in data:
        c.summary = data["summary"]
    if "assignee_id" in data:
        c.assignee_id = data["assignee_id"]
        
    db.session.commit()
    g.target_override = f"Case #{case_id}: {c.title}"
    return jsonify({"id": c.id, "status": c.status})

@app.route("/api/alerts/<int:alert_id>/promote", methods=["POST"])
@jwt_required
@audit_log_action("Promote Alert to Case")
def promote_to_case(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.case_id:
        return jsonify({"error": "Alert already linked to a case", "case_id": alert.case_id}), 400
    
    data = request.get_json(force=True) or {}
    new_case = Case(
        title=data.get("title", f"Investigation: {alert.title}"),
        priority=alert.severity,
        summary=f"Case promoted from Alert #{alert_id}: {alert.message}",
        due_at=datetime.now(timezone.utc) + timedelta(hours=24), # Default 24h SLA
        assignee_id=g.user.id
    )
    db.session.add(new_case)
    db.session.flush()
    
    alert.case_id = new_case.id
    db.session.commit()
    
    g.target_override = f"Case #{new_case.id} from Alert #{alert_id}"
    return jsonify({"case_id": new_case.id, "message": "Alert promoted to case"}), 201


# ──────────────────────────────────────────────────────────────────────────────
# API — THREAT INTEL
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/threat-intel", methods=["GET"])
@jwt_required
def get_threat_intel():
    indicators = ThreatIndicator.query.order_by(ThreatIndicator.created_at.desc()).all()
    return jsonify([
        {
            "id": i.id,
            "indicator_type": i.indicator_type,
            "value": i.value,
            "source": i.source,
            "severity": i.severity,
            "created_at": i.created_at.isoformat()
        } for i in indicators
    ])

@app.route("/api/threat-intel", methods=["POST"])
@jwt_required
@audit_log_action("Add Threat Indicator")
def add_threat_intel():
    data = request.get_json(force=True)
    indicator = ThreatIndicator(
        indicator_type=data.get("indicator_type", "ip"),
        value=data.get("value"),
        source=data.get("source", "manual"),
        severity=data.get("severity", "medium")
    )
    db.session.add(indicator)
    db.session.commit()
    g.target_override = f"Indicator: {indicator.value}"
    return jsonify({"id": indicator.id, "message": "Indicator added"}), 201

@app.route("/api/threat-intel/<int:id>", methods=["DELETE"])
@jwt_required
@audit_log_action("Delete Threat Indicator")
def delete_threat_intel(id):
    indicator = ThreatIndicator.query.get_or_404(id)
    db.session.delete(indicator)
    db.session.commit()
    return jsonify({"message": "Indicator deleted"})

# ──────────────────────────────────────────────────────────────────────────────
# API — DETECTION RULES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
@jwt_required
def get_rules():
    """Return all loaded rules from the rule manager (in-memory from YAML)."""
    rules = rule_manager.rules
    return jsonify([
        {
            "id": i,
            "name": r.get("name"),
            "event_type": r.get("event_type"),
            "severity": r.get("severity", "warning"),
            "mitre_tactic": r.get("mitre_tactic"),
            "mitre_technique": r.get("mitre_technique"),
            "condition": r.get("condition", {}),
            "message": r.get("message", ""),
            "is_active": r.get("is_active", True),
        }
        for i, r in enumerate(rules)
    ])

@app.route("/api/rules", methods=["POST"])
@jwt_required
@audit_log_action("Create Detection Rule")
def create_rule():
    """Add a new rule to the default_rules.yaml file and reload."""
    data = request.get_json(force=True)
    new_rule = {
        "name": data.get("name", "New Rule"),
        "event_type": data.get("event_type", "failed_login"),
        "severity": data.get("severity", "warning"),
        "mitre_tactic": data.get("mitre_tactic"),
        "mitre_technique": data.get("mitre_technique"),
        "condition": data.get("condition", {"field": "description", "operator": "contains", "value": ""}),
        "message": data.get("message", "Custom rule triggered"),
        "is_active": True,
    }

    rules_path = os.path.join(base_dir, "rules", "default_rules.yaml")
    try:
        with open(rules_path, "r") as f:
            yaml_data = yaml.safe_load(f) or {"rules": []}
        yaml_data["rules"].append(new_rule)
        with open(rules_path, "w") as f:
            yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
        rule_manager.load_rules()
        return jsonify({"message": "Rule created", "total_rules": len(rule_manager.rules)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required
@audit_log_action("Delete Detection Rule")
def delete_rule(rule_id):
    """Delete a rule by index from default_rules.yaml."""
    rules_path = os.path.join(base_dir, "rules", "default_rules.yaml")
    try:
        with open(rules_path, "r") as f:
            yaml_data = yaml.safe_load(f) or {"rules": []}
        rules = yaml_data.get("rules", [])
        if rule_id < 0 or rule_id >= len(rules):
            return jsonify({"error": "Rule not found"}), 404
        deleted = rules.pop(rule_id)
        yaml_data["rules"] = rules
        with open(rules_path, "w") as f:
            yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
        rule_manager.load_rules()
        return jsonify({"message": f"Rule '{deleted.get('name')}' deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rules/reload", methods=["POST"])
@jwt_required
def reload_rules():
    """Hot-reload all rules from YAML files."""
    rule_manager.load_rules()
    return jsonify({"message": "Rules reloaded", "total_rules": len(rule_manager.rules)})

# ──────────────────────────────────────────────────────────────────────────────
# API — PLAYBOOKS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/playbooks", methods=["GET"])
@jwt_required
def get_playbooks():
    playbooks = Playbook.query.all()
    return jsonify([
        {
            "id": p.id,
            "name": p.name,
            "actions": json.loads(p.actions) if isinstance(p.actions, str) else p.actions,
            "is_active": p.is_active,
            "created_at": p.created_at.isoformat() if p.created_at else None
        } for p in playbooks
    ])

@app.route("/api/playbooks", methods=["POST"])
@jwt_required
@audit_log_action("Create Playbook")
def create_playbook():
    data = request.get_json(force=True)
    pb = Playbook(
        name=data.get("name"),
        actions=json.dumps(data.get("actions", [])),
        is_active=data.get("is_active", True)
    )
    db.session.add(pb)
    db.session.commit()
    return jsonify({"id": pb.id, "message": "Playbook created"}), 201

@app.route("/api/playbooks/<int:pb_id>/execute/<int:alert_id>", methods=["POST"])
@jwt_required
@audit_log_action("Execute Playbook")
def execute_playbook(pb_id, alert_id):
    success = PlaybookRunner.run(pb_id, alert_id)
    if success:
        return jsonify({"message": "Playbook executed successfully"})
    return jsonify({"error": "Playbook execution failed"}), 500


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
    if request.path.startswith("/auth") or request.path.startswith("/api"):
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
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