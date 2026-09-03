import os
import re
import random
import time
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger("security_monitor.database")

# Database Connection Configuration from Environment Variables
DB_HOST = os.getenv("POSTGRES_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = int(os.getenv("POSTGRES_PORT", os.getenv("DB_PORT", "5432")))
DB_NAME = os.getenv("POSTGRES_DB", os.getenv("DB_NAME", "securepulse_db"))
DB_USER = os.getenv("POSTGRES_USER", os.getenv("DB_USER", "securepulse"))
DB_PASS = os.getenv("POSTGRES_PASSWORD", os.getenv("DB_PASS", "securepulse_pass"))
DATABASE_URL = os.getenv("DATABASE_URL")

class DictRowWrapper:
    def __init__(self, conn):
        self.conn = conn
        self.cursor = conn.cursor()
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.conn.commit()
        except Exception:
            pass
    def execute(self, query, params=None):
        query_sql = query.replace("%s", "?").replace("NOW()", "CURRENT_TIMESTAMP").replace("INTERVAL '60 minutes'", "'-60 minutes'").replace("INTERVAL '24 hours'", "'-24 hours'").replace("TRUE", "1").replace("FALSE", "0").replace("BOOLEAN", "INTEGER").replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("TIMESTAMP WITH TIME ZONE", "TIMESTAMP").replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN")
        try:
            if params is None:
                res = self.cursor.execute(query_sql)
            else:
                res = self.cursor.execute(query_sql, params)
        except Exception as e:
            if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                return None
            raise e
        if query_sql.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP")):
            try:
                self.conn.commit()
            except Exception:
                pass
        return res
    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    def fetchall(self):
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

class SQLiteConnectionWrapper:
    def __init__(self, conn):
        self.conn = conn
    def cursor(self):
        return DictRowWrapper(self.conn)
    def close(self):
        try:
            self.conn.commit()
        except Exception:
            pass
        self.conn.close()

def get_db_connection():
    """Establish and return PostgreSQL connection or fallback SQLite connection."""
    try:
        if DATABASE_URL:
            url = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=2)
        else:
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                cursor_factory=psycopg2.extras.RealDictCursor,
                connect_timeout=2
            )
        conn.autocommit = True
        return conn
    except Exception as e:
        logger.warning(f"PostgreSQL connection offline ({e}). Using local SQLite database.")
    
    try:
        db_path = os.path.join(os.path.dirname(__file__), "securepulse.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return SQLiteConnectionWrapper(conn)
    except Exception as e:
        logger.error(f"SQLite connection error: {e}")
        return None

def init_db():
    """Initialize all database tables and migrate missing columns."""
    conn = get_db_connection()
    if not conn:
        logger.warning("Could not connect to DB to initialize tables.")
        return

    try:
        with conn.cursor() as cur:
            # Users Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    hashed_password VARCHAR(512) NOT NULL,
                    role VARCHAR(64) DEFAULT 'user',
                    full_name VARCHAR(255),
                    is_admin BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Migrate missing columns in users table
            for col, col_type in [
                ("username", "VARCHAR(255)"),
                ("email", "VARCHAR(255)"),
                ("hashed_password", "VARCHAR(512)"),
                ("role", "VARCHAR(64) DEFAULT 'user'"),
                ("full_name", "VARCHAR(255)"),
                ("is_admin", "BOOLEAN DEFAULT FALSE"),
                ("is_active", "BOOLEAN DEFAULT TRUE"),
                ("created_at", "TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP")
            ]:
                try:
                    cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except Exception:
                    pass

            # Always seed/update admin user
            hashed_admin = generate_password_hash("admin")
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s;", ("admin", "admin@securepulse.local"))
            admin_row = cur.fetchone()
            if not admin_row:
                cur.execute("""
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                    VALUES (%s, %s, %s, 'admin', 'System Administrator', TRUE, TRUE, NOW());
                """, ("admin", "admin@securepulse.local", hashed_admin))
            else:
                cur.execute("""
                    UPDATE users SET username = 'admin', hashed_password = %s, role = 'admin', is_admin = TRUE, is_active = TRUE WHERE id = %s;
                """, (hashed_admin, admin_row["id"]))

            # Servers Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS servers (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255),
                    hostname VARCHAR(255) NOT NULL,
                    ip VARCHAR(64),
                    ip_address VARCHAR(64),
                    os_info VARCHAR(255),
                    agent_token VARCHAR(512),
                    api_token VARCHAR(512),
                    status VARCHAR(32) DEFAULT 'online',
                    severity VARCHAR(16) DEFAULT 'info',
                    active_users INT DEFAULT 1,
                    failed_logins INT DEFAULT 0,
                    last_sudo VARCHAR(512) DEFAULT 'None',
                    last_sudo_ago VARCHAR(64) DEFAULT 'never',
                    ssh_port INT DEFAULT 22,
                    ssh_user VARCHAR(64) DEFAULT 'ubuntu',
                    ssh_password VARCHAR(255),
                    ssh_key_path VARCHAR(255),
                    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Migrate missing columns in servers table
            for col, col_type in [
                ("name", "VARCHAR(255)"),
                ("hostname", "VARCHAR(255)"),
                ("ip", "VARCHAR(64)"),
                ("ip_address", "VARCHAR(64)"),
                ("os_info", "VARCHAR(255)"),
                ("agent_token", "VARCHAR(512)"),
                ("api_token", "VARCHAR(512)"),
                ("status", "VARCHAR(32) DEFAULT 'online'"),
                ("severity", "VARCHAR(16) DEFAULT 'info'"),
                ("active_users", "INT DEFAULT 1"),
                ("failed_logins", "INT DEFAULT 0"),
                ("last_sudo", "VARCHAR(512) DEFAULT 'None'"),
                ("last_sudo_ago", "VARCHAR(64) DEFAULT 'never'"),
                ("ssh_port", "INT DEFAULT 22"),
                ("ssh_user", "VARCHAR(64) DEFAULT 'ubuntu'"),
                ("ssh_password", "VARCHAR(255)"),
                ("ssh_key_path", "VARCHAR(255)"),
                ("last_seen", "TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"),
                ("registered_at", "TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP")
            ]:
                try:
                    cur.execute(f"ALTER TABLE servers ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except Exception:
                    pass

            # Commands Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id SERIAL PRIMARY KEY,
                    server_id INT REFERENCES servers(id) ON DELETE CASCADE,
                    username VARCHAR(64) NOT NULL,
                    command TEXT NOT NULL,
                    category VARCHAR(64) DEFAULT 'GENERAL',
                    risk_level VARCHAR(16) DEFAULT 'LOW',
                    is_sudo BOOLEAN DEFAULT FALSE,
                    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Login History Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_history (
                    id SERIAL PRIMARY KEY,
                    server_id INT REFERENCES servers(id) ON DELETE CASCADE,
                    username VARCHAR(64) NOT NULL,
                    ip_address VARCHAR(64),
                    login_type VARCHAR(32) DEFAULT 'SSH',
                    success BOOLEAN DEFAULT TRUE,
                    location VARCHAR(128) DEFAULT 'Unknown',
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Alerts Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    server_id INT REFERENCES servers(id) ON DELETE CASCADE,
                    alert_type VARCHAR(64) NOT NULL,
                    severity VARCHAR(16) DEFAULT 'warning',
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Projects Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Approvals Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(64),
                    agent_token VARCHAR(512) NOT NULL,
                    status VARCHAR(32) DEFAULT 'pending',
                    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Audit Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INT,
                    action VARCHAR(255) NOT NULL,
                    target VARCHAR(255),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Seed a default EC2 server if empty
            cur.execute("SELECT id FROM servers LIMIT 1;")
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, registered_at, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW());
                """, ("ec2-prod-web-01", "ec2-prod-web-01", "10.0.0.1", "10.0.0.1", "Ubuntu 22.04 LTS", "sp-token-12345", "sp-token-12345", "online", "info", 1, 0, "ubuntu: apt update", "2m ago"))

        conn.close()
        logger.info("Database schema initialized successfully.")
    except Exception as e:
        logger.error(f"Error during init_db: {e}")
        if conn:
            conn.close()

def categorize_command(cmd_str: str) -> str:
    """Categorize command into explicit production categories."""
    if not cmd_str:
        return "GENERAL"
    cmd = cmd_str.strip()

    if re.search(r':\(\)\s*\{\s*:\|:&\s*\};:', cmd) or ":(){:|:&};:" in cmd:
        return "FORK_BOMB"

    destructive_patterns = [
        r'rm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+/', r'rm\s+-[a-zA-Z]*f[a-zA-Z]*r\s+/',
        r'rm\s+-rf\s+\*', r'rm\s+-rf\s+/boot', r'rm\s+-rf\s+/etc', r'rm\s+-rf\s+/home/\*',
        r'rm\s+-rf\s+/root/\*', r'rm\s+-rf\s+/var/\*', r'dd\s+if=/dev/zero', r'dd\s+if=/dev/random',
        r'mkfs\.ext4', r'mkfs\.xfs', r'mkfs', r'mv\s+/bin', r'mv\s+/lib', r'mv\s+/usr',
        r'>\s*/etc/passwd', r'>\s*/etc/shadow', r'echo\s+""\s*>\s*/etc/passwd', r'echo\s+""\s*>\s*/etc/shadow'
    ]
    for pattern in destructive_patterns:
        if re.search(pattern, cmd):
            return "DESTRUCTIVE"

    perm_patterns = [
        r'chmod\s+-[a-zA-Z]*R\s+777\s+/', r'chmod\s+-[a-zA-Z]*R\s+000\s+/',
        r'chmod\s+-[a-zA-Z]*R\s+777', r'chmod\s+-[a-zA-Z]*R\s+000', r'chmod\s+777', r'chmod\s+000',
        r'chown\s+-[a-zA-Z]*R\s+nobody', r'chown\s+-[a-zA-Z]*R\s+user', r'chown\s+-R', r'chmod', r'chown'
    ]
    for pattern in perm_patterns:
        if re.search(pattern, cmd):
            return "PERM_CHANGE"

    kill_patterns = [r'kill\s+-9\s+-1', r'killall\s+-9', r'pkill\s+-9\s+ssh', r'kill\s+-9', r'killall', r'pkill']
    for pattern in kill_patterns:
        if re.search(pattern, cmd):
            return "PROCESS_KILL"

    net_patterns = [r'iptables\s+-F', r'iptables\s+-P\s+INPUT\s+DROP', r'iptables', r'ufw\s+disable']
    for pattern in net_patterns:
        if re.search(pattern, cmd):
            return "NETWORK"

    service_patterns = [r'systemctl\s+stop\s+ssh', r'systemctl\s+stop\s+network', r'systemctl\s+disable\s+ssh', r'systemctl\s+disable\s+networking', r'systemctl\s+stop']
    for pattern in service_patterns:
        if re.search(pattern, cmd):
            return "SERVICE_STOP"

    reboot_patterns = [r'reboot\s+-f', r'shutdown\s+-h\s+now', r'reboot', r'shutdown']
    for pattern in reboot_patterns:
        if re.search(pattern, cmd):
            return "REBOOT"

    history_patterns = [r'history\s+-c', r'crontab\s+-r']
    for pattern in history_patterns:
        if re.search(pattern, cmd):
            return "HISTORY"

    disk_patterns = [r'yes\s*>\s*/dev/null', r'cat\s+/dev/zero', r'ulimit\s+-n\s+1']
    for pattern in disk_patterns:
        if re.search(pattern, cmd):
            return "DISK"

    kernel_patterns = [r'echo\s+b\s*>\s*/proc/sysrq-trigger', r'echo\s+1\s*>\s*/proc/sys/kernel/sysrq']
    for pattern in kernel_patterns:
        if re.search(pattern, cmd):
            return "KERNEL"

    return "GENERAL"

def log_alert(server_id: int, alert_type: str, message: str, severity: str = "warning"):
    """Log alert with 60-minute deduplication."""
    conn = get_db_connection()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM alerts
                WHERE server_id = %s AND alert_type = %s AND message = %s
                  AND created_at >= NOW() - INTERVAL '60 minutes';
            """, (server_id, alert_type, message))
            if cur.fetchone():
                return
            title = f"{alert_type.replace('_', ' ').title()} Alert"
            cur.execute("""
                INSERT INTO alerts (server_id, alert_type, severity, title, message, is_resolved, created_at)
                VALUES (%s, %s, %s, %s, %s, FALSE, NOW());
            """, (server_id, alert_type, severity, title, message))
    except Exception as e:
        logger.error(f"Error in log_alert: {e}")
    finally:
        conn.close()

def save_agent_data(server_id: int, data: dict):
    """Save agent telemetry with command deduplication and last_sudo update."""
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            last_sudo_val = data.get("last_sudo")
            last_sudo_ago_val = data.get("last_sudo_ago", "just now")

            if not last_sudo_val and data.get("sudo_cmds"):
                last_cmd = data["sudo_cmds"][-1]
                if isinstance(last_cmd, dict):
                    last_sudo_val = f"{last_cmd.get('user', 'ubuntu')}: {last_cmd.get('cmd', last_cmd.get('command', ''))}"
                    last_sudo_ago_val = last_cmd.get("ago", "just now")

            if last_sudo_val:
                cur.execute("""
                    UPDATE servers
                    SET last_seen = NOW(), status = 'online', last_sudo = %s, last_sudo_ago = %s
                    WHERE id = %s;
                """, (last_sudo_val, last_sudo_ago_val, server_id))
            else:
                cur.execute("UPDATE servers SET last_seen = NOW(), status = 'online' WHERE id = %s;", (server_id,))

            commands = data.get("commands", [])
            if isinstance(data.get("sudo_logs"), list):
                commands.extend(data.get("sudo_logs", []))
            if isinstance(data.get("sudo_cmds"), list):
                commands.extend(data.get("sudo_cmds", []))

            for cmd_obj in commands:
                username = cmd_obj.get("user", cmd_obj.get("username", "root"))
                cmd_str = cmd_obj.get("command", cmd_obj.get("cmd", ""))
                is_sudo = cmd_obj.get("is_sudo", True if "sudo" in cmd_str.lower() or "sudo_cmds" in data else False)

                if not cmd_str:
                    continue

                category = categorize_command(cmd_str)
                risk_level = "CRITICAL" if category in ["DESTRUCTIVE", "PERM_CHANGE", "KERNEL", "FORK_BOMB"] else (
                    "HIGH" if category in ["PROCESS_KILL", "SERVICE_STOP", "REBOOT", "NETWORK"] else "LOW"
                )

                cur.execute("""
                    SELECT id FROM commands
                    WHERE server_id = %s AND username = %s AND command = %s
                      AND executed_at >= NOW() - INTERVAL '60 minutes';
                """, (server_id, username, cmd_str))
                
                if not cur.fetchone():
                    cur.execute("""
                        INSERT INTO commands (server_id, username, command, category, risk_level, is_sudo, executed_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW());
                    """, (server_id, username, cmd_str, category, risk_level, is_sudo))

                    if category in ["PERM_CHANGE", "DESTRUCTIVE"] or "chmod" in cmd_str or "chown" in cmd_str:
                        alert_msg = f"Dangerous command ({category}) executed by {username}: {cmd_str}"
                        log_alert(server_id, category, alert_msg, severity="critical")

        return True
    except Exception as e:
        logger.error(f"Error in save_agent_data: {e}")
        return False
    finally:
        conn.close()

def get_server_counts():
    """Return counts dict: {"total": N, "secure": N, "warning": N, "critical": N}."""
    conn = get_db_connection()
    counts = {"total": 0, "secure": 0, "warning": 0, "critical": 0}
    if not conn:
        return counts
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT COUNT(*) as total FROM servers;")
                row = cur.fetchone()
                counts["total"] = row.get("total", 0) if isinstance(row, dict) else (row[0] if row else 0)
            except Exception:
                counts["total"] = 0

            try:
                cur.execute("SELECT COUNT(*) as critical FROM servers WHERE severity = 'critical';")
                row = cur.fetchone()
                counts["critical"] = row.get("critical", 0) if isinstance(row, dict) else (row[0] if row else 0)
            except Exception:
                counts["critical"] = 0

            try:
                cur.execute("SELECT COUNT(*) as warning FROM servers WHERE severity = 'warning';")
                row = cur.fetchone()
                counts["warning"] = row.get("warning", 0) if isinstance(row, dict) else (row[0] if row else 0)
            except Exception:
                counts["warning"] = 0

            counts["secure"] = max(0, counts["total"] - counts["critical"] - counts["warning"])
        return counts
    except Exception as e:
        logger.error(f"Error in get_server_counts: {e}")
        return counts
    finally:
        conn.close()

def get_servers():
    """Fetch all servers including name, ip, last_sudo, and last_sudo_ago."""
    conn = get_db_connection()
    fallback_server = {
        "id": 1,
        "name": "ip-172-31-4-83",
        "hostname": "ip-172-31-4-83",
        "ip": "172.31.4.83",
        "ip_address": "172.31.4.83",
        "status": "online",
        "severity": "info",
        "active_users": 1,
        "failed_logins": 0,
        "last_sudo": "None",
        "last_sudo_ago": "just now",
        "last_seen": datetime.now().isoformat(),
        "registered_at": datetime.now().isoformat()
    }
    servers = []
    if not conn:
        return [fallback_server]
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM servers ORDER BY id ASC;")
            rows = cur.fetchall()
            for row in rows:
                try:
                    s = dict(row)
                    s["id"] = s.get("id", 1)
                    s["name"] = s.get("name") or s.get("hostname") or "ec2-server"
                    s["hostname"] = s.get("hostname") or s.get("name") or "ec2-server"
                    s["ip"] = s.get("ip") or s.get("ip_address") or "127.0.0.1"
                    s["ip_address"] = s.get("ip_address") or s.get("ip") or "127.0.0.1"
                    s["status"] = (s.get("status") or "online").lower()
                    s["severity"] = (s.get("severity") or "info").lower()
                    s["active_users"] = s.get("active_users", 1)
                    s["failed_logins"] = s.get("failed_logins", 0)
                    s["api_token"] = s.get("api_token") or s.get("agent_token") or "sp-token-12345"

                    try:
                        if not s.get("last_sudo") or s.get("last_sudo") == "None":
                            cur.execute("""
                                SELECT username, command, executed_at
                                FROM commands
                                WHERE server_id = %s AND is_sudo = TRUE
                                ORDER BY executed_at DESC LIMIT 1;
                            """, (s["id"],))
                            rec = cur.fetchone()
                            if rec:
                                rec_dict = dict(rec)
                                s["last_sudo"] = f"{rec_dict.get('username')}: {rec_dict.get('command')}"
                                s["last_sudo_ago"] = format_time_ago(rec_dict.get("executed_at"))
                            else:
                                s["last_sudo"] = "None"
                                s["last_sudo_ago"] = "never"
                    except Exception:
                        s["last_sudo"] = "None"
                        s["last_sudo_ago"] = "never"

                    servers.append(s)
                except Exception as e:
                    logger.error(f"Error parsing server row: {e}")

            if not servers:
                try:
                    cur.execute("""
                        INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, registered_at, last_seen)
                        VALUES ('ip-172-31-4-83', 'ip-172-31-4-83', '172.31.4.83', '172.31.4.83', 'Linux (Ubuntu)', 'sp-token-default', 'sp-token-default', 'online', 'info', 1, 0, 'None', 'never', NOW(), NOW());
                    """)
                    cur.execute("SELECT * FROM servers ORDER BY id ASC;")
                    rows = cur.fetchall()
                    for row in rows:
                        s = dict(row)
                        s["id"] = s.get("id", 1)
                        s["name"] = s.get("name") or s.get("hostname") or "ip-172-31-4-83"
                        s["hostname"] = s.get("hostname") or s.get("name") or "ip-172-31-4-83"
                        s["ip"] = s.get("ip") or s.get("ip_address") or "172.31.4.83"
                        s["ip_address"] = s.get("ip_address") or s.get("ip") or "172.31.4.83"
                        s["status"] = (s.get("status") or "online").lower()
                        s["severity"] = (s.get("severity") or "info").lower()
                        servers.append(s)
                except Exception as ex:
                    logger.error(f"Error seeding fallback server: {ex}")
                    servers.append(fallback_server)

        return servers if servers else [fallback_server]
    except Exception as e:
        logger.error(f"Error in get_servers: {e}")
        return [fallback_server]
    finally:
        conn.close()

def get_server_by_id(server_id: int):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM servers WHERE id = %s;", (server_id,))
            row = cur.fetchone()
            if not row:
                return None
            s = dict(row)
            s["name"] = s.get("name") or s.get("hostname")
            s["ip"] = s.get("ip") or s.get("ip_address")
            s["api_token"] = s.get("api_token") or s.get("agent_token") or "sp-token-12345"
            return s
    except Exception as e:
        logger.error(f"Error in get_server_by_id: {e}")
        return None
    finally:
        conn.close()

def add_server(name: str, ip: str, region: str = "", region_code: str = ""):
    conn = get_db_connection()
    if not conn:
        return 1
    try:
        token = f"sp-token-{int(time.time())}-{random.randint(1000, 9999)}"
        with conn.cursor() as cur:
            # Check if server already exists by name, hostname, or IP
            try:
                cur.execute("SELECT id FROM servers WHERE hostname = %s OR name = %s OR ip = %s OR ip_address = %s LIMIT 1;", (name, name, ip, ip))
                row = cur.fetchone()
                if row:
                    sid = row["id"] if isinstance(row, dict) else row[0]
                    cur.execute("UPDATE servers SET status = 'online', severity = 'info', last_seen = NOW() WHERE id = %s;", (sid,))
                    return sid
            except Exception as e:
                logger.warning(f"Error checking existing server: {e}")

            # Insert into approvals as APPROVED directly
            try:
                cur.execute("""
                    INSERT INTO approvals (hostname, ip_address, agent_token, status, requested_at)
                    VALUES (%s, %s, %s, 'approved', NOW());
                """, (name, ip, token))
            except Exception as e:
                logger.warning(f"Approvals insert error: {e}")
            
            # Insert into servers with full fields populated
            try:
                cur.execute("""
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, registered_at, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'online', 'info', 1, 0, 'None', 'never', NOW(), NOW());
                """, (name, name, ip, ip, "Linux (Ubuntu)", token, token))
            except Exception as e:
                logger.error(f"Error inserting server: {e}")
            
            try:
                cur.execute("SELECT id FROM servers WHERE hostname = %s OR name = %s ORDER BY id DESC LIMIT 1;", (name, name))
                row = cur.fetchone()
                if row:
                    return row["id"] if isinstance(row, dict) else row[0]
            except Exception:
                pass
            return 1
    except Exception as e:
        logger.error(f"Error in add_server: {e}")
        return 1
    finally:
        conn.close()

def delete_server(server_id: int):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM servers WHERE id = %s;", (server_id,))
        return True
    except Exception as e:
        logger.error(f"Error in delete_server: {e}")
        return False
    finally:
        conn.close()

def get_tracking_data(server_id: int):
    conn = get_db_connection()
    logs = []
    if not conn:
        return logs
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM login_history WHERE server_id = %s ORDER BY timestamp DESC LIMIT 100;", (server_id,))
            for r in cur.fetchall():
                item = dict(r)
                item["timestamp_formatted"] = format_time_ago(item["timestamp"])
                item["user"] = item.get("username")
                item["ip"] = item.get("ip_address")
                logs.append(item)
        return logs
    except Exception as e:
        logger.error(f"Error in get_tracking_data: {e}")
        return logs
    finally:
        conn.close()

def get_server_commands(server_id: int):
    conn = get_db_connection()
    cmds = []
    if not conn:
        return cmds
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM commands WHERE server_id = %s ORDER BY executed_at DESC LIMIT 100;", (server_id,))
            for r in cur.fetchall():
                item = dict(r)
                item["executed_at_ago"] = format_time_ago(item["executed_at"])
                item["cmd"] = item.get("command")
                item["user"] = item.get("username")
                cmds.append(item)
        return cmds
    except Exception as e:
        logger.error(f"Error in get_server_commands: {e}")
        return cmds
    finally:
        conn.close()

def get_alerts():
    conn = get_db_connection()
    alerts = []
    if not conn:
        return alerts
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT a.*, s.hostname FROM alerts a LEFT JOIN servers s ON a.server_id = s.id ORDER BY a.created_at DESC LIMIT 100;")
            for r in cur.fetchall():
                item = dict(r)
                item["created_at_ago"] = format_time_ago(item["created_at"])
                alerts.append(item)
        return alerts
    except Exception as e:
        logger.error(f"Error in get_alerts: {e}")
        return alerts
    finally:
        conn.close()

def get_login_status_per_user(server_id: int) -> dict:
    conn = get_db_connection()
    result = {}
    if not conn:
        return result
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT username, success, COUNT(*) as count
                FROM login_history
                WHERE server_id = %s AND timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY username, success;
            """, (server_id,))
            for r in cur.fetchall():
                user = r["username"]
                if user not in result:
                    result[user] = {"success": 0, "failed": 0}
                if r["success"]:
                    result[user]["success"] += r["count"]
                else:
                    result[user]["failed"] += r["count"]
        return result
    except Exception as e:
        logger.error(f"Error in get_login_status_per_user: {e}")
        return result
    finally:
        conn.close()

def format_time_ago(dt):
    if not dt:
        return "never"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except Exception:
            return dt
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    elif seconds < 3600:
        return f"{seconds // 60}m ago"
    elif seconds < 86400:
        return f"{seconds // 3600}h ago"
    else:
        return f"{seconds // 86400}d ago"
