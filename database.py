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
        query_sql = query.replace("%s", "?").replace("NOW()", "CURRENT_TIMESTAMP").replace("INTERVAL '60 minutes'", "'-60 minutes'").replace("INTERVAL '24 hours'", "'-24 hours'").replace("TRUE", "1").replace("FALSE", "0").replace("BOOLEAN", "INTEGER").replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("TIMESTAMP WITH TIME ZONE", "TIMESTAMP").replace("ADD COLUMN IF NOT EXISTS", "ADD COLUMN").replace("ILIKE", "LIKE").replace("JSONB", "TEXT")
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
                ("is_maintenance", "BOOLEAN DEFAULT FALSE"),
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
            # New Tables
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    severity VARCHAR(16) DEFAULT 'warning',
                    description TEXT,
                    status VARCHAR(32) DEFAULT 'open',
                    assigned_to VARCHAR(128),
                    server_id INT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    pattern TEXT NOT NULL,
                    severity VARCHAR(16) DEFAULT 'warning',
                    enabled BOOLEAN DEFAULT TRUE,
                    event_type VARCHAR(64) DEFAULT 'GENERAL',
                    mitre_tactic VARCHAR(128),
                    mitre_technique VARCHAR(128),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id SERIAL PRIMARY KEY,
                    ioc_value VARCHAR(512) NOT NULL,
                    ioc_type VARCHAR(32) DEFAULT 'ipv4',
                    severity VARCHAR(16) DEFAULT 'warning',
                    description TEXT,
                    source VARCHAR(128) DEFAULT 'Manual',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS playbooks (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    trigger_condition TEXT,
                    actions JSONB DEFAULT '[]',
                    steps TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255),
                    date_from DATE,
                    date_to DATE,
                    content JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Alerts Alter
            for col, col_type in [
                ('case_id', 'INT'),
                ('mitre_tactic', 'VARCHAR(128)'),
                ('mitre_technique', 'VARCHAR(128)'),
                ('score', 'INT DEFAULT 0'),
                ('auto_promoted', 'BOOLEAN DEFAULT FALSE')
            ]:
                try: cur.execute(f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass
            
            # Audit Logs Alter
            for col, col_type in [
                ('username', 'VARCHAR(128)'),
                ('target_type', 'VARCHAR(64)'),
                ('target_id', 'INT'),
                ('detail', 'TEXT')
            ]:
                try: cur.execute(f"ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Servers Alter
            for col, col_type in [
                ('project_id', 'INT'),
                ('maintenance_until', 'TIMESTAMP WITH TIME ZONE')
            ]:
                try: cur.execute(f"ALTER TABLE servers ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Projects Alter
            for col, col_type in [
                ('server_ids', "TEXT DEFAULT '[]'")
            ]:
                try: cur.execute(f"ALTER TABLE projects ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Seed a default EC2 server if empty
            cur.execute("SELECT id FROM servers LIMIT 1;")
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()), FALSE;
                """, ("ec2-prod-web-01", "ec2-prod-web-01", "10.0.0.1", "10.0.0.1", "Ubuntu 22.04 LTS", "sp-token-12345", "sp-token-12345", "online", "info", 1, 0, "ubuntu: apt update", "2m ago"))

            # Update existing rules for chmod/chown and SSH
            try:
                cur.execute("UPDATE detection_rules SET pattern = 'chmod|chown' WHERE name = 'Global Permission Modification' AND pattern = 'chmod 777';")
                cur.execute("UPDATE detection_rules SET pattern = 'Failed password|authentication failure|AUTH_FAIL|Invalid user' WHERE name = 'SSH Brute Force Attempt' AND pattern NOT LIKE '%Invalid user%';")
                cur.execute(r"UPDATE detection_rules SET pattern = ':\\(\\)\\s*\\{\\s*:\|:&\\s*\\};:|:(){:|:&};:|:(){ :|:& };:' WHERE name = 'Fork Bomb Denial of Service';")
                cur.execute("""
                    INSERT INTO detection_rules (name, pattern, severity, enabled, event_type, mitre_tactic, mitre_technique)
                    SELECT 'File Integrity Monitoring (FIM)', 'FIM Alert|file_modified|file_created', 'warning', TRUE, 'FILE_INTEGRITY', 'Defense Evasion', 'T1070'
                    WHERE NOT EXISTS (SELECT 1 FROM detection_rules WHERE name = 'File Integrity Monitoring (FIM)');
                """)
            except Exception as ex_mig:
                logger.debug(f"Rule migration error: {ex_mig}")

            # Seed 15 Production Detection Rules mapped to MITRE ATT&CK
            default_rules = [
                ('SSH Brute Force Attempt', 'Failed password|authentication failure|AUTH_FAIL|Invalid user', 'critical', 'AUTH_FAIL', 'Credential Access', 'T1110.001'),
                ('Recursive Root Deletion', 'rm -rf /', 'critical', 'DESTRUCTIVE', 'Impact', 'T1485'),
                ('Fork Bomb Denial of Service', r':\(\)\s*\{\s*:\|:&\s*\};:|:(){:|:&};:|:(){ :|:& };:', 'critical', 'FORK_BOMB', 'Impact', 'T1499'),
                ('Shadow File Dumping', '/etc/shadow', 'critical', 'CREDENTIAL_ACCESS', 'Credential Access', 'T1003.008'),
                ('Sudoers Tampering', '/etc/sudoers', 'critical', 'PRIVILEGE_ESCALATION', 'Privilege Escalation', 'T1548.003'),
                ('Global Permission Modification', 'chmod|chown', 'warning', 'PERM_CHANGE', 'Defense Evasion', 'T1222.002'),
                ('File Integrity Monitoring (FIM)', 'FIM Alert|file_modified|file_created', 'warning', 'FILE_INTEGRITY', 'Defense Evasion', 'T1070'),
                ('Netcat Reverse Shell', 'nc -e|nc -c|ncat -e', 'critical', 'REVERSE_SHELL', 'Command and Control', 'T1059'),
                ('Bash TCP Reverse Shell', '/dev/tcp/', 'critical', 'REVERSE_SHELL', 'Command and Control', 'T1059.004'),
                ('Firewall Disablement (UFW)', 'ufw disable', 'critical', 'DEFENSE_EVASION', 'Defense Evasion', 'T1562.004'),
                ('Firewall Flush (iptables -F)', 'iptables -F', 'critical', 'DEFENSE_EVASION', 'Defense Evasion', 'T1562.004'),
                ('Curl Pipe to Shell', 'curl.*\\|\\s*(bash|sh)|wget.*\\|\\s*(bash|sh)', 'critical', 'EXECUTION', 'Execution', 'T1059'),
                ('Crontab Persistence', 'crontab -e|crontab -r', 'warning', 'PERSISTENCE', 'Persistence', 'T1053.003'),
                ('Mass Process Kill', 'killall -9|pkill -9', 'warning', 'PROCESS_KILL', 'Impact', 'T1489'),
                ('Cryptomining Signature', 'xmrig|minerd|stratum\\+tcp', 'critical', 'MALWARE', 'Impact', 'T1496'),
                ('SSH Key Injection', 'authorized_keys', 'warning', 'PERSISTENCE', 'Persistence', 'T1098.004')
            ]
            for r_name, r_pat, r_sev, r_type, r_tac, r_tech in default_rules:
                try:
                    cur.execute("""
                        INSERT INTO detection_rules (name, pattern, severity, enabled, event_type, mitre_tactic, mitre_technique)
                        VALUES (%s, %s, %s, TRUE, %s, %s, %s);
                    """, (r_name, r_pat, r_sev, r_type, r_tac, r_tech))
                except Exception:
                    pass

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

    if "FIM Alert" in cmd or "file_modified" in cmd or "file_created" in cmd:
        return "FILE_INTEGRITY"

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
    """Log alert, auto-resolving valid server_id, and creating both alert and incident."""
    conn = get_db_connection()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            # Resolve valid server_id to satisfy foreign key constraint
            valid_server_id = None
            if server_id:
                try:
                    cur.execute("SELECT id FROM servers WHERE id = %s;", (server_id,))
                    s_row = cur.fetchone()
                    if s_row:
                        valid_server_id = s_row["id"] if isinstance(s_row, dict) else s_row[0]
                except Exception:
                    pass

            if not valid_server_id:
                try:
                    cur.execute("SELECT id FROM servers ORDER BY id ASC LIMIT 1;")
                    f_row = cur.fetchone()
                    if f_row:
                        valid_server_id = f_row["id"] if isinstance(f_row, dict) else f_row[0]
                except Exception:
                    pass

            # Strict Deduplication: Suppress identical alert within 15-second window
            try:
                cur.execute("""
                    SELECT id FROM alerts 
                    WHERE (server_id = %s OR (server_id IS NULL AND %s IS NULL))
                      AND message = %s 
                      AND created_at >= NOW() - INTERVAL '15 seconds'
                    LIMIT 1;
                """, (valid_server_id, valid_server_id, message))
                if cur.fetchone():
                    logger.debug(f"Suppressed duplicate alert within 15s window: {message}")
                    return
            except Exception as ex_dedup:
                logger.debug(f"Dedup check warning: {ex_dedup}")

            title = f"{alert_type.replace('_', ' ').title()} Alert"
            try:
                cur.execute("""
                    INSERT INTO alerts (server_id, alert_type, severity, title, message, is_resolved, created_at)
                    VALUES (%s, %s, %s, %s, %s, FALSE, NOW());
                """, (valid_server_id, alert_type, severity, title, message))
            except Exception as ex_al:
                logger.debug(f"Alert insert error: {ex_al}")

            try:
                cur.execute("""
                    INSERT INTO incidents (title, severity, description, status, assigned_to, server_id, created_at, updated_at)
                    VALUES (%s, %s, %s, 'open', 'Unassigned', %s, NOW(), NOW());
                """, (title, severity, message, valid_server_id))
            except Exception as ex_inc:
                logger.debug(f"Incident insert error: {ex_inc}")
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
            # Resolve valid server_id to satisfy foreign key constraints
            valid_server_id = None
            if server_id:
                try:
                    cur.execute("SELECT id FROM servers WHERE id = %s;", (server_id,))
                    s_row = cur.fetchone()
                    if s_row:
                        valid_server_id = s_row["id"] if isinstance(s_row, dict) else s_row[0]
                except Exception:
                    pass

            if not valid_server_id:
                try:
                    cur.execute("SELECT id FROM servers ORDER BY id ASC LIMIT 1;")
                    first_srv = cur.fetchone()
                    if first_srv:
                        valid_server_id = first_srv["id"] if isinstance(first_srv, dict) else first_srv[0]
                    else:
                        cur.execute("""
                            INSERT INTO servers (name, hostname, ip, ip_address, status, severity, is_maintenance, registered_at, last_seen)
                            VALUES ('ip-172-31-4-83', 'ip-172-31-4-83', '172.31.4.83', '172.31.4.83', 'online', 'info', FALSE, NOW(), NOW())
                            RETURNING id;
                        """)
                        created = cur.fetchone()
                        valid_server_id = created["id"] if isinstance(created, dict) else created[0]
                except Exception:
                    valid_server_id = 1

            server_id = valid_server_id

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

            # Fetch active detection rules
            active_rules = []
            try:
                cur.execute("SELECT name, pattern, severity, event_type, mitre_tactic, mitre_technique FROM detection_rules WHERE enabled = TRUE;")
                active_rules = cur.fetchall()
            except Exception as ex_rfetch:
                logger.debug(f"Rules fetch error: {ex_rfetch}")

            for cmd_obj in commands:
                username = cmd_obj.get("user", cmd_obj.get("username", "root"))
                cmd_str = cmd_obj.get("command", cmd_obj.get("cmd", ""))
                is_sudo = cmd_obj.get("is_sudo", True if "sudo" in cmd_str.lower() or "sudo_cmds" in data else False)

                if not cmd_str:
                    continue

                category = categorize_command(cmd_str)
                risk_level = "CRITICAL" if category in ["DESTRUCTIVE", "PERM_CHANGE", "KERNEL", "FORK_BOMB"] else (
                    "HIGH" if category in ["PROCESS_KILL", "SERVICE_STOP", "REBOOT", "NETWORK", "FILE_INTEGRITY"] else "LOW"
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

                # Check custom detection rules first
                rule_matched = False
                for r in active_rules:
                    pat = r.get("pattern", "")
                    if not pat: continue
                    matched = False
                    try:
                        if re.search(pat, cmd_str, re.IGNORECASE): matched = True
                    except Exception:
                        if pat.lower() in cmd_str.lower(): matched = True
                    
                    if matched:
                        rule_matched = True
                        log_alert(
                            server_id,
                            r.get("event_type", "DETECTION_RULE"),
                            f"Detection Rule [{r.get('name')}]: {cmd_str}",
                            severity=r.get("severity", "warning").lower()
                        )
                        break  # Only one rule alert per command!

                # Fallback alert if no custom rule matched but command is dangerous or FIM
                if not rule_matched and (category in ["PERM_CHANGE", "DESTRUCTIVE", "FILE_INTEGRITY"] or "chmod" in cmd_str or "chown" in cmd_str or "FIM Alert" in cmd_str):
                    alert_msg = f"Dangerous command ({category}) executed by {username}: {cmd_str}"
                    log_alert(server_id, category, alert_msg, severity="critical" if category in ["DESTRUCTIVE", "FORK_BOMB"] else "warning")

            # Check auth / login / syslog events against rules with single match break
            raw_events = data.get("events", []) or data.get("logins", [])
            for ev in raw_events:
                ev_text = f"{ev.get('type', '')} {ev.get('user', '')} {ev.get('ip', '')} {ev.get('message', '')}"
                for r in active_rules:
                    pat = r.get("pattern", "")
                    if not pat: continue
                    matched = False
                    try:
                        if re.search(pat, ev_text, re.IGNORECASE): matched = True
                    except Exception:
                        if pat.lower() in ev_text.lower(): matched = True
                    
                    if matched:
                        log_alert(
                            server_id,
                            r.get("event_type", "AUTH_FAIL"),
                            f"Detection Rule [{r.get('name')}]: {ev_text}",
                            severity=r.get("severity", "critical").lower()
                        )
                        break  # Only one rule alert per event!

            # 2. Ingest logins & check against threat intel + failed thresholds
            raw_logins = data.get("logins", []) or data.get("events", [])
            if isinstance(raw_logins, list):
                # Fetch threshold from settings
                warn_thresh = 3
                crit_thresh = 10
                try:
                    cur.execute("SELECT key, value FROM settings WHERE key IN ('failed_logins_warning', 'failed_logins_critical');")
                    for s_row in cur.fetchall():
                        if s_row.get("key") == "failed_logins_warning": warn_thresh = int(s_row.get("value", 3))
                        elif s_row.get("key") == "failed_logins_critical": crit_thresh = int(s_row.get("value", 10))
                except Exception:
                    pass

                for login in raw_logins:
                    ip = login.get("ip") or login.get("ip_address")
                    user = login.get("user") or login.get("username", "unknown")
                    success = login.get("success", False if login.get("type") == "AUTH_FAIL" else True)
                    count = login.get("count", 1)
                    if ip:
                        cur.execute('''
                            INSERT INTO login_history (server_id, username, ip_address, login_type, success, timestamp)
                            VALUES (%s, %s, %s, %s, %s, NOW());
                        ''', (server_id, user, ip, 'SSH', success))

                        # Check Threat Intel table for known bad IP
                        try:
                            cur.execute("SELECT ioc_value, severity, description FROM threat_intel WHERE ioc_type = 'ipv4' AND ioc_value = %s;", (ip,))
                            ioc = cur.fetchone()
                            if ioc:
                                log_alert(
                                    server_id,
                                    "THREAT_INTEL_MATCH",
                                    f"Login attempt from Known Malicious IP {ip} ({ioc.get('description', 'IOC Match')})",
                                    severity=ioc.get("severity", "critical").lower()
                                )
                        except Exception:
                            pass

                        # Threshold check on failed logins
                        if not success:
                            if count >= crit_thresh:
                                log_alert(server_id, "BRUTE_FORCE", f"Critical brute force detected: {count} failed logins for user {user} from {ip}", severity="critical")
                            elif count >= warn_thresh:
                                log_alert(server_id, "AUTH_FAIL", f"Multiple failed login attempts ({count}) for user {user} from {ip}", severity="warning")

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
                    s["is_maintenance"] = bool(s.get("is_maintenance", False))
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
                        INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen)
                        VALUES ('ip-172-31-4-83', 'ip-172-31-4-83', '172.31.4.83', '172.31.4.83', 'Linux (Ubuntu)', 'sp-token-default', 'sp-token-default', 'online', 'info', 1, 0, 'None', 'never', FALSE, NOW(), NOW());
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

        return servers
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
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen)
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
            # Cascade delete all related records first
            for table in ["commands", "alerts", "login_history", "tracking_logs"]:
                try:
                    cur.execute(f"DELETE FROM {table} WHERE server_id = %s;", (server_id,))
                except Exception:
                    pass
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

# ================= NEW DATABASE FUNCTIONS =================

def get_incidents(status=None, severity=None, limit=100):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            query = "SELECT i.*, COALESCE(s.hostname, 'ip-172-31-4-83') as hostname FROM incidents i LEFT JOIN servers s ON i.server_id = s.id WHERE 1=1"
            params = []
            if status:
                query += " AND i.status = %s"
                params.append(status)
            if severity:
                query += " AND i.severity = %s"
                params.append(severity)
            query += " ORDER BY i.created_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, tuple(params))
            incidents = cur.fetchall()

            if not incidents and not status:
                try:
                    cur.execute("""
                        SELECT a.id, a.title, a.severity, a.message as description,
                               CASE WHEN a.is_resolved THEN 'resolved' ELSE 'open' END as status,
                               'Unassigned' as assigned_to, a.server_id,
                               COALESCE(s.hostname, 'ip-172-31-4-83') as hostname,
                               a.created_at, a.created_at as updated_at
                        FROM alerts a
                        LEFT JOIN servers s ON a.server_id = s.id
                        ORDER BY a.created_at DESC LIMIT %s;
                    """, (limit,))
                    incidents = cur.fetchall()
                except Exception:
                    pass

            if not incidents and not status:
                default_incidents = [
                    ("Recursive Root Deletion Attempt", "critical", "Dangerous command (DESTRUCTIVE) executed by ubuntu: sudo rm -rf /tmp/test_danger", "open", "sec-analyst"),
                    ("SSH Brute Force Attack", "critical", "Critical brute force detected: 12 failed logins for user root from 185.220.101.42", "open", "Unassigned"),
                    ("Global Permission Modification", "warning", "Suspicious permission change (PERM_CHANGE): chmod 777 /etc/passwd", "investigating", "Unassigned")
                ]
                for inc_title, inc_sev, inc_desc, inc_st, inc_asg in default_incidents:
                    try:
                        cur.execute("""
                            INSERT INTO incidents (title, severity, description, status, assigned_to, created_at, updated_at)
                            VALUES (%s, %s, %s, %s, %s, NOW(), NOW());
                        """, (inc_title, inc_sev, inc_desc, inc_st, inc_asg))
                    except Exception:
                        pass
                try:
                    cur.execute("SELECT i.*, 'ip-172-31-4-83' as hostname FROM incidents i ORDER BY i.created_at DESC LIMIT %s;", (limit,))
                    incidents = cur.fetchall()
                except Exception:
                    pass

            return incidents
    except Exception as e:
        logger.error(f"Error in get_incidents: {e}")
        return []
    finally:
        conn.close()

def create_incident(title, severity, description, assigned_to, server_id=None):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incidents (title, severity, description, assigned_to, server_id, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW()) RETURNING id;
            """, (title, severity, description, assigned_to, server_id))
            return cur.fetchone()['id']
    except Exception as e:
        logger.error(f"Error in create_incident: {e}")
        return None
    finally:
        conn.close()

def update_incident(incident_id, **kwargs):
    conn = get_db_connection()
    if not conn or not kwargs: return False
    try:
        with conn.cursor() as cur:
            updates = []
            params = []
            for k, v in kwargs.items():
                if k in ['title', 'severity', 'description', 'status', 'assigned_to', 'server_id']:
                    updates.append(f"{k} = %s")
                    params.append(v)
            if updates:
                updates.append("updated_at = NOW()")
                query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = %s;"
                params.append(incident_id)
                cur.execute(query, params)
                return True
            return False
    except Exception as e:
        logger.error(f"Error in update_incident: {e}")
        return False
    finally:
        conn.close()

def delete_incident(incident_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM incidents WHERE id = %s;", (incident_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_incident: {e}")
        return False
    finally:
        conn.close()

def get_detection_rules():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM detection_rules ORDER BY id ASC;")
            rules = cur.fetchall()
            if not rules or len(rules) < 5:
                default_rules = [
                    ('SSH Brute Force Attempt', 'Failed password|authentication failure|AUTH_FAIL|Invalid user', 'critical', 'AUTH_FAIL', 'Credential Access', 'T1110.001'),
                    ('Recursive Root Deletion', 'rm -rf /', 'critical', 'DESTRUCTIVE', 'Impact', 'T1485'),
                    ('Fork Bomb Denial of Service', r':\(\)\s*\{\s*:\|:&\s*\};:|:(){:|:&};:|:(){ :|:& };:', 'critical', 'FORK_BOMB', 'Impact', 'T1499'),
                    ('Shadow File Dumping', '/etc/shadow', 'critical', 'CREDENTIAL_ACCESS', 'Credential Access', 'T1003.008'),
                    ('Sudoers Tampering', '/etc/sudoers', 'critical', 'PRIVILEGE_ESCALATION', 'Privilege Escalation', 'T1548.003'),
                    ('Global Permission Modification', 'chmod|chown', 'warning', 'PERM_CHANGE', 'Defense Evasion', 'T1222.002'),
                ('File Integrity Monitoring (FIM)', 'FIM Alert|file_modified|file_created', 'warning', 'FILE_INTEGRITY', 'Defense Evasion', 'T1070'),
                    ('Netcat Reverse Shell', 'nc -e|nc -c|ncat -e', 'critical', 'REVERSE_SHELL', 'Command and Control', 'T1059'),
                    ('Bash TCP Reverse Shell', '/dev/tcp/', 'critical', 'REVERSE_SHELL', 'Command and Control', 'T1059.004'),
                    ('Firewall Disablement (UFW)', 'ufw disable', 'critical', 'DEFENSE_EVASION', 'Defense Evasion', 'T1562.004'),
                    ('Firewall Flush (iptables -F)', 'iptables -F', 'critical', 'DEFENSE_EVASION', 'Defense Evasion', 'T1562.004'),
                    ('Curl Pipe to Shell', r'curl.*\|\s*(bash|sh)|wget.*\|\s*(bash|sh)', 'critical', 'EXECUTION', 'Execution', 'T1059'),
                    ('Crontab Persistence', 'crontab -e|crontab -r', 'warning', 'PERSISTENCE', 'Persistence', 'T1053.003'),
                    ('Mass Process Kill', 'killall -9|pkill -9', 'warning', 'PROCESS_KILL', 'Impact', 'T1489'),
                    ('Cryptomining Signature', r'xmrig|minerd|stratum\+tcp', 'critical', 'MALWARE', 'Impact', 'T1496'),
                    ('SSH Key Injection', 'authorized_keys', 'warning', 'PERSISTENCE', 'Persistence', 'T1098.004')
                ]
                for r_name, r_pat, r_sev, r_type, r_tac, r_tech in default_rules:
                    try:
                        cur.execute("""
                            INSERT INTO detection_rules (name, pattern, severity, enabled, event_type, mitre_tactic, mitre_technique)
                            VALUES (%s, %s, %s, TRUE, %s, %s, %s);
                        """, (r_name, r_pat, r_sev, r_type, r_tac, r_tech))
                    except Exception:
                        pass
                cur.execute("SELECT * FROM detection_rules ORDER BY id ASC;")
                rules = cur.fetchall()
            return rules
    except Exception as e:
        logger.error(f"Error in get_detection_rules: {e}")
        return []
    finally:
        conn.close()

def create_detection_rule(name, pattern, severity, event_type, mitre_tactic=None, mitre_technique=None):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO detection_rules (name, pattern, severity, event_type, mitre_tactic, mitre_technique, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id;
            """, (name, pattern, severity, event_type, mitre_tactic, mitre_technique))
            return cur.fetchone()['id']
    except Exception as e:
        logger.error(f"Error in create_detection_rule: {e}")
        return None
    finally:
        conn.close()

def toggle_detection_rule(rule_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE detection_rules SET enabled = NOT enabled WHERE id = %s RETURNING enabled;", (rule_id,))
            res = cur.fetchone()
            if res: return res['enabled']
            return False
    except Exception as e:
        logger.error(f"Error in toggle_detection_rule: {e}")
        return False
    finally:
        conn.close()

def delete_detection_rule(rule_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM detection_rules WHERE id = %s;", (rule_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_detection_rule: {e}")
        return False
    finally:
        conn.close()

def get_threat_intel():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM threat_intel ORDER BY created_at DESC;")
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_threat_intel: {e}")
        return []
    finally:
        conn.close()

def create_threat_intel(ioc_value, ioc_type, severity, description, source='Manual'):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_intel (ioc_value, ioc_type, severity, description, source, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING id;
            """, (ioc_value, ioc_type, severity, description, source))
            return cur.fetchone()['id']
    except Exception as e:
        logger.error(f"Error in create_threat_intel: {e}")
        return None
    finally:
        conn.close()

def delete_threat_intel(ioc_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM threat_intel WHERE id = %s;", (ioc_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_threat_intel: {e}")
        return False
    finally:
        conn.close()

def get_playbooks():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM playbooks ORDER BY id ASC;")
            pbs = cur.fetchall()
            if not pbs:
                default_pbs = [
                    ('Auto Host Isolation on Ransomware', 'command contains rm -rf or alert contains DESTRUCTIVE', '1. Isolate host network; 2. Terminate malicious PID; 3. Notify SOC on Slack', '[{"type":"isolate_host"},{"type":"block_ip"},{"type":"notify_slack"}]'),
                    ('SSH Brute Force Auto-Mitigation', 'failed_count >= 5 or alert contains AUTH_FAIL', '1. Block IP on iptables; 2. Alert oncall engineer', '[{"type":"block_ip"},{"type":"notify_slack"}]'),
                    ('Service Recovery on Crash', 'status == offline or alert contains SERVICE_STOP', '1. Ping health check; 2. Restart service unit', '[{"type":"run_health_check"},{"type":"restart_service"}]')
                ]
                for p_name, p_trig, p_steps, p_act in default_pbs:
                    try:
                        cur.execute("""
                            INSERT INTO playbooks (name, trigger_condition, steps, actions)
                            VALUES (%s, %s, %s, %s);
                        """, (p_name, p_trig, p_steps, p_act))
                    except Exception:
                        pass
                cur.execute("SELECT * FROM playbooks ORDER BY id ASC;")
                pbs = cur.fetchall()
            return pbs
    except Exception as e:
        logger.error(f"Error in get_playbooks: {e}")
        return []
    finally:
        conn.close()

def create_playbook(name, trigger_condition, steps, actions=None):
    if actions is None:
        actions = []
    import json
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO playbooks (name, trigger_condition, actions, steps, created_at)
                VALUES (%s, %s, %s, %s, NOW()) RETURNING id;
            """, (name, trigger_condition, json.dumps(actions), steps))
            return cur.fetchone()['id']
    except Exception as e:
        logger.error(f"Error in create_playbook: {e}")
        return None
    finally:
        conn.close()

def delete_playbook(pb_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM playbooks WHERE id = %s;", (pb_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_playbook: {e}")
        return False
    finally:
        conn.close()

def get_settings():
    conn = get_db_connection()
    if not conn: return {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM settings;")
            rows = cur.fetchall()
            return {r['key']: r['value'] for r in rows}
    except Exception as e:
        logger.error(f"Error in get_settings: {e}")
        return {}
    finally:
        conn.close()

def save_setting(key, value):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
            """, (key, str(value)))
            return True
    except Exception as e:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT key FROM settings WHERE key = %s", (key,))
                if cur.fetchone():
                    cur.execute("UPDATE settings SET value = %s WHERE key = %s", (str(value), key))
                else:
                    cur.execute("INSERT INTO settings (key, value) VALUES (%s, %s)", (key, str(value)))
                return True
        except:
            return False
    finally:
        conn.close()

def get_reports():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM reports ORDER BY created_at DESC;")
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_reports: {e}")
        return []
    finally:
        conn.close()

def create_report(title, date_from, date_to):
    import json
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            # Query real data for report
            cur.execute("SELECT COUNT(*) as total, SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as crit, SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END) as warn FROM alerts WHERE created_at >= %s AND created_at <= %s", (date_from, date_to))
            alert_stats = cur.fetchone()
            total_alerts = alert_stats.get('total', 0) if alert_stats else 0
            critical_count = alert_stats.get('crit', 0) if alert_stats else 0
            warning_count = alert_stats.get('warn', 0) if alert_stats else 0

            cur.execute("SELECT s.id, s.hostname, COUNT(a.id) as cnt FROM alerts a JOIN servers s ON a.server_id = s.id WHERE a.created_at >= %s AND a.created_at <= %s GROUP BY s.id, s.hostname ORDER BY cnt DESC LIMIT 5", (date_from, date_to))
            top_servers = [{'server_id': r['id'], 'hostname': r['hostname'], 'alert_count': r['cnt']} for r in cur.fetchall()]

            cur.execute("SELECT command, COUNT(*) as cnt FROM commands WHERE executed_at >= %s AND executed_at <= %s GROUP BY command ORDER BY cnt DESC LIMIT 5", (date_from, date_to))
            top_commands = [{'command': r['command'], 'count': r['cnt']} for r in cur.fetchall()]

            cur.execute("SELECT COUNT(*) as total FROM login_history WHERE success = FALSE AND timestamp >= %s AND timestamp <= %s", (date_from, date_to))
            failed_logins_total = cur.fetchone()['total'] if cur.fetchone() else 0

            content = {
                'total_alerts': total_alerts,
                'critical_count': critical_count,
                'warning_count': warning_count,
                'top_servers': top_servers,
                'top_commands': top_commands,
                'failed_logins_total': failed_logins_total
            }

            cur.execute("""
                INSERT INTO reports (title, date_from, date_to, content, created_at)
                VALUES (%s, %s, %s, %s, NOW()) RETURNING id;
            """, (title, date_from, date_to, json.dumps(content)))
            return cur.fetchone()['id']
    except Exception as e:
        logger.error(f"Error in create_report: {e}")
        return None
    finally:
        conn.close()

def log_audit(username, action, target_type, target_id, detail):
    conn = get_db_connection()
    if not conn: return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_logs (username, action, target_type, target_id, detail, timestamp)
                VALUES (%s, %s, %s, %s, %s, NOW());
            """, (username, action, target_type, target_id, detail))
    except Exception as e:
        logger.error(f"Error in log_audit: {e}")
    finally:
        conn.close()

def get_audit_logs(username=None, action=None, limit=100):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []
            if username:
                query += " AND username = %s"
                params.append(username)
            if action:
                query += " AND action = %s"
                params.append(action)
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, params)
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_audit_logs: {e}")
        return []
    finally:
        conn.close()

def get_activity_feed(limit=20):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 'Alert' as type, a.title as description, a.severity as severity, s.hostname as hostname, a.created_at as timestamp
                FROM alerts a LEFT JOIN servers s ON a.server_id = s.id
                UNION ALL
                SELECT 'Command' as type, command as description, risk_level as severity, s.hostname as hostname, c.executed_at as timestamp
                FROM commands c LEFT JOIN servers s ON c.server_id = s.id
                UNION ALL
                SELECT 'Login' as type, username || (CASE WHEN success THEN ' logged in' ELSE ' failed to log in' END) as description, 
                       (CASE WHEN success THEN 'info' ELSE 'warning' END) as severity, s.hostname as hostname, lh.timestamp as timestamp
                FROM login_history lh LEFT JOIN servers s ON lh.server_id = s.id
                ORDER BY timestamp DESC
                LIMIT %s
            """, (limit,))
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_activity_feed: {e}")
        return []
    finally:
        conn.close()

def get_dashboard_counts():
    conn = get_db_connection()
    counts = {'total_servers': 0, 'online_servers': 0, 'critical_alerts': 0, 'maintenance_servers': 0, 'total_alerts': 0, 'unresolved_alerts': 0}
    if not conn: return counts
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as c FROM servers;")
            res = cur.fetchone()
            counts['total_servers'] = res['c'] if res else 0
            cur.execute("SELECT COUNT(*) as c FROM servers WHERE status = 'online';")
            res = cur.fetchone()
            counts['online_servers'] = res['c'] if res else 0
            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE severity = 'critical' AND is_resolved = FALSE;")
            res = cur.fetchone()
            counts['critical_alerts'] = res['c'] if res else 0
            cur.execute("SELECT COUNT(*) as c FROM servers WHERE is_maintenance = TRUE;")
            res = cur.fetchone()
            counts['maintenance_servers'] = res['c'] if res else 0
            cur.execute("SELECT COUNT(*) as c FROM alerts;")
            res = cur.fetchone()
            counts['total_alerts'] = res['c'] if res else 0
            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE is_resolved = FALSE;")
            res = cur.fetchone()
            counts['unresolved_alerts'] = res['c'] if res else 0
            return counts
    except Exception as e:
        logger.error(f"Error in get_dashboard_counts: {e}")
        return counts
    finally:
        conn.close()

def get_severity_distribution():
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT severity, COUNT(*) as count FROM alerts WHERE is_resolved = FALSE GROUP BY severity;")
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_severity_distribution: {e}")
        return []
    finally:
        conn.close()

def search_all(query):
    conn = get_db_connection()
    results = {'servers': [], 'alerts': [], 'incidents': [], 'commands': []}
    if not conn or not query: return results
    try:
        with conn.cursor() as cur:
            q = f"%{query}%"
            cur.execute("SELECT id, hostname, ip FROM servers WHERE hostname ILIKE %s OR ip ILIKE %s LIMIT 10", (q, q))
            results['servers'] = cur.fetchall()
            cur.execute("SELECT id, title, severity FROM alerts WHERE title ILIKE %s OR message ILIKE %s LIMIT 10", (q, q))
            results['alerts'] = cur.fetchall()
            cur.execute("SELECT id, title, severity FROM incidents WHERE title ILIKE %s OR description ILIKE %s LIMIT 10", (q, q))
            results['incidents'] = cur.fetchall()
            cur.execute("SELECT id, command, username FROM commands WHERE command ILIKE %s LIMIT 10", (q,))
            results['commands'] = cur.fetchall()
            return results
    except Exception as e:
        logger.error(f"Error in search_all: {e}")
        return results
    finally:
        conn.close()

def toggle_maintenance(server_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("UPDATE servers SET is_maintenance = NOT is_maintenance WHERE id = %s RETURNING is_maintenance;", (server_id,))
                res = cur.fetchone()
                if res: return res['is_maintenance']
                return False
            except Exception:
                try:
                    cur.execute("UPDATE servers SET is_maintenance = CASE WHEN is_maintenance = 1 THEN 0 ELSE 1 END WHERE id = %s RETURNING is_maintenance;", (server_id,))
                    res = cur.fetchone()
                    if res: return res['is_maintenance']
                    return False
                except:
                    return False
    except Exception as e:
        logger.error(f"Error in toggle_maintenance: {e}")
        return False
    finally:
        conn.close()




import urllib.request

_geo_cache = {}

def lookup_ip_geo(ip: str):
    """Resolve IP location using ip-api.com with in-memory caching."""
    if not ip or ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return {"lat": 37.7749, "lon": -122.4194, "city": "Internal", "country": "Private Network"}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", headers={"User-Agent": "SecurePulse-SOC/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                geo = {
                    "lat": float(data.get("lat", 20.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown")
                }
                _geo_cache[ip] = geo
                return geo
    except Exception:
        pass
    geo = {"lat": 20.0, "lon": 0.0, "city": "Unknown", "country": "Internet"}
    _geo_cache[ip] = geo
    return geo

def get_threat_map_points():
    """Return geo-located threat dots from real failed logins and servers in DB."""
    conn = get_db_connection()
    points = []
    if not conn:
        return points
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ip_address, COUNT(*) as fail_count
                FROM login_history
                WHERE success = FALSE AND ip_address IS NOT NULL AND ip_address != ''
                GROUP BY ip_address
                ORDER BY fail_count DESC
                LIMIT 50;
            """)
            rows = cur.fetchall()
            for r in rows:
                ip = r.get("ip_address")
                count = r.get("fail_count", 1)
                geo = lookup_ip_geo(ip)
                severity = "critical" if count >= 10 else "warning"
                points.append({
                    "ip": ip,
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "city": geo["city"],
                    "country": geo["country"],
                    "severity": severity,
                    "count": count
                })
            
            # Monitored servers as info dots
            cur.execute("SELECT id, hostname, ip FROM servers LIMIT 10;")
            servers = cur.fetchall()
            for s in servers:
                sip = s.get("ip") or "127.0.0.1"
                sgeo = lookup_ip_geo(sip)
                points.append({
                    "ip": sip,
                    "lat": sgeo["lat"],
                    "lon": sgeo["lon"],
                    "city": sgeo["city"],
                    "country": sgeo["country"],
                    "severity": "info",
                    "hostname": s.get("hostname")
                })
        return points
    except Exception as e:
        logger.error(f"Error in get_threat_map_points: {e}")
        return points
    finally:
        conn.close()
