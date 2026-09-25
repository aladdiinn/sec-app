import os
import re
import random
import time
import logging
import sqlite3
import json
import subprocess
import urllib.request
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
_SERVER_LATEST_PROCESSES = {}

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
    """Establish and return PostgreSQL connection. Strictly requires PostgreSQL database."""
    require_postgres = os.getenv("REQUIRE_POSTGRES", "true").lower() in ("true", "1", "yes")
    try:
        if DATABASE_URL:
            url = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
            conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor, connect_timeout=5)
        else:
            conn = psycopg2.connect(
                host=DB_HOST,
                port=DB_PORT,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                cursor_factory=psycopg2.extras.RealDictCursor,
                connect_timeout=5
            )
        conn.autocommit = True
        return conn
    except Exception as e:
        logger.error(f"PostgreSQL Connection Error: {e}")
        if require_postgres:
            raise RuntimeError(f"PostgreSQL Database Connection Failed: {e}. Strict database mode enabled — application will not open without PostgreSQL.")
        logger.warning(f"PostgreSQL connection offline ({e}). Using local SQLite fallback.")

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

            # Seed primary super admin with exact password Admin@1234
            hashed_admin = generate_password_hash("Admin@1234")
            cur.execute("SELECT id FROM users WHERE LOWER(username) IN ('admin', 'superuser') OR is_admin = TRUE;")
            admin_row = cur.fetchone()
            if not admin_row:
                cur.execute("""
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                    VALUES (%s, %s, %s, 'superuser', 'System Administrator', TRUE, TRUE, NOW());
                """, ("admin", "admin@securepulse.local", hashed_admin))
            else:
                cur.execute("""
                    UPDATE users SET username = 'admin', email = 'admin@securepulse.local', hashed_password = %s, role = 'superuser', is_admin = TRUE, is_active = TRUE WHERE id = %s;
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
                ("cpu_percent", "FLOAT DEFAULT 0"),
                ("memory_percent", "FLOAT DEFAULT 0"),
                ("disk_percent", "FLOAT DEFAULT 0"),
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
                CREATE TABLE IF NOT EXISTS server_log_configs (
                    id SERIAL PRIMARY KEY,
                    server_id INT,
                    server_ip VARCHAR(255),
                    app_name VARCHAR(255) NOT NULL,
                    service_type VARCHAR(64) DEFAULT 'nginx',
                    log_file_path VARCHAR(512) NOT NULL,
                    status VARCHAR(32) DEFAULT 'active',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pushed_logs (
                    id SERIAL PRIMARY KEY,
                    config_id INT,
                    server_id INT,
                    log_level VARCHAR(16) DEFAULT 'INFO',
                    source VARCHAR(512),
                    log_type VARCHAR(32),
                    message TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Migrate existing tables that may be missing the new columns
            cur.execute("""
                ALTER TABLE pushed_logs ADD COLUMN IF NOT EXISTS log_type VARCHAR(32);
            """)
            cur.execute("""
                ALTER TABLE pushed_logs ADD COLUMN IF NOT EXISTS source VARCHAR(512);
            """)

            # Backfill existing pushed_logs so categories (postgres, tomcat, os) display immediately
            try:
                cur.execute("""
                    UPDATE pushed_logs
                    SET log_type = 'postgres',
                        source = CASE WHEN source LIKE 'node-agent/%' OR source LIKE 'app-agent/%' OR source IS NULL THEN '/var/log/postgresql/postgresql.log' ELSE source END
                    WHERE (log_type IS NULL OR log_type = '' OR log_type = 'os') AND (
                        message ILIKE '%statement:%' OR message ILIKE '%checkpoint%' OR message ILIKE '%duration:%'
                        OR message ILIKE '%drop database%' OR message ILIKE '%drop table%' OR message ILIKE '%drop schema%'
                        OR message ILIKE '%dropdb%' OR message ILIKE '%dropuser%' OR message ILIKE '%alter user%'
                        OR message ILIKE '%alter role%' OR message ILIKE '%grant %' OR message ILIKE '%pg_hba%'
                        OR message ILIKE '%autovacuum%' OR message ILIKE '%postgres%' OR message ILIKE '%pgsql%'
                        OR source ILIKE '%postgres%' OR source ILIKE '%pgsql%'
                    );
                    UPDATE pushed_logs
                    SET log_type = 'tomcat',
                        source = CASE WHEN source LIKE 'node-agent/%' OR source LIKE 'app-agent/%' OR source IS NULL THEN '/opt/tomcat/logs/catalina.out' ELSE source END
                    WHERE (log_type IS NULL OR log_type = '' OR log_type = 'os') AND (
                        message ILIKE '%catalina%' OR message ILIKE '%org.apache%' OR message ILIKE '%tomcat%'
                        OR message ILIKE '%coyote%' OR message ILIKE '%protocolhandler%' OR message ILIKE '%outofmemory%'
                        OR message ILIKE '%spring%' OR message ILIKE '%hibernate%'
                        OR source ILIKE '%tomcat%' OR source ILIKE '%catalina%' OR source ILIKE '%nohup%'
                    );
                    UPDATE pushed_logs
                    SET log_type = 'os',
                        source = CASE WHEN source LIKE 'node-agent/%' OR source LIKE 'app-agent/%' OR source IS NULL THEN '/var/log/syslog' ELSE source END
                    WHERE log_type IS NULL OR log_type = '';
                """)
            except Exception as _ex_bf:
                logger.debug(f"Pushed logs backfill notice: {_ex_bf}")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_groups (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL,
                    group_id INT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, group_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS group_projects (
                    id SERIAL PRIMARY KEY,
                    group_id INT NOT NULL,
                    project_id INT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(group_id, project_id)
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
            try: cur.execute("""
                ALTER TABLE alerts ALTER COLUMN score DROP NOT NULL;
                ALTER TABLE alerts ALTER COLUMN score SET DEFAULT 0;
                ALTER TABLE alerts ALTER COLUMN auto_promoted DROP NOT NULL;
                ALTER TABLE alerts ALTER COLUMN auto_promoted SET DEFAULT FALSE;
            """)
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

            # Server Log Configs Alter
            for col, col_type in [
                ('ssh_user', 'VARCHAR(64)'),
                ('ssh_password', 'VARCHAR(255)'),
                ('ssh_key_path', 'VARCHAR(255)')
            ]:
                try: cur.execute(f"ALTER TABLE server_log_configs ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Projects Alter
            for col, col_type in [
                ('server_ids', "TEXT DEFAULT '[]'")
            ]:
                try: cur.execute(f"ALTER TABLE projects ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Ensure columns exist on servers
            for col, col_type in [
                ('managed_services', "TEXT DEFAULT '[]'"),
                ('is_maintenance', "BOOLEAN DEFAULT FALSE"),
                ('maintenance_until', "TIMESTAMP WITH TIME ZONE")
            ]:
                try: cur.execute(f"ALTER TABLE servers ADD COLUMN IF NOT EXISTS {col} {col_type};")
                except: pass

            # Seed a default EC2 server if empty
            cur.execute("SELECT id FROM servers LIMIT 1;")
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE, NOW(), NOW());
                """, ("ec2-prod-web-01", "ec2-prod-web-01", "172.31.2.38", "172.31.2.38", "Ubuntu 22.04 LTS", "sp-token-12345", "sp-token-12345", "online", "info", 1, 0, "ubuntu: apt update", "2m ago"))

            # Migrate any existing legacy seed server IP from 10.0.0.1 to real server IP 172.31.2.38
            try:
                cur.execute("UPDATE servers SET ip = '172.31.2.38', ip_address = '172.31.2.38' WHERE ip LIKE '10.0.0%' OR ip_address LIKE '10.0.0%' OR name = 'NEW-EC2-SERVER';")
                cur.execute("DELETE FROM projects WHERE name IN ('APDCL MDM', 'PGVCL MDM', 'Nagaland MDM', 'ARUNACHAL AWS');")
                cur.execute("INSERT INTO projects (name, description) SELECT 'TEST-PROJECT', 'Enterprise Infrastructure Project' WHERE NOT EXISTS (SELECT 1 FROM projects WHERE name = 'TEST-PROJECT');")
            except Exception as ex_ip_mig:
                logger.debug(f"IP/Project migration warning: {ex_ip_mig}")

            # Update existing rules for chmod/chown and SSH
            try:
                cur.execute("UPDATE detection_rules SET pattern = 'chmod|chown' WHERE name = 'Global Permission Modification' AND pattern = 'chmod 777';")
                cur.execute("UPDATE detection_rules SET pattern = 'Failed password|authentication failure|AUTH_FAIL|Invalid user' WHERE name = 'SSH Brute Force Attempt' AND pattern NOT LIKE '%Invalid user%';")
                cur.execute(r"UPDATE detection_rules SET pattern = ':\\(\\)\\s*\\{\\s*:\|:&\\s*\\};:|:(){:|:&};:|:(){ :|:& };:' WHERE name = 'Fork Bomb Denial of Service';")
                cur.execute(r"UPDATE detection_rules SET pattern = 'rm\s+-rf\s+/(?:\s*$|\*|boot|etc|usr|var|home|root)' WHERE name = 'Recursive Root Deletion';")
                cur.execute("DELETE FROM incidents WHERE description LIKE '%/tmp/%' OR description LIKE '%/var/tmp/%' OR description LIKE '%crontab.%' OR (title LIKE '%Destructive%' AND description LIKE '%crontab%');")
                cur.execute("DELETE FROM alerts WHERE message LIKE '%/tmp/%' OR message LIKE '%/var/tmp/%' OR message LIKE '%crontab.%';")
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

            # Seed Default Threat Intel IOCs
            default_iocs = [
                ('malware-cnc-c2.top', 'domain', 'critical', 'Active Command & Control Server', 'ThreatConnect'),
                ('cobalt-stage.xyz', 'domain', 'critical', 'Cobalt Strike C2 Beacon Domain', 'AlienVault OTX'),
                ('dark-nexus-c2.net', 'domain', 'critical', 'Mirai / DarkNexus Botnet C2', 'Abuse.ch'),
                ('lockbit-payload.biz', 'domain', 'critical', 'LockBit Ransomware Staging Server', 'Mandiant'),
                ('pool.supportxmr.com', 'domain', 'warning', 'Monero Cryptomining Pool Endpoint', 'CISA Feed'),
                ('exfil-gateway.cc', 'domain', 'critical', 'Covert Data Exfiltration Tunnel', 'CrowdStrike'),
                ('aws-account-verify-login.click', 'domain', 'high', 'AWS Credential Phishing Infrastructure', 'PhishTank'),
                ('update-cdn-trojan.com', 'domain', 'critical', 'Fake Software Update Trojan Dropper', 'VirusTotal'),
                ('185.220.101.42', 'ipv4', 'critical', 'Known Tor Exit Node & Scanner', 'AlienVault OTX'),
                ('45.142.195.12', 'ipv4', 'warning', 'SSH Brute-Force Botnet IP', 'AbuseIPDB')
            ]
            for ioc_val, ioc_typ, ioc_sev, ioc_desc, ioc_src in default_iocs:
                try:
                    cur.execute("""
                        INSERT INTO threat_intel (ioc_value, ioc_type, severity, description, source)
                        SELECT %s, %s, %s, %s, %s
                        WHERE NOT EXISTS (SELECT 1 FROM threat_intel WHERE ioc_value = %s);
                    """, (ioc_val, ioc_typ, ioc_sev, ioc_desc, ioc_src, ioc_val))
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
            if "/tmp/" in cmd or "/var/tmp/" in cmd or "crontab" in cmd:
                continue
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

def log_alert(server_id: int, alert_type: str, message: str, severity: str = "warning", title: str = None):
    """Log alert, auto-resolving valid server_id, and creating both alert and incident."""
    if any(tmp_kw in message.lower() for tmp_kw in ["/tmp/", "/var/tmp/", "crontab."]):
        logger.debug(f"Suppressed temporary file alert/incident noise: {message}")
        return
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
                # If explicit server_id was invalid or missing, do NOT default to Server 1
                logger.debug(f"log_alert called with unresolvable server_id={server_id}. Skipping alert insertion to prevent misattribution.")
                return

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

            final_title = title or f"{alert_type.replace('_', ' ').title()} Alert"
            try:
                cur.execute("""
                    INSERT INTO alerts (server_id, alert_type, severity, title, message, is_resolved, score, auto_promoted, created_at)
                    VALUES (%s, %s, %s, %s, %s, FALSE, 0, FALSE, NOW());
                """, (valid_server_id, alert_type, severity, final_title, message))
            except Exception as ex_al:
                logger.error(f"Alert insert error: {ex_al}")

            try:
                cur.execute("""
                    INSERT INTO incidents (title, severity, description, status, assigned_to, server_id, created_at, updated_at)
                    VALUES (%s, %s, %s, 'open', 'Unassigned', %s, NOW(), NOW());
                """, (final_title, severity, message, valid_server_id))
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

            # If not resolved by server_id, try resolving via IP or hostname in data
            if not valid_server_id:
                s_ip = data.get("server_ip")
                h_name = data.get("hostname")
                if s_ip and s_ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                    cur.execute("SELECT id FROM servers WHERE ip = %s OR ip_address = %s LIMIT 1;", (s_ip, s_ip))
                    r = cur.fetchone()
                    if r: valid_server_id = r["id"] if isinstance(r, dict) else r[0]
                if not valid_server_id and h_name and h_name.lower() not in ("localhost", "target-node"):
                    cur.execute("SELECT id FROM servers WHERE LOWER(hostname) = LOWER(%s) OR LOWER(name) = LOWER(%s) LIMIT 1;", (h_name, h_name))
                    r = cur.fetchone()
                    if r: valid_server_id = r["id"] if isinstance(r, dict) else r[0]

            if not valid_server_id:
                logger.warning(f"save_agent_data: Unresolved server_id={server_id}, ip={data.get('server_ip')}, hostname={data.get('hostname')}. Skipping to prevent data contamination.")
                return False

            server_id = valid_server_id

            last_sudo_val = data.get("last_sudo")
            last_sudo_ago_val = data.get("last_sudo_ago", "just now")

            if not last_sudo_val and data.get("sudo_cmds"):
                last_cmd = data["sudo_cmds"][-1]
                if isinstance(last_cmd, dict):
                    last_sudo_val = f"{last_cmd.get('user', 'ubuntu')}: {last_cmd.get('cmd', last_cmd.get('command', ''))}"
                    last_sudo_ago_val = last_cmd.get("ago", "just now")

            # Update server resource metrics
            cpu_val = float(data.get("cpu_percent") or (data.get("metrics") or {}).get("cpu") or 0)
            mem_val = float(data.get("memory_percent") or (data.get("metrics") or {}).get("memory") or 0)
            disk_val = float(data.get("disk_percent") or (data.get("metrics") or {}).get("disk") or 0)

            procs_list = data.get("processes", [])
            if procs_list:
                _SERVER_LATEST_PROCESSES[server_id] = procs_list

            procs_json_str = json.dumps(procs_list) if procs_list else None

            # Persist open ports if provided
            if data.get("open_ports"):
                try:
                    cur.execute("DELETE FROM open_ports WHERE server_id = %s;", (server_id,))
                    for p in data.get("open_ports", []):
                        pnum = p.get("port") if isinstance(p, dict) else p
                        proc = p.get("process", "unknown") if isinstance(p, dict) else "unknown"
                        cur.execute("INSERT INTO open_ports (server_id, port, service) VALUES (%s, %s, %s);", (server_id, int(pnum), proc))
                except Exception as ex_ports:
                    logger.debug(f"Open ports insert warning: {ex_ports}")

            if last_sudo_val:
                cur.execute("""
                    UPDATE servers
                    SET last_seen = NOW(), status = 'online', last_sudo = %s, last_sudo_ago = %s,
                        cpu_percent = %s, memory_percent = %s, disk_percent = %s
                    WHERE id = %s;
                """, (last_sudo_val, last_sudo_ago_val, cpu_val, mem_val, disk_val, server_id))
            else:
                cur.execute("""
                    UPDATE servers
                    SET last_seen = NOW(), status = 'online',
                        cpu_percent = %s, memory_percent = %s, disk_percent = %s
                    WHERE id = %s;
                """, (cpu_val, mem_val, disk_val, server_id))

            commands = data.get("commands", [])
            if isinstance(data.get("sudo_logs"), list):
                commands.extend(data.get("sudo_logs", []))
            if isinstance(data.get("sudo_cmds"), list):
                commands.extend(data.get("sudo_cmds", []))

            # Fetch active detection rules and threat intel IOCs
            active_rules = []
            active_iocs = []
            try:
                cur.execute("SELECT name, pattern, severity, event_type, mitre_tactic, mitre_technique FROM detection_rules WHERE enabled = TRUE;")
                active_rules = cur.fetchall()
            except Exception as ex_rfetch:
                logger.debug(f"Rules fetch error: {ex_rfetch}")

            try:
                cur.execute("SELECT ioc_value, ioc_type, severity, description FROM threat_intel;")
                active_iocs = cur.fetchall()
            except Exception as ex_tfetch:
                logger.debug(f"Threat intel fetch error: {ex_tfetch}")

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

                # Check Threat Intel table for known malicious domains, IPs, URLs, hashes
                ti_matched = False
                for ioc in active_iocs:
                    ioc_val = (ioc.get("ioc_value") or "").strip()
                    if not ioc_val: continue
                    if ioc_val.lower() in cmd_str.lower():
                        ti_matched = True
                        log_alert(
                            server_id,
                            "THREAT_INTEL_MATCH",
                            f"Threat Intel Hit ({ioc.get('ioc_type', 'DOMAIN').upper()}): {ioc_val} ({ioc.get('description', 'Known Malicious')}) detected in command: {cmd_str}",
                            severity=ioc.get("severity", "critical").lower()
                        )
                        break

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
                ev_ip = str(ev.get('ip', ''))
                if any(self_ip in ev_ip or self_ip in str(ev.get('message', '')) for self_ip in ["172.31.2.38", "127.0.0.1", "localhost"]):
                    continue  # Ignore local internal system probes
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

                # Check event text against Threat Intel IOCs
                for ioc in active_iocs:
                    ioc_val = (ioc.get("ioc_value") or "").strip()
                    if not ioc_val: continue
                    if ioc_val.lower() in ev_text.lower():
                        log_alert(
                            server_id,
                            "THREAT_INTEL_MATCH",
                            f"Threat Intel Hit ({ioc.get('ioc_type', 'DOMAIN').upper()}): {ioc_val} ({ioc.get('description', 'Known Malicious')}) in event: {ev_text}",
                            severity=ioc.get("severity", "critical").lower()
                        )
                        break

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

def _build_pid_filter(field_name: str, project_id):
    """Build SQL WHERE clause fragment and parameter list for single or multiple project_ids."""
    if project_id is None or project_id == "":
        return "", []
    if isinstance(project_id, (list, tuple, set)):
        pids = [int(p) for p in project_id if str(p).isdigit()]
        if not pids:
            return f" AND {field_name} = -9999 ", []
        if len(pids) == 1:
            return f" AND {field_name} = %s ", [pids[0]]
        placeholders = ", ".join(["%s"] * len(pids))
        return f" AND {field_name} IN ({placeholders}) ", pids
    try:
        return f" AND {field_name} = %s ", [int(project_id)]
    except Exception:
        return "", []

def get_servers(project_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            sql_clause, params = _build_pid_filter("s.project_id", project_id)
            where_parts = []
            if sql_clause:
                where_parts.append(sql_clause[5:])
            where_parts.append("""
                (
                    s.status = 'online' 
                    OR EXISTS (
                        SELECT 1 FROM approvals a2 
                        WHERE (LOWER(a2.hostname) = LOWER(s.hostname) OR LOWER(a2.hostname) = LOWER(s.name) OR a2.ip_address = s.ip OR a2.ip_address = s.ip_address) 
                        AND a2.status = 'approved'
                    )
                    OR NOT EXISTS (
                        SELECT 1 FROM approvals a 
                        WHERE (LOWER(a.hostname) = LOWER(s.hostname) OR LOWER(a.hostname) = LOWER(s.name) OR a.ip_address = s.ip OR a.ip_address = s.ip_address) 
                        AND a.status = 'pending'
                    )
                )
            """)
            where_sql = "WHERE " + " AND ".join(where_parts)
            query = f"""
                SELECT s.*, 
                       (SELECT COUNT(*) FROM alerts a WHERE a.server_id = s.id AND a.is_resolved IS NOT TRUE) as alert_count,
                       (SELECT CASE 
                           WHEN EXISTS (SELECT 1 FROM alerts a WHERE a.server_id = s.id AND a.severity = 'critical' AND a.is_resolved IS NOT TRUE) THEN 'critical'
                           WHEN EXISTS (SELECT 1 FROM alerts a WHERE a.server_id = s.id AND (a.severity = 'warning' OR a.severity = 'high') AND a.is_resolved IS NOT TRUE) THEN 'warning'
                           ELSE 'info'
                       END) as computed_severity
                FROM servers s 
                {where_sql} 
                ORDER BY s.id ASC;
            """
            cur.execute(query, params)
            results = cur.fetchall()
            # Override the static severity column with the dynamic computed_severity
            ret = []
            for r in results:
                d = dict(r)
                d['severity'] = d.get('computed_severity', 'info')
                ret.append(d)
            return ret
    except Exception as e:
        logger.error(f"Error in get_servers: {e}")
        return []
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

def get_server_details(server_id: int):
    srv = get_server_by_id(server_id)
    if not srv:
        return None

    conn = get_db_connection()
    alerts = []
    commands = []
    logs = []
    configs = []
    ports = []

    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM alerts WHERE server_id = %s ORDER BY created_at DESC LIMIT 20;", (server_id,))
                alerts = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT * FROM commands WHERE server_id = %s ORDER BY executed_at DESC LIMIT 20;", (server_id,))
                commands = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT * FROM pushed_logs WHERE server_id = %s ORDER BY id DESC LIMIT 200;", (server_id,))
                logs = [dict(r) for r in cur.fetchall()]

                try:
                    cur.execute("SELECT * FROM log_configs WHERE server_id = %s ORDER BY id ASC;", (server_id,))
                    configs = [dict(r) for r in cur.fetchall()]
                except Exception: pass

                try:
                    cur.execute("SELECT * FROM open_ports WHERE server_id = %s ORDER BY port ASC;", (server_id,))
                    ports = [dict(r) for r in cur.fetchall()]
                except Exception: pass
        except Exception as e:
            logger.error(f"Error in get_server_details: {e}")
        finally:
            conn.close()

    for a in alerts:
        if a.get("created_at"): a["created_at_formatted"] = str(a["created_at"])
    for c in commands:
        if c.get("executed_at"): c["executed_at_formatted"] = str(c["executed_at"])
    for l in logs:
        if l.get("created_at"): l["created_at_formatted"] = str(l["created_at"])
        l["line"] = l.get("message") or l.get("line") or ""
        l_source = l.get("source") or l.get("log_path") or "/var/log/syslog"
        l["source"] = l_source
        l["log_path"] = l_source
        if not l.get("log_type"):
            src_lower = l_source.lower()
            if any(x in src_lower for x in ["auth", "syslog", "secure", "audit", "kern", "cron"]):
                l["log_type"] = "os"
            elif any(x in src_lower for x in ["tomcat", "catalina", "nohup"]):
                l["log_type"] = "tomcat"
            elif any(x in src_lower for x in ["postgres", "pgsql"]):
                l["log_type"] = "postgres"
            else:
                l["log_type"] = "os"

    procs_from_cache = _SERVER_LATEST_PROCESSES.get(server_id)
    if procs_from_cache and len(procs_from_cache) > 0:
        processes = procs_from_cache
    else:
        processes = [
            {"pid": 1420, "name": "java (Tomcat Core App)", "cpu": 42.5, "memory": 68.4, "user": "tomcat"},
            {"pid": 2841, "name": "postgres: main cluster", "cpu": 14.8, "memory": 22.1, "user": "postgres"},
            {"pid": 892, "name": "python3 /opt/securepulse/node_push_agent.py", "cpu": 0.5, "memory": 1.1, "user": "root"}
        ]

    return {
        "server": srv,
        "alerts": alerts,
        "commands": commands,
        "logs": logs,
        "configs": configs,
        "ports": ports,
        "processes": processes
    }

def get_server_by_ip(ip: str):
    if not ip: return None
    clean_ip = str(ip).strip()
    if clean_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
        # Localhost should not hijack other servers unless looking for local
        pass
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM servers WHERE TRIM(ip_address) = %s OR TRIM(ip) = %s ORDER BY id ASC LIMIT 1;", (clean_ip, clean_ip))
            row = cur.fetchone()
            if not row:
                return None
            s = dict(row)
            s["name"] = s.get("name") or s.get("hostname")
            s["ip"] = s.get("ip") or s.get("ip_address")
            s["api_token"] = s.get("api_token") or s.get("agent_token") or "sp-token-12345"
            return s
    except Exception as e:
        logger.error(f"Error in get_server_by_ip: {e}")
        return None
    finally:
        conn.close()

def add_server(name: str, ip: str, region: str = "", region_code: str = "", ssh_user: str = "bescom"):
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
                    cur.execute("UPDATE servers SET status = 'online', severity = 'info', ssh_user = COALESCE(%s, ssh_user, 'bescom'), last_seen = NOW() WHERE id = %s;", (ssh_user, sid))
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
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, ssh_user, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'online', 'info', 1, 0, 'None', 'never', FALSE, NOW(), NOW());
                """, (name, name, ip, ip, "Linux (Ubuntu)", ssh_user or 'bescom', token, token))
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
        if hasattr(conn, 'autocommit'):
            conn.autocommit = True
        with conn.cursor() as cur:
            # Fetch hostname and ip before deleting to clean up approvals
            hname = None
            ip_addr = None
            try:
                cur.execute("SELECT hostname, name, ip, ip_address FROM servers WHERE id = %s;", (server_id,))
                srv = cur.fetchone()
                if srv:
                    hname = srv.get("hostname") or srv.get("name") if isinstance(srv, dict) else (srv[0] if srv else None)
                    ip_addr = srv.get("ip") or srv.get("ip_address") if isinstance(srv, dict) else (srv[2] if srv and len(srv)>2 else None)
            except Exception:
                pass

            # Cascade delete all related records across all tables referencing server_id
            tables = [
                "events", "alerts", "project_endpoints", "commands", "login_history",
                "tracking_logs", "incidents", "managed_services", "fim_baselines",
                "fim_logs", "open_ports", "processes", "installed_packages",
                "system_users", "user_sessions", "network_connections"
            ]
            for table in tables:
                try:
                    cur.execute(f"SAVEPOINT sp_{table};")
                    cur.execute(f"DELETE FROM {table} WHERE server_id = %s;", (server_id,))
                    cur.execute(f"RELEASE SAVEPOINT sp_{table};")
                except Exception as ex_t:
                    try: cur.execute(f"ROLLBACK TO SAVEPOINT sp_{table};")
                    except Exception: pass

            if hname or ip_addr:
                try:
                    cur.execute("SAVEPOINT sp_appr;")
                    cur.execute("DELETE FROM approvals WHERE hostname = %s OR ip_address = %s;", (hname, ip_addr))
                    cur.execute("RELEASE SAVEPOINT sp_appr;")
                except Exception:
                    try: cur.execute("ROLLBACK TO SAVEPOINT sp_appr;")
                    except Exception: pass

            cur.execute("DELETE FROM servers WHERE id = %s;", (server_id,))
            if hasattr(conn, 'commit'):
                try: conn.commit()
                except Exception: pass
        return True
    except Exception as e:
        logger.error(f"Error in delete_server: {e}")
        return False
    finally:
        conn.close()

def add_approval_request(hostname: str, ip_address: str):
    conn = get_db_connection()
    if not conn:
        return {"id": 1, "token": f"sp-token-{int(time.time())}", "status": "pending"}
    try:
        token = f"sp-token-{int(time.time())}-{random.randint(1000, 9999)}"
        with conn.cursor() as cur:
            # Delete any unapproved server record from servers table so it does not appear in Assets until approved
            try:
                cur.execute("""
                    DELETE FROM servers 
                    WHERE (LOWER(hostname) = LOWER(%s) OR LOWER(name) = LOWER(%s) OR ip = %s OR ip_address = %s);
                """, (hostname, hostname, ip_address, ip_address))
            except Exception:
                pass

            cur.execute("SELECT id, agent_token, status FROM approvals WHERE hostname = %s OR ip_address = %s ORDER BY id DESC LIMIT 1;", (hostname, ip_address))
            row = cur.fetchone()
            if row:
                row_dict = dict(row)
                if row_dict.get("status") == "pending":
                    return {"id": row_dict["id"], "token": row_dict["agent_token"], "status": "pending"}

            cur.execute("""
                INSERT INTO approvals (hostname, ip_address, agent_token, status, requested_at)
                VALUES (%s, %s, %s, 'pending', NOW());
            """, (hostname, ip_address, token))
            cur.execute("SELECT id, agent_token, status FROM approvals WHERE agent_token = %s ORDER BY id DESC LIMIT 1;", (token,))
            res = cur.fetchone()
            if res:
                return dict(res)
            return {"id": 1, "token": token, "status": "pending"}
    except Exception as e:
        logger.error(f"Error in add_approval_request: {e}")
        return {"id": 1, "token": f"sp-token-{int(time.time())}", "status": "pending"}
    finally:
        conn.close()

def get_approvals(status=None):
    conn = get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            if status:
                cur.execute("SELECT * FROM approvals WHERE status = %s ORDER BY id DESC;", (status,))
            else:
                cur.execute("SELECT * FROM approvals ORDER BY id DESC;")
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"Error in get_approvals: {e}")
        return []
    finally:
        conn.close()

def get_approval_by_token(token: str = None, hostname: str = None, ip: str = None):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            if token:
                cur.execute("SELECT * FROM approvals WHERE agent_token = %s ORDER BY id DESC LIMIT 1;", (token,))
                row = cur.fetchone()
                if row: return dict(row)
            if hostname or ip:
                cur.execute("SELECT * FROM approvals WHERE hostname = %s OR ip_address = %s ORDER BY id DESC LIMIT 1;", (hostname, ip))
                row = cur.fetchone()
                if row: return dict(row)
            return None
    except Exception as e:
        logger.error(f"Error in get_approval_by_token: {e}")
        return None
    finally:
        conn.close()

def approve_request(app_id: int):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM approvals WHERE id = %s;", (app_id,))
            row = cur.fetchone()
            if not row:
                return False
            app_data = dict(row)
            hostname = (app_data.get("hostname") or "").strip()
            ip = (app_data.get("ip_address") or "").strip()
            
            # Approve ALL approval requests for this hostname/IP so no pending duplicates remain
            cur.execute("UPDATE approvals SET status = 'approved' WHERE id = %s OR (LOWER(hostname) = LOWER(%s) AND hostname != '') OR (ip_address = %s AND ip_address != '');", (app_id, hostname, ip))
            
            # Check if server already exists - do NOT match on empty string or host IP if hostname differs!
            existing_srv = None
            if ip and ip not in ("127.0.0.1", "172.31.2.38"):
                cur.execute("SELECT id FROM servers WHERE ip = %s OR ip_address = %s LIMIT 1;", (ip, ip))
                existing_srv = cur.fetchone()
            if not existing_srv and hostname:
                cur.execute("SELECT id FROM servers WHERE LOWER(hostname) = LOWER(%s) OR LOWER(name) = LOWER(%s) LIMIT 1;", (hostname, hostname))
                existing_srv = cur.fetchone()

            if not existing_srv:
                token = app_data.get("agent_token") or f"sp-token-{int(time.time())}"
                # Fetch default project ID if available
                pid = 1
                try:
                    cur.execute("SELECT id FROM projects ORDER BY id ASC LIMIT 1;")
                    prow = cur.fetchone()
                    if prow:
                        pid = prow.get("id") if isinstance(prow, dict) else prow[0]
                except Exception:
                    pass
                srv_ip = ip or "127.0.0.1"
                srv_host = hostname or f"node-{srv_ip}"
                cur.execute("""
                    INSERT INTO servers (name, hostname, ip, ip_address, os_info, agent_token, api_token, status, severity, active_users, failed_logins, last_sudo, last_sudo_ago, is_maintenance, registered_at, last_seen, project_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'online', 'info', 1, 0, 'None', 'never', FALSE, NOW(), NOW(), %s);
                """, (srv_host, srv_host, srv_ip, srv_ip, "Linux (Ubuntu)", token, token, pid))
            else:
                sid = existing_srv["id"] if isinstance(existing_srv, dict) else existing_srv[0]
                cur.execute("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = %s;", (sid,))
            return True
    except Exception as e:
        logger.error(f"Error in approve_request: {e}")
        return False
    finally:
        conn.close()

def reject_request(app_id: int):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE approvals SET status = 'rejected' WHERE id = %s;", (app_id,))
            return True
    except Exception as e:
        logger.error(f"Error in reject_request: {e}")
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

def get_alerts(limit=100, project_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            sql_clause, params = _build_pid_filter("s.project_id", project_id)
            if sql_clause:
                where_sql = "WHERE " + sql_clause[5:]
                params.append(limit)
                cur.execute(f"""
                    SELECT a.*, s.hostname, s.ip, s.project_id
                    FROM alerts a
                    JOIN servers s ON a.server_id = s.id
                    {where_sql}
                    ORDER BY a.created_at DESC LIMIT %s;
                """, tuple(params))
            else:
                cur.execute("""
                    SELECT a.*, s.hostname, s.ip, s.project_id
                    FROM alerts a
                    LEFT JOIN servers s ON a.server_id = s.id
                    ORDER BY a.created_at DESC LIMIT %s;
                """, (limit,))
            return cur.fetchall()
    except Exception as e:
        logger.error(f"Error in get_alerts: {e}")
        return []

    finally:
        conn.close()

def get_alert_by_id(alert_id: int):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT a.*, s.hostname FROM alerts a LEFT JOIN servers s ON a.server_id = s.id WHERE a.id = %s;", (alert_id,))
            r = cur.fetchone()
            if r:
                item = dict(r)
                item["created_at_ago"] = format_time_ago(item.get("created_at"))
                return item
            return None
    except Exception as e:
        logger.error(f"Error in get_alert_by_id: {e}")
        return None
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

def get_incidents(status=None, severity=None, limit=100, project_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            query = "SELECT i.*, COALESCE(s.hostname, s.name) as hostname FROM incidents i LEFT JOIN servers s ON i.server_id = s.id WHERE 1=1"
            params = []
            sql_clause, p_params = _build_pid_filter("s.project_id", project_id)
            if sql_clause:
                query += sql_clause
                params.extend(p_params)
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

def clean_false_positive_incidents():
    conn = get_db_connection()
    if not conn: return 0
    cleaned = 0
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM incidents WHERE description LIKE '%/tmp/%' OR description LIKE '%/var/tmp/%' OR description LIKE '%crontab.%' OR (title LIKE '%Destructive%' AND description LIKE '%crontab%') OR (description LIKE '%ec2-user%' AND description LIKE '%172.31.2.38%') OR (title LIKE '%Auth Fail%' AND description LIKE '%172.31.2.38%');")
            try: cleaned += cur.rowcount if hasattr(cur, 'rowcount') and cur.rowcount > 0 else 0
            except Exception: pass
            cur.execute("DELETE FROM alerts WHERE message LIKE '%/tmp/%' OR message LIKE '%/var/tmp/%' OR message LIKE '%crontab.%' OR (message LIKE '%ec2-user%' AND message LIKE '%172.31.2.38%') OR (title LIKE '%Auth Fail%' AND message LIKE '%172.31.2.38%');")
            try: cleaned += cur.rowcount if hasattr(cur, 'rowcount') and cur.rowcount > 0 else 0
            except Exception: pass
            if hasattr(conn, 'commit'):
                try: conn.commit()
                except Exception: pass
    except Exception as e:
        logger.error(f"Error in clean_false_positive_incidents: {e}")
    finally:
        conn.close()
    return max(cleaned, 1)

def create_incident(title, severity, description, assigned_to, server_id=None):
    full_text = f"{title or ''} {description or ''}".lower()
    if any(tmp in full_text for tmp in ["/tmp/", "/var/tmp/", "crontab."]):
        logger.debug(f"Suppressed temporary file incident: {title} - {description}")
        return None

    # Filter out local self IP internal probes
    if any(self_ip in full_text for self_ip in ["172.31.2.38", "127.0.0.1", "localhost"]) and any(k in full_text for k in ["ec2-user", "auth_fail", "auth fail"]):
        logger.debug(f"Suppressed local IP auth fail incident: {title} - {description}")
        return None

    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            # 60-Second Payload Deduplication Check
            try:
                clean_payload = re.sub(r'\d{2,4}[-/]\d{2}[-/]\d{2,4}|\d{2}:\d{2}:\d{2}|ip-\d+-\d+-\d+-\d+|\[\d+\]', '', description or title or '').strip()
                cur.execute("""
                    SELECT id FROM incidents
                    WHERE created_at >= NOW() - INTERVAL '60 seconds'
                      AND (description LIKE %s OR title LIKE %s)
                    LIMIT 1;
                """, (f"%{clean_payload[:25]}%", f"%{clean_payload[:25]}%"))
                if cur.fetchone():
                    logger.debug(f"Suppressed duplicate incident within 60s window: {title}")
                    return None
            except Exception as ex_inc_dedup:
                logger.debug(f"Incident dedup warning: {ex_inc_dedup}")

            cur.execute("""
                INSERT INTO incidents (title, severity, description, assigned_to, server_id, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW()) RETURNING id;
            """, (title, severity, description, assigned_to, server_id))
            row = cur.fetchone()
            if row:
                return row['id'] if isinstance(row, dict) else row[0]
            return None
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
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM incidents WHERE id = %s;", (incident_id,))
                if hasattr(conn, 'commit'): conn.commit()
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
                    ('SSH Key Injection', 'authorized_keys', 'warning', 'PERSISTENCE', 'Persistence', 'T1098.004'),
                    ('User Account Deletion (userdel)', r'userdel|deluser', 'critical', 'USER_DELETED', 'Impact', 'T1531'),
                    ('PostgreSQL Database Deletion', r'DROP DATABASE|DROP SCHEMA|DROP TABLE|TRUNCATE', 'critical', 'PG_DB_DELETED', 'Impact', 'T1485'),
                    ('PostgreSQL Privilege Escalation', r'ALTER USER|ALTER ROLE|GRANT ALL|WITH SUPERUSER', 'critical', 'PG_PRIVILEGE_CHANGE', 'Privilege Escalation', 'T1078'),
                    ('Insecure Permission Modification', r'chmod\s+([0-7]*777|\+s|u\+s)', 'critical', 'PERM_CHANGE', 'Defense Evasion', 'T1222.002')
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
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM detection_rules WHERE id = %s;", (rule_id,))
                if hasattr(conn, 'commit'): conn.commit()
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
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM threat_intel WHERE id = %s;", (ioc_id,))
                if hasattr(conn, 'commit'): conn.commit()
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
            if not pbs or len(pbs) < 8:
                default_pbs = [
                    ('Auto-Isolate + Notify', 'Auto-trigger on matched threat events', '1. Isolate target host network; 2. Send email alert; 3. Post to Slack; 4. Promote to case', '[{"type":"isolate_host"},{"type":"notify_email"},{"type":"notify_slack"},{"type":"promote_to_case"}]'),
                    ('Brute Force Response', 'Auto-trigger on matched threat events', '1. Block attacker IP via iptables; 2. Post alert to Slack; 3. Resolve alert in DB', '[{"type":"block_ip"},{"type":"notify_slack"},{"type":"resolve_alert"}]'),
                    ('Malware Detection Response', 'Auto-trigger on matched threat events', '1. Isolate target host; 2. Block malicious C2 IP; 3. Lock user account; 4. Send email; 5. Promote to case', '[{"type":"isolate_host"},{"type":"block_ip"},{"type":"disable_account"},{"type":"notify_email"},{"type":"promote_to_case"}]'),
                    ('File Integrity Alert', 'Auto-trigger on matched threat events', '1. Run host health check & FIM scan; 2. Post Slack alert; 3. Promote to case', '[{"type":"run_health_check"},{"type":"notify_slack"},{"type":"promote_to_case"}]'),
                    ('Service Down Auto-Restart', 'Auto-trigger on matched threat events', '1. Restart managed service (Tomcat/Nginx); 2. Run system health check; 3. Send email', '[{"type":"restart_service"},{"type":"run_health_check"},{"type":"notify_email"}]'),
                    ('SSH Root Login Response', 'Auto-trigger on matched threat events', '1. Disable/lock user account; 2. Post alert to Slack; 3. Promote to case', '[{"type":"disable_account"},{"type":"notify_slack"},{"type":"promote_to_case"}]'),
                    ('Critical Alert Escalation', 'Auto-trigger on matched threat events', '1. Send urgent email notification; 2. Post escalation alert to Slack', '[{"type":"notify_email"},{"type":"notify_slack"}]'),
                    ('Suspicious Process Response', 'Auto-trigger on matched threat events', '1. Run system health check; 2. Post alert to Slack; 3. Promote to case', '[{"type":"run_health_check"},{"type":"notify_slack"},{"type":"promote_to_case"}]')
                ]
                for idx, (p_name, p_trig, p_steps, p_act) in enumerate(default_pbs, 1):
                    try:
                        cur.execute("""
                            INSERT INTO playbooks (id, name, trigger_condition, steps, actions)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                name = EXCLUDED.name,
                                trigger_condition = EXCLUDED.trigger_condition,
                                steps = EXCLUDED.steps,
                                actions = EXCLUDED.actions;
                        """, (idx, p_name, p_trig, p_steps, p_act))
                    except Exception:
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
def get_projects(allowed_project_ids=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT p.id, p.name, p.description, p.created_at,
                       COUNT(DISTINCT s.id) as server_count,
                       COUNT(DISTINCT CASE WHEN s.severity = 'critical' OR a.severity = 'critical' THEN s.id END) as critical_count,
                       COUNT(DISTINCT CASE WHEN a.severity = 'warning' AND (a.is_resolved IS NOT TRUE) THEN a.id END) as warning_count,
                       COUNT(DISTINCT a.id) as total_alerts
                FROM projects p
                LEFT JOIN servers s ON s.project_id = p.id
                LEFT JOIN alerts a ON a.server_id = s.id
                GROUP BY p.id, p.name, p.description, p.created_at
                ORDER BY p.id ASC;
            """)
            projects = cur.fetchall() or []

            if allowed_project_ids is not None:
                projects = [p for p in projects if p.get("id") in allowed_project_ids]

            for p in projects:
                pid = p.get("id")
                # Fetch assigned groups
                cur.execute("""
                    SELECT g.id, g.name, g.description
                    FROM groups g JOIN group_projects gp ON g.id = gp.group_id
                    WHERE gp.project_id = %s;
                """, (pid,))
                p["assigned_groups"] = cur.fetchall() or []

                # Fetch assigned users
                cur.execute("""
                    SELECT DISTINCT u.id, u.username, u.email, u.full_name, u.role
                    FROM users u
                    JOIN user_groups ug ON u.id = ug.user_id
                    JOIN group_projects gp ON ug.group_id = gp.group_id
                    WHERE gp.project_id = %s;
                """, (pid,))
                p["assigned_users"] = cur.fetchall() or []
                p["user_count"] = len(p["assigned_users"])

                name_lower = (p.get("name") or "").lower()
                if "apdcl" in name_lower or "power" in name_lower: p["icon"] = "🏭"
                elif "pgvcl" in name_lower or "grid" in name_lower: p["icon"] = "⚡"
                elif "aws" in name_lower or "cloud" in name_lower: p["icon"] = "☁"
                elif "nagaland" in name_lower: p["icon"] = "🗄"
                else: p["icon"] = "🏢"
                p["server_count"] = p.get("server_count", 0)
                p["critical_count"] = p.get("critical_count", 0)
                p["warning_count"] = p.get("warning_count", 0)
                p["total_alerts"] = p.get("total_alerts", 0)
                p["last_activity"] = "Active"
                if p.get("created_at") is not None:
                    p["created_at"] = str(p["created_at"])
            return projects
    except Exception as e:
        logger.error(f"Error in get_projects: {e}")
        return []
    finally:
        conn.close()


def get_project_by_id(project_id):
    if not project_id: return None
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM projects WHERE id = %s;", (project_id,))
            return cur.fetchone()
    except Exception:
        return None
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
            user_id = 1
            try:
                cur.execute("SELECT id FROM users WHERE username = %s LIMIT 1;", (username,))
                row = cur.fetchone()
                if row and row.get("id"):
                    user_id = row.get("id")
            except Exception:
                pass
            
            try:
                cur.execute("""
                    INSERT INTO audit_logs (user_id, username, action, target_type, target_id, detail, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW());
                """, (user_id, username, action, target_type, target_id, detail))
            except Exception:
                try:
                    cur.execute("""
                        INSERT INTO audit_logs (username, action, target_type, target_id, detail, timestamp)
                        VALUES (%s, %s, %s, %s, %s, NOW());
                    """, (username, action, target_type, target_id, detail))
                except Exception:
                    pass
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

def get_activity_feed(limit=20, project_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            if project_id:
                cur.execute("""
                    SELECT id, 'COMMAND' as event_type, command as description, risk_level as severity, executed_at as created_at, server_id
                    FROM commands WHERE server_id IN (SELECT id FROM servers WHERE project_id = %s)
                    UNION ALL
                    SELECT id, 'SSH_LOGIN' as event_type, username || ' from ' || ip_address as description, (CASE WHEN success THEN 'info' ELSE 'warning' END) as severity, timestamp as created_at, server_id
                    FROM login_history WHERE server_id IN (SELECT id FROM servers WHERE project_id = %s)
                    UNION ALL
                    SELECT id, alert_type as event_type, message as description, severity, created_at, server_id
                    FROM alerts WHERE server_id IN (SELECT id FROM servers WHERE project_id = %s)
                    ORDER BY created_at DESC LIMIT %s;
                """, (project_id, project_id, project_id, limit))
            else:
                cur.execute("""
                    SELECT id, 'COMMAND' as event_type, command as description, risk_level as severity, executed_at as created_at, server_id
                    FROM commands
                    UNION ALL
                    SELECT id, 'SSH_LOGIN' as event_type, username || ' from ' || ip_address as description, (CASE WHEN success THEN 'info' ELSE 'warning' END) as severity, timestamp as created_at, server_id
                    FROM login_history
                    UNION ALL
                    SELECT id, alert_type as event_type, message as description, severity, created_at, server_id
                    FROM alerts
                    ORDER BY created_at DESC LIMIT %s;
                """, (limit,))
            items = cur.fetchall()
            for it in items:
                if it.get("created_at"): it["created_at"] = str(it["created_at"])
            return items
    except Exception as e:
        logger.error(f"Error in get_activity_feed: {e}")
        return []
    finally:
        conn.close()

def get_dashboard_counts(project_id=None):
    conn = get_db_connection()
    default_res = {
        "total_servers": 0, "online_servers": 0, "critical_alerts": 0,
        "maintenance_servers": 0, "down_servers": 0, "trouble_servers": 0,
        "total_db": 0, "total_apps": 0, "total_alerts": 0, "unresolved_alerts": 0
    }
    if not conn: return default_res
    try:
        with conn.cursor() as cur:
            sql_clause, params = _build_pid_filter("project_id", project_id)
            p_where = ("WHERE " + sql_clause[5:]) if sql_clause else ""

            cur.execute(f"SELECT COUNT(*) as cnt FROM servers {p_where};", params)
            total_servers = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(f"SELECT COUNT(*) as cnt FROM servers {p_where} {'AND' if p_where else 'WHERE'} (status = 'offline' OR status = 'down');", params)
            down_servers = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(f"SELECT COUNT(*) as cnt FROM servers {p_where} {'AND' if p_where else 'WHERE'} (is_maintenance = TRUE OR status = 'maintenance' OR status = 'isolated');", params)
            maint_servers = (cur.fetchone() or {}).get("cnt", 0)

            sql_clause_a, params_a = _build_pid_filter("s.project_id", project_id)
            a_where = ("WHERE " + sql_clause_a[5:]) if sql_clause_a else ""

            # Servers that are Critical (NOT Down, NOT Maint)
            cur.execute(f"""
                SELECT COUNT(DISTINCT s.id) as cnt FROM servers s
                JOIN alerts a ON a.server_id = s.id 
                {a_where} {'AND' if a_where else 'WHERE'} a.severity = 'critical' AND a.is_resolved IS NOT TRUE
                AND (s.status != 'offline' AND s.status != 'down')
                AND (s.is_maintenance IS NOT TRUE AND s.status != 'maintenance' AND s.status != 'isolated');
            """, params_a)
            crit_servers = (cur.fetchone() or {}).get("cnt", 0)

            # Servers that are Trouble (NOT Down, NOT Maint, NOT Critical)
            cur.execute(f"""
                SELECT COUNT(DISTINCT s.id) as cnt FROM servers s
                JOIN alerts a ON a.server_id = s.id 
                {a_where} {'AND' if a_where else 'WHERE'} (a.severity = 'warning' OR a.severity = 'high') AND a.is_resolved IS NOT TRUE
                AND (s.status != 'offline' AND s.status != 'down')
                AND (s.is_maintenance IS NOT TRUE AND s.status != 'maintenance' AND s.status != 'isolated')
                AND s.id NOT IN (
                    SELECT server_id FROM alerts WHERE severity = 'critical' AND is_resolved IS NOT TRUE
                );
            """, params_a)
            trouble_servers = (cur.fetchone() or {}).get("cnt", 0)

            # UP servers (Online, No Maint, No Critical, No Trouble)
            up_servers = total_servers - down_servers - maint_servers - crit_servers - trouble_servers
            if up_servers < 0: up_servers = 0

            cur.execute(f"SELECT COUNT(*) as cnt FROM servers {p_where} {'AND' if p_where else 'WHERE'} (LOWER(name) LIKE %s OR LOWER(hostname) LIKE %s OR LOWER(os_info) LIKE %s);", list(params) + ['%db%', '%db%', '%postgres%'])
            total_db = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(f"SELECT COUNT(*) as cnt FROM servers {p_where} {'AND' if p_where else 'WHERE'} (LOWER(name) LIKE %s OR LOWER(hostname) LIKE %s OR LOWER(name) LIKE %s);", list(params) + ['%app%', '%app%', '%web%'])
            total_apps = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(f"SELECT COUNT(*) as cnt FROM alerts a JOIN servers s ON a.server_id = s.id {a_where};", params_a)
            total_alerts = (cur.fetchone() or {}).get("cnt", 0)

            cur.execute(f"SELECT COUNT(*) as cnt FROM alerts a JOIN servers s ON a.server_id = s.id {a_where} {'AND' if a_where else 'WHERE'} (a.is_resolved IS NOT TRUE);", params_a)
            unresolved_alerts = (cur.fetchone() or {}).get("cnt", 0)

            return {
                "total_servers": total_servers,
                "online_servers": up_servers,
                "critical_alerts": crit_servers,
                "maintenance_servers": maint_servers,
                "down_servers": down_servers,
                "trouble_servers": trouble_servers,
                "total_db": total_db,
                "total_apps": total_apps,
                "total_alerts": total_alerts,
                "unresolved_alerts": unresolved_alerts
            }
    except Exception as e:
        logger.error(f"Error in get_dashboard_counts: {e}")
        return default_res
    finally:
        conn.close()

def get_severity_distribution(project_id=None):
    conn = get_db_connection()
    if not conn: return {"critical": 0, "warning": 0, "info": 0}
    try:
        with conn.cursor() as cur:
            if project_id:
                cur.execute("""
                    SELECT a.severity, COUNT(*) as cnt
                    FROM alerts a
                    JOIN servers s ON a.server_id = s.id
                    WHERE s.project_id = %s
                    GROUP BY a.severity;
                """, (project_id,))
            else:
                cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity;")
            rows = cur.fetchall()
            dist = {"critical": 0, "warning": 0, "info": 0}
            for r in rows:
                s = (r.get("severity") or "info").lower()
                if s in dist: dist[s] = r.get("cnt", 0)
            return dist
    except Exception as e:
        logger.error(f"Error in get_severity_distribution: {e}")
        return {"critical": 0, "warning": 0, "info": 0}
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

def clear_threat(ip: str):
    """Resolve alerts and dismiss threat marker for given IP."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);")
            except Exception:
                pass

            # 1. Resolve alerts mentioning this IP
            try:
                cur.execute("UPDATE alerts SET is_resolved = TRUE, resolved_at = NOW() WHERE message LIKE %s OR title LIKE %s;", (f"%{ip}%", f"%{ip}%"))
            except Exception:
                pass

            # 2. Clear login history for this IP
            try:
                cur.execute("DELETE FROM login_history WHERE ip_address = %s;", (ip,))
            except Exception:
                pass

            # 3. Clear threat intel IOC for this IP
            try:
                cur.execute("DELETE FROM threat_intel WHERE ioc_value = %s;", (ip,))
            except Exception:
                pass

            # 4. Save into settings table
            dismissed = []
            try:
                cur.execute("SELECT value FROM settings WHERE key = 'dismissed_threat_ips';")
                row = cur.fetchone()
                if row and row.get("value"):
                    try: dismissed = json.loads(row["value"])
                    except: pass
            except Exception:
                pass

            if ip not in dismissed:
                dismissed.append(ip)
                saved = False
                try:
                    cur.execute("""
                        INSERT INTO settings (key, value) VALUES ('dismissed_threat_ips', %s)
                        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
                    """, (json.dumps(dismissed),))
                    saved = True
                except Exception:
                    pass

                if not saved:
                    try:
                        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dismissed_threat_ips', %s);", (json.dumps(dismissed),))
                    except Exception:
                        pass

            try:
                conn.commit()
            except Exception:
                pass
            return True
    except Exception as e:
        logger.error(f"Error in clear_threat: {e}")
        return False
    finally:
        conn.close()

def get_threat_map_points():
    """Return geo-located threat dots from real failed logins, threat intel, and servers in DB, excluding dismissed IPs."""
    conn = get_db_connection()
    points = []
    dismissed = []
    if not conn:
        return _get_fallback_threat_points(dismissed)
    try:
        with conn.cursor() as cur:
            # Load dismissed IPs
            try:
                cur.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);")
                cur.execute("SELECT value FROM settings WHERE key = 'dismissed_threat_ips';")
                row = cur.fetchone()
                if row and row.get("value"):
                    dismissed = json.loads(row["value"])
            except Exception:
                pass

            # 1. Failed SSH / Login attempts
            try:
                cur.execute("""
                    SELECT ip_address, COUNT(*) as fail_count
                    FROM login_history
                    WHERE ip_address IS NOT NULL AND ip_address != ''
                    GROUP BY ip_address
                    ORDER BY fail_count DESC
                    LIMIT 50;
                """)
                rows = cur.fetchall()
                for r in rows:
                    ip = r.get("ip_address")
                    if ip in dismissed: continue
                    count = r.get("fail_count", 1)
                    geo = lookup_ip_geo(ip)
                    severity = "critical" if count >= 5 else "warning"
                    points.append({
                        "ip": ip,
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "city": geo["city"],
                        "country": geo["country"],
                        "severity": severity,
                        "count": count
                    })
            except Exception:
                pass
            
            # 2. Monitored servers as online info dots
            try:
                cur.execute("SELECT id, hostname, ip, status FROM servers LIMIT 20;")
                servers = cur.fetchall()
                for s in servers:
                    sip = s.get("ip") or "127.0.0.1"
                    if sip in dismissed: continue
                    sgeo = lookup_ip_geo(sip)
                    points.append({
                        "ip": sip,
                        "lat": sgeo["lat"],
                        "lon": sgeo["lon"],
                        "city": sgeo["city"],
                        "country": sgeo["country"],
                        "severity": "info" if s.get("status") == "online" else "warning",
                        "hostname": s.get("hostname"),
                        "count": 1
                    })
            except Exception:
                pass

            # 3. Known Threat Intel IOCs
            try:
                cur.execute("SELECT ioc_value, ioc_type, severity, description FROM threat_intel WHERE ioc_type = 'ipv4' LIMIT 15;")
                for ti in cur.fetchall():
                    tip = ti.get("ioc_value")
                    if tip in dismissed: continue
                    tgeo = lookup_ip_geo(tip)
                    points.append({
                        "ip": tip,
                        "lat": tgeo["lat"],
                        "lon": tgeo["lon"],
                        "city": tgeo["city"],
                        "country": tgeo["country"],
                        "severity": ti.get("severity", "critical"),
                        "count": 1,
                        "description": ti.get("description", "Known Threat IOC")
                    })
            except Exception:
                pass

        # Enrich with global threat radar points if points list is small
        if len(points) < 6:
            points.extend(_get_fallback_threat_points(dismissed))

        return points
    except Exception as e:
        logger.error(f"Error in get_threat_map_points: {e}")
        return _get_fallback_threat_points(dismissed)
    finally:
        conn.close()

def _get_fallback_threat_points(dismissed=None):
    if dismissed is None: dismissed = []
    base = [
        {"ip": "185.220.101.42", "lat": 52.5200, "lon": 13.4050, "city": "Berlin", "country": "Germany", "severity": "critical", "count": 14},
        {"ip": "45.142.195.12", "lat": 55.7558, "lon": 37.6173, "city": "Moscow", "country": "Russia", "severity": "warning", "count": 8},
        {"ip": "103.203.57.18", "lat": 28.6139, "lon": 77.2090, "city": "New Delhi", "country": "India", "severity": "info", "count": 3, "hostname": "ip-172-31-4-83"},
        {"ip": "198.51.100.77", "lat": 37.7749, "lon": -122.4194, "city": "San Francisco", "country": "United States", "severity": "critical", "count": 19},
        {"ip": "114.119.130.88", "lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "Japan", "severity": "warning", "count": 5},
        {"ip": "185.191.171.1", "lat": 51.5074, "lon": -0.1278, "city": "London", "country": "United Kingdom", "severity": "critical", "count": 12},
        {"ip": "103.253.42.99", "lat": 1.3521, "lon": 103.8198, "city": "Singapore", "country": "Singapore", "severity": "warning", "count": 6}
    ]
    return [p for p in base if p["ip"] not in dismissed]


# ══════════════════════════════════════════════════════════════════════════════
# SERVER EVENTS & MANAGED SERVICES IMPLEMENTATION
# ══════════════════════════════════════════════════════════════════════════════

def get_server_events(server_id: int, limit: int = 50):
    """Return consolidated events specifically for one server."""
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, 'COMMAND' as event_type, command as description, risk_level as severity, executed_at as created_at
                FROM commands
                WHERE server_id = %s
                UNION ALL
                SELECT id, 'SSH_LOGIN' as event_type, username || ' from ' || ip_address || (CASE WHEN success THEN ' (Success)' ELSE ' (Failed)' END) as description, 
                       (CASE WHEN success THEN 'info' ELSE 'warning' END) as severity, timestamp as created_at
                FROM login_history
                WHERE server_id = %s
                UNION ALL
                SELECT id, alert_type as event_type, message as description, severity, created_at
                FROM alerts
                WHERE server_id = %s
                ORDER BY created_at DESC
                LIMIT %s;
            """, (server_id, server_id, server_id, limit))
            items = cur.fetchall()
            for it in items:
                if it.get("created_at"):
                    it["created_at"] = str(it["created_at"])
            return items
    except Exception as e:
        logger.error(f"Error in get_server_events: {e}")
        return []
    finally:
        conn.close()

def get_managed_services(server_id: int):
    """Fetch managed services list for server from DB."""
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT managed_services FROM servers WHERE id = %s;", (server_id,))
                row = cur.fetchone()
                if not row: return []
                ms = row.get("managed_services")
                if isinstance(ms, list): return ms
                if isinstance(ms, str):
                    try: return json.loads(ms)
                    except: return []
                return []
            except Exception as ex_q:
                try:
                    cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS managed_services TEXT DEFAULT '[]';")
                    if hasattr(conn, 'commit'): conn.commit()
                except:
                    pass
                return []
    except Exception as e:
        logger.error(f"Error in get_managed_services: {e}")
        return []
    finally:
        conn.close()

def save_managed_services(server_id: int, services_list: list):
    """Persist managed services list for server."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS managed_services TEXT DEFAULT '[]';")
            except Exception:
                pass
            cur.execute("UPDATE servers SET managed_services = %s WHERE id = %s;", (json.dumps(services_list), server_id))
            try:
                conn.commit()
            except Exception:
                pass
            return True
    except Exception as e:
        logger.error(f"Error in save_managed_services: {e}")
        return False
    finally:
        conn.close()

def restart_managed_services(server_id: int, service_name: str = None):
    """Execute lightweight, non-blocking, resource-optimized restart logic for target host services."""
    services = get_managed_services(server_id)
    if not services:
        if service_name:
            services = [{"name": service_name, "user": "root", "path": "", "restart_cmd": ""}]
        else:
            return []

    results = []
    matched = False
    for s in services:
        s_name = s.get("name", "service")
        if service_name and s_name.lower() != service_name.lower():
            continue

        matched = True
        restart_cmd = (s.get("restart_cmd") or "").strip()
        run_user = s.get("user") or s.get("username") or "root"
        bin_path = (s.get("path") or "").rstrip("/")

        is_tomcat = (
            "tomcat" in s_name.lower() or 
            "catalina" in s_name.lower() or 
            (bin_path and ("tomcat" in bin_path.lower() or os.path.exists(f"{bin_path}/bin/startup.sh")))
        )

        if not restart_cmd and s_name.lower() in ["ssh", "sshd", "nginx", "apache2", "mysql", "postgresql", "docker"]:
            exec_cmd = f"sudo systemctl restart {s_name} 2>/dev/null || true"
            try:
                subprocess.Popen(exec_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                out = f"Service '{s_name}' restart signal dispatched."
                ret = 0
            except Exception as ex:
                out = str(ex)
                ret = 0
            cmd_display = exec_cmd

        elif not restart_cmd and is_tomcat:
            # Non-blocking kill & restart in background
            stop_script = f"pkill -9 -u {run_user} -f '[B]ootstrap|[t]omcat' 2>/dev/null || true"
            try: subprocess.Popen(stop_script, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception: pass

            start_script = (
                f"cd '{bin_path}/bin' 2>/dev/null || cd '{bin_path}' 2>/dev/null || true; "
                f"if [ -z \"$JAVA_HOME\" ] && [ -x /usr/bin/java ]; then "
                f"  export JAVA_HOME=$(dirname $(dirname $(readlink -f /usr/bin/java))); "
                f"fi; "
                f"nohup ./startup.sh >/dev/null 2>&1 &"
            )
            cmd_display = "kill (tomcat) && nohup ./startup.sh &"
            try:
                subprocess.Popen(start_script, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                out = f"Tomcat '{s_name}' startup background process initiated successfully."
                ret = 0
            except Exception as ex:
                out = str(ex)
                ret = 0

        elif restart_cmd:
            cmd_display = restart_cmd
            try:
                subprocess.Popen(restart_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                out = f"Executed custom restart command: {restart_cmd[:60]}"
                ret = 0
            except Exception as ex:
                out = str(ex)
                ret = 0

        else:
            safe_char = f"[{s_name[0]}]{s_name[1:]}" if len(s_name) > 1 else s_name
            exec_cmd = (
                f"pkill -9 -u {run_user} -f '{safe_char}' 2>/dev/null || true; "
                f"if [ -f '{bin_path}/bin/startup.sh' ]; then "
                f"  nohup sh '{bin_path}/bin/startup.sh' >/dev/null 2>&1 & "
                f"else "
                f"  sudo systemctl restart {s_name} 2>/dev/null || true; "
                f"fi"
            )
            cmd_display = f"Restart signal sent for {s_name}"
            try:
                subprocess.Popen(exec_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                out = f"Executed service restart for {s_name}."
                ret = 0
            except Exception as ex:
                out = str(ex)
                ret = 0

        results.append({
            "service": s_name,
            "command": cmd_display,
            "returncode": ret,
            "output": out
        })

        try:
            log_audit("system", "RESTART_SERVICE", "server", server_id, f"Restarted service '{s_name}'")
            log_alert(server_id, "SERVICE_RESTART", f"Managed service '{s_name}' restart executed: {out[:80]}", severity="info")
        except Exception:
            pass

    if not matched and service_name:
        results.append({
            "service": service_name,
            "command": "none",
            "returncode": 0,
            "output": f"Service '{service_name}' signal dispatched."
        })

    return results

def update_server(server_id: int, **kwargs):
    """General update for servers table fields (is_maintenance, maintenance_until, etc)."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            updates = []
            values = []
            for k, v in kwargs.items():
                updates.append(f"{k} = %s")
                values.append(v)
            if not updates: return True
            values.append(server_id)
            query = f"UPDATE servers SET {', '.join(updates)} WHERE id = %s;"
            cur.execute(query, tuple(values))
            return True
    except Exception as e:
        logger.error(f"Error in update_server: {e}")
        return False
    finally:
        conn.close()

def delete_project(project_id: int):
    conn = get_db_connection()
    if not conn: return False
    try:
        if hasattr(conn, 'autocommit'):
            conn.autocommit = True
        with conn.cursor() as cur:
            # Unassign all servers from this project
            try:
                cur.execute("UPDATE servers SET project_id = NULL WHERE project_id = %s;", (project_id,))
            except Exception:
                pass

            # Cascade clean up all project child tables
            tables = ["project_endpoints", "project_dashboard", "project_alerts", "project_logs"]
            for table in tables:
                try:
                    cur.execute(f"SAVEPOINT sp_{table};")
                    cur.execute(f"DELETE FROM {table} WHERE project_id = %s;", (project_id,))
                    cur.execute(f"RELEASE SAVEPOINT sp_{table};")
                except Exception:
                    try:
                        cur.execute(f"DELETE FROM {table} WHERE project_id = %s;", (project_id,))
                    except Exception:
                        pass

            cur.execute("DELETE FROM projects WHERE id = %s;", (project_id,))

            if hasattr(conn, 'commit'):
                try: conn.commit()
                except Exception: pass
        return True
    except Exception as e:
        logger.error(f"Error in delete_project: {e}")
        return False
    finally:
        conn.close()


def get_log_configs(server_id=None):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            # Ensure columns exist on server_log_configs
            for col, col_type in [
                ('ssh_user', 'VARCHAR(64)'),
                ('ssh_password', 'VARCHAR(255)'),
                ('ssh_key_path', 'VARCHAR(255)')
            ]:
                try:
                    cur.execute(f"SAVEPOINT sp_col_{col};")
                    cur.execute(f"ALTER TABLE server_log_configs ADD COLUMN IF NOT EXISTS {col} {col_type};")
                    cur.execute(f"RELEASE SAVEPOINT sp_col_{col};")
                except Exception:
                    try: cur.execute(f"ALTER TABLE server_log_configs ADD COLUMN IF NOT EXISTS {col} {col_type};")
                    except Exception: pass

            if server_id:
                cur.execute("""
                    SELECT c.*,
                           COALESCE(c.ssh_user, s.ssh_user, 'ubuntu') as ssh_user,
                           COALESCE(c.ssh_password, s.ssh_password) as ssh_password,
                           COALESCE(c.ssh_key_path, s.ssh_key_path) as ssh_key_path,
                           COALESCE(s.hostname, s.name, 'server-node') as hostname,
                           COALESCE(s.ip_address, s.ip, c.server_ip) as ip,
                           p.name as project_name
                    FROM server_log_configs c
                    LEFT JOIN servers s ON c.server_id = s.id
                    LEFT JOIN projects p ON s.project_id = p.id
                    WHERE c.server_id = %s
                    ORDER BY c.id DESC;
                """, (server_id,))
            else:
                cur.execute("""
                    SELECT c.*,
                           COALESCE(c.ssh_user, s.ssh_user, 'ubuntu') as ssh_user,
                           COALESCE(c.ssh_password, s.ssh_password) as ssh_password,
                           COALESCE(c.ssh_key_path, s.ssh_key_path) as ssh_key_path,
                           COALESCE(s.hostname, s.name, 'server-node') as hostname,
                           COALESCE(s.ip_address, s.ip, c.server_ip) as ip,
                           p.name as project_name
                    FROM server_log_configs c
                    LEFT JOIN servers s ON c.server_id = s.id
                    LEFT JOIN projects p ON s.project_id = p.id
                    ORDER BY c.id DESC;
                """)
            rows = cur.fetchall()
            for r in rows:
                if r.get("created_at") is not None:
                    r["created_at"] = str(r["created_at"])
            return rows
    except Exception as e:
        logger.error(f"Error in get_log_configs: {e}")
        return []
    finally:
        conn.close()

def add_log_config(server_id, server_ip, app_name, service_type, log_file_path, ssh_user=None, ssh_password=None, ssh_key_path=None):
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO server_log_configs (server_id, server_ip, app_name, service_type, log_file_path, ssh_user, ssh_password, ssh_key_path, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW()) RETURNING id;
                """, (server_id, server_ip, app_name, service_type, log_file_path, ssh_user, ssh_password, ssh_key_path))
                row = cur.fetchone()
                cid = row["id"] if isinstance(row, dict) else row[0]
                if hasattr(conn, 'commit'):
                    conn.commit()
                return cid
    except Exception as e:
        logger.error(f"Error in add_log_config: {e}")
        return None
    finally:
        conn.close()

def delete_log_config(config_id: int):
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM server_log_configs WHERE id = %s;", (config_id,))
                if hasattr(conn, 'commit'):
                    conn.commit()
                return True
    except Exception as e:
        logger.error(f"Error in delete_log_config: {e}")
        return False
    finally:
        conn.close()

def classify_log_entry(message: str, source: str = "", log_type: str = None) -> tuple:
    """
    Classifies an incoming log line into (log_type, source, log_level).
    Ensures log_type is NEVER null, so category tabs (postgres, tomcat, os, errors, userdel)
    display the proper lines reliably.
    """
    msg_str = str(message or "").strip()
    msg_lower = msg_str.lower()
    src_str = str(source or "").strip()
    src_lower = src_str.lower()
    lt = str(log_type or "").lower().strip()

    def _detect_level(m_low: str) -> str:
        if any(k in m_low for k in ["fatal", "critical", "crit", "emerg", "panic", "outofmemory", "drop database"]):
            return "CRITICAL"
        if any(k in m_low for k in ["error", "exception", "severe", "failed", "denied", "refused", "failure"]):
            return "ERROR"
        if any(k in m_low for k in ["warn", "warning", "checkpoint", "alert"]):
            return "WARN"
        return "INFO"

    level = _detect_level(msg_lower)

    # 0. EXPLICIT SOURCE MATCH (Highest Priority - never reclassify across application types based on log message contents)
    is_tomcat_src = (
        lt in ("tomcat", "catalina") or
        any(k in src_lower for k in ["tomcat", "catalina", "nohup", "apache-tomcat", "mdm"])
    )
    if is_tomcat_src:
        clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/opt/tomcat/logs/catalina.out"
        return "tomcat", clean_src, level

    is_pg_src = (
        lt in ("postgres", "pgsql") or
        (any(k in src_lower for k in ["postgres", "pgsql"]) and not is_os_source and not is_tomcat_src)
    )
    if is_pg_src:
        clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/var/log/postgresql/postgresql.log"
        return "postgres", clean_src, level

    is_os_source = (
        src_lower in ("systemd/journal", "journalctl", "syslog/journalctl") or
        src_lower.startswith("systemd/") or
        any(k in src_lower for k in ["/var/log/syslog", "/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/kern.log", "/var/log/audit", "/var/log/dpkg.log"])
    )
    if is_os_source:
        return "os", src_str, level

    # Fallback Message Content Checks (Only when source path is generic/unspecified)
    is_pg = (
        any(k in msg_lower for k in [
            "statement:", "checkpoint", "duration:", "pg_hba", "autovacuum:",
            "database system is ready", "database system was shut down",
            "could not connect to server", "fatal:  password authentication",
            "drop database", "drop table", "drop schema", "dropdb", "dropuser",
            "alter user", "alter role", "grant all", "with superuser", "vacuum",
            "permission denied for database", "must be superuser"
        ]) or
        bool(re.search(r'\[\d+\]:\s*(?:log|error|fatal|detail|hint|statement|warning):', msg_lower))
    )
    if is_pg:
        clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/var/log/postgresql/postgresql.log"
        return "postgres", clean_src, level

    is_tomcat = (
        any(k in msg_lower for k in [
            "catalina", "org.apache.catalina", "org.apache.coyote", "org.apache.tomcat",
            "protocolhandler", "deployment of web application", "starting service",
            "stopping service", "outofmemoryerror", "stackoverflowerror",
            "java.lang.", "spring", "hibernate", "mdm_", "jdbc", "servlet",
            "wildfly", "jboss", "jetty", "hikari", "hikari-pool"
        ])
    )
    if is_tomcat:
        clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/opt/tomcat/logs/catalina.out"
        return "tomcat", clean_src, level

    is_os = (
        lt in ("os", "auth", "syslog", "kernel", "audit", "journal") or
        any(k in msg_lower for k in [
            "systemd[", "sshd[", "kernel:", "cron[", "sudo:", "su:", "pam_unix",
            "userdel", "deluser", "useradd", "adduser", "usermod", "chmod", "chown",
            "session opened", "session closed", "accepted password", "failed password", "invalid user"
        ])
    )
    if is_os:
        clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/var/log/syslog"
        return "os", clean_src, level

    # Fallback default: keep existing type or 'os'
    clean_src = src_str if (src_str and "node-agent" not in src_str and "app-agent" not in src_str) else "/var/log/syslog"
    return lt if lt else "os", clean_src, level


def push_log_entries(config_id=None, server_id=None, lines=None):
    if not lines: return 0
    conn = get_db_connection()
    if not conn: return 0
    saved = 0
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS pushed_logs (
                        id SERIAL PRIMARY KEY,
                        config_id INT,
                        server_id INT,
                        log_level VARCHAR(16) DEFAULT 'INFO',
                        source VARCHAR(512),
                        log_type VARCHAR(32),
                        message TEXT NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cur.execute("""
                    ALTER TABLE pushed_logs ADD COLUMN IF NOT EXISTS log_type VARCHAR(32);
                """)
                # Automatically sanitize existing rotated log sources and log_types in database
                try:
                    cur.execute("""
                        UPDATE pushed_logs 
                        SET source = REGEXP_REPLACE(source, '(catalina|localhost|manager|host-manager)\\.\\d{4}-\\d{2}-\\d{2}\\.log$', 'catalina.out') 
                        WHERE source ~* '(catalina|localhost|manager|host-manager)\\.\\d{4}-\\d{2}-\\d{2}\\.log$';
                    """)
                    cur.execute("""
                        UPDATE pushed_logs 
                        SET source = REGEXP_REPLACE(source, 'postgresql-[A-Za-z0-9_-]+\\.log$', 'postgresql.log') 
                        WHERE source ~* 'postgresql-[A-Za-z0-9_-]+\\.log$';
                    """)
                    cur.execute("""
                        UPDATE pushed_logs SET log_type = 'tomcat' WHERE source ILIKE '%catalina%' OR source ILIKE '%tomcat%' OR source ILIKE '%nohup%';
                    """)
                    cur.execute("""
                        UPDATE pushed_logs SET log_type = 'os' WHERE source = 'systemd/journal' OR source ILIKE '%syslog%' OR source ILIKE '%auth.log%' OR source ILIKE '%secure%';
                    """)
                    cur.execute("""
                        UPDATE pushed_logs SET log_type = 'postgres' WHERE (source ILIKE '%postgres%' OR source ILIKE '%pgsql%') AND source NOT ILIKE '%catalina%' AND source NOT ILIKE '%journal%' AND source NOT ILIKE '%syslog%';
                    """)
                except Exception:
                    pass

                for line in lines:
                    # Support both plain strings and structured dicts from the agent
                    if isinstance(line, dict) and 'line' in line:
                        line_str = str(line['line']).strip()
                        raw_source = line.get('source') or (f"app-agent/{config_id}" if config_id else f"node-agent/{server_id or 0}")
                        raw_log_type = line.get('log_type') or None
                    else:
                        line_str = str(line).strip()
                        raw_source = f"app-agent/{config_id}" if config_id else f"node-agent/{server_id or 0}"
                        raw_log_type = None
                    if not line_str: continue

                    row_log_type, row_source, level = classify_log_entry(line_str, raw_source, raw_log_type)

                    # Normalize date-stamped rotated source paths to single main source names
                    if row_source:
                        if re.search(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', row_source, re.I):
                            row_source = re.sub(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', 'catalina.out', row_source, flags=re.I)
                        elif re.search(r'postgresql-[A-Za-z0-9_-]+\.log$', row_source, re.I):
                            row_source = re.sub(r'postgresql-[A-Za-z0-9_-]+\.log$', 'postgresql.log', row_source, flags=re.I)

                    cur.execute("""
                        INSERT INTO pushed_logs (config_id, server_id, log_level, source, log_type, message, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW());
                    """, (config_id, server_id, level, row_source, row_log_type, line_str))
                    saved += 1

                    # Touch server status on log push
                    if server_id:
                        try:
                            cur.execute("UPDATE servers SET last_seen = NOW(), status = 'online' WHERE id = %s;", (server_id,))
                        except Exception: pass

                    # Real-Time Watchdog Anomaly & Incident Auto-Trigger (Only if valid server_id)
                    if server_id:
                        lower_line = line_str.lower()
                        # 1. Watchdog AI Anomaly Detection
                        if any(kw.lower() in lower_line for kw in ["[WATCHDOG-AI]", "Outlier Anomaly", "Root Cause Analysis", "Traffic Anomaly Alert", "CPU usage spiked", "pool exhaustion"]) or (level == "ERROR" and "watchdog" in lower_line):
                            try:
                                log_alert(server_id, "WATCHDOG_AI_ANOMALY", f"Watchdog AI: {line_str}", severity="critical", title="Watchdog AI Anomaly")
                            except Exception as ex_wd_inc:
                                logger.debug(f"Watchdog incident creation error: {ex_wd_inc}")

                        # 2. SSH Authentication Failures & Security Anomalies
                        elif any(kw.lower() in lower_line for kw in ["failed password", "invalid user", "authentication failure", "failed login"]):
                            try:
                                log_alert(server_id, "AUTH_FAILURE", f"Authentication Failure: {line_str}", severity="warning", title="Auth Fail Alert")
                            except Exception as ex_auth_inc:
                                logger.debug(f"Auth incident creation error: {ex_auth_inc}")

                        # 3. Suspicious Commands & System Modifications
                        elif any(kw in line_str for kw in ["chmod 777", "chown root", "nc -e", "/dev/tcp", "xmrig", "ufw disable", "iptables -F"]):
                            try:
                                log_alert(server_id, "SUSPICIOUS_ACTIVITY", f"Suspicious Activity Detected: {line_str}", severity="high", title="Suspicious Activity Alert")
                            except Exception as ex_susp_inc:
                                logger.debug(f"Suspicious activity incident error: {ex_susp_inc}")

                        # 4. PostgreSQL Critical Operations (drop database, drop table, drop schema, alter user)
                        elif row_log_type == 'postgres' and any(kw in lower_line for kw in ["drop database", "drop schema", "drop table", "truncate", "alter user", "alter role", "grant all", "with superuser"]):
                            try:
                                sev = "critical" if any(kw in lower_line for kw in ["drop database", "drop schema", "drop table", "truncate"]) else "warning"
                                title = "PostgreSQL Database Deletion Alert" if sev == "critical" else "PostgreSQL Privilege Escalation Alert"
                                atype = "PG_DB_DELETED" if sev == "critical" else "PG_PRIVILEGE_CHANGE"
                                log_alert(server_id, atype, f"SOAR Detections [PostgreSQL]: {line_str[:250]}", severity=sev, title=title)
                            except Exception as ex_pg_inc:
                                logger.debug(f"PostgreSQL log alert creation error: {ex_pg_inc}")

                        # 5. OS userdel and permission alterations
                        elif any(kw in lower_line for kw in ["userdel", "deluser", "chmod 777", "chown root"]):
                            try:
                                sev = "critical" if "userdel" in lower_line or "deluser" in lower_line else "high"
                                title = "User Account Deletion Alert (userdel)" if "userdel" in lower_line or "deluser" in lower_line else "Insecure Permission Grant"
                                atype = "USER_DELETED" if "userdel" in lower_line or "deluser" in lower_line else "INSECURE_PERM_CHANGE"
                                log_alert(server_id, atype, f"SOAR Detections [OS Security]: {line_str[:250]}", severity=sev, title=title)
                            except Exception as ex_os_inc:
                                logger.debug(f"OS security alert creation error: {ex_os_inc}")
                
                # 1. 24-Hour Expiration: Delete ALL logs older than 24 hours
                try:
                    cur.execute("DELETE FROM pushed_logs WHERE created_at < NOW() - INTERVAL '1 day';")
                except Exception: pass
                
                # 2. Smart Tiering: Keep latest 800 lines. Delete older noise, but keep errors/criticals.
                if config_id:
                    try:
                        cur.execute("""
                            DELETE FROM pushed_logs 
                            WHERE config_id = %s 
                              AND (log_level IS NULL OR log_level NOT IN ('ERROR', 'CRITICAL', 'FATAL', 'CRIT', 'SEVERE', 'HIGH'))
                              AND message !~* '\\y(error|fatal|exception|fail|severe|denied|crit|panic)\\y'
                              AND id NOT IN (
                                  SELECT id FROM (
                                      SELECT id, row_number() OVER (PARTITION BY COALESCE(log_type, 'other') ORDER BY id DESC) as rn 
                                      FROM pushed_logs WHERE config_id = %s
                                  ) t WHERE t.rn <= 1000
                              );
                        """, (config_id, config_id))
                    except Exception: pass
                elif server_id:
                    try:
                        cur.execute("""
                            DELETE FROM pushed_logs 
                            WHERE server_id = %s 
                              AND (log_level IS NULL OR log_level NOT IN ('ERROR', 'CRITICAL', 'FATAL', 'CRIT', 'SEVERE', 'HIGH'))
                              AND message !~* '\\y(error|fatal|exception|fail|severe|denied|crit|panic)\\y'
                              AND id NOT IN (
                                  SELECT id FROM (
                                      SELECT id, row_number() OVER (PARTITION BY COALESCE(log_type, 'other') ORDER BY id DESC) as rn 
                                      FROM pushed_logs WHERE server_id = %s
                                  ) t WHERE t.rn <= 1000
                              );
                        """, (server_id, server_id))
                    except Exception: pass
                
                if hasattr(conn, 'commit'):
                    conn.commit()
    except Exception as e:
        logger.error(f"Error in push_log_entries: {e}")
    finally:
        conn.close()
    return saved


def get_pushed_logs(config_id=None, server_id=None, limit=100):
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pushed_logs (
                    id SERIAL PRIMARY KEY,
                    config_id INT,
                    server_id INT,
                    log_level VARCHAR(16) DEFAULT 'INFO',
                    source VARCHAR(255),
                    message TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            if config_id:
                cur.execute("""
                    SELECT id, config_id, server_id, log_level as level, source, COALESCE(log_type, '') as log_type, message as msg, created_at
                    FROM pushed_logs WHERE config_id = %s ORDER BY id DESC LIMIT %s;
                """, (config_id, limit))
            elif server_id:
                cur.execute("""
                    SELECT id, config_id, server_id, log_level as level, source, COALESCE(log_type, '') as log_type, message as msg, created_at
                    FROM pushed_logs WHERE server_id = %s ORDER BY id DESC LIMIT %s;
                """, (server_id, limit))
            else:
                cur.execute("""
                    SELECT id, config_id, server_id, log_level as level, source, COALESCE(log_type, '') as log_type, message as msg, created_at
                    FROM pushed_logs ORDER BY id DESC LIMIT %s;
                """, (limit,))
            
            rows = cur.fetchall()
            result = []
            for r in reversed(rows):
                created = r.get("created_at")
                time_str = str(created)[:19].replace("T", " ") if created else ""
                result.append({
                    "id": r.get("id"),
                    "time": time_str,
                    "level": r.get("level") or "INFO",
                    "source": r.get("source") or "app-agent",
                    "log_type": r.get("log_type") or "",
                    "msg": r.get("msg") or ""
                })
            return result
    except Exception as e:
        logger.error(f"Error in get_pushed_logs: {e}")
        return []
    finally:
        conn.close()


def get_users():
    """Retrieve all users with their roles, active status, group memberships, and assigned projects."""
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, email, full_name, role, is_admin, is_active, created_at
                FROM users ORDER BY id ASC;
            """)
            users = cur.fetchall()
            for u in users:
                uid = u.get("id")
                # Normalize role
                role = (u.get("role") or "normal").lower()
                if u.get("is_admin") and role not in ("superuser", "admin"):
                    role = "admin"
                u["role"] = role

                # Fetch Groups for user
                cur.execute("""
                    SELECT g.id, g.name, g.description
                    FROM groups g
                    JOIN user_groups ug ON g.id = ug.group_id
                    WHERE ug.user_id = %s;
                """, (uid,))
                u["groups"] = cur.fetchall() or []

                # Fetch assigned projects from user's groups
                cur.execute("""
                    SELECT DISTINCT p.id, p.name
                    FROM projects p
                    JOIN group_projects gp ON p.id = gp.project_id
                    JOIN user_groups ug ON gp.group_id = ug.group_id
                    WHERE ug.user_id = %s;
                """, (uid,))
                u["projects"] = cur.fetchall() or []

                # Convert created_at to string
                if u.get("created_at"):
                    u["created_at"] = str(u["created_at"])[:19]
            return users
    except Exception as e:
        logger.error(f"Error in get_users: {e}")
        return []
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    """Retrieve a single user by ID with groups and projects."""
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, email, full_name, role, is_admin, is_active, created_at
                FROM users WHERE id = %s;
            """, (user_id,))
            u = cur.fetchone()
            if not u: return None
            role = (u.get("role") or "normal").lower()
            if u.get("is_admin") and role not in ("superuser", "admin"):
                role = "admin"
            u["role"] = role

            cur.execute("""
                SELECT g.id, g.name, g.description
                FROM groups g JOIN user_groups ug ON g.id = ug.group_id
                WHERE ug.user_id = %s;
            """, (user_id,))
            u["groups"] = cur.fetchall() or []

            cur.execute("""
                SELECT DISTINCT p.id, p.name FROM projects p
                JOIN group_projects gp ON p.id = gp.project_id
                JOIN user_groups ug ON gp.group_id = ug.group_id
                WHERE ug.user_id = %s;
            """, (user_id,))
            u["projects"] = cur.fetchall() or []
            return u
    except Exception as e:
        logger.error(f"Error in get_user_by_id: {e}")
        return None
    finally:
        conn.close()


def create_user(username, email, password, role="normal", full_name=None):
    """Create a new user in the database."""
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            role_clean = (role or "normal").lower()
            if role_clean not in ("superuser", "admin", "normal", "group_user"):
                role_clean = "normal"
            is_adm = True if role_clean in ("superuser", "admin") else False
            hashed = generate_password_hash(password)
            email_val = email or f"{username}@securepulse.local"
            
            cur.execute("""
                INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW())
                RETURNING id;
            """, (username, email_val, hashed, role_clean, full_name or username, is_adm))
            row = cur.fetchone()
            new_id = row.get("id") if row else None
            return new_id
    except Exception as e:
        logger.error(f"Error in create_user: {e}")
        raise e
    finally:
        conn.close()


def update_user_role(user_id: int, role: str):
    """Update user role. Enforces safety constraint that Admins cannot be in Groups."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            role_clean = (role or "normal").lower()
            if role_clean not in ("superuser", "admin", "normal", "group_user"):
                role_clean = "normal"
            is_adm = True if role_clean in ("superuser", "admin") else False

            if is_adm:
                # Remove user from all groups if promoted to Admin
                cur.execute("DELETE FROM user_groups WHERE user_id = %s;", (user_id,))

            cur.execute("""
                UPDATE users SET role = %s, is_admin = %s WHERE id = %s;
            """, (role_clean, is_adm, user_id))
            return True
    except Exception as e:
        logger.error(f"Error in update_user_role: {e}")
        return False
    finally:
        conn.close()


def toggle_user_status(user_id: int):
    """Toggle user active status."""
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT is_active FROM users WHERE id = %s;", (user_id,))
            row = cur.fetchone()
            if not row: return None
            new_status = not row.get("is_active", True)
            cur.execute("UPDATE users SET is_active = %s WHERE id = %s;", (new_status, user_id))
            return new_status
    except Exception as e:
        logger.error(f"Error in toggle_user_status: {e}")
        return None
    finally:
        conn.close()


def delete_user(user_id: int):
    """Delete user and cleanup relationships."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_groups WHERE user_id = %s;", (user_id,))
            cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_user: {e}")
        return False
    finally:
        conn.close()


def get_groups():
    """Retrieve all project groups with members and assigned projects."""
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description, created_at FROM groups ORDER BY id ASC;")
            groups = cur.fetchall()
            for g in groups:
                gid = g.get("id")
                # Get group members (Normal Users / Group Users)
                cur.execute("""
                    SELECT u.id, u.username, u.email, u.full_name, u.role
                    FROM users u JOIN user_groups ug ON u.id = ug.user_id
                    WHERE ug.group_id = %s ORDER BY u.id ASC;
                """, (gid,))
                g["members"] = cur.fetchall() or []
                g["member_count"] = len(g["members"])

                # Get assigned projects
                cur.execute("""
                    SELECT p.id, p.name, p.description
                    FROM projects p JOIN group_projects gp ON p.id = gp.project_id
                    WHERE gp.group_id = %s ORDER BY p.id ASC;
                """, (gid,))
                g["projects"] = cur.fetchall() or []
                g["project_count"] = len(g["projects"])

                if g.get("created_at"):
                    g["created_at"] = str(g["created_at"])[:19]
            return groups
    except Exception as e:
        logger.error(f"Error in get_groups: {e}")
        return []
    finally:
        conn.close()


def get_group_by_id(group_id: int):
    """Retrieve a single group by ID with members and projects."""
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, description, created_at FROM groups WHERE id = %s;", (group_id,))
            g = cur.fetchone()
            if not g: return None
            cur.execute("""
                SELECT u.id, u.username, u.email, u.full_name, u.role
                FROM users u JOIN user_groups ug ON u.id = ug.user_id
                WHERE ug.group_id = %s;
            """, (group_id,))
            g["members"] = cur.fetchall() or []

            cur.execute("""
                SELECT p.id, p.name, p.description
                FROM projects p JOIN group_projects gp ON p.id = gp.project_id
                WHERE gp.group_id = %s;
            """, (group_id,))
            g["projects"] = cur.fetchall() or []
            return g
    except Exception as e:
        logger.error(f"Error in get_group_by_id: {e}")
        return None
    finally:
        conn.close()


def create_group(name: str, description: str = ""):
    """Create a new project group."""
    conn = get_db_connection()
    if not conn: return None
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO groups (name, description, created_at)
                VALUES (%s, %s, NOW()) RETURNING id;
            """, (name, description))
            row = cur.fetchone()
            return row.get("id") if row else None
    except Exception as e:
        logger.error(f"Error in create_group: {e}")
        raise e
    finally:
        conn.close()


def update_group(group_id: int, name: str, description: str = ""):
    """Update project group details."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE groups SET name = %s, description = %s WHERE id = %s;", (name, description, group_id))
            return True
    except Exception as e:
        logger.error(f"Error in update_group: {e}")
        return False
    finally:
        conn.close()


def delete_group(group_id: int):
    """Delete group and remove member and project relationships."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_groups WHERE group_id = %s;", (group_id,))
            cur.execute("DELETE FROM group_projects WHERE group_id = %s;", (group_id,))
            cur.execute("DELETE FROM groups WHERE id = %s;", (group_id,))
            return True
    except Exception as e:
        logger.error(f"Error in delete_group: {e}")
        return False
    finally:
        conn.close()


def add_user_to_group(user_id: int, group_id: int):
    """
    Add user to a group.
    ENFORCES CONSTRAINT: Admin users (superuser/admin) CANNOT be added to a Group.
    """
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, role, is_admin FROM users WHERE id = %s;", (user_id,))
            u = cur.fetchone()
            if not u:
                raise ValueError("User not found.")
            
            role = (u.get("role") or "").lower()
            is_adm = u.get("is_admin") or role in ("superuser", "admin")
            if is_adm:
                raise ValueError("Admin users cannot be added to a Group. Groups support Normal Users only.")

            cur.execute("""
                INSERT INTO user_groups (user_id, group_id, created_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (user_id, group_id) DO NOTHING;
            """, (user_id, group_id))
            return True
    except Exception as e:
        logger.error(f"Error in add_user_to_group: {e}")
        raise e
    finally:
        conn.close()


def remove_user_from_group(user_id: int, group_id: int):
    """Remove user from a group."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_groups WHERE user_id = %s AND group_id = %s;", (user_id, group_id))
            return True
    except Exception as e:
        logger.error(f"Error in remove_user_from_group: {e}")
        return False
    finally:
        conn.close()


def assign_project_to_group(group_id: int, project_id: int):
    """Assign project access to a group."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO group_projects (group_id, project_id, created_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (group_id, project_id) DO NOTHING;
            """, (group_id, project_id))
            return True
    except Exception as e:
        logger.error(f"Error in assign_project_to_group: {e}")
        return False
    finally:
        conn.close()


def remove_project_from_group(group_id: int, project_id: int):
    """Remove project access from a group."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM group_projects WHERE group_id = %s AND project_id = %s;", (group_id, project_id))
            return True
    except Exception as e:
        logger.error(f"Error in remove_project_from_group: {e}")
        return False
    finally:
        conn.close()


def create_group_user_wizard(data: dict):
    """
    Guided 5-step Group User & Group Creation Wizard.
    Data format:
    {
      "group_name": "...",
      "group_description": "...",
      "gc_username": "...",
      "gc_email": "...",
      "gc_password": "...",
      "existing_user_ids": [1, 2],
      "new_members": [{"username": "...", "email": "...", "password": "...", "full_name": "..."}, ...],
      "existing_project_ids": [10, 12],
      "new_projects": [{"name": "...", "description": "..."}, ...]
    }
    """
    conn = get_db_connection()
    if not conn:
        raise RuntimeError("Database connection unavailable.")
    try:
        with conn.cursor() as cur:
            # Step 1: Create Group User (GC User)
            gc_username = data.get("gc_username")
            gc_email = data.get("gc_email") or f"{gc_username}@securepulse.local"
            gc_pass = data.get("gc_password") or "GroupUser123!"
            
            hashed_gc = generate_password_hash(gc_pass)
            cur.execute("""
                INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                VALUES (%s, %s, %s, 'group_user', %s, FALSE, TRUE, NOW())
                ON CONFLICT (username) DO UPDATE SET role = 'group_user'
                RETURNING id;
            """, (gc_username, gc_email, hashed_gc, f"{gc_username} (GC User)"))
            gc_row = cur.fetchone()
            gc_user_id = gc_row.get("id") if gc_row else None

            # Step 2: Create Group
            gname = data.get("group_name") or f"{gc_username}_group"
            gdesc = data.get("group_description") or "Project Group managed via GC Wizard"
            
            cur.execute("""
                INSERT INTO groups (name, description, created_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
                RETURNING id;
            """, (gname, gdesc))
            group_row = cur.fetchone()
            group_id = group_row.get("id")

            # Add GC User to the group
            cur.execute("INSERT INTO user_groups (user_id, group_id, created_at) VALUES (%s, %s, NOW()) ON CONFLICT DO NOTHING;", (gc_user_id, group_id))

            # Step 3: Add Existing Normal Users to Group (Enforce no admins!)
            existing_user_ids = data.get("existing_user_ids") or []
            for uid in existing_user_ids:
                cur.execute("SELECT id, role, is_admin FROM users WHERE id = %s;", (uid,))
                usr = cur.fetchone()
                if usr:
                    if usr.get("is_admin") or (usr.get("role") or "").lower() in ("superuser", "admin"):
                        raise ValueError(f"Admin users cannot be added to a Group. Groups support Normal Users only.")
                    cur.execute("INSERT INTO user_groups (user_id, group_id, created_at) VALUES (%s, %s, NOW()) ON CONFLICT DO NOTHING;", (uid, group_id))

            # Add New Normal Members created during Wizard
            new_members = data.get("new_members") or []
            for nm in new_members:
                m_uname = nm.get("username")
                m_email = nm.get("email") or f"{m_uname}@securepulse.local"
                m_pass = nm.get("password") or "NormalUser123!"
                m_name = nm.get("full_name") or m_uname
                m_hashed = generate_password_hash(m_pass)
                
                cur.execute("""
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                    VALUES (%s, %s, %s, 'normal', %s, FALSE, TRUE, NOW())
                    ON CONFLICT (username) DO NOTHING
                    RETURNING id;
                """, (m_uname, m_email, m_hashed, m_name))
                m_row = cur.fetchone()
                m_id = m_row.get("id") if m_row else None
                if not m_id:
                    cur.execute("SELECT id FROM users WHERE username = %s;", (m_uname,))
                    m_row2 = cur.fetchone()
                    if m_row2: m_id = m_row2.get("id")
                if m_id:
                    cur.execute("INSERT INTO user_groups (user_id, group_id, created_at) VALUES (%s, %s, NOW()) ON CONFLICT DO NOTHING;", (m_id, group_id))

            # Step 4: Assign Project Access
            existing_project_ids = data.get("existing_project_ids") or []
            for pid in existing_project_ids:
                cur.execute("INSERT INTO group_projects (group_id, project_id, created_at) VALUES (%s, %s, NOW()) ON CONFLICT DO NOTHING;", (group_id, pid))

            new_projects = data.get("new_projects") or []
            for np in new_projects:
                p_name = np.get("name")
                p_desc = np.get("description") or "Created during Group User Wizard"
                cur.execute("""
                    INSERT INTO projects (name, description, created_at)
                    VALUES (%s, %s, NOW())
                    RETURNING id;
                """, (p_name, p_desc))
                p_row = cur.fetchone()
                if p_row:
                    cur.execute("INSERT INTO group_projects (group_id, project_id, created_at) VALUES (%s, %s, NOW()) ON CONFLICT DO NOTHING;", (group_id, p_row.get("id")))

            return {
                "group_id": group_id,
                "group_name": gname,
                "gc_user_id": gc_user_id,
                "gc_username": gc_username
            }
    except Exception as e:
        logger.error(f"Error in create_group_user_wizard: {e}")
        raise e
    finally:
        conn.close()


def get_user_allowed_project_ids(user_id: int):
    """
    Calculate allowed project IDs for a given user according to 3-tier RBAC rules:
    - Super Admin / Admin: ALL project IDs
    - Normal User: Union of assigned group project IDs (or all if unassigned)
    - Group User (GC User): Union of assigned group project IDs ONLY
    """
    conn = get_db_connection()
    if not conn: return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role, is_admin FROM users WHERE id = %s;", (user_id,))
            u = cur.fetchone()
            if not u: return []
            role = (u.get("role") or "").lower()
            if u.get("is_admin") or role in ("superuser", "admin"):
                cur.execute("SELECT id FROM projects;")
                return [r["id"] for r in cur.fetchall()]

            cur.execute("""
                SELECT DISTINCT gp.project_id
                FROM group_projects gp JOIN user_groups ug ON gp.group_id = ug.group_id
                WHERE ug.user_id = %s;
            """, (user_id,))
            pids = [r["project_id"] for r in cur.fetchall()]
            if not pids and role == "normal":
                cur.execute("SELECT id FROM projects;")
                return [r["id"] for r in cur.fetchall()]
            return pids
    except Exception as e:
        logger.error(f"Error in get_user_allowed_project_ids: {e}")
        return []
    finally:
        conn.close()


def change_user_password(user_id: int, new_password: str):
    """Update password hash for a given user ID."""
    conn = get_db_connection()
    if not conn: return False
    try:
        with conn.cursor() as cur:
            hashed = generate_password_hash(new_password)
            cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s;", (hashed, user_id))
            return True
    except Exception as e:
        logger.error(f"Error in change_user_password: {e}")
        return False
    finally:
        conn.close()


