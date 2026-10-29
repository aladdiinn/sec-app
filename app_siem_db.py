import logging
from datetime import datetime, timezone, timedelta
import psycopg2
import psycopg2.extras

logger = logging.getLogger("security_monitor.app_siem_db")

def init_app_siem_schema(conn):
    """
    Additive & Idempotent initialization of Application SIEM tables,
    partitioned app_events table, composite indexes, and helper functions.
    Safe to run repeatedly.
    """
    if not conn:
        logger.warning("No database connection provided to init_app_siem_schema.")
        return False

    with conn.cursor() as cur:
        # 1. applications table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                primary_url VARCHAR(512) NOT NULL,
                environment VARCHAR(50) DEFAULT 'Production',
                description TEXT,
                status VARCHAR(50) DEFAULT 'WAITING',
                project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
                settings JSONB DEFAULT '{}'::jsonb,
                created_by VARCHAR(100),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        # Idempotent column check for applications
        for col, col_type in [
            ("environment", "VARCHAR(50) DEFAULT 'Production'"),
            ("description", "TEXT"),
            ("status", "VARCHAR(50) DEFAULT 'WAITING'"),
            ("project_id", "INTEGER REFERENCES projects(id) ON DELETE SET NULL"),
            ("settings", "JSONB DEFAULT '{}'::jsonb"),
            ("created_by", "VARCHAR(100)"),
            ("created_at", "TIMESTAMPTZ DEFAULT NOW()"),
            ("updated_at", "TIMESTAMPTZ DEFAULT NOW()")
        ]:
            try:
                cur.execute(f"ALTER TABLE applications ADD COLUMN IF NOT EXISTS {col} {col_type};")
            except Exception:
                pass

        # 2. application_components table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS application_components (
                id SERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                role VARCHAR(50) NOT NULL,
                node_name VARCHAR(255) NOT NULL,
                node_ip VARCHAR(100) NOT NULL,
                machine_id VARCHAR(128),
                linked_server_id INTEGER REFERENCES servers(id) ON DELETE SET NULL,
                token_hash VARCHAR(128) NOT NULL UNIQUE,
                enrollment_token VARCHAR(128),
                enrollment_expires_at TIMESTAMPTZ,
                collector_version VARCHAR(50),
                status VARCHAR(50) DEFAULT 'WAITING',
                last_seen TIMESTAMPTZ,
                last_event_at TIMESTAMPTZ,
                config_readiness JSONB DEFAULT '{}'::jsonb,
                drops_counter BIGINT DEFAULT 0,
                events_counter BIGINT DEFAULT 0,
                clock_offset_ms INTEGER DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        for col, col_type in [
            ("machine_id", "VARCHAR(128)"),
            ("linked_server_id", "INTEGER REFERENCES servers(id) ON DELETE SET NULL"),
            ("enrollment_token", "VARCHAR(128)"),
            ("enrollment_expires_at", "TIMESTAMPTZ"),
            ("collector_version", "VARCHAR(50)"),
            ("status", "VARCHAR(50) DEFAULT 'WAITING'"),
            ("last_seen", "TIMESTAMPTZ"),
            ("last_event_at", "TIMESTAMPTZ"),
            ("config_readiness", "JSONB DEFAULT '{}'::jsonb"),
            ("drops_counter", "BIGINT DEFAULT 0"),
            ("events_counter", "BIGINT DEFAULT 0"),
            ("clock_offset_ms", "INTEGER DEFAULT 0"),
            ("enabled", "BOOLEAN DEFAULT TRUE"),
            ("target_port", "VARCHAR(20)"),
            ("target_db_name", "VARCHAR(100)"),
            ("last_heartbeat", "TIMESTAMPTZ"),
            ("monitored_files", "JSONB DEFAULT '[]'::jsonb")
        ]:
            try:
                cur.execute(f"ALTER TABLE application_components ADD COLUMN IF NOT EXISTS {col} {col_type};")
            except Exception:
                pass

        # 3. app_events table (Partitioned by Day)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_events (
                id BIGSERIAL,
                event_time TIMESTAMPTZ NOT NULL,
                received_time TIMESTAMPTZ DEFAULT NOW(),
                application_id INTEGER NOT NULL,
                component_id INTEGER NOT NULL,
                node VARCHAR(255),
                source_type VARCHAR(50),
                event_type VARCHAR(50) NOT NULL,
                client_ip VARCHAR(100),
                is_trusted_proxy BOOLEAN DEFAULT FALSE,
                raw_client_ip VARCHAR(100),
                user_name VARCHAR(255),
                user_role VARCHAR(100),
                session_hash VARCHAR(64),
                method VARCHAR(16),
                url_path TEXT,
                query_masked TEXT,
                status_code INTEGER,
                bytes_sent BIGINT,
                duration_ms INTEGER,
                user_agent TEXT,
                db_user VARCHAR(100),
                db_name VARCHAR(100),
                db_object TEXT,
                statement_excerpt TEXT,
                severity VARCHAR(30) DEFAULT 'info',
                parse_status VARCHAR(30) DEFAULT 'parsed',
                dedup_key VARCHAR(128),
                raw JSONB,
                PRIMARY KEY (id, event_time)
            ) PARTITION BY RANGE (event_time);
        """)

        # Create default partition for events falling outside specific day ranges
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_events_default
            PARTITION OF app_events DEFAULT;
        """)

        # Create rolling daily partitions for 7 days in the past and 30 days ahead
        now_dt = datetime.now(timezone.utc)
        for offset in range(-7, 31):
            day_start = (now_dt + timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            part_name = f"app_events_y{day_start.strftime('%Y_m%m_d%d')}"
            try:
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {part_name}
                    PARTITION OF app_events
                    FOR VALUES FROM ('{day_start.isoformat()}') TO ('{day_end.isoformat()}');
                """)
            except Exception as e:
                logger.debug(f"Partition {part_name} creation note: {e}")

        # Indexes on partitioned table
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_app_events_app_time ON app_events (application_id, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_ip ON app_events (application_id, client_ip, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_user ON app_events (application_id, user_name, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_session ON app_events (application_id, session_hash, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_type ON app_events (application_id, event_type, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_sev ON app_events (application_id, severity, event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_app_events_dedup ON app_events (dedup_key);
        """)

        # 4. app_rules table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_rules (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                rule_type VARCHAR(50) NOT NULL,
                severity VARCHAR(30) NOT NULL,
                mitre_technique_id VARCHAR(50),
                mitre_tactic VARCHAR(100),
                enabled BOOLEAN DEFAULT TRUE,
                application_id INTEGER REFERENCES applications(id) ON DELETE CASCADE,
                threshold INTEGER DEFAULT 1,
                window_seconds INTEGER DEFAULT 60,
                conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                required_data VARCHAR(100),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        # 5. app_incidents & app_incident_events
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_incidents (
                id SERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                title VARCHAR(255) NOT NULL,
                attacker_key VARCHAR(255) NOT NULL,
                attacker_type VARCHAR(50) DEFAULT 'ip',
                client_ip VARCHAR(100),
                user_name VARCHAR(255),
                session_hash VARCHAR(64),
                severity VARCHAR(30) NOT NULL,
                status VARCHAR(50) DEFAULT 'Open',
                first_event_at TIMESTAMPTZ NOT NULL,
                last_event_at TIMESTAMPTZ NOT NULL,
                events_count INTEGER DEFAULT 1,
                stages_count INTEGER DEFAULT 1,
                mitre_tactics JSONB DEFAULT '[]'::jsonb,
                owner VARCHAR(100),
                notes TEXT,
                audit_id INTEGER,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_app_incidents_app ON app_incidents (application_id, last_event_at DESC);
            CREATE INDEX IF NOT EXISTS idx_app_incidents_status ON app_incidents (application_id, status);
            CREATE INDEX IF NOT EXISTS idx_app_incidents_attacker ON app_incidents (application_id, attacker_key, status);

            CREATE TABLE IF NOT EXISTS app_incident_events (
                id SERIAL PRIMARY KEY,
                incident_id INTEGER NOT NULL REFERENCES app_incidents(id) ON DELETE CASCADE,
                event_time TIMESTAMPTZ NOT NULL,
                node_name VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                rule_name VARCHAR(255) NOT NULL,
                mitre_technique VARCHAR(50),
                step_summary TEXT NOT NULL,
                raw_event_id BIGINT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_app_inc_events_inc ON app_incident_events (incident_id, event_time ASC);
        """)

        # 6. app_suppressions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_suppressions (
                id SERIAL PRIMARY KEY,
                application_id INTEGER REFERENCES applications(id) ON DELETE CASCADE,
                rule_id INTEGER REFERENCES app_rules(id) ON DELETE CASCADE,
                rule_name VARCHAR(255),
                target_pattern TEXT NOT NULL,
                reason TEXT NOT NULL,
                expires_at TIMESTAMPTZ,
                created_by VARCHAR(100),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        # 7. app_baselines
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_baselines (
                id SERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                baseline_type VARCHAR(50) NOT NULL,
                metric_name VARCHAR(100) NOT NULL,
                stats JSONB NOT NULL DEFAULT '{}'::jsonb,
                learning_complete BOOLEAN DEFAULT FALSE,
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (application_id, baseline_type, metric_name)
            );
        """)

        # 8. project_apps link table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS project_apps (
                id SERIAL PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                assigned_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (project_id, application_id)
            );
        """)

        # 9. app_users_synced table (Identity & Privilege state)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_users_synced (
                id SERIAL PRIMARY KEY,
                application_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
                username VARCHAR(255) NOT NULL,
                role VARCHAR(100),
                is_enabled BOOLEAN DEFAULT TRUE,
                created_at_db TIMESTAMPTZ,
                last_login_db TIMESTAMPTZ,
                first_seen_in_soc TIMESTAMPTZ DEFAULT NOW(),
                last_seen_in_soc TIMESTAMPTZ,
                observed_tier VARCHAR(50) DEFAULT 'PUBLIC',
                flags JSONB DEFAULT '[]'::jsonb,
                UNIQUE (application_id, username)
            );

            CREATE INDEX IF NOT EXISTS idx_app_users_app_user ON app_users_synced (application_id, username);
        """)

        # 10. Starter Application Rules
        starter_rules = [
            ("Brute Force on Login URL", "Detects high volume of failed login attempts targeting the login URL.", "threshold", "critical", "T1110", "Credential Access", 10, 60, {"event_type": "auth_failure"}, "needs login_url"),
            ("Password Spraying", "Multiple distinct usernames targeted from a single IP address.", "threshold", "critical", "T1110.003", "Credential Access", 5, 120, {"event_type": "auth_failure", "group_by": "client_ip", "distinct": "user_name"}, None),
            ("Credential Stuffing", "High rate of login attempts using various IPs targeting specific accounts.", "threshold", "critical", "T1110.004", "Credential Access", 10, 300, {"event_type": "auth_failure", "group_by": "user_name", "distinct": "client_ip"}, None),
            ("Login Success After Failures", "Successful login immediately following multiple failed authentication attempts from the same source.", "sequence", "high", "T1078", "Defense Evasion", 1, 180, {"seq": ["auth_failure", "auth_success"]}, None),
            ("Unknown User Authentication", "Successful authentication for a username not present in the synced users catalog.", "identity", "critical", "T1078.001", "Persistence", 1, 60, {"flag": "UNKNOWN_USER"}, "needs users table"),
            ("Disabled or Deleted Account Activity", "Authentication or session activity from an account flagged as inactive, deleted, or disabled.", "identity", "critical", "T1078.003", "Persistence", 1, 60, {"flag": "DISABLED_ACCOUNT"}, "needs users table"),
            ("Privilege Tier Violation", "User accessing a RESTRICTED area without having the required role or observed authorization.", "identity", "high", "T1068", "Privilege Escalation", 1, 60, {"tier": "RESTRICTED"}, "needs privilege tiers"),
            ("Single Session Multi-IP Concurrency", "A single session token hash used concurrently from two distinct geographic IP addresses.", "pattern", "high", "T1539", "Credential Access", 2, 300, {"group_by": "session_hash", "distinct": "client_ip"}, None),
            ("SQL Injection Attack Pattern", "Detected common SQL injection syntax and signatures in URL path, query parameter, or headers.", "pattern", "critical", "T1190", "Initial Access", 1, 60, {"pattern": "sqli"}, None),
            ("Cross-Site Scripting (XSS)", "Detected script injection markers (<script>, javascript:, onerror=) in web request parameters.", "pattern", "high", "T1190", "Initial Access", 1, 60, {"pattern": "xss"}, None),
            ("Path Traversal Attempt", "Detected directory traversal sequence (../, %2e%2e) attempting unauthorized file system access.", "pattern", "critical", "T1083", "Discovery", 1, 60, {"pattern": "traversal"}, None),
            ("Log4Shell / JNDI Injection", "Detected JNDI lookup strings (${jndi:ldap, ${jndi:rmi) in request payload or headers.", "pattern", "critical", "T1190", "Initial Access", 1, 60, {"pattern": "jndi"}, None),
            ("Web Shell Upload & Execution", "File upload endpoint access immediately followed by a request to a newly created script (.jsp, .war).", "sequence", "critical", "T1505.003", "Persistence", 1, 120, {"seq": ["file_upload", "jsp_exec"]}, None),
            ("Database Role / Privilege Change", "ALTER ROLE, GRANT, or CREATE ROLE executed directly in the database.", "pattern", "critical", "T1098", "Persistence", 1, 60, {"event_type": "db_role_change"}, "needs pgaudit"),
            ("Unauthorized DDL Execution", "DROP TABLE, TRUNCATE, or ALTER TABLE executed outside designated maintenance windows.", "pattern", "critical", "T1485", "Impact", 1, 60, {"event_type": "db_ddl"}, "needs pgaudit"),
            ("Direct Users Table Tampering", "Modification (INSERT/UPDATE/DELETE) on the users or credentials table by an unapproved database user.", "pattern", "critical", "T1565.001", "Impact", 1, 60, {"event_type": "db_write", "target": "users_table"}, "needs pgaudit"),
            ("Mass Data Exfiltration / COPY TO", "Database COPY TO statement or exceptionally high row count export detected.", "threshold", "critical", "T1005", "Exfiltration", 1, 60, {"event_type": "db_read", "operation": "COPY_TO"}, "needs pgaudit"),
            ("Component Silent / Deadman Alert", "Collector has ceased sending heartbeats or telemetry for over 10 minutes.", "absence", "high", "T1562.001", "Defense Evasion", 1, 600, {"absence_seconds": 600}, None)
        ]

        for r_name, r_desc, r_type, r_sev, r_mitre_id, r_mitre_tac, r_thresh, r_win, r_cond, r_req in starter_rules:
            try:
                cur.execute("""
                    INSERT INTO app_rules (name, description, rule_type, severity, mitre_technique_id, mitre_tactic, threshold, window_seconds, conditions, required_data, enabled)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                    ON CONFLICT (name) DO NOTHING;
                """, (r_name, r_desc, r_type, r_sev, r_mitre_id, r_mitre_tac, r_thresh, r_win, psycopg2.extras.Json(r_cond), r_req))
            except Exception:
                pass

    logger.info("Application SIEM database schema initialized successfully.")
    return True


def delete_old_app_events(conn, retention_days=30, batch_size=5000):
    """
    Deletes events older than retention_days in batches of batch_size.
    Designed for non-blocking background cleanup.
    Returns total deleted count.
    """
    if not conn:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    total_deleted = 0
    with conn.cursor() as cur:
        while True:
            cur.execute("""
                DELETE FROM app_events
                WHERE (id, event_time) IN (
                    SELECT id, event_time
                    FROM app_events
                    WHERE event_time < %s
                    LIMIT %s
                );
            """, (cutoff, batch_size))
            deleted = cur.rowcount
            total_deleted += deleted
            if deleted < batch_size:
                break
    return total_deleted

import secrets
import hashlib

def create_application(conn, name: str, primary_url: str, environment: str = "Production", description: str = "", project_id: int = None, settings: dict = None, created_by: str = "system", status: str = "WAITING"):
    """Creates a new application record and optional project mapping."""
    if not conn:
        return None
    settings_json = psycopg2.extras.Json(settings or {})
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO applications (name, primary_url, environment, description, status, project_id, settings, created_by, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            RETURNING id, name, primary_url, environment, description, status, project_id, settings, created_at;
        """, (name, primary_url, environment, description, status, project_id, settings_json, created_by))
        app = dict(cur.fetchone())

        if project_id:
            try:
                cur.execute("""
                    INSERT INTO project_apps (project_id, application_id)
                    VALUES (%s, %s)
                    ON CONFLICT (project_id, application_id) DO NOTHING;
                """, (project_id, app['id']))
            except Exception as e:
                logger.error(f"Error associating app {app['id']} with project {project_id}: {e}")

        return app

def format_time_ago(dt):
    if not dt:
        return "never"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 10:
        return "Just Now"
    if diff < 60:
        return f"{int(diff)} s ago"
    if diff < 3600:
        return f"{int(diff // 60)} min ago"
    if diff < 86400:
        return f"{int(diff // 3600)} h ago"
    return f"{int(diff // 86400)} d ago"

def get_applications(conn, project_id=None, status_filter=None):
    """
    Returns list of applications enriched with:
    - Component reporting counts (e.g. '3/3' or '0/2')
    - Events per minute (over last 5 min)
    - Open incidents count
    - Last event time ago
    - Dynamic status (NORMAL, TROUBLE, CRITICAL, DOWN, MAINT, WAITING)
    - Project name
    """
    if not conn:
        return []
    
    with conn.cursor() as cur:
        params = []
        where_clauses = ["1=1"]
        # Without approval an app does not appear in Total Apps (like server assets)
        if not status_filter or status_filter.lower() not in ('all_including_pending', 'pending_approval', 'pending'):
            where_clauses.append("a.status != 'PENDING_APPROVAL'")

        # Project scoping filter
        if project_id is not None:
            if isinstance(project_id, list):
                if project_id:
                    where_clauses.append("a.project_id = ANY(%s)")
                    params.append(project_id)
                else:
                    where_clauses.append("1=0")
            else:
                where_clauses.append("a.project_id = %s")
                params.append(int(project_id))

        sql = f"""
            SELECT 
                a.id, a.name, a.primary_url, a.environment, a.description, a.status,
                a.project_id, a.settings, a.created_by, a.created_at, a.updated_at,
                p.name as project_name,
                COUNT(c.id) as total_components,
                COUNT(c.id) FILTER (WHERE c.last_seen >= NOW() - INTERVAL '10 minutes') as reporting_components,
                MAX(c.last_seen) as last_seen_component,
                MAX(c.last_event_at) as last_event_at,
                (
                    SELECT COUNT(*) 
                    FROM app_incidents inc 
                    WHERE inc.application_id = a.id AND inc.status IN ('Open', 'Investigating')
                ) as open_incidents,
                (
                    SELECT COUNT(*) FILTER (WHERE inc2.severity = 'critical')
                    FROM app_incidents inc2 
                    WHERE inc2.application_id = a.id AND inc2.status IN ('Open', 'Investigating')
                ) as critical_incidents,
                (
                    SELECT COUNT(*) FILTER (WHERE inc3.severity = 'high')
                    FROM app_incidents inc3 
                    WHERE inc3.application_id = a.id AND inc3.status IN ('Open', 'Investigating')
                ) as high_incidents,
                (
                    SELECT COALESCE(ROUND(COUNT(*)::numeric / 5.0, 0), 0)
                    FROM app_events ev
                    WHERE ev.application_id = a.id AND ev.event_time >= NOW() - INTERVAL '5 minutes'
                ) as events_per_min
            FROM applications a
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN application_components c ON a.id = c.application_id AND c.enabled = TRUE
            WHERE {" AND ".join(where_clauses)}
            GROUP BY a.id, p.name
            ORDER BY a.name ASC;
        """
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

        result = []
        now_utc = datetime.now(timezone.utc)
        for r in rows:
            item = dict(r)
            total_comp = item.get("total_components", 0)
            rep_comp = item.get("reporting_components", 0)
            crit_inc = item.get("critical_incidents", 0)
            high_inc = item.get("high_incidents", 0)
            open_inc = int(item.get("open_incidents", 0))
            last_ev = item.get("last_event_at")
            
            # Format last event time strictly from real events
            if last_ev:
                item["last_event_formatted"] = format_time_ago(last_ev)
            else:
                item["last_event_formatted"] = "never"

            item["components_ratio"] = f"{rep_comp}/{total_comp}"
            item["events_per_min"] = int(item.get("events_per_min", 0))
            item["open_incidents"] = open_inc

            # Stale check (> 5 mins since last event)
            is_stale = False
            if last_ev:
                if last_ev.tzinfo is None:
                    last_ev_tz = last_ev.replace(tzinfo=timezone.utc)
                else:
                    last_ev_tz = last_ev
                is_stale = (now_utc - last_ev_tz).total_seconds() > 300

            # Evaluate Unified Status & Telemetry Banner
            settings = item.get("settings") or {}
            is_maint = settings.get("maintenance_mode", False) or item.get("status") == "MAINT"

            if is_maint:
                dyn_status = "MAINT"
                status_color = "b"
                status_desc = "Maintenance mode active"
                telemetry_banner = "MAINTENANCE Scheduled Maintenance Window"
            elif crit_inc > 0:
                dyn_status = "CRITICAL"
                status_color = "r"
                status_desc = f"{crit_inc} Open critical incident{'s' if crit_inc>1 else ''}"
                telemetry_banner = f"CRITICAL {open_inc} Open Incident(s) | Threat Detected"
            elif high_inc > 0:
                dyn_status = "TROUBLE"
                status_color = "a"
                status_desc = f"{high_inc} Open high incident{'s' if high_inc>1 else ''}"
                telemetry_banner = "TROUBLE Application anomaly detected"
            elif not last_ev:
                # App has never sent an event: Awaiting first event in grey, UP state
                dyn_status = "UP"
                status_color = "m"
                status_desc = "Awaiting first event"
                telemetry_banner = "AWAITING FIRST EVENT"
            elif is_stale:
                dyn_status = "TROUBLE"
                status_color = "a"
                time_str = format_time_ago(last_ev)
                status_desc = f"No telemetry for {time_str}"
                telemetry_banner = f"NO TELEMETRY: last event {time_str}"
            elif rep_comp == 0 and total_comp > 0:
                dyn_status = "DOWN"
                status_color = "r"
                status_desc = "All components offline"
                telemetry_banner = "OFFLINE / SILENT Telemetry disconnected"
            elif rep_comp < total_comp and total_comp > 0:
                dyn_status = "TROUBLE"
                status_color = "a"
                status_desc = f"{total_comp - rep_comp} component(s) silent"
                telemetry_banner = f"TROUBLE {total_comp - rep_comp} component(s) silent"
            else:
                dyn_status = "UP"
                status_color = "ok"
                status_desc = "Application Telemetry Active"
                telemetry_banner = "NORMAL Application Telemetry Active"

            item["computed_status"] = dyn_status
            item["dynamic_status"] = dyn_status
            item["status_color"] = status_color
            item["status_desc"] = status_desc
            item["telemetry_banner"] = telemetry_banner

            # Apply status filter if specified
            if status_filter and status_filter.lower() not in ('all', 'all_including_pending'):
                if dyn_status.lower() != status_filter.lower():
                    continue

            result.append(item)

        return result

def get_application_by_id(conn, app_id: int):
    """Retrieves full application details with components, enriched metrics & live status."""
    if not conn:
        return None
    with conn.cursor() as cur:
        cur.execute("""
            SELECT a.*, p.name as project_name,
                   (
                       SELECT COUNT(*) 
                       FROM app_incidents inc 
                       WHERE inc.application_id = a.id AND inc.status IN ('Open', 'Investigating')
                   ) as open_incidents,
                   (
                       SELECT COUNT(*) FILTER (WHERE inc2.severity = 'critical')
                       FROM app_incidents inc2 
                       WHERE inc2.application_id = a.id AND inc2.status IN ('Open', 'Investigating')
                   ) as critical_incidents,
                   (
                       SELECT COUNT(*) FILTER (WHERE inc3.severity = 'high')
                       FROM app_incidents inc3 
                       WHERE inc3.application_id = a.id AND inc3.status IN ('Open', 'Investigating')
                   ) as high_incidents,
                   (
                       SELECT COALESCE(ROUND(COUNT(*)::numeric / 5.0, 0), 0)
                       FROM app_events ev
                       WHERE ev.application_id = a.id AND ev.event_time >= NOW() - INTERVAL '5 minutes'
                   ) as events_per_min,
                   (
                       SELECT MAX(event_time)
                       FROM app_events ev2
                       WHERE ev2.application_id = a.id
                   ) as last_event_at
            FROM applications a
            LEFT JOIN projects p ON a.project_id = p.id
            WHERE a.id = %s;
        """, (app_id,))
        row = cur.fetchone()
        if not row:
            return None
        app = dict(row)

        last_ev = app.get("last_event_at")
        app["events_per_min"] = int(app.get("events_per_min", 0))
        app["open_incidents"] = int(app.get("open_incidents", 0))
        app["critical_incidents"] = int(app.get("critical_incidents", 0))
        app["high_incidents"] = int(app.get("high_incidents", 0))
        app["last_event_formatted"] = format_time_ago(last_ev) if last_ev else "never"

        cur.execute("""
            SELECT c.*, s.hostname as linked_server_hostname, s.ip as linked_server_ip,
                   (
                       SELECT MAX(event_time)
                       FROM app_events ev
                       WHERE ev.component_id = c.id
                   ) as component_last_event_at
            FROM application_components c
            LEFT JOIN servers s ON c.linked_server_id = s.id
            WHERE c.application_id = %s
            ORDER BY c.role DESC, c.node_name ASC;
        """, (app_id,))
        raw_components = cur.fetchall()
        now_utc = datetime.now(timezone.utc)
        components = []
        for raw_c in raw_components:
            c = dict(raw_c)
            # Evaluate component live status strictly based on real events
            c_last_ev = c.get("component_last_event_at") or c.get("last_event_at")
            if not c_last_ev:
                c["status"] = "AWAITING FIRST EVENT"
            else:
                if c_last_ev.tzinfo is None:
                    c_ev_tz = c_last_ev.replace(tzinfo=timezone.utc)
                else:
                    c_ev_tz = c_last_ev
                sec_ago = (now_utc - c_ev_tz).total_seconds()
                if sec_ago <= 300: # received event within last 5 minutes
                    c["status"] = "RECEIVING"
                else:
                    c["status"] = "SILENT"
            components.append(c)
        app["components"] = components
        return app

def update_application(conn, app_id: int, **kwargs):
    """Updates application settings or attributes."""
    if not conn or not kwargs:
        return False
    set_clauses = []
    params = []
    for k, v in kwargs.items():
        if k == 'settings' and isinstance(v, dict):
            set_clauses.append("settings = %s")
            params.append(psycopg2.extras.Json(v))
        else:
            set_clauses.append(f"{k} = %s")
            params.append(v)
    set_clauses.append("updated_at = NOW()")
    params.append(app_id)

    with conn.cursor() as cur:
        cur.execute(f"UPDATE applications SET {', '.join(set_clauses)} WHERE id = %s RETURNING id;", tuple(params))
        res = cur.fetchone()
        return bool(res)

def delete_application(conn, app_id: int):
    """Deletes application record and cleans up associated events and link tables."""
    if not conn:
        return False
    with conn.cursor() as cur:
        try:
            cur.execute("DELETE FROM app_events WHERE application_id = %s;", (app_id,))
        except Exception as e:
            logger.warning(f"Note deleting events for app {app_id}: {e}")
        cur.execute("DELETE FROM applications WHERE id = %s RETURNING id;", (app_id,))
        res = cur.fetchone()
        return bool(res)

def add_application_component(conn, app_id: int, role: str, node_name: str, node_ip: str, machine_id: str = None, port: str = None, db_name: str = None):
    """
    Registers a component and generates a 1-time enrollment token expiring in 1 hour.
    Automatically links to existing server asset if machine_id or IP matches.
    Stores target port and database name for precision multi-instance targeting.
    """
    if not conn:
        return None
    
    enrollment_token = secrets.token_hex(16)
    token_hash = hashlib.sha256(enrollment_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    config_readiness = psycopg2.extras.Json({"port": port, "db_name": db_name})

    with conn.cursor() as cur:
        # Check if matching server exists to link
        linked_srv_id = None
        if machine_id:
            cur.execute("SELECT id FROM servers WHERE (hostname = %s OR ip = %s) LIMIT 1;", (machine_id, node_ip))
            srv = cur.fetchone()
            if srv:
                linked_srv_id = srv['id']
        if not linked_srv_id and node_ip:
            cur.execute("SELECT id FROM servers WHERE ip = %s LIMIT 1;", (node_ip,))
            srv = cur.fetchone()
            if srv:
                linked_srv_id = srv['id']

        # Ensure columns exist
        try:
            cur.execute("ALTER TABLE application_components ADD COLUMN IF NOT EXISTS target_port VARCHAR(20);")
            cur.execute("ALTER TABLE application_components ADD COLUMN IF NOT EXISTS target_db_name VARCHAR(100);")
        except Exception:
            pass

        cur.execute("""
            INSERT INTO application_components (
                application_id, role, node_name, node_ip, machine_id, linked_server_id,
                token_hash, enrollment_token, enrollment_expires_at, target_port, target_db_name,
                config_readiness, status, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'PENDING_APPROVAL', NOW())
            RETURNING id, application_id, role, node_name, node_ip, linked_server_id, enrollment_token, status, target_port, target_db_name;
        """, (app_id, role, node_name, node_ip, machine_id, linked_srv_id, token_hash, enrollment_token, expires_at, str(port) if port else None, db_name, config_readiness))
        comp = dict(cur.fetchone())
        return comp

def get_application_components(conn, app_id: int):
    """Returns all components for an application."""
    if not conn:
        return []
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.*, s.hostname as server_hostname
            FROM application_components c
            LEFT JOIN servers s ON c.linked_server_id = s.id
            WHERE c.application_id = %s
            ORDER BY c.role DESC, c.node_name ASC;
        """, (app_id,))
        return [dict(r) for r in cur.fetchall()]

def delete_application_component(conn, app_id: int, comp_id: int):
    """Deletes an application component."""
    if not conn:
        return False
    with conn.cursor() as cur:
        cur.execute("DELETE FROM application_components WHERE id = %s AND application_id = %s RETURNING id;", (comp_id, app_id))
        res = cur.fetchone()
        return bool(res)
