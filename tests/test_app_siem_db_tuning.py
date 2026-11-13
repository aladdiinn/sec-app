import unittest
import re
from datetime import datetime, timezone, timedelta

# Import or define the refactored PostgreSQL parser and evaluator
PG_LOG_PATTERNS = [
    # 1. JVVNL production format: [timestamp]user@host->db:app [pid]LEVEL: msg
    re.compile(r'^\[(?P<time>[^\]]+)\](?P<user>[^@\s]+)@(?P<client>[^->\s]+)->(?P<db>[^:\s]+):(?P<app>.*?)\s*\[(?P<pid>\d+)\](?P<level>[A-Z]+):\s+(?P<msg>.+)$'),
    # 2. Key-value format: timestamp [pid] [line] user=%u,db=%d,client=%h,app=%a LEVEL: msg
    re.compile(r'^(?P<time>[0-9\-]+ [0-9:\.]+(?: [A-Z]+)?)\s+\[(?P<pid>\d+)\](?:\s*\[\d+-\d+\])?:?\s+user=(?P<user>[^,]*),db=(?P<db>[^,]*),client=(?P<client>[^,]*),app=(?P<app>[^\s]*)\s+(?P<level>[A-Z]+):\s+(?P<msg>.+)$'),
    # 3. Standard user@db format: timestamp [pid] user@db LEVEL: msg
    re.compile(r'^(?P<time>[0-9\-]+ [0-9:\.]+(?: [A-Z]+)?)\s+\[(?P<pid>\d+)\](?:\s*\[\d+-\d+\])?:?\s+(?:(?P<user>[^@\s]+)@(?P<db>[^\s]+)\s+)?(?P<level>[A-Z]+):\s+(?P<msg>.+)$')
]

def parse_postgres_raw_log(raw_line: str):
    """Parses raw PostgreSQL log lines across various log_line_prefix configurations."""
    for pat in PG_LOG_PATTERNS:
        m = pat.match(raw_line)
        if m:
            d = m.groupdict()
            return {
                "matched": True,
                "time": d.get("time"),
                "user": d.get("user") or None,
                "client_ip": d.get("client") or None,
                "db_name": d.get("db") or None,
                "app_name": (d.get("app") or "").strip() or None,
                "pid": int(d.get("pid")) if d.get("pid") and d.get("pid").isdigit() else None,
                "level": (d.get("level") or "INFO").upper(),
                "msg": d.get("msg", "").strip()
            }
    # Fallback if prefix doesn't match standard patterns
    m_level = re.search(r'\b(LOG|FATAL|ERROR|WARNING|INFO|DETAIL|HINT|STATEMENT):\s+(.+)$', raw_line)
    if m_level:
        return {
            "matched": False,
            "time": None,
            "user": None,
            "client_ip": None,
            "db_name": None,
            "app_name": None,
            "pid": None,
            "level": m_level.group(1).upper(),
            "msg": m_level.group(2).strip()
        }
    return {
        "matched": False,
        "time": None,
        "user": None,
        "client_ip": None,
        "db_name": None,
        "app_name": None,
        "pid": None,
        "level": "INFO",
        "msg": raw_line.strip()
    }

def is_internal_ip(ip: str, project_subnets=None) -> bool:
    if not ip or ip in ("-", "unknown", "localhost", "127.0.0.1", "::1"):
        return True
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip):
        return True
    if project_subnets:
        for s in project_subnets:
            if ip in s or s.startswith(ip.rsplit('.', 1)[0]):
                return True
    return False

def evaluate_postgres_security_event_v2(raw_line: str, project_subnets=None, recent_context=None):
    """
    Refactored PostgreSQL log security evaluator.
    Strictly distinguishes DML queries (LOG: execute ... UPDATE ...) from real FATAL auth failures.
    """
    parsed = parse_postgres_raw_log(raw_line)
    level = parsed["level"]
    msg = parsed["msg"]
    user = parsed["user"]
    client_ip = parsed["client_ip"]
    db_name = parsed["db_name"]
    app_name = parsed["app_name"]
    msg_lower = msg.lower()

    # Self-collector exclusion: socadmin or 127.0.0.1
    if user in ("socadmin", "bsmart_soc") or client_ip in ("127.0.0.1", "::1", "localhost"):
        return "DB_MAINTENANCE", "info", "SOC Agent Telemetry", None, user, client_ip, db_name, level, {}

    # DML / Query execution checks: Level is LOG or statement: / execute / parse / bind / duration
    is_dml_or_timing = level == "LOG" or any(msg_lower.startswith(k) for k in ("execute ", "statement:", "parse ", "bind ", "duration:", "connection received"))
    
    if is_dml_or_timing:
        # Check for Destructive DDL
        if re.search(r'statement:\s*(DROP\s+TABLE|DROP\s+DATABASE|DROP\s+SCHEMA|TRUNCATE)', msg, re.IGNORECASE):
            return "DB_DESTRUCTIVE_DDL", "critical", "Destructive Database DDL Command (DROP/TRUNCATE)", "T1485 - Data Destruction", user, client_ip, db_name, level, {}
        # Privilege escalation
        if re.search(r'statement:\s*(?:ALTER|CREATE)\s+(?:USER|ROLE).* SUPERUSER ', msg, re.IGNORECASE) or \
           re.search(r'statement:\s*GRANT\s+(?:pg_execute_server_program|pg_read_server_files|pg_write_server_files) ', msg, re.IGNORECASE) or \
           re.search(r'statement:\s*GRANT\s+ALL\s+PRIVILEGES\s+ON\s+DATABASE ', msg, re.IGNORECASE):
            return "DB_PRIVILEGE_ESCALATION", "critical", "Database Superuser Privilege Escalation", "T1078 - Valid Accounts", user, client_ip, db_name, level, {}
        # Normal query / DML (e.g. UPDATE ... paymentstatus='2' ... failed_resp='auth failed')
        return "DB_LOG", "info", None, None, user, client_ip, db_name, level, {}

    # Real Authentication Failures: Strictly requires FATAL / ERROR / WARNING level
    is_auth_failure = False
    if level in ("FATAL", "ERROR", "WARNING"):
        if "password authentication failed" in msg_lower or \
           "no pg_hba.conf entry" in msg_lower or \
           ("role" in msg_lower and "does not exist" in msg_lower) or \
           "authentication failed for user" in msg_lower or \
           "pam authentication failed" in msg_lower:
            is_auth_failure = True

    if is_auth_failure:
        m_u = re.search(r'(?:for user|role)\s+["\']?([^"\'\s,]+)["\']?', msg, re.IGNORECASE)
        target_user = m_u.group(1) if m_u else (user or "unknown")
        
        # Correlated Multi-Signal Severity Matrix:
        internal_src = is_internal_ip(client_ip, project_subnets)
        is_admin_role = target_user.lower() in ("postgres", "root", "superuser", "rdsadmin", "administrator")
        
        signals = []
        if not internal_src:
            signals.append(f"External Source IP: {client_ip}")
        if is_admin_role:
            signals.append(f"Privileged Administrative Target Role: {target_user}")

        # Check multi-signal correlation context if provided
        ctx = recent_context or {}
        distinct_users = ctx.get("distinct_users_count", 1)
        velocity_per_min = ctx.get("velocity_per_min", 1)
        has_success_after_fail = ctx.get("success_after_fail", False)

        if distinct_users >= 3:
            signals.append(f"Credential Spraying: {distinct_users} distinct DB roles targeted")
        if has_success_after_fail:
            signals.append("Compromise Indicator: Successful authorization followed authentication failures")

        # Determine Severity based on correlated signals:
        if has_success_after_fail:
            sev = "critical"
        elif len(signals) >= 2 or (not internal_src and is_admin_role) or distinct_users >= 3:
            sev = "high"
        elif not internal_src or is_admin_role or velocity_per_min >= 10:
            sev = "medium"
        else:
            # Single or repeated internal retry on ordinary user
            sev = "low" if velocity_per_min <= 3 else "medium"

        evidence = {
            "signals": signals,
            "target_user": target_user,
            "client_ip": client_ip or "missing from log_line_prefix",
            "db_name": db_name,
            "internal_src": internal_src,
            "is_admin_role": is_admin_role
        }

        title = f"Database Authentication Failure ({target_user})"
        if sev == "low" or sev == "medium":
            title += " - Stale / Misconfigured Credential"

        return "DB_AUTH_FAILURE", sev, title, "T1110 - Brute Force", target_user, client_ip, db_name, level, evidence

    # Connection pool starvation / DoS
    if "remaining connection slots are reserved" in msg_lower or "too many connections" in msg_lower:
        return "DB_CONNECTION_EXHAUSTION", "high", "Database Connection Pool Starvation", "T1499 - Endpoint Denial of Service", user, client_ip, db_name, level, {}

    # SQL Syntax error
    if "syntax error at or near" in msg_lower:
        return "DB_SQL_ERROR", "low", "Database Query Syntax Error", "T1190 - Exploit Public-Facing Application", user, client_ip, db_name, level, {}

    return "DB_LOG", "info", None, None, user, client_ip, db_name, level, {}


class TestAppSiemTuning(unittest.TestCase):

    def test_t1_payment_update_is_not_auth_failure(self):
        """T1: Benign payment UPDATE containing failed_resp='auth failed' must NOT generate DB_AUTH_FAILURE."""
        line = (
            "[2026-11-13 04:58:33.307 IST]app_deployment@192.168.150.15->jvvnl_ncms:PostgreSQL JDBC Driver [4109186]"
            "LOG:  execute <unnamed>: UPDATE jvvnlpgrs.ncpt_onlinepaymentsbd SET paymentstatus='2',payment_notupdatedt = now(),"
            "failed_resp='{\"objectid\":\"transaction\",\"transactionid\":\"EHMPOV621XT82X\",\"orderid\":\"926110713422206601522\","
            "\"mercid\":\"JVVNLPGV2\",\"transaction_date\":\"2026-11-07T13:43:02+05:30\",\"amount\":\"162.00\","
            "\"surcharge\":\"0.00\",\"discount\":\"0.00\",\"charge_amount\":\"162.00\",\"currency\":\"356\","
            "\"error\":\"auth failed at gateway\"}'"
        )
        ev_type, sev, title, mitre, u, c_ip, db, lvl, ev = evaluate_postgres_security_event_v2(line)
        self.assertEqual(ev_type, "DB_LOG")
        self.assertEqual(sev, "info")
        self.assertEqual(u, "app_deployment")
        self.assertEqual(c_ip, "192.168.150.15")
        self.assertEqual(db, "jvvnl_ncms")

    def test_t2_fields_extracted_from_log_line_prefix(self):
        """T2: User, client IP, db, and app name properly populated instead of '-' and 'unknown'."""
        line = "[2026-11-13 04:58:33.307 IST]app_deployment@192.168.150.15->jvvnl_ncms:PostgreSQL JDBC Driver [4109186]LOG:  duration: 0.082 ms  bind <unnamed>: UPDATE ..."
        parsed = parse_postgres_raw_log(line)
        self.assertTrue(parsed["matched"])
        self.assertEqual(parsed["user"], "app_deployment")
        self.assertEqual(parsed["client_ip"], "192.168.150.15")
        self.assertEqual(parsed["db_name"], "jvvnl_ncms")
        self.assertEqual(parsed["app_name"], "PostgreSQL JDBC Driver")
        self.assertEqual(parsed["pid"], 4109186)
        self.assertEqual(parsed["level"], "LOG")

    def test_t3_collector_self_traffic_zero_alerts(self):
        """T3: Agent/collector self-traffic generates 0 alerts."""
        line = "2026-11-13 05:02:00.100 UTC [9999] [3-1] user=socadmin,db=bsmart_soc,client=127.0.0.1,app=psql LOG: statement: SELECT 1"
        ev_type, sev, title, mitre, u, c_ip, db, lvl, ev = evaluate_postgres_security_event_v2(line)
        self.assertEqual(ev_type, "DB_MAINTENANCE")
        self.assertEqual(sev, "info")

    def test_t4_internal_auth_failure_capped_at_low_or_medium(self):
        """T4: Single internal auth failure is LOW; repeated internal is MEDIUM (never isolated HIGH)."""
        line = "[2026-11-13 04:59:00.123 IST]app_user@192.168.10.50->jvvnl_ncms:[unknown] [4109190]FATAL:  password authentication failed for user \"app_user\""
        
        # Single event (velocity 1/min)
        ev_type, sev, title, mitre, u, c_ip, db, lvl, ev = evaluate_postgres_security_event_v2(
            line, recent_context={"velocity_per_min": 1, "distinct_users_count": 1}
        )
        self.assertEqual(ev_type, "DB_AUTH_FAILURE")
        self.assertEqual(sev, "low")
        self.assertEqual(u, "app_user")
        self.assertEqual(c_ip, "192.168.10.50")
        self.assertIn("Stale / Misconfigured Credential", title)

        # Repeated event (velocity 5/min)
        ev_type2, sev2, title2, mitre2, u2, c_ip2, db2, lvl2, ev2 = evaluate_postgres_security_event_v2(
            line, recent_context={"velocity_per_min": 5, "distinct_users_count": 1}
        )
        self.assertEqual(sev2, "medium")

    def test_t5_external_attack_or_spray_escalates_to_high(self):
        """T5: Multi-user spray or external attack on admin role escalates to HIGH."""
        # 1. External IP attacking postgres
        ext_line = "2026-11-13 05:00:00 UTC [1234] postgres@prod FATAL: password authentication failed for user \"postgres\""
        # Context: external IP 203.0.113.5
        parsed = parse_postgres_raw_log(ext_line)
        parsed_with_ip = "[2026-11-13 05:00:00 UTC]postgres@203.0.113.5->prod:[unknown] [1234]FATAL: password authentication failed for user \"postgres\""
        ev_type, sev, title, mitre, u, c_ip, db, lvl, ev = evaluate_postgres_security_event_v2(
            parsed_with_ip, recent_context={"velocity_per_min": 5, "distinct_users_count": 1}
        )
        self.assertEqual(ev_type, "DB_AUTH_FAILURE")
        self.assertEqual(sev, "high")
        self.assertIn("External Source IP", ev["signals"][0])

        # 2. Credential spray across 3 users from internal IP
        spray_line = "[2026-11-13 05:00:00 UTC]test_user@192.168.10.200->prod:[unknown] [1234]FATAL: password authentication failed for user \"test_user\""
        ev_type2, sev2, title2, mitre2, u2, c_ip2, db2, lvl2, ev2 = evaluate_postgres_security_event_v2(
            spray_line, recent_context={"velocity_per_min": 5, "distinct_users_count": 4}
        )
        self.assertEqual(sev2, "high")
        self.assertTrue(any("Credential Spraying" in s for s in ev2["signals"]))

    def test_t6_success_after_failure_escalates_to_critical(self):
        """T6: Success after failure escalates to CRITICAL."""
        line = "[2026-11-13 05:00:00 UTC]victim_user@203.0.113.88->prod:[unknown] [1234]FATAL: password authentication failed for user \"victim_user\""
        ev_type, sev, title, mitre, u, c_ip, db, lvl, ev = evaluate_postgres_security_event_v2(
            line, recent_context={"velocity_per_min": 2, "distinct_users_count": 1, "success_after_fail": True}
        )
        self.assertEqual(sev, "critical")
        self.assertTrue(any("Compromise Indicator" in s for s in ev["signals"]))

if __name__ == "__main__":
    unittest.main()
