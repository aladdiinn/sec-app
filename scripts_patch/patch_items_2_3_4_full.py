import re

print("[*] Patching app.py for Items 2, 3, and 4...")

with open("app.py", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Add _sqli_tracker, _sqli_lock and cross-log correlation buffers
target_buf = """# In-memory sliding tracker for mass parameter enumeration (IDOR / Scraping detection)
_scraping_tracker = {}
_scraping_lock = threading.Lock()"""

replacement_buf = """# In-memory sliding tracker for mass parameter enumeration (IDOR / Scraping detection)
_scraping_tracker = {}
_scraping_lock = threading.Lock()

# In-memory sliding tracker for SQL injection velocity / multi-signal escalation
_sqli_tracker = {}
_sqli_lock = threading.Lock()

# Cross-log correlation buffer (catalina / postgres errors <-> web access log requests)
from collections import deque
_recent_cross_log_web_events = deque(maxlen=500)
_recent_cross_log_db_errors = deque(maxlen=500)
_cross_log_lock = threading.Lock()"""

if "_sqli_tracker = {}" not in code:
    code = code.replace(target_buf, replacement_buf)
    print("[+] Added SQLi and cross-log buffers to app.py")

# 2. Update make_evidence to use dynamic rule_version
target_ev = """    def make_evidence(rule_id, rule_name, conf, why, signals, fp_indicators, action, matched_val=None, thresh_val=None):
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "rule_version": "2.4","""

replacement_ev = """    def make_evidence(rule_id, rule_name, conf, why, signals, fp_indicators, action, matched_val=None, thresh_val=None):
        cache = _get_rule_cache()
        rule_rec = cache.get(rule_id) or cache.get(rule_name) or {}
        dynamic_ver = rule_rec.get("version") or 1
        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "rule_version": str(dynamic_ver),"""

if '"rule_version": "2.4"' in code:
    code = code.replace(target_ev, replacement_ev)
    print("[+] Updated make_evidence to read dynamic rule version")

# 3. Update SQL Injection detection in evaluate_web_security_event
target_sqli = """    # 1. SQL Injection (Enterprise Strict Syntax Verification)
    for sqli_pat in SQLI_PATTERNS:
        if sqli_pat.search(full_target_lower):
            has_db_err = any(e in full_line for e in ("syntax error", "psycopg2", "org.postgresql", "sqlexception", "ora-", "mysql_error"))
            
            if status == 500:
                if has_db_err:
                    sev = "critical"
                    conf = "HIGH"
                    why = "SQL injection payload triggered confirmed database execution failure (HTTP 500 with DB syntax error)."
                    sig = ["SQL injection syntax matched", "HTTP 500 status code", "Database error keyword in logs"]
                else:
                    sev = "medium"
                    conf = "MEDIUM"
                    why = "SQL injection payload triggered HTTP 500 server error (unconfirmed DB execution)."
                    sig = ["SQL injection syntax matched", "HTTP 500 status code"]
                return "SQL_INJECTION", sev, "SQL Injection Attempt", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "SQL Injection Exploit", conf, why, sig, "Application runtime NullPointerException unrelated to database.", "Inspect application exception logs.")
            elif status in (200, 201):
                sev = "low"
                conf = "LOW"
                why = f"SQL syntax payload sent to endpoint returning HTTP {status} (single request unconfirmed execution)."
                sig = ["SQL syntax in query parameter", f"HTTP {status} response"]
                return "SQL_INJECTION_PROBE", sev, "SQL Injection Probe (HTTP 200)", "T1190 - Exploit Public-Facing Application", make_evidence("W02", "SQL Injection Probe", conf, why, sig, "Benign search term or text containing SQL keywords.", "Monitor IP for repeated injection variants.")
            else:
                sev = "low"
                conf = "LOW"
                why = f"Blocked SQL injection attempt rejected with HTTP {status}."
                sig = ["SQL syntax in query parameter", f"Blocked with HTTP {status}"]
                return "SQL_INJECTION_PROBE", sev, f"Blocked SQL Injection Probe (HTTP {status})", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "Blocked SQL Injection", conf, why, sig, "Security filter correctly dropped request.", "No action needed; safely rejected.")"""

replacement_sqli = """    # 1. SQL Injection (Enterprise Strict Syntax Verification & Multi-Signal Escalation)
    for sqli_pat in SQLI_PATTERNS:
        if sqli_pat.search(full_target_lower):
            now_t = time.time()
            with _sqli_lock:
                ip_hist = _sqli_tracker.setdefault(ip, [])
                ip_hist = [t for t in ip_hist if now_t - t < 300]
                ip_hist.append(now_t)
                _sqli_tracker[ip] = ip_hist
                sqli_velocity = len(ip_hist)

            # Check cross-log buffer for any DB error within +/- 10s on the node/application
            correlated_db_err = False
            with _cross_log_lock:
                for t_err, r_err, app_err_id in _recent_cross_log_db_errors:
                    if abs(now_t - t_err) <= 10.0:
                        correlated_db_err = True
                        break

            has_db_err = correlated_db_err or any(e in full_line for e in ("syntax error", "psycopg2", "org.postgresql", "sqlexception", "ora-", "mysql_error"))

            # Independent signals:
            abnormal_size = bool(status in (200, 201) and bytes_sent and bytes_sent >= 10000)
            repeated_attempts = bool(sqli_velocity >= 3)
            is_extraction = bool(re.search(r'\\b(?:union\\s+select|select\\s+.*\\s+from|waitfor\\s+delay|pg_sleep)\\b', full_target_lower))

            signals_fired = [f"SQL syntax matched in query: {clean_p}"]
            if abnormal_size:
                signals_fired.append(f"Independent Signal: Abnormal response size ({bytes_sent} bytes returned on injected query)")
            if repeated_attempts:
                signals_fired.append(f"Independent Signal: Velocity spike ({sqli_velocity} SQLi attempts from IP in 5 min)")
            if has_db_err:
                signals_fired.append("Independent Signal: Correlated database syntax/runtime error in server logs")
            if is_extraction:
                signals_fired.append("Independent Signal: Data extraction / schema discovery payload (UNION/SELECT/SLEEP)")

            if status == 500:
                if has_db_err:
                    sev = "critical"
                    conf = "HIGH"
                    why = "SQL injection payload triggered confirmed database execution failure (HTTP 500 with correlated DB syntax error)."
                elif repeated_attempts:
                    sev = "high"
                    conf = "HIGH"
                    why = f"Sustained SQL injection attack cluster ({sqli_velocity} attempts) triggering HTTP 500 errors."
                else:
                    sev = "medium"
                    conf = "MEDIUM"
                    why = "SQL injection payload triggered HTTP 500 server error (unconfirmed DB execution)."
                return "SQL_INJECTION", sev, "SQL Injection Attempt", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "SQL Injection Exploit", conf, why, signals_fired, "Application runtime NullPointerException unrelated to database.", "Inspect application exception logs.")
            elif status in (200, 201):
                if abnormal_size or has_db_err:
                    sev = "critical"
                    conf = "HIGH"
                    why = f"Confirmed SQL injection data extraction (HTTP {status} with abnormal response size {bytes_sent} bytes)."
                    return "SQL_INJECTION", sev, "Successful SQL Injection Data Extraction (HTTP 200)", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "SQL Injection Data Extraction", conf, why, signals_fired, "Legitimate administrative query or report.", "Audit endpoint data protection and parameterization.")
                elif repeated_attempts:
                    sev = "high"
                    conf = "HIGH"
                    why = f"Sustained SQL injection attack cluster ({sqli_velocity} attempts from {ip}) accepted with HTTP {status}."
                    return "SQL_INJECTION", sev, "Sustained SQL Injection Attack Cluster (HTTP 200)", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "Sustained SQL Injection Attack", conf, why, signals_fired, "Automated vulnerability scanner probe against secured endpoint.", "Review endpoint sanitization.")
                else:
                    sev = "low"
                    conf = "LOW"
                    why = f"SQL syntax payload sent to endpoint returning HTTP {status} (single request unconfirmed execution)."
                    return "SQL_INJECTION_PROBE", sev, "SQL Injection Probe (HTTP 200)", "T1190 - Exploit Public-Facing Application", make_evidence("W02", "SQL Injection Probe", conf, why, signals_fired, "Benign search term or text containing SQL keywords.", "Monitor IP for repeated injection variants.")
            else:
                sev = "medium" if repeated_attempts else "low"
                conf = "MEDIUM" if repeated_attempts else "LOW"
                why = f"Blocked SQL injection attempt rejected with HTTP {status}."
                return "SQL_INJECTION_PROBE", sev, f"Blocked SQL Injection Probe (HTTP {status})", "T1190 - Exploit Public-Facing Application", make_evidence("W01", "Blocked SQL Injection", conf, why, signals_fired, "Security filter correctly dropped request.", "No action needed; safely rejected.")"""

code = code.replace(target_sqli, replacement_sqli)
print("[+] Updated SQL injection escalation logic with multi-signal detection")

# 4. Update api_get_app_rules to check bytes_sent capability & set MISSING_DATA_SOURCE
target_rules_api = """@app.get("/api/apps/{app_id}/rules")
def api_get_app_rules(request: Request, app_id: int):
    \"\"\"Retrieves active detection rules for an application.\"\"\"
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    conn = db.get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(\"\"\"
                SELECT id, name, description, rule_type, severity, mitre_technique_id, mitre_tactic, enabled, threshold, window_seconds
                FROM app_rules
                WHERE application_id IS NULL OR application_id = %s
                ORDER BY id ASC;
            \"\"\", (app_id,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]"""

replacement_rules_api = """@app.get("/api/apps/{app_id}/rules")
def api_get_app_rules(request: Request, app_id: int):
    \"\"\"Retrieves active detection rules for an application.\"\"\"
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    conn = db.get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            has_bytes = False
            try:
                cur.execute("SELECT 1 FROM app_events WHERE application_id = %s AND bytes_sent > 0 LIMIT 1;", (app_id,))
                has_bytes = bool(cur.fetchone())
            except Exception:
                has_bytes = False

            cur.execute(\"\"\"
                SELECT id, name, description, rule_type, severity, mitre_technique_id, mitre_tactic, enabled, threshold, window_seconds, COALESCE(version, 1) as version
                FROM app_rules
                WHERE application_id IS NULL OR application_id = %s
                ORDER BY id ASC;
            \"\"\", (app_id,))
            rows = cur.fetchall()
            rules_out = []
            for r in rows:
                rd = dict(r)
                # Requirement 2: 15 MB / Exfiltration rule shows MISSING_DATA_SOURCE if bytes_sent has never been collected
                if ("15 MB" in (rd.get("name") or "") or "Exfiltration" in (rd.get("name") or "") or rd.get("id") in (17,)):
                    if not has_bytes:
                        rd["data_source_status"] = "MISSING_DATA_SOURCE"
                        rd["missing_data_reason"] = "Field bytes_sent not collected. Tomcat AccessLogValve requires %b or %B pattern."
                    else:
                        rd["data_source_status"] = "COLLECTED"
                else:
                    rd["data_source_status"] = "COLLECTED"
                rules_out.append(rd)
            return rules_out"""

code = code.replace(target_rules_api, replacement_rules_api)
print("[+] Updated api_get_app_rules with MISSING_DATA_SOURCE verification")

with open("app.py", "w", encoding="utf-8") as f:
    f.write(code)
print("[+] Wrote updated app.py successfully.")

# 5. Update templates/app_detail_modal.html for MISSING_DATA_SOURCE badge
with open("templates/app_detail_modal.html", "r", encoding="utf-8") as f:
    modal_code = f.read()

target_modal_status = """                        <td style="padding:8px 12px">
                            <span style="color:var(--green); font-weight:700">● Active</span>
                        </td>"""

replacement_modal_status = """                        <td style="padding:8px 12px">
                            ${r.data_source_status === 'MISSING_DATA_SOURCE'
                                ? `<span class="badge" style="background:rgba(245,158,11,0.2); color:#f59e0b; border:1px solid rgba(245,158,11,0.4); font-size:10px; padding:2px 8px; border-radius:4px; font-weight:700; white-space:nowrap;" title="${escapeHtml(r.missing_data_reason || 'Missing data source')}"><i class="fas fa-exclamation-triangle"></i> MISSING DATA SOURCE</span>`
                                : `<span style="color:var(--green); font-weight:700">● Active</span>`
                            }
                        </td>"""

if target_modal_status in modal_code:
    modal_code = modal_code.replace(target_modal_status, replacement_modal_status)
    with open("templates/app_detail_modal.html", "w", encoding="utf-8") as f:
        f.write(modal_code)
    print("[+] Updated templates/app_detail_modal.html with MISSING DATA SOURCE badge")
