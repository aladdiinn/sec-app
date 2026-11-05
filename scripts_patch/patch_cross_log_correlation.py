import re

print("[*] Adding cross-log correlation engine into app.py...")

with open("app.py", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Enhance catalina exception handling for DB_EXCEPTION
old_cat_exception = """        elif any(k in cat_lower for k in ("severe", "fatal")):
            ev_type = "APP_EXCEPTION"
            sev = "info"
            rule_title = "Application Runtime Exception"
        elif "exception" in cat_lower:
            if any(fw in cat_lower for fw in ("org.apache.", "java.lang.", "java.util.", "classnotfound")):
                continue
            ev_type = "APP_EXCEPTION"
            sev = "info"
            rule_title = "Application Runtime Exception" """

new_cat_exception = """        elif any(k in cat_lower for k in ("psqlexception", "sqlexception", "syntax error at or near", "jdbcexception")):
            ev_type = "DB_EXCEPTION"
            sev = "high"
            rule_title = "Correlated Database SQL Execution Exception"
            mitre_tag = "T1190 - Exploit Public-Facing Application"
            with _cross_log_lock:
                _recent_cross_log_db_errors.append((time.time(), raw_line, actual_app_id))
        elif any(k in cat_lower for k in ("severe", "fatal")):
            ev_type = "APP_EXCEPTION"
            sev = "info"
            rule_title = "Application Runtime Exception"
        elif "exception" in cat_lower:
            if any(fw in cat_lower for fw in ("org.apache.", "java.lang.", "java.util.", "classnotfound")):
                continue
            ev_type = "APP_EXCEPTION"
            sev = "info"
            rule_title = "Application Runtime Exception" """

code = code.replace(old_cat_exception.strip(), new_cat_exception.strip())

# 2. In postgresql log evaluation, also record to cross-log buffer if SQL error
old_pg_eval = """        if source_type in ("postgres", "database") or role == "database":
            ev_type, sev, rule_title, mitre_tag, db_user, db_name, db_lvl = evaluate_postgres_security_event(raw_line)"""

new_pg_eval = """        if source_type in ("postgres", "database") or role == "database":
            ev_type, sev, rule_title, mitre_tag, db_user, db_name, db_lvl = evaluate_postgres_security_event(raw_line)
            if "syntax error" in raw_line.lower() or "error" in raw_line.lower():
                with _cross_log_lock:
                    _recent_cross_log_db_errors.append((time.time(), raw_line, actual_app_id))"""

code = code.replace(old_pg_eval, new_pg_eval)

# 3. In web event processing, record to cross-log buffer
old_web_eval = """            sanitized_path = redact_sensitive_params(raw_path)
            eval_res = evaluate_web_security_event(
                method, raw_path, status_code, user, c_ip, raw_line=raw_line, bytes_sent=bytes_sent
            )"""

new_web_eval = """            sanitized_path = redact_sensitive_params(raw_path)
            with _cross_log_lock:
                _recent_cross_log_web_events.append((time.time(), actual_app_id, c_ip, raw_path))
            eval_res = evaluate_web_security_event(
                method, raw_path, status_code, user, c_ip, raw_line=raw_line, bytes_sent=bytes_sent
            )"""

code = code.replace(old_web_eval, new_web_eval)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(code)

print("[+] Successfully enhanced cross-log correlation in app.py")
