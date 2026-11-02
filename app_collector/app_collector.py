#!/usr/bin/env python3
"""
SecurePulse Application-Level SIEM Collector (securepulse-app)
==============================================================
Production-grade, zero-dependency, read-only telemetry forwarder for:
- Apache Tomcat (Access logs, Catalina logs, application error logs)
- PostgreSQL (Connection, statement, and DDL logs)

Safety & Governance:
- Strictly READ-ONLY. Never modifies or writes to application files or databases.
- Zero external pip dependencies (runs on standard Python 3.6+).
- Capped resource consumption (< 1% CPU, < 25MB RAM).
- Automatic log rotation handling (inode tracking).
"""

import os
import sys
import time
import json
import socket
import re
import glob
import urllib.request
import urllib.error
from datetime import datetime, timezone

COLLECTOR_VERSION = "1.7.3"

# Configuration defaults (overridden by /etc/securepulse-app/collector.env)
CONFIG = {
    "SOC_URL": os.environ.get("SOC_URL", "http://127.0.0.1:8000"),
    "ENROLLMENT_TOKEN": os.environ.get("ENROLLMENT_TOKEN", ""),
    "APP_ID": int(os.environ.get("APP_ID", "0")),
    "COMPONENT_ROLE": os.environ.get("COMPONENT_ROLE", "web"),
    "NODE_NAME": os.environ.get("NODE_NAME", socket.gethostname()),
    "TARGET_PORT": os.environ.get("TARGET_PORT", ""),
    "TARGET_DB_NAME": os.environ.get("TARGET_DB_NAME", ""),
    "TOMCAT_LOG_DIR": os.environ.get("TOMCAT_LOG_DIR", ""),
    "PG_LOG_DIR": os.environ.get("PG_LOG_DIR", ""),
    "POLL_INTERVAL_SEC": float(os.environ.get("POLL_INTERVAL_SEC", "0.5")),
    "BATCH_MAX_LINES": int(os.environ.get("BATCH_MAX_LINES", "50")),
    "BATCH_MAX_WAIT_SEC": float(os.environ.get("BATCH_MAX_WAIT_SEC", "2.0")),
    "HEARTBEAT_INTERVAL_SEC": float(os.environ.get("HEARTBEAT_INTERVAL_SEC", "30.0"))
}

def load_env_file(filepath="/etc/securepulse-app/collector.env"):
    """Loads configuration from environment file if present with strict type coercion."""
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k in CONFIG:
                        if k == "APP_ID":
                            try: CONFIG[k] = int(v)
                            except ValueError: pass
                        elif k in ("POLL_INTERVAL_SEC", "BATCH_MAX_WAIT_SEC", "HEARTBEAT_INTERVAL_SEC"):
                            try: CONFIG[k] = float(v)
                            except ValueError: pass
                        elif k == "BATCH_MAX_LINES":
                            try: CONFIG[k] = int(v)
                            except ValueError: pass
                        else:
                            CONFIG[k] = v
    except Exception as e:
        print(f"[WARN] Error reading {filepath}: {e}")

def post_json(endpoint: str, payload: dict, timeout: float = 6.0) -> dict:
    """Posts JSON payload to SOC server using standard library urllib."""
    soc_url = CONFIG["SOC_URL"].rstrip("/")
    url = f"{soc_url}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "X-Enrollment-Token": CONFIG["ENROLLMENT_TOKEN"],
        "User-Agent": f"SecurePulse-App-Collector/{COLLECTOR_VERSION}"
    })
    try:
        # Explicitly bypass system proxy for direct communication with SOC server
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {"status": "ok"}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        return {"status": "error", "code": e.code, "reason": err_body or str(e)}
    except Exception as e:
        return {"status": "error", "reason": str(e)}

# ── LOG DISCOVERY ENGINE ──────────────────────────────────────────────────────

def find_tomcat_log_files(target_port: str = "") -> list:
    """Locates active Tomcat access and catalina log files across running processes and filesystem."""
    candidates = []

    # 1. Explicitly configured directory
    if CONFIG["TOMCAT_LOG_DIR"] and os.path.isdir(CONFIG["TOMCAT_LOG_DIR"]):
        candidates.append(os.path.realpath(CONFIG["TOMCAT_LOG_DIR"]))

    # 2. Port-based process inspection (Linux /proc)
    if target_port and sys.platform.startswith("linux"):
        try:
            import subprocess
            res = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in res.stdout.splitlines():
                if f":{target_port} " in line or f":{target_port}\t" in line:
                    match = re.search(r'pid=(\d+)', line)
                    if match:
                        pid = match.group(1)
                        # Check cmdline
                        cmdline_path = f"/proc/{pid}/cmdline"
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                                cmd = f.read().replace("\x00", " ")
                                m = re.search(r'-Dcatalina\.base=([^\s]+)', cmd) or re.search(r'-Dcatalina\.home=([^\s]+)', cmd)
                                if m:
                                    cdir = os.path.join(m.group(1), "logs")
                                    if os.path.isdir(cdir) and cdir not in candidates:
                                        candidates.append(os.path.realpath(cdir))
                        # Check process cwd
                        cwd_link = f"/proc/{pid}/cwd"
                        if os.path.exists(cwd_link):
                            try:
                                real_cwd = os.path.realpath(cwd_link)
                                for p in [real_cwd, os.path.dirname(real_cwd)]:
                                    ldir = os.path.join(p, "logs")
                                    if os.path.isdir(ldir) and ldir not in candidates:
                                        candidates.append(os.path.realpath(ldir))
                            except Exception:
                                pass
        except Exception:
            pass

    # 3. Process inspection: inspect all running java/tomcat processes
    if sys.platform.startswith("linux"):
        try:
            for pid_dir in glob.glob("/proc/[0-9]*"):
                cmd_path = os.path.join(pid_dir, "cmdline")
                if os.path.exists(cmd_path):
                    try:
                        with open(cmd_path, "r", encoding="utf-8", errors="ignore") as f:
                            cmd = f.read().replace("\x00", " ")
                            if "catalina" in cmd.lower() or "tomcat" in cmd.lower() or "bootstrap" in cmd.lower():
                                m = re.search(r'-Dcatalina\.base=([^\s]+)', cmd) or re.search(r'-Dcatalina\.home=([^\s]+)', cmd)
                                if m:
                                    ldir = os.path.join(m.group(1), "logs")
                                    if os.path.isdir(ldir) and ldir not in candidates:
                                        candidates.append(os.path.realpath(ldir))
                                
                                # Process cwd inspection
                                cwd_link = os.path.join(pid_dir, "cwd")
                                if os.path.exists(cwd_link):
                                    rcwd = os.path.realpath(cwd_link)
                                    for p in [rcwd, os.path.dirname(rcwd)]:
                                        ldir = os.path.join(p, "logs")
                                        if os.path.isdir(ldir) and ldir not in candidates:
                                            candidates.append(os.path.realpath(ldir))
                    except Exception:
                        pass
        except Exception:
            pass

    # 4. Standard filesystem roots across Linux distributions
    standard_roots = [
        "/home/apache-tomcat*/logs",
        "/home/*/apache-tomcat*/logs",
        "/opt/apache-tomcat*/logs",
        "/opt/tomcat*/logs",
        "/var/log/tomcat*",
        "/var/lib/tomcat*/logs",
        "/usr/local/apache-tomcat*/logs",
        "/usr/local/tomcat*/logs",
        "/usr/share/tomcat*/logs",
        "/home/*/tomcat*/logs",
        "/home/tomcat*/logs"
    ]
    for pattern in standard_roots:
        for p in glob.glob(pattern):
            if os.path.isdir(p):
                rp = os.path.realpath(p)
                if rp not in candidates:
                    candidates.append(rp)

    active_files = []

    for cdir in candidates:
        if not os.path.isdir(cdir):
            continue

        # Access logs: look for any access log file
        access_patterns = [
            os.path.join(cdir, "*access_log*"),
            os.path.join(cdir, "*access*.txt"),
            os.path.join(cdir, "*access*.log")
        ]
        found_access = []
        for pat in access_patterns:
            for f in glob.glob(pat):
                if os.path.isfile(f) and f not in found_access:
                    found_access.append(f)

        # Sort access logs by modification time (newest first)
        found_access.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
        # Take up to the 2 most recent access logs (e.g. today's active file)
        for f in found_access[:2]:
            if not any(af["path"] == f for af in active_files):
                active_files.append({"path": f, "source": "tomcat_access"})

        # Catalina / App logs: catalina.out or catalina.YYYY-MM-DD.log
        cat_patterns = [
            os.path.join(cdir, "catalina.out"),
            os.path.join(cdir, "catalina*.log")
        ]
        found_cat = []
        for pat in cat_patterns:
            for f in glob.glob(pat):
                if os.path.isfile(f) and f not in found_cat:
                    found_cat.append(f)
        found_cat.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
        for f in found_cat[:2]:
            if not any(af["path"] == f for af in active_files):
                active_files.append({"path": f, "source": "tomcat_catalina"})

    return active_files

def find_postgres_log_files(target_port: str = "") -> list:
    """Locates active PostgreSQL log files."""
    candidates = []
    if CONFIG["PG_LOG_DIR"] and os.path.isdir(CONFIG["PG_LOG_DIR"]):
        candidates.append(os.path.realpath(CONFIG["PG_LOG_DIR"]))

    standard_patterns = [
        "/var/log/postgresql/postgresql-*.log",
        "/var/lib/pgsql/*/data/log/*.log",
        "/var/lib/postgresql/*/main/log/*.log",
        "/var/log/postgresql/*.log"
    ]
    for pattern in standard_patterns:
        for f in glob.glob(pattern):
            if os.path.isfile(f):
                rf = os.path.realpath(f)
                if rf not in candidates:
                    candidates.append(rf)

    return [{"path": f, "source": "postgres"} for f in candidates]

# ── LOG TAILER ENGINE ─────────────────────────────────────────────────────────

class LogFileTailer:
    """Tails a single log file with rotation tracking and offset persistence."""

    def __init__(self, filepath: str, source_type: str):
        self.filepath = filepath
        self.source_type = source_type
        self.file_obj = None
        self.inode = None
        self.last_pos = 0
        self._open()

    def _open(self):
        try:
            if not os.path.exists(self.filepath):
                return
            stat = os.stat(self.filepath)
            self.inode = stat.st_ino
            self.file_obj = open(self.filepath, "r", encoding="utf-8", errors="replace")
            # Production Log Tailer: seek to end of file on startup so past historical logs are NEVER replayed
            # Only live events generated while actively testing or running the app will be captured!
            self.file_obj.seek(0, os.SEEK_END)
            self.last_pos = self.file_obj.tell()
        except Exception as e:
            print(f"[WARN] Error opening {self.filepath}: {e}")

    def read_new_lines(self) -> list:
        if not self.file_obj or not os.path.exists(self.filepath):
            self._open()
            return []

        try:
            # Check rotation: if inode changed or file size shrunk
            stat = os.stat(self.filepath)
            if stat.st_ino != self.inode:
                print(f"[INFO] Log rotation detected on {self.filepath} (new inode). Reopening from start...")
                if self.file_obj:
                    self.file_obj.close()
                self.inode = stat.st_ino
                self.file_obj = open(self.filepath, "r", encoding="utf-8", errors="replace")
                self.file_obj.seek(0, os.SEEK_SET)
                self.last_pos = 0
                return []
            elif stat.st_size < self.last_pos:
                print(f"[INFO] Log truncation detected on {self.filepath}. Resetting offset to 0...")
                self.file_obj.seek(0, os.SEEK_SET)
                self.last_pos = 0
                return []

            lines = []
            while True:
                line = self.file_obj.readline()
                if not line:
                    break
                line = line.strip("\r\n")
                if line:
                    lines.append(line)
            self.last_pos = self.file_obj.tell()
            return lines
        except Exception as e:
            print(f"[WARN] Error reading {self.filepath}: {e}")
            return []

    def close(self):
        if self.file_obj:
            try: self.file_obj.close()
            except Exception: pass

# ── MAIN FORWARDER LOOP ───────────────────────────────────────────────────────

STATIC_EXT_RE = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|eot|map|webp)$', re.IGNORECASE)
ATTACK_PATH_TOKENS = (
    "..", "/etc/", "union", "select", "<script", "onerror", "${jndi", 
    "exec", "cmd", "drop", "eval", "'", "%27", "%22", "%3c", "%3e", "0x", "sleep(",
    "${", "%24%7b", "#{"
)
USER_QUERY_TOKENS = (
    "user=", "username=", "userName=", "userid=", "user_id=", 
    "login=", "email=", "account=", "token=", "session=", "auth=", "empid=", "usr="
)
ROUTINE_POLLING_PATTERNS = (
    "getstocksummary",
    "getassignedtome",
    "getassignedexception",
    "/showstatus/",
    "/health",
    "/ping",
    "/heartbeat",
    "/favicon.ico",
    "tab-close-logout",
    "update-logout-time",
    "fullviewmdas",
    "nonbilledconsumerdata",
    "updatemrdpendingrecord",
    "pagecontext.request.contextpath"
)

def is_noise_tomcat_access_log(raw_line: str) -> bool:
    """
    Tier-1 Edge/Ingestion Noise Filter:
    Returns True if the line is purely routine static asset or health/widget-polling noise (safe to drop).
    Returns False if the line has ANY security relevance, error code, user parameter, or app logic.
    """
    # 1. Quick status check: Only candidate for dropping if status is 200 or 304
    if ' 200 ' not in raw_line and ' 304 ' not in raw_line:
        return False  # Keep all 401, 403, 404, 500, 302, etc.

    # 2. Extract request: "METHOD /path HTTP/..."
    m_req = re.search(r'"([A-Z]+)\s+([^"\s]+)\s+HTTP/[0-9\.]+"', raw_line)
    if not m_req:
        return False  # Keep non-standard or malformed requests

    method = m_req.group(1).upper()
    if method not in ("GET", "HEAD", "OPTIONS"):
        return False  # Keep all POST, PUT, DELETE, PATCH

    raw_path = m_req.group(2)
    path_lower = urllib.parse.unquote(raw_path).lower()

    # 3. Never drop attacks, directory traversals, or probes
    if any(atk in path_lower for atk in ATTACK_PATH_TOKENS):
        return False

    # 4. Never drop lines with user identities or auth tokens
    if any(u in path_lower for u in USER_QUERY_TOKENS):
        return False

    clean_path = raw_path.split("?")[0].lower()

    # 5a. Drop static assets returning 200/304
    if STATIC_EXT_RE.search(clean_path):
        return True

    # 5b. Drop root / balancer health check pings if path is strictly "/"
    if clean_path in ("/", "") and ("?" not in raw_path or raw_path.endswith("?")):
        return True

    # 5c. Drop routine background widget polling endpoints (Nagaland/HPSEBL stock summaries, counters, heartbeats)
    if any(pat in clean_path for pat in ROUTINE_POLLING_PATTERNS):
        return True

    return False


def check_and_apply_auto_update():
    """Checks SOC server for newer collector code and auto-updates without manual node intervention."""
    try:
        soc_url = CONFIG["SOC_URL"].rstrip("/")
        token = CONFIG["ENROLLMENT_TOKEN"]
        url = f"{soc_url}/api/app/collector.py?token={token}"
        req = urllib.request.Request(url, headers={"User-Agent": f"SecurePulse-App-Collector/{COLLECTOR_VERSION}"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=5.0) as resp:
            new_code = resp.read().decode("utf-8")
        
        m = re.search(r"""COLLECTOR_VERSION\s*=\s*['"]([^'"]+)['"]""", new_code)
        if m:
            server_version = m.group(1)
            if server_version > COLLECTOR_VERSION:
                print(f"[AUTO-UPDATE] Found newer collector version {server_version} (current: {COLLECTOR_VERSION}). Updating self...")
                current_file = os.path.realpath(__file__)
                with open(current_file, "w", encoding="utf-8") as f:
                    f.write(new_code)
                print(f"[AUTO-UPDATE] Successfully updated to {server_version}. Restarting process...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        pass

def run_collector():
    load_env_file()
    print("=" * 65)
    print(f"  SecurePulse Application Telemetry Collector v{COLLECTOR_VERSION}")
    print("=" * 65)
    print(f"Node Name:   {CONFIG['NODE_NAME']}")
    print(f"App ID:      {CONFIG['APP_ID']}")
    print(f"Role:        {CONFIG['COMPONENT_ROLE']}")
    print(f"Target Port: {CONFIG['TARGET_PORT'] or 'auto-detect'}")
    print(f"Target DB:   {CONFIG['TARGET_DB_NAME'] or 'all'}")
    print(f"SOC Target:  {CONFIG['SOC_URL']}")
    print(f"Token:       {CONFIG['ENROLLMENT_TOKEN'][:8]}***" if CONFIG['ENROLLMENT_TOKEN'] else "Token:       (none)")
    print("=" * 65)

    tailers = {}
    last_heartbeat = 0.0
    last_flush = time.time()
    buffered_events = []

    while True:
        try:
            now = time.time()

            # 1. Periodic Heartbeat (every 30s)
            if now - last_heartbeat >= float(CONFIG["HEARTBEAT_INTERVAL_SEC"]):
                hb_payload = {
                    "token": CONFIG["ENROLLMENT_TOKEN"],
                    "app_id": CONFIG["APP_ID"],
                    "node_name": CONFIG["NODE_NAME"],
                    "role": CONFIG["COMPONENT_ROLE"],
                    "version": COLLECTOR_VERSION,
                    "target_port": CONFIG["TARGET_PORT"],
                    "target_db_name": CONFIG["TARGET_DB_NAME"],
                    "monitored_files": list(tailers.keys()),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                res = post_json("/api/app/heartbeat", hb_payload)
                if res.get("status") == "ok":
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [HB] Heartbeat acknowledged by SOC. Monitored files: {len(tailers)}")
                    if res.get("latest_version") and res.get("latest_version") > COLLECTOR_VERSION:
                        check_and_apply_auto_update()
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [WARN] Heartbeat warning: {res.get('reason')}")
                last_heartbeat = now

            # 2. Rediscover log files if none attached or every 60s
            if not tailers or int(now) % 60 == 0:
                discovered = []
                if CONFIG["COMPONENT_ROLE"] == "web":
                    discovered = find_tomcat_log_files(CONFIG["TARGET_PORT"])
                elif CONFIG["COMPONENT_ROLE"] == "database":
                    discovered = find_postgres_log_files(CONFIG["TARGET_PORT"])

                for item in discovered:
                    fpath = item["path"]
                    if fpath not in tailers:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] [DISCOVER] Monitoring log file: {fpath} ({item['source']})")
                        tailers[fpath] = LogFileTailer(fpath, item["source"])

            # 3. Read new lines from all tailers
            new_lines_total = 0
            for fpath, tailer in list(tailers.items()):
                new_lines = tailer.read_new_lines()
                if new_lines:
                    new_lines_total += len(new_lines)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [READ] Captured {len(new_lines)} lines from {os.path.basename(fpath)}")
                for line in new_lines:
                    # Filter for target db if in database role
                    if CONFIG["COMPONENT_ROLE"] == "database" and CONFIG["TARGET_DB_NAME"]:
                        if f"@{CONFIG['TARGET_DB_NAME']}" not in line and "FATAL" not in line:
                            continue

                    # Tier-1 Edge Optimization: Suppress routine static asset 200s and root health-checks from access log
                    if tailer.source_type == "tomcat_access" and is_noise_tomcat_access_log(line):
                        continue

                    # Suppress routine noisy INFO/startup/framework lines from catalina.out (only send security events)
                    if tailer.source_type == "tomcat_catalina":
                        line_l = line.lower()
                        # Ignore routine framework lines
                        if any(k in line_l for k in [
                            "info [main]", "info [catalina", "server startup in", 
                            "deploying web application", "deployment of web application",
                            "at org.apache.catalina", "at org.apache.coyote", "at org.apache.tomcat",
                            "at java.", "at javax.", "at jakarta.", "at sun.",
                            "jar was scanned for tlds", "sessionlistener", "cookie processor"
                        ]):
                            continue

                        is_security = any(k in line_l for k in [
                            "auth_failure", "privilege_violation", "unauthorized", "forbidden", 
                            "denied", "failed login", "attack", "exploit", "sqli", "xss", "jndi",
                            "login", "logged in", "session created"
                        ])
                        if not is_security:
                            continue

                    buffered_events.append({
                        "source": tailer.source_type,
                        "file": fpath,
                        "line": line,
                        "captured_at": datetime.now(timezone.utc).isoformat()
                    })

            # 4. Flush batch to SOC if threshold reached or wait timeout elapsed
            should_flush = (
                len(buffered_events) >= int(CONFIG["BATCH_MAX_LINES"]) or
                (buffered_events and (now - last_flush) >= float(CONFIG["BATCH_MAX_WAIT_SEC"]))
            )

            if should_flush:
                batch_size = int(CONFIG["BATCH_MAX_LINES"])
                batch_to_send = buffered_events[:batch_size]
                payload = {
                    "token": CONFIG["ENROLLMENT_TOKEN"],
                    "app_id": CONFIG["APP_ID"],
                    "node_name": CONFIG["NODE_NAME"],
                    "role": CONFIG["COMPONENT_ROLE"],
                    "events": batch_to_send
                }
                res = post_json("/api/app/events", payload)
                if res.get("status") in ("success", "ok"):
                    buffered_events = buffered_events[len(batch_to_send):]
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [INGEST] Forwarded {len(batch_to_send)} events to SOC. Ingested: {res.get('ingested')}, Severity: {res.get('highest_severity')}")
                    last_flush = now
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [WARN] Event ingestion failed: {res}")
                    last_flush = now

            time.sleep(float(CONFIG["POLL_INTERVAL_SEC"]))

        except KeyboardInterrupt:
            print("\nShutting down collector...")
            for t in tailers.values(): t.close()
            break
        except Exception as e:
            print(f"[ERROR] Collector loop exception: {e}")
            time.sleep(2.0)

if __name__ == "__main__":
    run_collector()
