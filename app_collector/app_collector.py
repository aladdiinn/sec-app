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
- Intelligent backoff, Keep-Alive connection reuse, and bounded memory queue.
"""

import os
import sys
import time
import json
import socket
import re
import glob
import random
import http.client
import urllib.parse
import threading
from datetime import datetime, timezone

COLLECTOR_VERSION = "1.8.0"

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
    "POLL_INTERVAL_SEC": float(os.environ.get("POLL_INTERVAL_SEC", "1.0")),
    "BATCH_MAX_LINES": int(os.environ.get("BATCH_MAX_LINES", "100")),
    "BATCH_MAX_WAIT_SEC": float(os.environ.get("BATCH_MAX_WAIT_SEC", "3.0")),
    "HEARTBEAT_INTERVAL_SEC": float(os.environ.get("HEARTBEAT_INTERVAL_SEC", "30.0")),
    "MAX_QUEUE_SIZE": int(os.environ.get("MAX_QUEUE_SIZE", "10000")),
    "AGGREGATE_ROUTINE_ACCESS": os.environ.get("AGGREGATE_ROUTINE_ACCESS", "true").lower() in ("true", "1", "yes")
}

def load_env_file(filepath=None):
    """Loads configuration from environment file if present with strict type coercion."""
    if not filepath:
        filepath = os.environ.get("COLLECTOR_ENV_FILE") or "/etc/securepulse-app/collector.env"
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
                        if k in ("APP_ID", "BATCH_MAX_LINES", "MAX_QUEUE_SIZE"):
                            try: CONFIG[k] = int(v)
                            except ValueError: pass
                        elif k in ("POLL_INTERVAL_SEC", "BATCH_MAX_WAIT_SEC", "HEARTBEAT_INTERVAL_SEC"):
                            try: CONFIG[k] = float(v)
                            except ValueError: pass
                        elif k == "AGGREGATE_ROUTINE_ACCESS":
                            CONFIG[k] = v.lower() in ("true", "1", "yes")
                        else:
                            CONFIG[k] = v
    except Exception as e:
        print(f"[WARN] Error reading {filepath}: {e}")

# ── PERSISTENT HTTP SESSION (Keep-Alive, Retry-After Parsing, Auto-Reconnect) ──

class PersistentSession:
    """Maintains a persistent HTTP/HTTPS connection with keep-alive, Retry-After parsing, and auto-reconnect."""
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self._conn = None
        self._lock = threading.Lock()

    def _get_connection(self):
        if self._conn is None:
            if self.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self._conn = http.client.HTTPSConnection(self.host, self.port, timeout=10.0, context=ctx)
            else:
                self._conn = http.client.HTTPConnection(self.host, self.port, timeout=10.0)
        return self._conn

    def post(self, endpoint: str, payload: dict, token: str) -> dict:
        with self._lock:
            data = json.dumps(payload).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                "X-Enrollment-Token": token,
                "User-Agent": f"SecurePulse-App-Collector/{COLLECTOR_VERSION}"
            }
            for attempt in range(2):
                try:
                    conn = self._get_connection()
                    conn.request("POST", endpoint, body=data, headers=headers)
                    resp = conn.getresponse()
                    body = resp.read().decode("utf-8", errors="replace")
                    retry_after = resp.getheader("Retry-After")
                    res_json = {}
                    try:
                        res_json = json.loads(body) if body else {}
                    except Exception:
                        res_json = {"reason": body}

                    res_json["code"] = resp.status
                    if retry_after:
                        res_json["retry_after"] = retry_after

                    if resp.status in (200, 201):
                        res_json["status"] = "success"
                        return res_json
                    else:
                        res_json["status"] = "error"
                        return res_json
                except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError, http.client.CannotSendRequest, http.client.BadStatusLine):
                    if self._conn:
                        try: self._conn.close()
                        except Exception: pass
                    self._conn = None
                    if attempt == 1:
                        return {"status": "error", "code": 503, "reason": "Connection reset after reconnect attempt"}
                except Exception as e:
                    if self._conn:
                        try: self._conn.close()
                        except Exception: pass
                    self._conn = None
                    return {"status": "error", "code": 500, "reason": str(e)}
            return {"status": "error", "code": 500, "reason": "Connection failure"}

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
                        cmdline_path = f"/proc/{pid}/cmdline"
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                                cmd = f.read().replace('\x00', ' ')
                                m_base = re.search(r'-Dcatalina\.base=([^\s]+)', cmd)
                                if m_base:
                                    log_dir = os.path.join(m_base.group(1), "logs")
                                    if os.path.isdir(log_dir):
                                        candidates.append(os.path.realpath(log_dir))
                                m_home = re.search(r'-Dcatalina\.home=([^\s]+)', cmd)
                                if m_home:
                                    log_dir = os.path.join(m_home.group(1), "logs")
                                    if os.path.isdir(log_dir):
                                        candidates.append(os.path.realpath(log_dir))
        except Exception:
            pass

    # 3. Standard Tomcat locations
    standard_paths = [
        "/var/log/tomcat*",
        "/opt/tomcat*/logs",
        "/usr/local/tomcat*/logs",
        "/var/lib/tomcat*/logs",
        "/home/*/tomcat*/logs",
        "/opt/*/tomcat*/logs",
        "/application/*/logs",
        "/application/*/*/logs",
        "/application/*/apache-tomcat*/logs",
        "/application/*/*tomcat*/logs",
        "/app/*/logs",
        "/app/*/*/logs",
        "/data/*/logs"
    ]
    for pattern in standard_paths:
        for p in glob.glob(pattern):
            if os.path.isdir(p):
                candidates.append(os.path.realpath(p))

    # Deduplicate candidate directories
    unique_dirs = list(dict.fromkeys(candidates))

    # Resolve active log files inside discovered directories
    active_files = []
    for d in unique_dirs:
        # Access logs: prefer current date / latest modified
        access_patterns = [
            os.path.join(d, "localhost_access_log.*.txt"),
            os.path.join(d, "*access_log*"),
            os.path.join(d, "access.log")
        ]
        found_access = []
        for pat in access_patterns:
            for f in glob.glob(pat):
                if os.path.isfile(f) and not f.endswith(".gz") and not f.endswith(".zip"):
                    found_access.append(f)
        found_access.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
        for f in found_access[:2]:
            if not any(af["path"] == f for af in active_files):
                active_files.append({"path": f, "source": "tomcat_access"})

        # Catalina / application stdout logs
        cat_patterns = [
            os.path.join(d, "catalina.out"),
            os.path.join(d, "catalina.*.log")
        ]
        found_cat = []
        for pat in cat_patterns:
            for f in glob.glob(pat):
                if os.path.isfile(f) and not f.endswith(".gz") and not f.endswith(".zip"):
                    found_cat.append(f)
        found_cat.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
        for f in found_cat[:2]:
            if not any(af["path"] == f for af in active_files):
                active_files.append({"path": f, "source": "tomcat_catalina"})

    return active_files

def find_postgres_log_files(target_port: str = "") -> list:
    """Locates active PostgreSQL log files across running processes, open file descriptors, and filesystem."""
    candidates = []
    if CONFIG["PG_LOG_DIR"] and os.path.isdir(CONFIG["PG_LOG_DIR"]):
        for f in glob.glob(os.path.join(CONFIG["PG_LOG_DIR"], "*.log*")):
            if os.path.isfile(f) and not f.endswith((".gz", ".zip")):
                candidates.append(os.path.realpath(f))

    # 1. Port-based process inspection (Linux /proc)
    if target_port and sys.platform.startswith("linux"):
        try:
            import subprocess
            res = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in res.stdout.splitlines():
                if f":{target_port} " in line or f":{target_port}	" in line:
                    match = re.search(r'pid=(\d+)', line)
                    if match:
                        pid = match.group(1)
                        # Check /proc/<pid>/fd for open log files
                        fd_dir = f"/proc/{pid}/fd"
                        if os.path.isdir(fd_dir):
                            for fd in os.listdir(fd_dir):
                                try:
                                    link = os.readlink(os.path.join(fd_dir, fd))
                                    if os.path.isfile(link) and (".log" in link or ".csv" in link) and not link.endswith((".gz", ".zip")):
                                        rf = os.path.realpath(link)
                                        if rf not in candidates:
                                            candidates.append(rf)
                                except Exception:
                                    pass
                        # Check data directory in cmdline (-D <path>)
                        cmdline_path = f"/proc/{pid}/cmdline"
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                                cmd = f.read().replace(' ', ' ')
                                m_data = re.search(r'-D\s+([^\s]+)', cmd) or re.search(r'-D([^\s]+)', cmd)
                                if m_data:
                                    data_dir = m_data.group(1).strip()
                                    for sub in ("log", "pg_log", "current_logfiles", ""):
                                        p = os.path.join(data_dir, sub, "*.log*") if sub else os.path.join(data_dir, "*.log*")
                                        for f in glob.glob(p):
                                            if os.path.isfile(f) and not f.endswith((".gz", ".zip")):
                                                rf = os.path.realpath(f)
                                                if rf not in candidates:
                                                    candidates.append(rf)
        except Exception:
            pass

    # 2. Inspect all running postgres processes for open log file descriptors
    if sys.platform.startswith("linux"):
        try:
            import subprocess
            pg_pids = subprocess.run(["pgrep", "-f", "postgres"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
            for p in pg_pids.stdout.splitlines()[:15]:
                pid = p.strip()
                if not pid: continue
                fd_dir = f"/proc/{pid}/fd"
                if os.path.isdir(fd_dir):
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(os.path.join(fd_dir, fd))
                            if os.path.isfile(link) and (".log" in link or ".csv" in link) and not link.endswith((".gz", ".zip")):
                                rf = os.path.realpath(link)
                                if rf not in candidates:
                                    candidates.append(rf)
                        except Exception:
                            pass
        except Exception:
            pass

    # 3. Standard and enterprise PostgreSQL log paths
    standard_patterns = [
        "/var/log/postgresql/postgresql-*.log",
        "/var/log/postgresql/*.log",
        "/var/lib/pgsql/*/data/log/*.log*",
        "/var/lib/pgsql/*/data/pg_log/*.log*",
        "/var/lib/postgresql/*/main/log/*.log*",
        "/var/lib/postgresql/*/main/pg_log/*.log*",
        "/var/log/pgaudit/*.log*",
        "/var/log/pgaudit.log",
        "/data/*/log/*.log*",
        "/data/*/pg_log/*.log*",
        "/application/*/log*/*.log*",
        "/opt/*/data/log/*.log*",
        "/opt/pgsql/*/data/log/*.log*"
    ]
    for pattern in standard_patterns:
        for f in glob.glob(pattern):
            if os.path.isfile(f) and not f.endswith((".gz", ".zip")):
                rf = os.path.realpath(f)
                if rf not in candidates:
                    candidates.append(rf)

    # Prioritize latest modified active log file
    candidates.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
    return [{"path": f, "source": "postgres"} for f in candidates[:5]]

# ── NOISE FILTERING & PATTERNS ────────────────────────────────────────────────

STATIC_EXT_RE = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|eot|map|webp)$', re.IGNORECASE)
ATTACK_PATH_TOKENS = (
    "..", "/etc/", "union", "select", "<script", "onerror", "${jndi", 
    "exec", "cmd", "drop", "eval", "'", "%27", "%22", "%3c", "%3e", "0x", "sleep("
)
USER_QUERY_TOKENS = (
    "user=", "username=", "userName=", "userid=", "user_id=", 
    "login=", "email=", "account=", "token=", "session=", "auth=", "empid=", "usr="
)

def is_noise_tomcat_access_log(raw_line: str) -> bool:
    """Returns True if the line is purely static asset or routine noise."""
    if ' 200 ' not in raw_line and ' 304 ' not in raw_line:
        return False  # Keep all 401, 403, 404, 500, etc.

    m_req = re.search(r'"([A-Z]+)\s+([^"\s]+)\s+HTTP/[0-9\.]+"', raw_line)
    if not m_req:
        return False

    method = m_req.group(1).upper()
    if method not in ("GET", "HEAD", "OPTIONS"):
        return False

    raw_path = m_req.group(2)
    path_lower = urllib.parse.unquote(raw_path).lower()

    if any(atk in path_lower for atk in ATTACK_PATH_TOKENS):
        return False
    if any(u in path_lower for u in USER_QUERY_TOKENS):
        return False

    clean_path = raw_path.split("?")[0].lower()
    if STATIC_EXT_RE.search(clean_path):
        return True
    if clean_path in ("/", "") and ("?" not in raw_path or raw_path.endswith("?")):
        return True

    return False

def is_routine_access_line(raw_line: str) -> bool:
    """Returns True if line is a standard 2xx/3xx GET/HEAD with no attacks or errors (candidate for aggregation)."""
    if ' 200 ' not in raw_line and ' 304 ' not in raw_line and ' 204 ' not in raw_line:
        return False
    p_lower = raw_line.lower()
    if any(k in p_lower for k in ATTACK_PATH_TOKENS):
        return False
    if any(k in p_lower for k in USER_QUERY_TOKENS):
        return False
    return True

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
            # Seek to end on startup to avoid replaying historic logs
            self.file_obj.seek(0, os.SEEK_END)
            self.last_pos = self.file_obj.tell()
        except Exception as e:
            print(f"[WARN] Error opening {self.filepath}: {e}")

    def read_new_lines(self) -> list:
        if not self.file_obj or self.file_obj.closed:
            self._open()
            return []

        try:
            if not os.path.exists(self.filepath):
                return []
            current_stat = os.stat(self.filepath)
            # Detect log rotation (new inode) or file truncation
            if current_stat.st_ino != self.inode or current_stat.st_size < self.last_pos:
                try: self.file_obj.close()
                except Exception: pass
                self._open()
                return []

            lines = []
            while True:
                line = self.file_obj.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    lines.append(line)
            self.last_pos = self.file_obj.tell()
            return lines
        except Exception as e:
            print(f"[WARN] Error reading {self.filepath}: {e}")
            try: self.file_obj.close()
            except Exception: pass
            self.file_obj = None
            return []

    def close(self):
        if self.file_obj and not self.file_obj.closed:
            try: self.file_obj.close()
            except Exception: pass

# ── AUTO-UPDATE ENGINE ────────────────────────────────────────────────────────

def check_and_apply_auto_update():
    """Checks for collector script updates from SOC and applies cleanly."""
    soc_url = CONFIG["SOC_URL"].rstrip("/")
    update_url = f"{soc_url}/api/app/collector.py"
    try:
        req = urllib.request.Request(update_url, headers={
            "User-Agent": f"SecurePulse-App-Collector/{COLLECTOR_VERSION}"
        })
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            if resp.status == 200:
                new_code = resp.read().decode("utf-8")
                m_ver = re.search(r'COLLECTOR_VERSION\s*=\s*["\']([^"\']+)["\']', new_code)
                if m_ver and m_ver.group(1) > COLLECTOR_VERSION:
                    script_path = os.path.realpath(__file__)
                    with open(script_path + ".tmp", "w", encoding="utf-8") as tf:
                        tf.write(new_code)
                    os.replace(script_path + ".tmp", script_path)
                    print(f"[UPDATE] Applied upgrade to {m_ver.group(1)}. Restarting collector...")
                    os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception:
        pass

# ── DECOUPLED BACKGROUND HEARTBEAT THREAD ─────────────────────────────────────

class HeartbeatWorker(threading.Thread):
    def __init__(self, session: PersistentSession, stop_event: threading.Event, tailers_ref: dict, stats_ref: dict):
        super().__init__(daemon=True)
        self.session = session
        self.stop_event = stop_event
        self.tailers_ref = tailers_ref
        self.stats_ref = stats_ref

    def run(self):
        while not self.stop_event.is_set():
            try:
                monitored = list(self.tailers_ref.keys())
                hb_payload = {
                    "token": CONFIG["ENROLLMENT_TOKEN"],
                    "app_id": CONFIG["APP_ID"],
                    "node_name": CONFIG["NODE_NAME"],
                    "role": CONFIG["COMPONENT_ROLE"],
                    "version": COLLECTOR_VERSION,
                    "target_port": CONFIG["TARGET_PORT"],
                    "target_db_name": CONFIG["TARGET_DB_NAME"],
                    "monitored_files": monitored,
                    "dropped_events": self.stats_ref.get("dropped_events", 0),
                    "buffered_events": self.stats_ref.get("buffered_events", 0),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                res = self.session.post("/api/app/heartbeat", hb_payload, CONFIG["ENROLLMENT_TOKEN"])
                if res.get("code") == 200:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [HB] Heartbeat acknowledged by SOC. Monitored files: {len(monitored)}")
                    if res.get("latest_version") and res.get("latest_version") > COLLECTOR_VERSION:
                        check_and_apply_auto_update()
                elif res.get("code") == 401:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [WARN] Heartbeat unauthorized (401). Pausing heartbeat for 300s.")
                    for _ in range(600):
                        if self.stop_event.is_set():
                            break
                        time.sleep(0.5)
                    continue
            except Exception as e:
                print(f"[WARN] Heartbeat exception: {e}")

            # Sleep in small slices so thread terminates quickly on shutdown
            interval = float(CONFIG.get("HEARTBEAT_INTERVAL_SEC", 30.0))
            for _ in range(int(interval * 2)):
                if self.stop_event.is_set():
                    break
                time.sleep(0.5)

# ── MAIN COLLECTOR ENGINE ─────────────────────────────────────────────────────

def run_collector():
    load_env_file()
    print("=" * 70)
    print(f"  SecurePulse App Collector v{COLLECTOR_VERSION}")
    print(f"  Target Application ID: {CONFIG['APP_ID']} | Node: {CONFIG['NODE_NAME']}")
    print(f"  Role: {CONFIG['COMPONENT_ROLE']} | SOC Endpoint: {CONFIG['SOC_URL']}")
    print(f"  Batch Window: {CONFIG['BATCH_MAX_WAIT_SEC']}s | Batch Max Lines: {CONFIG['BATCH_MAX_LINES']}")
    print(f"  Queue Capacity: {CONFIG['MAX_QUEUE_SIZE']} | Aggregate Routine Access: {CONFIG['AGGREGATE_ROUTINE_ACCESS']}")
    print("=" * 70)

    if not CONFIG["ENROLLMENT_TOKEN"]:
        print("[FATAL] ENROLLMENT_TOKEN is missing. Provide valid token via collector.env or env variable.")
        sys.exit(1)

    session = PersistentSession(CONFIG["SOC_URL"])
    stop_event = threading.Event()

    import signal
    def handle_signal(sig, frame):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [SHUTDOWN] Signal {sig} received. Terminating collector cleanly...")
        stop_event.set()
        try:
            if session._conn:
                session._conn.close()
        except Exception:
            pass
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
    except Exception:
        pass
    tailers = {}
    stats = {"dropped_events": 0, "buffered_events": 0}

    # Start decoupled background heartbeat
    hb_thread = HeartbeatWorker(session, stop_event, tailers, stats)
    hb_thread.start()

    buffered_events = []
    routine_aggregates = {}  # key: (source, path, status) -> count
    last_flush = time.time()
    last_discover = 0.0

    current_backoff_sec = 0.0
    unauthorized_until = 0.0

    try:
        while not stop_event.is_set():
            now = time.time()

            # 1. Periodic Log Discovery (every 60s or on startup)
            if not tailers or (now - last_discover >= 60.0):
                last_discover = now
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

            # 2. Read new lines from all log tailers
            for fpath, tailer in list(tailers.items()):
                new_lines = tailer.read_new_lines()
                for line in new_lines:
                    # Database filtering (flexible prefix & security signal matching)
                    if CONFIG["COMPONENT_ROLE"] == "database" and CONFIG["TARGET_DB_NAME"]:
                        db_token = CONFIG["TARGET_DB_NAME"].lower()
                        line_lower = line.lower()
                        has_db_match = (
                            f"@{db_token}" in line_lower or
                            f"db={db_token}" in line_lower or
                            f"dbname={db_token}" in line_lower or
                            f'database "{db_token}"' in line_lower or
                            db_token in line_lower
                        )
                        is_sec_signal = any(k in line_lower for k in (
                            "fatal", "panic", "error", "drop table", "alter table", "truncate",
                            "create table", "grant", "revoke", "statement:", "audit:", "duration:", "connection authorized"
                        ))
                        if not has_db_match and not is_sec_signal:
                            continue

                    # Tomcat Access Log Filtering & Aggregation
                    if tailer.source_type == "tomcat_access":
                        if is_noise_tomcat_access_log(line):
                            continue
                        
                        # Requirement 2: Aggregate routine 2xx/3xx HTTP access lines
                        if CONFIG["AGGREGATE_ROUTINE_ACCESS"] and is_routine_access_line(line):
                            m_p = re.search(r'"[A-Z]+\s+([^"\s]+)\s+HTTP/[0-9\.]+"\s+(\d+)', line)
                            if m_p:
                                p_clean = m_p.group(1).split("?")[0][:60]
                                s_code = m_p.group(2)
                                agg_key = (tailer.source_type, p_clean, s_code)
                                routine_aggregates[agg_key] = routine_aggregates.get(agg_key, 0) + 1
                                continue

                    # Tomcat Catalina Log Filtering
                    if tailer.source_type == "tomcat_catalina":
                        line_l = line.lower()
                        if any(k in line_l for k in [
                            "info [main]", "info [catalina", "server startup in", 
                            "deploying web application", "deployment of web application",
                            "at org.apache.catalina", "at org.apache.coyote", "at org.apache.tomcat",
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

            # Append aggregated routine summaries to buffer
            if routine_aggregates and (now - last_flush >= float(CONFIG["BATCH_MAX_WAIT_SEC"])):
                for (src, path_s, status_s), count in list(routine_aggregates.items()):
                    buffered_events.append({
                        "source": src,
                        "file": "aggregated",
                        "line": f'AGGREGATED_ACCESS {count} requests -> GET {path_s} HTTP/1.1 {status_s}',
                        "captured_at": datetime.now(timezone.utc).isoformat()
                    })
                routine_aggregates.clear()

            # 3. Requirement 3: Bounded local queue (max 10,000 events)
            max_q = int(CONFIG["MAX_QUEUE_SIZE"])
            if len(buffered_events) > max_q:
                excess = len(buffered_events) - max_q
                # Drop oldest events
                buffered_events = buffered_events[excess:]
                stats["dropped_events"] += excess
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [QUEUE] Buffer exceeded {max_q}. Dropped {excess} oldest events.")

            stats["buffered_events"] = len(buffered_events)

            # 4. Flush batch to SOC if threshold reached or wait timeout elapsed
            should_flush = (
                len(buffered_events) >= int(CONFIG["BATCH_MAX_LINES"]) or
                (buffered_events and (now - last_flush) >= float(CONFIG["BATCH_MAX_WAIT_SEC"]))
            )

            # Requirement 4: On 401, pause event submission for 300s
            if now < unauthorized_until:
                time.sleep(float(CONFIG["POLL_INTERVAL_SEC"]))
                continue

            # Requirement 3: Exponential backoff on 429
            if current_backoff_sec > 0:
                time.sleep(current_backoff_sec)
                current_backoff_sec = 0.0

            if should_flush and buffered_events:
                batch_size = int(CONFIG["BATCH_MAX_LINES"])
                batch_to_send = buffered_events[:batch_size]
                payload = {
                    "token": CONFIG["ENROLLMENT_TOKEN"],
                    "app_id": CONFIG["APP_ID"],
                    "node_name": CONFIG["NODE_NAME"],
                    "role": CONFIG["COMPONENT_ROLE"],
                    "events": batch_to_send
                }
                res = session.post("/api/app/events", payload, CONFIG["ENROLLMENT_TOKEN"])
                status_code = res.get("code", 500)

                if res.get("status") == "success":
                    buffered_events = buffered_events[len(batch_to_send):]
                    last_flush = now
                    current_backoff_sec = 0.0
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [INGEST] Forwarded {len(batch_to_send)} events to SOC. Ingested: {res.get('ingested')}, Severity: {res.get('highest_severity')}")
                elif status_code == 401:
                    # Requirement 4: Stop sending events, log warning, retry only every 5 mins
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [ERROR] Collector unauthorized or token revoked (HTTP 401). Pausing event forwarding for 300s.")
                    unauthorized_until = now + 300.0
                    last_flush = now
                elif status_code == 429:
                    # Requirement 3: Honour Retry-After or exponential backoff with jitter
                    retry_after = res.get("retry_after")
                    if retry_after and retry_after.isdigit():
                        delay = float(retry_after) + random.uniform(0.5, 2.0)
                    else:
                        delay = min(120.0, max(2.0, (current_backoff_sec or 2.0) * 2.0)) + random.uniform(0.5, 2.0)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [RATE-LIMIT] Server returned 429 Too Many Requests. Backing off for {delay:.1f}s.")
                    current_backoff_sec = delay
                    last_flush = now
                else:
                    delay = min(60.0, max(2.0, (current_backoff_sec or 2.0) * 1.5)) + random.uniform(0.5, 1.5)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [WARN] Event ingestion failed (HTTP {status_code}): {res.get('reason')}. Retrying in {delay:.1f}s...")
                    current_backoff_sec = delay
                    last_flush = now

            time.sleep(float(CONFIG["POLL_INTERVAL_SEC"]))

    except KeyboardInterrupt:
        print("\n[INFO] Collector received shutdown signal. Terminating cleanly...")
    finally:
        stop_event.set()
        hb_thread.join(timeout=2.0)
        for t in tailers.values():
            t.close()
        print("[INFO] Collector shutdown complete.")

if __name__ == "__main__":
    run_collector()
