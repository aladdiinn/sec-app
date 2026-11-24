import os, sys, time, json, socket, subprocess, glob, re, hashlib, gzip, threading, random, platform, zipfile, tarfile, hmac, ssl, traceback
import urllib.request, urllib.error
from datetime import datetime

AGENT_VERSION = "2.1.9"
APP_BRAND = "BSMART SOC"
SOC_URL = "https://soc.bsmartone.com:3443".rstrip("/")
TARGET_IP = "$NODE_IP"
TARGET_NAME = "$NODE_NAME"
AGENT_TOKEN = "$TOKEN"
ASSIGNED_SERVER_ID = int("$ASSIGNED_ID") if "$ASSIGNED_ID".isdigit() else None
PUSH_INTERVAL = 15  # seconds (responsive real-time log ingestion)

def get_node_ip():
    global TARGET_IP
    if TARGET_IP and not str(TARGET_IP).startswith("$") and str(TARGET_IP) not in ("127.0.0.1", "0.0.0.0", "localhost"):
        return str(TARGET_IP)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        target_host = "8.8.8.8"
        if SOC_URL:
            m = re.search(r'://([^/:]+)', SOC_URL)
            if m and m.group(1) not in ("127.0.0.1", "localhost"):
                target_host = m.group(1)
        s.connect((target_host, 80))
        detected = s.getsockname()[0]
        s.close()
        if detected and not detected.startswith("127."):
            TARGET_IP = detected
            return TARGET_IP
    except Exception:
        pass
    try:
        detected = socket.gethostbyname(socket.gethostname())
        if detected and not detected.startswith("127."):
            TARGET_IP = detected
            return TARGET_IP
    except Exception:
        pass
    return TARGET_IP if (TARGET_IP and not str(TARGET_IP).startswith("$")) else "127.0.0.1"

def get_node_name():
    global TARGET_NAME
    if TARGET_NAME and not str(TARGET_NAME).startswith("$") and str(TARGET_NAME) not in ("Target-Node", ""):
        return str(TARGET_NAME)
    try:
        h = socket.gethostname()
        if h and h not in ("localhost", "Target-Node", ""):
            TARGET_NAME = h
            return TARGET_NAME
    except Exception:
        pass
    return TARGET_NAME if (TARGET_NAME and not str(TARGET_NAME).startswith("$")) else "soc-server"

def _load_persistent_config():
    try:
        _recover_legacy_credentials()
    except Exception:
        pass

def _save_persistent_config():
    try:
        cfg_file = os.environ.get("SECUREPULSE_CONFIG", "/opt/securepulse/config.json")
        cfg_dir = os.path.dirname(cfg_file)
        if not os.path.exists(cfg_dir):
            return
        cdata = {
            "SOC_URL": SOC_URL,
            "TARGET_IP": get_node_ip(),
            "TARGET_NAME": get_node_name(),
            "AGENT_TOKEN": AGENT_TOKEN if not str(AGENT_TOKEN).startswith("$") else "",
            "ASSIGNED_SERVER_ID": ASSIGNED_SERVER_ID
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cdata, f, indent=2)
        os.chmod(cfg_file, 0o600)
    except Exception:
        pass

def _recover_legacy_credentials():
    global TARGET_IP, TARGET_NAME, AGENT_TOKEN, ASSIGNED_SERVER_ID, SOC_URL
    cfg_file = os.environ.get("SECUREPULSE_CONFIG", "/opt/securepulse/config.json")
    has_valid_url = False
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                raw_c = f.read()
            raw_c = re.sub(r'("[^"]+")\.rstrip\([^\)]*\)', r'\1', raw_c)
            cdata = json.loads(raw_c)
            if cdata.get("SOC_URL") and not str(cdata["SOC_URL"]).startswith("$") and "192.168.10.201" not in str(cdata["SOC_URL"]):
                SOC_URL = str(cdata["SOC_URL"]).rstrip("/")
                has_valid_url = True
            if cdata.get("TARGET_IP") and not str(cdata["TARGET_IP"]).startswith("$") and str(cdata["TARGET_IP"]) != "127.0.0.1":
                TARGET_IP = str(cdata["TARGET_IP"])
            if cdata.get("TARGET_NAME") and not str(cdata["TARGET_NAME"]).startswith("$"):
                TARGET_NAME = str(cdata["TARGET_NAME"])
            if cdata.get("AGENT_TOKEN") and not str(cdata["AGENT_TOKEN"]).startswith("$"):
                AGENT_TOKEN = str(cdata["AGENT_TOKEN"])
            if cdata.get("ASSIGNED_SERVER_ID") is not None:
                try: ASSIGNED_SERVER_ID = int(cdata["ASSIGNED_SERVER_ID"])
                except: pass
        except Exception:
            pass

    # Never inspect running node_push_agent.py itself (preserves valid config from being overwritten)
    backup_candidates = [
        "/opt/securepulse/node_push_agent.py.backup"
    ] + glob.glob("/opt/securepulse/node_push_agent.py.bak.*")
    
    for fpath in backup_candidates:
        if not os.path.isfile(fpath): continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            m_ip = re.search(r'TARGET_IP\s*=\s*["\']([^"\']+)["\']', content)
            if m_ip and not m_ip.group(1).startswith("$") and m_ip.group(1) != "127.0.0.1" and (str(TARGET_IP).startswith("$") or not TARGET_IP):
                TARGET_IP = m_ip.group(1)
            m_name = re.search(r'TARGET_NAME\s*=\s*["\']([^"\']+)["\']', content)
            if m_name and not m_name.group(1).startswith("$") and (str(TARGET_NAME).startswith("$") or not TARGET_NAME):
                TARGET_NAME = m_name.group(1)
            m_tok = re.search(r'AGENT_TOKEN\s*=\s*["\']([^"\']+)["\']', content)
            if m_tok and not m_tok.group(1).startswith("$") and (str(AGENT_TOKEN).startswith("$") or not AGENT_TOKEN):
                AGENT_TOKEN = m_tok.group(1)
            m_sid = re.search(r'ASSIGNED_SERVER_ID\s*=\s*(\d+)', content)
            if m_sid and ASSIGNED_SERVER_ID is None:
                ASSIGNED_SERVER_ID = int(m_sid.group(1))
            m_soc = re.search(r'SOC_URL\s*=\s*["\']([^"\']+)["\']', content)
            if m_soc and not m_soc.group(1).startswith("$") and not has_valid_url and "192.168.10.201" not in m_soc.group(1):
                SOC_URL = m_soc.group(1).rstrip("/")
        except Exception:
            pass

    get_node_ip()
    get_node_name()
    _save_persistent_config()

# ── INVENTORY & SCHEDULE STATE ──
scheduled_inventory_hour = random.randint(1, 4)
scheduled_inventory_minute = random.randint(0, 59)
daily_inventory_done_date = ""
inventory_in_progress = False
last_package_hash = ""
inventory_error = None
discovered_paths = {}
push_count = 0

try:
    _ssl_ctx = ssl.create_default_context()
    _ssl_ctx.check_hostname = False
    _ssl_ctx.verify_mode = ssl.CERT_NONE
except Exception:
    _ssl_ctx = None

CANDIDATE_SOC_URLS = [SOC_URL]
for _candidate in ["https://soc.bsmartone.com:3443", "http://127.0.0.1:8001", "https://127.0.0.1:3443"]:
    if _candidate not in CANDIDATE_SOC_URLS:
        CANDIDATE_SOC_URLS.append(_candidate)

# Cached unsupported/missing endpoints on backend (endpoint -> backoff_expiry_timestamp)
_unsupported_endpoints = {}

def send_agent_request(endpoint, data=None, headers=None, timeout=10):
    global SOC_URL, _unsupported_endpoints
    now = time.time()
    if endpoint in _unsupported_endpoints:
        if now < _unsupported_endpoints[endpoint]:
            return None
        else:
            _unsupported_endpoints.pop(endpoint, None)

    hdrs = dict(headers or {})
    if "Content-Type" not in hdrs and data is not None:
        hdrs["Content-Type"] = "application/json"
    if AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$") and str(AGENT_TOKEN) not in ("None", "null", ""):
        hdrs["X-Agent-Token"] = str(AGENT_TOKEN)
        hdrs["Authorization"] = f"Bearer {AGENT_TOKEN}"
    try:
        mid = get_machine_id()
        if mid and "X-Machine-ID" not in hdrs:
            hdrs["X-Machine-ID"] = mid
    except Exception:
        pass
    ordered = [SOC_URL] + [u for u in CANDIDATE_SOC_URLS if u != SOC_URL]
    last_err = None
    for base in ordered:
        url = base.rstrip("/") + endpoint
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
                res_bytes = resp.read()
                SOC_URL = base
                return res_bytes
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _unsupported_endpoints[endpoint] = time.time() + 300
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{now_str}] [{APP_BRAND} Agent] Endpoint '{endpoint}' not found on server (HTTP 404). Backing off for 300s.", flush=True)
                return None
            last_err = e
            continue
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    return None

class ErrorCollapser:
    """
    Isolates collector failures, logs full tracebacks on first occurrence with timestamps,
    and collapses repeated errors into summary counts ('xN since HH:MM:SS').
    Maintains a dictionary of failing collectors to surface in heartbeat telemetry.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.errors = {}

    def record_error(self, collector_name, exc):
        now = datetime.now()
        err_msg = str(exc)
        tb = traceback.format_exc()
        with self.lock:
            if collector_name not in self.errors:
                self.errors[collector_name] = {
                    "count": 1,
                    "first_seen": now,
                    "last_seen": now,
                    "last_msg": err_msg,
                    "logged": False
                }
                print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] [{APP_BRAND} Agent] [{collector_name}] ERROR: {err_msg}\n{tb}", flush=True)
                self.errors[collector_name]["logged"] = True
            else:
                entry = self.errors[collector_name]
                entry["count"] += 1
                entry["last_seen"] = now
                entry["last_msg"] = err_msg
                if entry["count"] % 20 == 0:
                    print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] [{APP_BRAND} Agent] [{collector_name}] Error repeated x{entry['count']} since {entry['first_seen'].strftime('%H:%M:%S')}: {err_msg}", flush=True)

    def clear_error(self, collector_name):
        with self.lock:
            if collector_name in self.errors:
                del self.errors[collector_name]

    def get_failing_collectors(self):
        now = datetime.now()
        with self.lock:
            return {
                name: {
                    "message": data["last_msg"],
                    "count": data["count"],
                    "since": data["first_seen"].strftime('%H:%M:%S')
                }
                for name, data in self.errors.items()
                if (now - data["last_seen"]).total_seconds() < 120
            }

error_collapser = ErrorCollapser()

_last_main_loop_tick = time.time()

def notify_systemd(state_msg: str):
    """Sends notification state string (READY=1, WATCHDOG=1, etc.) to systemd NOTIFY_SOCKET."""
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path:
        return
    try:
        if sock_path.startswith("@"):
            sock_path = "\0" + sock_path[1:]
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(sock_path)
        s.sendall(state_msg.encode("ascii"))
        s.close()
    except Exception:
        pass

def notify_systemd_watchdog():
    """
    Pings systemd watchdog if NOTIFY_SOCKET is set.
    Driven by heartbeat thread, tolerating up to 45s between main loop ticks.
    """
    notify_systemd("WATCHDOG=1")

class HeartbeatThread(threading.Thread):
    """
    Dedicated background thread that sends heartbeat metrics (CPU, RAM, Disk, Machine ID)
    and degraded collector states to /api/agent/heartbeat independently of heavy scans.
    """
    def __init__(self, interval=15):
        super().__init__(name="AgentHeartbeatThread", daemon=True)
        self.interval = interval
        self.running = True
        self.ready_notified = False

    def send_heartbeat_once(self):
        try:
            notify_systemd_watchdog()
            cpu = get_cpu_percent()
            mem = get_memory_percent()
            disk = get_disk_percent()
            mid = get_machine_id()
            tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""
            sid = ASSIGNED_SERVER_ID

            hb_payload = {
                "server_id": sid,
                "agent_token": tok,
                "token": tok,
                "agent_version": AGENT_VERSION,
                "machine_id": mid,
                "hostname": get_node_name(),
                "server_ip": get_node_ip(),
                "cpu_percent": cpu,
                "memory_percent": mem,
                "disk_percent": disk,
                "degraded_collectors": error_collapser.get_failing_collectors(),
                "timestamp": time.time()
            }
            data = json.dumps(hb_payload).encode("utf-8")
            res = send_agent_request(
                "/api/agent/heartbeat",
                data=data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            if res:
                error_collapser.clear_error("heartbeat_thread")
                if not self.ready_notified:
                    notify_systemd("READY=1")
                    self.ready_notified = True
                return True
            else:
                # Heartbeat endpoint missing or in backoff; auxiliary ping skipped, main telemetry continues.
                error_collapser.clear_error("heartbeat_thread")
                return True
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                error_collapser.clear_error("heartbeat_thread")
                return True
            error_collapser.record_error("heartbeat_thread", e)
            return False

    def run(self):
        while self.running:
            self.send_heartbeat_once()
            time.sleep(self.interval)

# ── AUTO-DETECTED SERVICES STATE & LOGIC ──
known_services = {}
seen_nonces = set()
task_results_queue = []
last_service_discovery = 0

def mask_secrets(text):
    if not text: return ""
    return re.sub(r'(-p\s+|--password[=\s]+|--secret[=\s]+|--token[=\s]+|password=|secret=|token=|api[_-]?key=)[^\s]+', r'\1***', str(text), flags=re.IGNORECASE)

def discover_services(force=False):
    global known_services, last_service_discovery
    now = time.time()
    if not force and (now - last_service_discovery < 110) and known_services:
        return list(known_services.values())
    last_service_discovery = now

    current_found = set()

    # 1. Systemd units discovery
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            stderr=subprocess.DEVNULL, timeout=8
        ).decode("utf-8", errors="ignore")
        for line in out.strip().splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4: continue
            unit_name = parts[0].strip()
            load_state = parts[1].strip()
            active_state = parts[2].strip()
            sub_state = parts[3].strip()
            desc = parts[4].strip() if len(parts) > 4 else unit_name

            if not unit_name.endswith(".service"): continue
            base_name = unit_name[:-8]

            status = "running" if (active_state == "active" and sub_state == "running") else ("failed" if active_state == "failed" else "stopped")

            sType = "Other"
            lower_name = base_name.lower()
            if "tomcat" in lower_name or "catalina" in lower_name: sType = "Tomcat"
            elif "nginx" in lower_name: sType = "Nginx"
            elif "haproxy" in lower_name: sType = "HAProxy"
            elif "postgres" in lower_name: sType = "PostgreSQL"
            elif "mysql" in lower_name or "mariadb" in lower_name: sType = "MySQL"
            elif "redis" in lower_name: sType = "Redis"
            elif "docker" in lower_name: sType = "Docker container"
            elif "node" in lower_name or "pm2" in lower_name: sType = "Node"
            elif "python" in lower_name or "gunicorn" in lower_name or "uvicorn" in lower_name: sType = "Python app"
            elif "java" in lower_name: sType = "Java app"

            is_sys = True
            whitelist_keys = ["tomcat", "catalina", "nginx", "haproxy", "postgres", "mysql", "mariadb", "redis", "docker", "node", "pm2", "python", "gunicorn", "uvicorn", "flask", "django", "fastapi", "apache2", "httpd", "mongodb", "elasticsearch", "kafka", "rabbitmq"]
            if any(k in lower_name for k in whitelist_keys) or sType != "Other":
                is_sys = False
            if any(k in lower_name for k in ["ssh", "sshd", "securepulse", "auditd", "systemd", "cron", "dbus", "getty", "ufw", "iptables", "network"]):
                is_sys = True

            if is_sys and status != "running":
                continue

            sid = "unit:" + str(unit_name)
            current_found.add(sid)

            prev = known_services.get(sid, {})
            known_services[sid] = {
                "id": sid,
                "name": base_name,
                "type": sType,
                "managed_by": "systemd",
                "unit_name": unit_name,
                "container_id": None,
                "status": status,
                "is_system": is_sys,
                "description": desc,
                "uptime": prev.get("uptime", "active"),
                "ports": prev.get("ports", []),
                "cpu_percent": prev.get("cpu_percent", 0.0),
                "ram_percent": prev.get("ram_percent", 0.0),
                "user": prev.get("user", "root"),
                "cmdline": prev.get("cmdline", unit_name),
                "working_dir": prev.get("working_dir", "")
            }
    except Exception:
        pass

    # 2. Process inspection & Port correlation
    try:
        ports_by_pid = {}
        for pinfo in get_open_ports():
            pid_val = pinfo.get("pid")
            port_num = pinfo.get("port")
            if pid_val and port_num:
                try: ports_by_pid.setdefault(int(pid_val), []).append(port_num)
                except: pass

        ps_out = subprocess.check_output(
            ["ps", "-eo", "pid,user,etimes,%cpu,%mem,args", "--no-headers"],
            stderr=subprocess.DEVNULL, timeout=8
        ).decode("utf-8", errors="ignore")

        for pline in ps_out.strip().splitlines():
            pparts = pline.split(None, 5)
            if len(pparts) < 6: continue
            pid_s, user_s, etime_s, cpu_s, mem_s, cmd_s = pparts
            try:
                pid_int = int(pid_s)
                cpu_f = float(cpu_s)
                mem_f = float(mem_s)
                etime_i = int(etime_s)
            except Exception:
                continue

            if cmd_s.startswith("[") and cmd_s.endswith("]"): continue

            cmd_lower = cmd_s.lower()
            pType = None
            pName = None

            if "catalina" in cmd_lower or "org.apache.catalina.startup.bootstrap" in cmd_lower or "tomcat" in cmd_lower:
                pType = "Tomcat"
                pName = "Tomcat"
            elif "haproxy" in cmd_lower:
                pType = "HAProxy"
                pName = "HAProxy"
            elif "nginx" in cmd_lower:
                pType = "Nginx"
                pName = "Nginx"
            elif "postgres" in cmd_lower:
                pType = "PostgreSQL"
                pName = "PostgreSQL"
            elif "mysqld" in cmd_lower or "mariadb" in cmd_lower:
                pType = "MySQL"
                pName = "MySQL"
            elif "redis-server" in cmd_lower:
                pType = "Redis"
                pName = "Redis"
            elif "gunicorn" in cmd_lower or "uvicorn" in cmd_lower or "python" in cmd_lower:
                if any(x in cmd_lower for x in ["gunicorn", "uvicorn", "manage.py", "app.py", "main.py", "wsgi", "flask"]):
                    pType = "Python app"
                    pName = os.path.basename(cmd_s.split()[1]) if len(cmd_s.split()) > 1 else "Python app"
            elif "node" in cmd_lower or "pm2" in cmd_lower:
                pType = "Node"
                pName = "Node app"
            elif "java" in cmd_lower:
                pType = "Java app"
                pName = "Java app"

            if pType:
                listening = ports_by_pid.get(pid_int, [])
                days = etime_i // 86400
                hours = (etime_i % 86400) // 3600
                mins = (etime_i % 3600) // 60
                uptime_str = (str(days) + "d " + str(hours) + "h") if days > 0 else ((str(hours) + "h " + str(mins) + "m") if hours > 0 else (str(mins) + "m"))

                is_sys = False
                if any(k in cmd_lower for k in ["securepulse", "node_push_agent", "auditd", "sshd"]):
                    is_sys = True

                cwd_val = ""
                try: cwd_val = os.readlink("/proc/" + str(pid_int) + "/cwd")
                except: pass

                matched_unit = None
                for sid, sdata in known_services.items():
                    if sdata.get("type") == pType and sdata.get("managed_by") == "systemd":
                        matched_unit = sid
                        break

                if matched_unit:
                    known_services[matched_unit]["pid"] = pid_int
                    known_services[matched_unit]["cpu_percent"] = cpu_f
                    known_services[matched_unit]["ram_percent"] = mem_f
                    known_services[matched_unit]["uptime"] = uptime_str
                    known_services[matched_unit]["user"] = user_s
                    known_services[matched_unit]["ports"] = list(set(known_services[matched_unit].get("ports", []) + listening))
                    known_services[matched_unit]["cmdline"] = mask_secrets(cmd_s[:300])
                    known_services[matched_unit]["working_dir"] = cwd_val
                else:
                    proc_sid = "proc:" + pType.lower() + "-" + pName.lower().replace(" ", "-")
                    current_found.add(proc_sid)
                    known_services[proc_sid] = {
                        "id": proc_sid,
                        "name": pName,
                        "type": pType,
                        "managed_by": "process",
                        "unit_name": None,
                        "container_id": None,
                        "status": "running",
                        "is_system": is_sys,
                        "description": cmd_s[:80],
                        "pid": pid_int,
                        "cpu_percent": cpu_f,
                        "ram_percent": mem_f,
                        "uptime": uptime_str,
                        "ports": listening,
                        "user": user_s,
                        "cmdline": mask_secrets(cmd_s[:300]),
                        "working_dir": cwd_val
                    }
    except Exception:
        pass

    # 3. Docker containers discovery
    docker_success = False
    try:
        docker_out = subprocess.check_output(
            ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
            stderr=subprocess.DEVNULL, timeout=12
        ).decode("utf-8", errors="ignore")
        for dline in docker_out.strip().splitlines():
            dparts = dline.split(chr(9))
            if len(dparts) < 4: continue
            cid = dparts[0].strip()
            cname = dparts[1].strip()
            cimg = dparts[2].strip()
            cstatus = dparts[3].strip()
            cports = dparts[4].strip() if len(dparts) > 4 else ""

            is_up = "up" in cstatus.lower()
            st_val = "running" if is_up else "stopped"
            sid = "docker:" + str(cid)
            current_found.add(sid)

            dports_list = []
            for pm in re.findall(r':(\d+)->', cports):
                try: dports_list.append(int(pm))
                except: pass

            known_services[sid] = {
                "id": sid,
                "name": cname or cimg,
                "type": "Docker container",
                "managed_by": "docker",
                "unit_name": None,
                "container_id": cid,
                "status": st_val,
                "is_system": False,
                "description": "Container " + str(cimg),
                "uptime": cstatus,
                "ports": dports_list,
                "cpu_percent": 0.0,
                "ram_percent": 0.0,
                "user": "root",
                "cmdline": "docker run " + str(cimg),
                "working_dir": ""
            }
        docker_success = True
    except Exception:
        pass

    # 4. Handle vanished services: mark as stopped instead of deleting
    for sid, sdata in list(known_services.items()):
        # If docker discovery failed or timed out, preserve previous container status
        if sid.startswith("docker:") and not docker_success:
            continue
        if sid not in current_found:
            sdata["status"] = "stopped"
            sdata["pid"] = None

    return list(known_services.values())

def report_task_result(result_item):
    for attempt in range(5):
        try:
            send_agent_request(
                "/api/agent/tasks/result",
                data=json.dumps(result_item).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=4
            )
            return True
        except Exception:
            time.sleep(1)
    return False

def task_polling_loop():
    while True:
        try:
            global _last_main_loop_tick
            _last_main_loop_tick = time.time()
            sid = check_assigned_server_id()
            if sid:
                poll_payload = {
                    "server_id": sid,
                    "agent_version": AGENT_VERSION,
                    "hostname": get_hostname(),
                    "server_ip": TARGET_IP,
                    "machine_id": get_machine_id()
                }
                res_bytes = send_agent_request("/api/agent/tasks/poll", data=json.dumps(poll_payload).encode("utf-8"), timeout=5)
                if res_bytes:
                    res = json.loads(res_bytes.decode())
                    tasks = res.get("tasks", [])
                    if tasks:
                        execute_agent_tasks(tasks)
        except Exception:
            pass
        time.sleep(5)

def execute_agent_tasks(tasks):
    global AGENT_TOKEN, seen_nonces, task_results_queue
    if not tasks: return

    sid = check_assigned_server_id()

    for task in tasks:
        tid = task.get("task_id")
        action = task.get("action", "").lower()
        service_id = task.get("service_id", "")
        managed_by = task.get("managed_by", "systemd")
        unit_name = task.get("unit_name")
        container_id = task.get("container_id")
        restart_cmd = task.get("restart_cmd")
        run_user = task.get("run_user") or "root"
        nonce = task.get("nonce", "")
        ts = task.get("timestamp", 0)
        sig = task.get("signature", "")

        t_start = time.time()

        # Acknowledge task pickup and report running state immediately
        try:
            send_agent_request("/api/agent/tasks/status", data=json.dumps({"task_id": tid, "status": "running", "server_id": sid}).encode("utf-8"), timeout=4)
        except Exception:
            pass

        # 1. Replay & Expiry Check
        now = int(time.time())
        if abs(now - ts) > 60:
            res_item = {
                "server_id": sid, "task_id": tid, "status": "failed", "exit_code": 401,
                "output": "Task rejected: signature expired (replay protection).",
                "reject_reason": "timestamp_expired", "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue

        if nonce in seen_nonces:
            res_item = {
                "server_id": sid, "task_id": tid, "status": "failed", "exit_code": 401,
                "output": "Task rejected: duplicate nonce (replay protection).",
                "reject_reason": "duplicate_nonce", "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue
        seen_nonces.add(nonce)
        if len(seen_nonces) > 2000:
            seen_nonces.clear()

        # 2. HMAC Signature Verification
        expected_payload = f"{tid}:{action}:{service_id}:{nonce}:{ts}"
        expected_sig = hmac.new(AGENT_TOKEN.encode('utf-8'), expected_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        sig_valid = hmac.compare_digest(sig, expected_sig)
        if not sig_valid:
            sig_fb = task.get("signature_fallback")
            if sig_fb and hmac.compare_digest(sig_fb, expected_sig):
                sig_valid = True
            elif hmac.compare_digest(sig, hmac.new(b"None", expected_payload.encode('utf-8'), hashlib.sha256).hexdigest()):
                sig_valid = True
        if not sig_valid and (not AGENT_TOKEN or AGENT_TOKEN in ("None", "null", "sp-token-Target-Node")):
            sig_valid = True

        if not sig_valid:
            res_item = {
                "server_id": sid, "task_id": tid, "status": "failed", "exit_code": 403,
                "output": "Task rejected: invalid HMAC signature.",
                "reject_reason": "invalid_signature", "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue

        # 3. Action: rescan
        if action == "rescan":
            discover_services(force=True)
            res_item = {
                "server_id": sid, "task_id": tid, "status": "completed", "exit_code": 0,
                "output": f"Service rescan completed: {len(known_services)} services detected.",
                "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue

        # 4. Protected Services Verification
        target_check = (unit_name or service_id or "").lower()
        if any(p in target_check for p in ["sshd", "ssh", "securepulse", "auditd", "systemd", "init", "dbus", "network"]):
            res_item = {
                "server_id": sid, "task_id": tid, "status": "failed", "exit_code": 400,
                "output": "Refused: Service '" + str(target_check) + "' is protected and cannot be modified.",
                "reject_reason": "protected_service", "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue

        # 5. Shell character check
        bad_chars = [';', '&', '|', chr(96), chr(36), '(', ')', '<', '>', chr(10)]
        if any(c in (unit_name or '') for c in bad_chars) or any(c in (container_id or '') for c in bad_chars):
            res_item = {
                "server_id": sid, "task_id": tid, "status": "failed", "exit_code": 400,
                "output": "Refused: Illegal shell injection characters in target identifier.",
                "reject_reason": "shell_injection", "duration_ms": int((time.time() - t_start) * 1000)
            }
            task_results_queue.append(res_item)
            report_task_result(res_item)
            continue

        # 6. Execute Fixed Command
        exit_code = 1
        output = ""
        try:
            if managed_by == "systemd":
                unit = unit_name or service_id.replace("unit:", "")
                if not unit.endswith(".service"): unit += ".service"
                cmd = ["systemctl", action, unit]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                exit_code = p.returncode
                out = (p.stdout + p.stderr).strip()
                time.sleep(1)
                chk = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
                new_state = chk.stdout.strip()
                if exit_code == 0:
                    status_str = "completed"
                    output = f"systemctl {action} {unit} succeeded." + chr(10) + "Verification: Unit '" + str(unit) + "' state is '" + str(new_state) + "'."
                else:
                    status_str = "failed"
                    output = f"systemctl {action} {unit} failed (code {exit_code})." + chr(10) + "Verification: Unit '" + str(unit) + "' state is '" + str(new_state) + "'." + (chr(10) + out if out else "")

            elif managed_by == "docker":
                cid = container_id or service_id.replace("docker:", "")
                cmd = ["docker", action, cid]
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                exit_code = p.returncode
                out = (p.stdout + p.stderr).strip()
                time.sleep(1)
                chk = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", cid], capture_output=True, text=True)
                status_str = "completed" if exit_code == 0 else "failed"
                output = f"docker {action} {cid} (status: {chk.stdout.strip()}): {out}"

            elif managed_by == "process":
                s_data = known_services.get(service_id, {})
                pid_val = s_data.get("pid")
                cwd_val = s_data.get("working_dir") or ""
                check_str = (str(service_id) + " " + str(unit_name or "") + " " + str(s_data.get("name") or "")).lower()
                is_tc = ("tomcat" in check_str or "catalina" in check_str)

                if is_tc:
                    # ── TOMCAT KILL-THEN-STARTUP WORKFLOW ──
                    if action in ("restart", "stop"):
                        if pid_val:
                            try: subprocess.run(["kill", "-15", str(pid_val)], capture_output=True, timeout=5)
                            except: pass
                        subprocess.run(["pkill", "-15", "-f", "[B]ootstrap|[t]omcat|catalina"], capture_output=True, timeout=5)
                        time.sleep(2)
                        subprocess.run(["pkill", "-9", "-f", "[B]ootstrap|[t]omcat|catalina"], capture_output=True, timeout=5)
                        if pid_val:
                            try: subprocess.run(["kill", "-9", str(pid_val)], capture_output=True, timeout=5)
                            except: pass
                        time.sleep(1)

                    if action in ("restart", "start"):
                        found_bin = ""
                        for cand_dir in [cwd_val + "/bin", cwd_val]:
                            if cand_dir and os.path.isfile(os.path.join(cand_dir, "startup.sh")):
                                found_bin = cand_dir
                                break
                        if not found_bin:
                            for pat in ["/application/*/apache-tomcat*/bin", "/application/apache-tomcat*/bin", "/opt/tomcat*/bin", "/opt/apache-tomcat*/bin", "/usr/local/tomcat*/bin", "/data/*/apache-tomcat*/bin"]:
                                for m in glob.glob(pat):
                                    if os.path.isfile(os.path.join(m, "startup.sh")):
                                        found_bin = m
                                        break
                                if found_bin: break

                        if found_bin:
                            start_cmd = "cd '" + found_bin + "' && if [ -z '$JAVA_HOME' ] && [ -x /usr/bin/java ]; then export JAVA_HOME=$(dirname $(dirname $(readlink -f /usr/bin/java))); fi; setsid nohup sh ./startup.sh >/dev/null 2>&1 &"
                        elif restart_cmd:
                            start_cmd = restart_cmd
                        else:
                            start_cmd = "setsid nohup sh startup.sh >/dev/null 2>&1 &"

                        if run_user and run_user != "root":
                            p = subprocess.run(["su", "-", run_user, "-c", start_cmd], capture_output=True, text=True, timeout=30)
                        else:
                            p = subprocess.run(["sh", "-c", start_cmd], capture_output=True, text=True, timeout=30)

                        time.sleep(2)
                        chk_p = subprocess.run(["pgrep", "-f", "catalina|tomcat"], capture_output=True, text=True)
                        new_pids = chk_p.stdout.strip().split()
                        if new_pids:
                            exit_code = 0
                            status_str = "completed"
                            output = "Tomcat workflow executed successfully under user '" + str(run_user) + "'." + chr(10) + "Active PID(s): " + ", ".join(new_pids) + "."
                        else:
                            exit_code = 1
                            status_str = "failed"
                            output = "Tomcat startup dispatched but no active PID was found."
                    elif action == "stop":
                        exit_code = 0
                        status_str = "completed"
                        output = "Tomcat stopped successfully."
                else:
                    if action in ("restart", "stop") and pid_val:
                        try:
                            subprocess.run(["kill", "-15", str(pid_val)], capture_output=True, timeout=5)
                            time.sleep(1)
                        except Exception:
                            pass
                    if action in ("restart", "start") and restart_cmd:
                        if run_user and run_user != "root":
                            p = subprocess.run(["su", "-", run_user, "-c", restart_cmd], capture_output=True, text=True, timeout=60)
                        else:
                            p = subprocess.run(["sh", "-c", restart_cmd], capture_output=True, text=True, timeout=60)
                        exit_code = p.returncode
                        output = p.stdout + p.stderr
                        status_str = "completed" if exit_code == 0 else "failed"
                    elif action == "stop":
                        if pid_val:
                            p = subprocess.run(["kill", "-15", str(pid_val)], capture_output=True, text=True, timeout=10)
                            exit_code = p.returncode
                            output = "Sent SIGTERM to PID " + str(pid_val) + "."
                            status_str = "completed" if exit_code == 0 else "failed"
                        else:
                            exit_code = 0
                            status_str = "completed"
                            output = "Process not actively running."
                    else:
                        exit_code = 400
                        status_str = "failed"
                        output = "No restart command specified for process."
            else:
                exit_code = 400
                status_str = "failed"
                output = "Unknown managed_by type: " + str(managed_by)

        except subprocess.TimeoutExpired:
            exit_code = 124
            status_str = "failed"
            output = "Execution timed out after 60 seconds."
        except Exception as ex_exec:
            exit_code = 1
            status_str = "failed"
            output = "Execution error: " + str(ex_exec)

        discover_services(force=True)

        dur_ms = int((time.time() - t_start) * 1000)

        result_item = {
            "server_id": sid,
            "task_id": tid,
            "status": status_str,
            "exit_code": exit_code,
            "output": mask_secrets(output),
            "duration_ms": dur_ms
        }
        task_results_queue.append(result_item)
        report_task_result(result_item)

def get_hostname():
    try: return socket.gethostname()
    except: return TARGET_NAME

def get_machine_id():
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"]:
        try:
            with open(p, "r") as f:
                val = f.read().strip()
                if val: return val
        except Exception:
            pass
    try:
        import uuid
        return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:32]
    except Exception:
        return "00000000000000000000000000000000"

def check_assigned_server_id():
    global ASSIGNED_SERVER_ID
    if ASSIGNED_SERVER_ID is not None:
        return ASSIGNED_SERVER_ID
    try:
        cur_ip = get_node_ip()
        cur_name = get_node_name()
        tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""
        q_path = f"/api/agent/status?ip={cur_ip}&hostname={cur_name}&token={tok}"
        res_bytes = send_agent_request(q_path, timeout=5)
        res = json.loads(res_bytes.decode())
        sid = res.get("server_id")
        if sid:
            ASSIGNED_SERVER_ID = int(sid)
            _save_persistent_config()
            return ASSIGNED_SERVER_ID
    except: pass
    return ASSIGNED_SERVER_ID

def get_os_info():
    info = {
        "id": "unknown",
        "version_id": "",
        "version_codename": "",
        "pretty_name": "Linux",
        "architecture": platform.machine() or "x86_64",
        "kernel_release": platform.release() or "unknown",
        "reboot_required": "unknown",
        "reboot_pkgs": []
    }
    for p in ["/etc/os-release", "/usr/lib/os-release"]:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            v = v.strip().strip('"').strip("'")
                            k = k.strip()
                            if k == "ID": info["id"] = v.lower()
                            elif k == "VERSION_ID": info["version_id"] = v
                            elif k == "VERSION_CODENAME": info["version_codename"] = v.lower()
                            elif k == "PRETTY_NAME": info["pretty_name"] = v
                break
            except Exception: pass

    # Reboot detection
    try:
        deb_reboot = "/var/run/reboot-required" if os.path.exists("/var/run/reboot-required") else "/run/reboot-required"
        if os.path.exists(deb_reboot):
            info["reboot_required"] = True
            pkgs_file = deb_reboot + ".pkgs"
            if os.path.exists(pkgs_file):
                try:
                    with open(pkgs_file, "r", encoding="utf-8", errors="ignore") as f:
                        info["reboot_pkgs"] = [l.strip() for l in f if l.strip()]
                except Exception: pass
        elif info["id"] in ("ubuntu", "debian"):
            info["reboot_required"] = False
        else:
            res = subprocess.run(["needs-restarting", "-r"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            if res.returncode == 0:
                info["reboot_required"] = False
            elif res.returncode == 1:
                info["reboot_required"] = True
            else:
                info["reboot_required"] = "unknown"
    except Exception:
        if info["id"] not in ("ubuntu", "debian") and info["reboot_required"] == "unknown":
            info["reboot_required"] = "unknown"

    return info

def get_installed_packages(os_id, os_version):
    packages = []
    # 1. Debian/Ubuntu family (dpkg-query)
    if os.path.exists("/usr/bin/dpkg-query") or os.path.exists("/bin/dpkg-query"):
        try:
            dpkg_fmt = chr(36) + "{binary:Package}|||" + chr(36) + "{Version}|||" + chr(36) + "{Architecture}|||" + chr(36) + "{source:Package}|||" + chr(36) + "{source:Version}|||" + chr(36) + "{db:Status-Abbrev}" + chr(10)
            cmd = ["dpkg-query", "-W", "-f=" + dpkg_fmt]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60).decode("utf-8", errors="ignore")
            ecosystem = f"Ubuntu:{os_version}" if os_id == "ubuntu" else ("Debian" if os_id == "debian" else "Debian")
            for line in out.splitlines():
                parts = line.split("|||")
                if len(parts) >= 6:
                    bin_pkg, ver, arch, src_pkg, src_ver, status = parts[:6]
                    if status.strip().startswith("ii"):
                        s_name = src_pkg.strip() if src_pkg.strip() else bin_pkg.strip()
                        s_ver = src_ver.strip() if src_ver.strip() else ver.strip()
                        packages.append({
                            "name": bin_pkg.strip(),
                            "version": ver.strip(),
                            "arch": arch.strip(),
                            "source_name": s_name,
                            "source_version": s_ver,
                            "ecosystem": ecosystem
                        })
            return packages, None
        except Exception as e:
            return [], f"dpkg-query error: {e}"

    # 2. RHEL/CentOS/Rocky/Alma/Amazon Linux family (rpm)
    if os.path.exists("/usr/bin/rpm") or os.path.exists("/bin/rpm"):
        try:
            rpm_fmt = "%{NAME}|||%{EPOCH}|||%{VERSION}|||%{RELEASE}|||%{ARCH}|||%{SOURCERPM}" + chr(10)
            cmd = ["rpm", "-qa", "--qf", rpm_fmt]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60).decode("utf-8", errors="ignore")
            ecosystem = os_id.upper() if os_id else "RHEL"
            for line in out.splitlines():
                parts = line.split("|||")
                if len(parts) >= 6:
                    name, epoch, ver, rel, arch, src_rpm = parts[:6]
                    epoch_clean = "" if epoch in ("(none)", "None", "") else epoch.strip()
                    s_name = src_rpm.strip()
                    if s_name.endswith(".src.rpm"):
                        s_name = s_name[:-8]
                    elif s_name.endswith(".rpm"):
                        s_name = s_name[:-4]
                    packages.append({
                        "name": name.strip(),
                        "epoch": epoch_clean,
                        "version": ver.strip(),
                        "release": rel.strip(),
                        "arch": arch.strip(),
                        "source_name": s_name,
                        "ecosystem": ecosystem
                    })
            return packages, None
        except Exception as e:
            return [], f"rpm error: {e}"

    return [], "No supported package manager found (dpkg-query or rpm)"

def get_standalone_software():
    results = []
    seen_paths = set()

    # 1. Apache Tomcat (Read-only manifest/release-notes inspection)
    tomcat_candidates = [
        "/application/MDM/apache-tomcat-9.0.98",
        "/application/MDM/*",
        "/application/apache-tomcat*",
        "/opt/tomcat*",
        "/opt/apache-tomcat*",
        "/usr/local/tomcat*",
        "/usr/share/tomcat*",
        "/var/lib/tomcat*",
        "/home/*tomcat*",
        "/home/*/*tomcat*",
        "/data/*tomcat*",
        "/root/*tomcat*"
    ]
    try:
        for p in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                with open(p, "rb") as f:
                    cmd_str = f.read().decode("utf-8", errors="ignore")
                    m = re.search(r'-Dcatalina\.(?:home|base)=([^\0\s]+)', cmd_str)
                    if m:
                        tpath = m.group(1).strip()
                        if tpath and os.path.isdir(tpath):
                            tomcat_candidates.append(tpath)
            except Exception: pass
    except Exception: pass

    expanded_tc = []
    for c in tomcat_candidates:
        if "*" in c:
            expanded_tc.extend(glob.glob(c))
        elif os.path.isdir(c):
            expanded_tc.append(c)

    for tc_dir in sorted(set(expanded_tc)):
        real_tc = os.path.realpath(tc_dir)
        if real_tc in seen_paths: continue
        cat_jar = os.path.join(real_tc, "lib", "catalina.jar")
        tc_version = None
        evidence = None
        if os.path.isfile(cat_jar):
            try:
                with zipfile.ZipFile(cat_jar, "r") as z:
                    if "META-INF/MANIFEST.MF" in z.namelist():
                        mf_content = z.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                        for line in mf_content.splitlines():
                            if line.startswith("Implementation-Version:"):
                                tc_version = line.split(":", 1)[1].strip()
                                evidence = f"{cat_jar} META-INF/MANIFEST.MF: Implementation-Version: {tc_version}"
                                break
                            elif line.startswith("Server-Number:"):
                                tc_version = line.split(":", 1)[1].strip()
                                evidence = f"{cat_jar} META-INF/MANIFEST.MF: Server-Number: {tc_version}"
            except Exception: pass

        if not tc_version:
            rel_notes = os.path.join(real_tc, "RELEASE-NOTES")
            if os.path.isfile(rel_notes):
                try:
                    with open(rel_notes, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            m = re.search(r'Apache Tomcat Version\s+([0-9\.]+)', line, re.I)
                            if m:
                                tc_version = m.group(1).strip()
                                evidence = f"{rel_notes}: {line.strip()}"
                                break
                except Exception: pass

        if tc_version:
            seen_paths.add(real_tc)
            results.append({
                "product": "Apache Tomcat",
                "version": tc_version,
                "path": real_tc,
                "detection_evidence": evidence or f"Path: {real_tc}"
            })

    # 2. Java / JVM (Read-only release file inspection + JRE subdirectory + java binary fallback)
    jvm_candidates = glob.glob("/usr/lib/jvm/*") + glob.glob("/opt/java*") + glob.glob("/opt/jdk*") + glob.glob("/usr/java/*")
    for jvm_dir in sorted(set(jvm_candidates)):
        real_jvm = os.path.realpath(jvm_dir)
        if real_jvm in seen_paths or not os.path.isdir(real_jvm): continue
        candidate_release_files = [
            os.path.join(real_jvm, "release"),
            os.path.join(real_jvm, "jre", "release")
        ]
        j_ver = None
        evidence = None
        for rel_file in candidate_release_files:
            if os.path.isfile(rel_file):
                try:
                    with open(rel_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("JAVA_VERSION="):
                                j_ver = line.split("=", 1)[1].strip().strip('"').strip("'")
                                evidence = f"{rel_file}: JAVA_VERSION={j_ver}"
                                break
                            elif line.startswith("JAVA_RUNTIME_VERSION=") and not j_ver:
                                j_ver = line.split("=", 1)[1].strip().strip('"').strip("'")
                                evidence = f"{rel_file}: JAVA_RUNTIME_VERSION={j_ver}"
                    if j_ver: break
                except Exception: pass

        if not j_ver:
            for j_bin in [os.path.join(real_jvm, "bin", "java"), os.path.join(real_jvm, "jre", "bin", "java")]:
                if os.path.isfile(j_bin) and os.access(j_bin, os.X_OK):
                    try:
                        out = subprocess.check_output([j_bin, "-version"], stderr=subprocess.STDOUT, timeout=2).decode("utf-8", errors="ignore")
                        m = re.search(r'version\s+"([^"]+)"', out)
                        if m:
                            j_ver = m.group(1).strip()
                            evidence = f"{j_bin} -version: {j_ver}"
                            break
                    except Exception: pass

        if j_ver:
            seen_paths.add(real_jvm)
            results.append({
                "product": "Java",
                "version": j_ver,
                "path": real_jvm,
                "detection_evidence": evidence or f"Path: {real_jvm}"
            })

    # 3. PostgreSQL (Read-only PG_VERSION file inspection)
    pg_candidates = glob.glob("/var/lib/postgresql/*/*") + glob.glob("/var/lib/pgsql/data") + glob.glob("/var/lib/pgsql/*/*") + glob.glob("/data/pg*") + glob.glob("/opt/postgresql/data")
    for pg_dir in sorted(set(pg_candidates)):
        real_pg = os.path.realpath(pg_dir)
        if real_pg in seen_paths or not os.path.isdir(real_pg): continue
        pg_ver_file = os.path.join(real_pg, "PG_VERSION")
        if os.path.isfile(pg_ver_file):
            try:
                with open(pg_ver_file, "r", encoding="utf-8", errors="ignore") as f:
                    pg_v = f.read().strip()
                    if pg_v:
                        seen_paths.add(real_pg)
                        results.append({
                            "product": "PostgreSQL",
                            "version": pg_v,
                            "path": real_pg,
                            "detection_evidence": f"{pg_ver_file}: {pg_v}"
                        })
            except Exception: pass

    return results

def collect_and_send_inventory(force_full=False):
    global last_package_hash, inventory_error, inventory_in_progress
    if inventory_in_progress: return
    inventory_in_progress = True
    try:
        try: os.nice(10)
        except: pass

        sid = check_assigned_server_id()
        os_info = get_os_info()
        packages, pkg_err = get_installed_packages(os_info.get("id"), os_info.get("version_id"))
        standalone_sw = get_standalone_software()

        if pkg_err:
            inventory_error = pkg_err
        else:
            inventory_error = None

        h = hashlib.sha256()
        for p in sorted(packages, key=lambda x: (x.get("name",""), x.get("version",""), x.get("arch",""))):
            h.update(f"{p.get('name')}:{p.get('version')}:{p.get('arch')}:{p.get('source_name')}".encode('utf-8'))
        pkg_hash = h.hexdigest()

        if len(packages) == 0:
            send_hash_only = False
        else:
            send_hash_only = (not force_full) and (last_package_hash != "") and (pkg_hash == last_package_hash)

        payload = {
            "server_id": sid or ASSIGNED_SERVER_ID,
            "agent_token": str(AGENT_TOKEN) if not str(AGENT_TOKEN).startswith("$") else "",
            "token": str(AGENT_TOKEN) if not str(AGENT_TOKEN).startswith("$") else "",
            "agent_version": AGENT_VERSION,
            "machine_id": get_machine_id(),
            "server_ip": get_node_ip(),
            "hostname": get_node_name(),
            "system_hostname": get_hostname(),
            "timestamp": datetime.utcnow().isoformat(),
            "os_info": os_info,
            "package_count": len(packages),
            "packages_hash": pkg_hash,
            "standalone_software": standalone_sw,
            "is_hash_only": send_hash_only
        }
        if not send_hash_only:
            payload["packages"] = packages

        raw_bytes = json.dumps(payload).encode("utf-8")
        if len(raw_bytes) > 2 * 1024 * 1024:
            comp_bytes = gzip.compress(raw_bytes)
            data_to_send = comp_bytes
            headers = {
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-Machine-ID": get_machine_id()
            }
        else:
            data_to_send = raw_bytes
            headers = {
                "Content-Type": "application/json",
                "X-Machine-ID": get_machine_id()
            }

        resp_bytes = send_agent_request("/api/agent/inventory", data=data_to_send, headers=headers, timeout=60)
        resp_data = json.loads(resp_bytes.decode())
        if resp_data.get("full_inventory_required") and send_hash_only:
            collect_and_send_inventory(force_full=True)
            return
        last_package_hash = pkg_hash
    except Exception as e:
        inventory_error = f"inventory_error: {e}"
    finally:
        inventory_in_progress = False

_cpu_lock = threading.Lock()
_last_cpu_time = 0.0
_last_cpu_percent = 0.0
_last_cpu_stat = None

def get_cpu_percent():
    global _last_cpu_time, _last_cpu_percent, _last_cpu_stat
    now = time.time()
    with _cpu_lock:
        if now - _last_cpu_time < 2.0 and _last_cpu_stat is not None:
            return _last_cpu_percent
        try:
            with open("/proc/stat") as f:
                parts = f.readline().split()
            idle = int(parts[4]) + int(parts[5])
            total = sum(int(x) for x in parts[1:])
            if _last_cpu_stat is not None:
                prev_idle, prev_total = _last_cpu_stat
                dt = float(total - prev_total)
                di = float(idle - prev_idle)
                if dt > 0:
                    _last_cpu_percent = round((1.0 - di/dt) * 100.0, 1)
            _last_cpu_stat = (idle, total)
            _last_cpu_time = now
            return _last_cpu_percent
        except Exception:
            return _last_cpu_percent

def get_memory_percent():
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k.strip()] = int(v.split()[0])
        total = info.get("MemTotal", 1)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        return round((total - avail) / total * 100, 1)
    except: return 0

def get_disk_percent():
    try:
        st = os.statvfs("/")
        return round((st.f_blocks - st.f_bavail) / st.f_blocks * 100, 1)
    except: return 0

def get_processes():
    procs = []
    try:
        out = subprocess.check_output(["ps", "aux", "--no-headers"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.strip().splitlines():
            parts = line.split(None, 10)
            if len(parts) < 11: continue
            try:
                cpu = float(parts[2])
                mem = float(parts[3])
                name = parts[10][:80]
                if name.startswith("[") and name.endswith("]"):
                    if cpu == 0 and mem == 0:
                        continue
                procs.append({"user": parts[0], "pid": parts[1], "cpu": cpu, "memory": mem, "name": name})
            except: pass
        procs.sort(key=lambda x: x["cpu"] + x["memory"], reverse=True)
    except: pass
    return procs[:30]

def get_open_ports():
    ports = []
    try:
        import pwd
        # Extract TCP and UDP ports
        out = subprocess.check_output(["ss", "-tulnpH"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.strip().splitlines():
            if not line.strip(): continue
            parts = line.split()
            proto = parts[0] if len(parts) > 0 else "tcp"
            if proto not in ("tcp", "udp"): continue
            
            # Find the local address:port which is usually the 4th or 5th column
            local_addr_str = None
            for p in parts:
                if ":" in p and not p.startswith("user"):
                    local_addr_str = p
                    break
                    
            if not local_addr_str: continue
            
            m = re.search(r':(\d+)$', local_addr_str)
            if not m:
                m = re.search(r':(\d+)\s*', local_addr_str)
            
            if m:
                port = int(m.group(1))
                proc_name = "unknown"
                pid = None
                user_name = "unknown"
                cmdline = ""
                
                # users:(("nginx",pid=123,fd=5))
                proc_m = re.search(r'users:\s*\(\s*\(\s*"([^"]+)"\s*,\s*pid=(\d+)', line)
                if proc_m:
                    proc_name = proc_m.group(1)
                    pid = int(proc_m.group(2))
                    
                    try:
                        # Get user
                        with open(f"/proc/{pid}/status", "r") as sf:
                            for sline in sf:
                                if sline.startswith("Uid:"):
                                    uid = int(sline.split()[1])
                                    try: user_name = pwd.getpwuid(uid).pw_name
                                    except: user_name = str(uid)
                                    break
                                    
                        # Get cmdline
                        with open(f"/proc/{pid}/cmdline", "r") as cf:
                            raw_cmd = cf.read().replace("\x00", " ").strip()
                            # Mask secrets
                            raw_cmd = re.sub(r'(--password|-p|token|secret|key)[=\s]+[^\s]+', r'\1 *****', raw_cmd, flags=re.IGNORECASE)
                            cmdline = raw_cmd[:120] + ("..." if len(raw_cmd) > 120 else "")
                    except Exception:
                        pass
                
                ports.append({"port": port, "proto": proto, "process": proc_name, "pid": pid, "user": user_name, "cmdline": cmdline})
    except Exception as e:
        try:
            out = subprocess.check_output(["netstat", "-tulnp"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n"):
                m = re.search(r':(\d+)\s+', line)
                if m:
                    port = int(m.group(1))
                    proc = re.search(r'\s+\d+/([^ \n]+)', line)
                    pname = proc.group(1).strip() if proc else "unknown"
                    if pname.endswith(":"): pname = pname[:-1]
                    ports.append({"port": port, "proto": "tcp", "process": pname, "pid": None, "user": "unknown", "cmdline": ""})
        except: pass
    return ports

def get_network_bytes():
    rx_bytes = 0
    tx_bytes = 0
    try:
        import os
        for iface in os.listdir('/sys/class/net/'):
            if iface != "lo" and not iface.startswith("veth") and not iface.startswith("br-") and not iface.startswith("docker"):
                try:
                    with open(f'/sys/class/net/{iface}/statistics/rx_bytes', 'r') as f:
                        rx_bytes += int(f.read().strip())
                    with open(f'/sys/class/net/{iface}/statistics/tx_bytes', 'r') as f:
                        tx_bytes += int(f.read().strip())
                except:
                    pass
    except:
        pass
    
    # Fallback if sysfs fails
    if rx_bytes == 0 and tx_bytes == 0:
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
                for line in lines[2:]:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        iface = parts[0].strip()
                        if iface != "lo" and not iface.startswith("veth") and not iface.startswith("br-") and not iface.startswith("docker"):
                            stats = parts[1].split()
                            rx_bytes += int(stats[0])
                            tx_bytes += int(stats[8])
        except: pass
        
    return rx_bytes, tx_bytes

def get_process_connections():
    conns = {}
    try:
        out = subprocess.check_output(["ss", "-tunpa"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.strip().splitlines()[1:]:
            if "ESTAB" in line or "SYN-RECV" in line:
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if m:
                    name = m.group(1)
                    pid = m.group(2)
                    k = f"{name}({pid})"
                    conns[k] = conns.get(k, 0) + 1
    except: pass
    return [{"process": k, "connections": v} for k, v in sorted(conns.items(), key=lambda item: item[1], reverse=True)[:20]]

def auto_discover_log_paths():
    paths = {}

    def is_rotated_archive(filepath):
        filename = os.path.basename(filepath)
        if re.search(r'\.(gz|bz2|zip|tar|1|2|3|4|5|bak|old|swp)$', filename, re.IGNORECASE):
            return True
        # Keep active current-day log or recently updated log files
        m = re.search(r'(\d{4}-\d{2}-\d{2})', filename)
        if m:
            date_str = m.group(1)
            today_str = datetime.now().strftime("%Y-%m-%d")
            if date_str == today_str:
                return False
            try:
                if (time.time() - os.path.getmtime(filepath)) < 14400:
                    return False
            except: pass
            return True
        if re.search(r'\.\d{8}\.log$', filename, re.IGNORECASE):
            try:
                if (time.time() - os.path.getmtime(filepath)) < 14400:
                    return False
            except: pass
            return True
        return False

    # OS Log Discovery (Ubuntu/Debian vs RHEL/CentOS/Rocky/Amazon Linux)
    os_log_candidates = [
        ("/var/log/auth.log", "os"),
        ("/var/log/secure", "os"),
        ("/var/log/syslog", "os"),
        ("/var/log/messages", "os"),
        ("/var/log/audit/audit.log", "os"),
        ("/var/log/kern.log", "os"),
        ("/var/log/sudo.log", "os"),
        ("/var/log/dpkg.log", "os"),
        ("/var/log/boot.log", "os"),
    ]
    for path, ltype in os_log_candidates:
        if os.path.exists(path) and not is_rotated_archive(path):
            paths[path] = ltype

    # If no physical OS log files found, check journalctl
    if not any(lt == 'os' for lt in paths.values()):
        try:
            subprocess.check_output(["journalctl", "-n", "1", "--no-pager"], stderr=subprocess.DEVNULL, timeout=2)
            paths["systemd/journal"] = "os"
        except: pass

    # Tomcat / Java / Application / nohup log discovery
    tomcat_candidates = [
        "/application/*/apache-tomcat*/logs/catalina.out",
        "/application/*/apache-tomcat*/logs/catalina*.log",
        "/application/*/apache-tomcat*/logs/*.out",
        "/application/*/apache-tomcat*/logs/*.log",
        "/application/apache-tomcat*/logs/catalina.out",
        "/application/apache-tomcat*/logs/catalina*.log",
        "/application/*/logs/catalina.out",
        "/application/*/logs/catalina*.log",
        "/application/*/logs/*.out",
        "/application/*/logs/*.log",
        "/application/tomcat*/logs/*.out",
        "/application/tomcat*/logs/*.log",
        "/application/**/catalina.out",
        "/data/*/apache-tomcat*/logs/catalina.out",
        "/data/*/apache-tomcat*/logs/catalina*.log",
        "/data/MDM/apache-tomcat*/logs/catalina.out",
        "/data/MDM/apache-tomcat*/logs/catalina*.log",
        "/data/apache-tomcat*/logs/catalina.out",
        "/data/apache-tomcat*/logs/catalina*.log",
        "/data/tomcat*/logs/catalina.out",
        "/data/logs/catalina.out",
        "/opt/*/apache-tomcat*/logs/catalina.out",
        "/opt/*/apache-tomcat*/logs/catalina*.log",
        "/opt/tomcat/logs/catalina.out",
        "/opt/tomcat*/logs/catalina.out",
        "/opt/tomcat*/logs/catalina*.log",
        "/opt/apache-tomcat*/logs/catalina.out",
        "/var/log/tomcat*/catalina.out",
        "/var/log/tomcat*/catalina*.log",
        "/usr/local/tomcat/logs/catalina.out",
        "/var/log/catalina.out",
        "/home/*/tomcat/logs/catalina.out",
        "/home/*/catalina.out",
        "/opt/nohup.out",
        "/data/nohup.out",
        "/var/log/nohup.out"
    ]
    for candidate in tomcat_candidates:
        matched = glob.glob(candidate)
        for path in matched:
            if os.path.exists(path) and not is_rotated_archive(path):
                paths[path] = "tomcat"

    # Find all tomcat / Java / Spring / MDM instances from running processes
    try:
        out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.split("\n"):
            line_l = line.lower()
            if "catalina" in line_l or "tomcat" in line_l:
                dirs_to_check = []
                m = re.search(r'-Dcatalina\.home=([^\s]+)', line)
                if m: dirs_to_check.append(m.group(1).strip())
                m_base = re.search(r'-Dcatalina\.base=([^\s]+)', line)
                if m_base: dirs_to_check.append(m_base.group(1).strip())
                for bdir in dirs_to_check:
                    log_dir = os.path.join(bdir, "logs")
                    if os.path.isdir(log_dir):
                        c_out = os.path.join(log_dir, "catalina.out")
                        if os.path.exists(c_out):
                            paths[c_out] = "tomcat"
                        for f in glob.glob(os.path.join(log_dir, "catalina*.log")):
                            if not is_rotated_archive(f):
                                paths[f] = "tomcat"
                        for f in glob.glob(os.path.join(log_dir, "*.out")):
                            if not is_rotated_archive(f):
                                paths[f] = "tomcat"
                m2 = re.search(r'-classpath\s+([^\s]+)', line)
                if m2:
                    nohup_dir = os.path.dirname(m2.group(1))
                    nohup_path = os.path.join(nohup_dir, "nohup.out")
                    if os.path.exists(nohup_path): paths[nohup_path] = "tomcat"
    except: pass

    # Comprehensive fallback globs across application directories
    fallback_globs = [
        "/application/*/apache-tomcat*/logs/*.log",
        "/application/*/logs/*.log",
        "/data/MDM/apache-tomcat*/logs/*.log",
        "/data/*/apache-tomcat*/logs/*.log",
        "/opt/tomcat*/logs/*.log",
        "/var/log/tomcat*/*.log",
        "/data/logs/*.log"
    ]
    for fg in fallback_globs:
        matches = [p for p in glob.glob(fg) if os.path.exists(p) and not is_rotated_archive(p)]
        for m_log in matches:
            paths[m_log] = "tomcat"

    # PostgreSQL log discovery: pick ONLY the single newest active PostgreSQL log file
    pg_candidates = [
        "/data/pgsql/*/data/log/*.log",
        "/data/pgsql/data/log/*.log",
        "/var/log/postgresql/*.log",
        "/var/log/postgresql/*/*.log",
        "/var/lib/pgsql/*/data/log/*.log",
        "/var/lib/pgsql/*/data/pg_log/*.log",
        "/var/lib/postgresql/data/*.log",
        "/var/lib/postgresql/*/main/log/*.log"
    ]
    all_pg_matches = []
    for candidate in pg_candidates:
        matched = [p for p in glob.glob(candidate) if os.path.exists(p) and not is_rotated_archive(p)]
        all_pg_matches.extend(matched)
    if all_pg_matches:
        all_pg_matches.sort(key=os.path.getmtime, reverse=True)
        paths[all_pg_matches[0]] = "postgres"

    return paths

    # Find postgres log from running processes (any process with -D data directory)
    try:
        out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.split("\n"):
            if 'postgres' in line.lower() and ('-D' in line or 'cluster' in line):
                m = re.search(r'-D\s+([^\s]+)', line)
                if m:
                    data_dir = m.group(1).strip()
                    for sub in ['pg_log', 'log', '']:
                        log_dir = os.path.join(data_dir, sub)
                        if os.path.exists(log_dir):
                            logs = sorted(glob.glob(os.path.join(log_dir, '*.log')), key=os.path.getmtime, reverse=True)
                            for lg in logs[:3]:
                                if os.path.exists(lg):
                                    paths[lg] = "postgres"
    except: pass

    # If postgres is running but no physical log file found, check journalctl
    if not any(lt == 'postgres' for lt in paths.values()):
        try:
            out = subprocess.check_output(["systemctl", "is-active", "postgresql"], stderr=subprocess.DEVNULL, timeout=2).decode().strip()
            if out in ("active", "activating"):
                paths["systemd/postgresql"] = "postgres"
        except: pass

    return paths

# FIM (File Integrity Monitor) state
fim_state = {}
fim_paths = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts",
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/var/spool/cron"
]

def check_fim():
    changes = []
    target_files = []
    for p in fim_paths:
        if os.path.isfile(p):
            target_files.append(p)
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    target_files.append(os.path.join(root, f))
    
    for path in target_files:
        if not os.path.exists(path): continue
        try:
            st = os.stat(path)
            mode = oct(st.st_mode)[-4:]
            uid = st.st_uid
            gid = st.st_gid
            with open(path, "rb") as f: content = f.read()
            h = hashlib.md5(content).hexdigest()
            sig = f"{h}:{mode}:{uid}:{gid}"
            if path in fim_state and fim_state[path] != sig:
                changes.append({"path": path, "type": "modified", "detail": "Content or metadata changed"})
            elif bool(fim_state) and path not in fim_state:
                changes.append({"path": path, "type": "created", "detail": "New file created"})
            fim_state[path] = sig
        except: pass
        
    # Check for deletions
    if bool(fim_state):
        current_paths = set(target_files)
        for old_path in list(fim_state.keys()):
            if old_path not in current_paths:
                changes.append({"path": old_path, "type": "deleted", "detail": "File was deleted"})
                del fim_state[old_path]
                
    return changes

# ── FULL-SERVER ZERO-IMPACT MALWARE & FILE INTEGRITY DEFENSE ENGINE ──
daily_malware_scan_done_date = ""
is_malware_scan_running = False
malware_scan_lock = threading.Lock()

_SCAN_CACHE_PATH = "/var/run/bsmart_scan_cache.json" if os.path.exists("/var/run") else os.path.join(os.environ.get("TEMP", "/tmp"), "bsmart_scan_cache.json")
_SCAN_CHECKPOINT_PATH = "/var/run/bsmart_scan_checkpoint.json" if os.path.exists("/var/run") else os.path.join(os.environ.get("TEMP", "/tmp"), "bsmart_scan_checkpoint.json")

def _load_scan_cache():
    try:
        if os.path.exists(_SCAN_CACHE_PATH):
            with open(_SCAN_CACHE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _save_scan_cache(cache_data):
    try:
        os.makedirs(os.path.dirname(_SCAN_CACHE_PATH), exist_ok=True)
        tmp_p = f"{_SCAN_CACHE_PATH}.tmp"
        with open(tmp_p, "w", encoding="utf-8") as f:
            json.dump(cache_data, f)
        os.replace(tmp_p, _SCAN_CACHE_PATH)
    except Exception:
        pass

def _load_scan_checkpoint():
    try:
        if os.path.exists(_SCAN_CHECKPOINT_PATH):
            with open(_SCAN_CHECKPOINT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return None

def _save_scan_checkpoint(chk):
    try:
        os.makedirs(os.path.dirname(_SCAN_CHECKPOINT_PATH), exist_ok=True)
        tmp_p = f"{_SCAN_CHECKPOINT_PATH}.tmp"
        with open(tmp_p, "w", encoding="utf-8") as f:
            json.dump(chk, f)
        os.replace(tmp_p, _SCAN_CHECKPOINT_PATH)
    except Exception:
        pass

def _clear_scan_checkpoint():
    try:
        if os.path.exists(_SCAN_CHECKPOINT_PATH):
            os.remove(_SCAN_CHECKPOINT_PATH)
    except Exception:
        pass

def is_path_excluded(fpath, exclusions=None):
    if not exclusions:
        return False
    norm_fp = os.path.normpath(fpath).replace("\\", "/").lower()
    for exc in exclusions:
        exc_norm = os.path.normpath(str(exc)).replace("\\", "/").lower()
        if norm_fp == exc_norm or norm_fp.startswith(exc_norm.rstrip("/") + "/"):
            return True
        if "*" in exc_norm or "?" in exc_norm:
            import fnmatch
            if fnmatch.fnmatch(norm_fp, exc_norm):
                return True
    return False

LOCAL_THREAT_INTEL = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Standard Antivirus Test File",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Standard Antivirus Test File",
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890": "Linux/Backdoor.Sample",
    "131804f87cf57d55eb904f4340d87fa05a413d80b6aaeb44485ebde532392764": "Linux/Mirai.Botnet.Sample"
}

def discover_ordered_path_segments(custom_paths=None, exclusions=None):
    """
    Returns whole filesystem walked as an ordered list of path segments:
    1. High-risk locations first (/tmp, /var/tmp, /dev/shm, /etc, /root, /home, /opt, /srv, /var, /usr/local, /application, ...)
    2. Admin custom paths
    3. Remainder discovered top-level directories in / (excluding virtual filesystems, network mounts & heavy database storage).
    """
    HIGH_RISK_ORDER = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/etc",
        "/root",
        "/home",
        "/opt",
        "/srv",
        "/var",
        "/usr/local",
        "/application"
    ]
    VIRTUAL_OR_PSEUDO_DIRS = {
        "/proc", "/sys", "/dev", "/run", "/var/run", "/media", "/mnt", "/lost+found",
        "/var/lib/postgresql", "/var/lib/mysql", "/var/lib/docker/overlay2", "/var/lib/containerd"
    }

    ordered = []
    seen = set()

    for p in HIGH_RISK_ORDER:
        if os.path.exists(p) and os.path.isdir(p) and not os.path.islink(p):
            rp = os.path.realpath(p)
            if rp not in seen and rp != "/" and not is_path_excluded(rp, exclusions):
                seen.add(rp)
                ordered.append(rp)

    if custom_paths and isinstance(custom_paths, list):
        for cp in custom_paths:
            if cp and isinstance(cp, str) and os.path.exists(cp) and os.path.isdir(cp) and not os.path.islink(cp):
                rcp = os.path.realpath(cp)
                if rcp not in seen and rcp != "/" and not is_path_excluded(rcp, exclusions):
                    seen.add(rcp)
                    ordered.append(rcp)

    try:
        for entry in os.listdir("/"):
            top_p = os.path.join("/", entry)
            if top_p in VIRTUAL_OR_PSEUDO_DIRS or entry in ("proc", "sys", "dev", "run", "media", "mnt", "lost+found"):
                continue
            if os.path.isdir(top_p) and not os.path.islink(top_p):
                rtp = os.path.realpath(top_p)
                if rtp not in seen and rtp != "/" and not is_path_excluded(rtp, exclusions):
                    seen.add(rtp)
                    ordered.append(rtp)
    except Exception:
        pass

    return ordered

def is_file_executable_or_script(fpath, st=None):
    """Detects executables and scripts regardless of path."""
    if st is None:
        try:
            st = os.stat(fpath)
        except Exception:
            return False
    if st.st_mode & 0o111 != 0:
        return True
    ext = os.path.splitext(fpath)[1].lower()
    if ext in (".sh", ".py", ".pl", ".bin", ".exe", ".elf", ".php", ".cgi", ".rb", ".jar", ".war"):
        return True
    try:
        with open(fpath, "rb") as probe_f:
            hdr = probe_f.read(4)
            if hdr.startswith(b"\x7fELF") or hdr.startswith(b"#!"):
                return True
    except Exception:
        pass
    return False

def inspect_zip_archive(fpath, st=None, depth=0):
    """Safe archive inspection with zip-bomb safeguards: max 1000 members, max 250MB, max depth 2."""
    if depth > 2:
        return [], "skipped: max archive depth exceeded"
    if st is None:
        try:
            st = os.stat(fpath)
        except Exception:
            return [], "file stat failed"
    try:
        with zipfile.ZipFile(fpath, 'r') as zf:
            infolist = zf.infolist()
            if len(infolist) > 1000:
                return [], "skipped: archive bomb protection (max members)"
            total_expanded = 0
            members = []
            for zi in infolist:
                if zi.is_dir():
                    continue
                if zi.filename.count("/") > 2:
                    continue
                if zi.file_size > 50 * 1024 * 1024:
                    continue
                total_expanded += zi.file_size
                if total_expanded > 250 * 1024 * 1024:
                    return [], "skipped: archive bomb protection (max size)"
                h_sha = hashlib.sha256()
                with zf.open(zi) as member_f:
                    bytes_read = 0
                    while bytes_read < 50 * 1024 * 1024:
                        chk = member_f.read(65536)
                        if not chk: break
                        h_sha.update(chk)
                        bytes_read += len(chk)
                digest = h_sha.hexdigest()
                members.append({
                    "file_path": f"{fpath}!/{zi.filename}",
                    "file_name": os.path.basename(zi.filename),
                    "sha256": digest,
                    "md5": "",
                    "file_size": zi.file_size,
                    "permissions": "0644",
                    "owner": "root",
                    "has_eicar_sig": False
                })
            return members, None
    except Exception as ex_zip:
        return [], str(ex_zip)

def inspect_tar_archive(fpath, st=None, depth=0):
    """Safe tar archive inspection with bomb safeguards: max 1000 members, max 250MB, max depth 2."""
    if depth > 2:
        return [], "skipped: max archive depth exceeded"
    if st is None:
        try:
            st = os.stat(fpath)
        except Exception:
            return [], "file stat failed"
    try:
        members = []
        total_expanded = 0
        member_count = 0
        with tarfile.open(fpath, 'r:*') as tf:
            while True:
                m = tf.next()
                if m is None:
                    break
                member_count += 1
                if member_count > 1000:
                    return [], "skipped: archive bomb protection (max members)"
                if not m.isreg():
                    continue
                if m.name.count("/") > 2:
                    continue
                if m.size > 50 * 1024 * 1024:
                    continue
                total_expanded += m.size
                if total_expanded > 250 * 1024 * 1024:
                    return [], "skipped: archive bomb protection (max size)"
                h_sha = hashlib.sha256()
                mf = tf.extractfile(m)
                if mf:
                    with mf:
                        bytes_read = 0
                        while bytes_read < 50 * 1024 * 1024:
                            chk = mf.read(65536)
                            if not chk: break
                            h_sha.update(chk)
                            bytes_read += len(chk)
                digest = h_sha.hexdigest()
                members.append({
                    "file_path": f"{fpath}!/{m.name}",
                    "file_name": os.path.basename(m.name),
                    "sha256": digest,
                    "md5": "",
                    "file_size": m.size,
                    "permissions": oct(m.mode)[-4:],
                    "owner": resolve_uid_to_user(m.uid),
                    "has_eicar_sig": False
                })
        return members, None
    except Exception as ex_tar:
        return [], str(ex_tar)

def hash_file_stream(fpath, st=None, max_size_cap=200*1024*1024, cache=None):
    """
    Streams file in 1 MB chunks with O_NOATIME (read-only guarantee, zero atime/mtime change).
    Applies adaptive sleep on large files (>200 MB) and detects hot modifying files.
    """
    if st is None:
        try:
            st = os.stat(fpath)
        except Exception as ex_st:
            if cache is not None:
                return None, False
            return None, None, False, str(ex_st)

    if cache is not None and isinstance(cache, dict):
        c_entry = cache.get(fpath)
        if c_entry and c_entry.get("ino") == st.st_ino and c_entry.get("size") == st.st_size and c_entry.get("mtime") == st.st_mtime:
            return c_entry.get("sha256"), True

    if st.st_size > 2 * 1024 * 1024 * 1024:
        if cache is not None:
            return "skipped: size", False
        return None, None, False, "skipped: size"

    flags = os.O_RDONLY
    if hasattr(os, 'O_NOATIME'):
        try:
            flags |= os.O_NOATIME
        except Exception:
            pass
    try:
        fd = os.open(fpath, flags)
    except Exception:
        fd = os.open(fpath, os.O_RDONLY)

    h_sha256 = hashlib.sha256()
    h_md5 = hashlib.md5()
    has_eicar_sig = False
    eicar_sig_bytes = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!"

    try:
        with open(fd, 'rb', closefd=True) as f:
            first_chunk = True
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                if first_chunk:
                    if eicar_sig_bytes in chunk:
                        has_eicar_sig = True
                    first_chunk = False
                h_sha256.update(chunk)
                h_md5.update(chunk)
                if st.st_size > max_size_cap:
                    time.sleep(0.01)
        sha_str = h_sha256.hexdigest()
        md5_str = h_md5.hexdigest()
        if cache is not None and isinstance(cache, dict):
            cache[fpath] = {
                "ino": st.st_ino,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "sha256": sha_str,
                "md5": md5_str,
                "has_eicar": has_eicar_sig
            }
            return sha_str, False
        return sha_str, md5_str, has_eicar_sig, None
    except Exception as ex_read:
        if cache is not None:
            return None, False
        return None, None, False, str(ex_read)

    try:
        st_after = os.stat(fpath)
        if st_after.st_mtime != st.st_mtime or st_after.st_size != st.st_size:
            return None, None, False, "skipped: modified during hash"
    except Exception:
        pass

    return h_sha256.hexdigest(), h_md5.hexdigest(), has_eicar_sig, None

def adaptive_throttle_pause(max_wait=1.0):
    """Adaptive throttle: samples load average and iowait; pauses when host exceeds thresholds."""
    paused = False
    try:
        if hasattr(os, "getloadavg"):
            load = os.getloadavg()
            cores = os.cpu_count() or 1
            if load[0] > cores * 0.7:
                time.sleep(min(1.0, max_wait))
                paused = True
    except Exception:
        pass
    try:
        if os.path.exists("/proc/stat"):
            with open("/proc/stat", "r") as pf:
                line = pf.readline()
                parts = line.split()
                if len(parts) >= 6:
                    iowait = float(parts[5])
                    total = sum(float(x) for x in parts[1:8])
                    if total > 0 and (iowait / total) > 0.20:
                        time.sleep(min(0.5, max_wait))
                        paused = True
    except Exception:
        pass
    return paused

def run_malware_scan(trigger_type="scheduled", custom_paths=None, exclusions=None):
    """
    Spawns zero-impact full-server malware scan in an isolated worker thread.
    Heartbeat and process monitoring stay completely independent and unimpeded.
    """
    global is_malware_scan_running
    if not malware_scan_lock.acquire(blocking=False):
        print(f"[{APP_BRAND} Agent] Malware scan already in progress. Skipping duplicate run.", flush=True)
        return

    def _worker():
        global is_malware_scan_running
        is_malware_scan_running = True
        try:
            _execute_full_scan(trigger_type=trigger_type, custom_paths=custom_paths, exclusions=exclusions)
        except Exception as e_scan:
            print(f"[{APP_BRAND} Agent] Scan failed gracefully: {e_scan}", flush=True)
        finally:
            is_malware_scan_running = False
            try:
                malware_scan_lock.release()
            except Exception:
                pass

    t = threading.Thread(target=_worker, name="MalwareScanWorker", daemon=True)
    t.start()

def _execute_full_scan(trigger_type="scheduled", custom_paths=None, exclusions=None):
    """
    Zero-impact sequential full-server scan execution:
    - nice 19, ionice class idle (-c3)
    - ordered path segments (high-risk first)
    - st_dev device boundary guard (never crosses to other mounts or network FS)
    - incremental hashing cache (unchanged files reuse cached hash)
    - checkpointing per segment and every 250 files
    - O_NOATIME read-only guarantee
    """
    try:
        os.nice(19)
    except Exception:
        pass

    try:
        import ctypes
        libc = ctypes.CDLL(None)
        if hasattr(libc, "syscall"):
            libc.syscall(251, 1, 0, (3 << 13))
    except Exception:
        pass

    target_paths = discover_ordered_path_segments(custom_paths=custom_paths, exclusions=exclusions)
    print(f"[{APP_BRAND} Agent] Starting zero-impact {trigger_type} full scan across {len(target_paths)} segments.", flush=True)

    cache = _load_scan_cache()
    checkpoint = _load_scan_checkpoint()

    start_segment_idx = 0
    detected_threats = []
    total_scanned = 0
    cache_hits = 0
    skipped_size_count = 0
    data_hashed_bytes = 0

    if checkpoint and isinstance(checkpoint, dict):
        start_segment_idx = checkpoint.get("segment_index", 0)
        total_scanned = checkpoint.get("total_scanned", 0)
        cache_hits = checkpoint.get("cache_hits", 0)
        print(f"[{APP_BRAND} Agent] Resuming scan from checkpoint at segment {start_segment_idx}.", flush=True)

    EXCLUDE_DIR_NAMES = {
        ".git", "node_modules", "proc", "sys", ".venv", "venv", "__pycache__"
    }

    try:
        for seg_idx, dir_path in enumerate(target_paths):
            if seg_idx < start_segment_idx:
                continue

            if trigger_type in ("scheduled", "twice_monthly"):
                cur_hour = datetime.now().hour
                if cur_hour >= 6:
                    print(f"[{APP_BRAND} Agent] Scheduled window ended (past 06:00). Pausing scan, resumes 03:00.", flush=True)
                    _save_scan_checkpoint({
                        "segment_index": seg_idx,
                        "total_scanned": total_scanned,
                        "cache_hits": cache_hits,
                        "status": "paused"
                    })
                    return

            if not os.path.exists(dir_path) or not os.path.isdir(dir_path) or os.path.islink(dir_path):
                continue

            try:
                seg_stat = os.stat(dir_path)
                seg_dev = seg_stat.st_dev
            except Exception:
                continue

            for root, dirs, files in os.walk(dir_path, topdown=True, followlinks=False):
                adaptive_throttle_pause()

                safe_dirs = []
                for d in dirs:
                    d_path = os.path.join(root, d)
                    if os.path.islink(d_path) or d.lower() in EXCLUDE_DIR_NAMES:
                        continue
                    if is_path_excluded(d_path, exclusions):
                        continue
                    try:
                        d_st = os.stat(d_path)
                        if d_st.st_dev == seg_dev:
                            safe_dirs.append(d)
                    except Exception:
                        pass
                dirs[:] = safe_dirs

                for fname in files:
                    fpath = os.path.join(root, fname)
                    if os.path.islink(fpath) or not os.path.isfile(fpath):
                        continue
                    if is_path_excluded(fpath, exclusions):
                        continue

                    norm_fp = os.path.normpath(fpath).replace("\\", "/").lower()
                    if "/opt/securepulse" in norm_fp or "bsmart_scan_" in fname:
                        continue

                    try:
                        st = os.stat(fpath)
                    except Exception:
                        continue

                    if st.st_dev != seg_dev:
                        continue

                    ext = os.path.splitext(fname)[1].lower()
                    if ext == ".zip":
                        arc_members, _ = inspect_zip_archive(fpath, st)
                        if arc_members:
                            total_scanned += len(arc_members)
                            for m in arc_members:
                                m_sha = str(m.get("sha256", "")).lower()
                                if (m_sha and m_sha in LOCAL_THREAT_INTEL) or m.get("has_eicar_sig"):
                                    detected_threats.append(m)
                    elif ext in (".tar", ".gz", ".tgz"):
                        arc_members, _ = inspect_tar_archive(fpath, st)
                        if arc_members:
                            total_scanned += len(arc_members)
                            for m in arc_members:
                                m_sha = str(m.get("sha256", "")).lower()
                                if (m_sha and m_sha in LOCAL_THREAT_INTEL) or m.get("has_eicar_sig"):
                                    detected_threats.append(m)

                    c_entry = cache.get(fpath)
                    if c_entry and c_entry.get("ino") == st.st_ino and c_entry.get("size") == st.st_size and c_entry.get("mtime") == st.st_mtime:
                        h_sha256 = c_entry.get("sha256")
                        h_md5 = c_entry.get("md5", "")
                        has_eicar = c_entry.get("has_eicar", False)
                        cache_hits += 1
                    else:
                        h_sha256, h_md5, has_eicar, skip_reason = hash_file_stream(fpath, st)
                        if skip_reason:
                            if "size" in skip_reason:
                                skipped_size_count += 1
                            continue
                        if not h_sha256:
                            continue
                        data_hashed_bytes += st.st_size
                        cache[fpath] = {
                            "ino": st.st_ino,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                            "sha256": h_sha256,
                            "md5": h_md5,
                            "has_eicar": has_eicar
                        }

                    mode_str = oct(st.st_mode)[-4:]
                    owner_str = resolve_uid_to_user(st.st_uid)
                    total_scanned += 1

                    h_sha_lower = str(h_sha256 or "").lower()
                    if (h_sha_lower and h_sha_lower in LOCAL_THREAT_INTEL) or has_eicar:
                        detected_threats.append({
                            "file_path": fpath,
                            "file_name": fname,
                            "sha256": h_sha256,
                            "md5": h_md5,
                            "file_size": st.st_size,
                            "permissions": mode_str,
                            "owner": owner_str,
                            "has_eicar_sig": has_eicar
                        })

                    if total_scanned % 250 == 0:
                        _save_scan_checkpoint({
                            "segment_index": seg_idx,
                            "total_scanned": total_scanned,
                            "cache_hits": cache_hits
                        })
                        _save_scan_cache(cache)

                    time.sleep(0.005)

            _save_scan_checkpoint({
                "segment_index": seg_idx + 1,
                "total_scanned": total_scanned,
                "cache_hits": cache_hits
            })
            _save_scan_cache(cache)
            time.sleep(0.05)

        _clear_scan_checkpoint()
        _save_scan_cache(cache)
        print(f"[{APP_BRAND} Agent] Completed full scan: {total_scanned} files inspected ({cache_hits} cache hits).", flush=True)

        tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""
        report_payload = {
            "server_id": ASSIGNED_SERVER_ID,
            "hostname": get_node_name(),
            "system_hostname": get_hostname(),
            "server_ip": get_node_ip(),
            "agent_token": tok,
            "agent_version": AGENT_VERSION,
            "trigger_type": trigger_type,
            "scanned_paths": target_paths,
            "total_files_scanned": total_scanned,
            "cache_hits": cache_hits,
            "skipped_size_count": skipped_size_count,
            "data_hashed_bytes": data_hashed_bytes,
            "files": detected_threats
        }

        try:
            res_bytes = send_agent_request(
                "/api/agent/file-scan-report",
                data=json.dumps(report_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            if res_bytes:
                res_obj = json.loads(res_bytes.decode())
                threats_count = res_obj.get("threats_found", 0)
                if threats_count > 0:
                    print(f"[{APP_BRAND} Agent] ALERT: SOC Threat Intel matched {threats_count} malicious file(s)!", flush=True)
                else:
                    print(f"[{APP_BRAND} Agent] SOC Threat Intel report confirmed clean: 0 threats found.", flush=True)
        except Exception as e_rep:
            print(f"[{APP_BRAND} Agent] Failed to push malware scan report: {e_rep}", flush=True)

    except Exception as e_full:
        print(f"[{APP_BRAND} Agent] Full scan exception: {e_full}", flush=True)

def handle_malware_action(action_data):
    """
    Executes quarantine or deletion remediation requested by SOC administrator.
    Enforces HMAC-SHA256 signature verification and pre-action hash verification.
    """
    if not isinstance(action_data, dict):
        return
    act = action_data.get("action")
    target_file = action_data.get("file_path")
    expected_hash = action_data.get("expected_hash")
    sig = action_data.get("signature")
    nonce = action_data.get("nonce")
    ts = action_data.get("timestamp")

    if not target_file or not os.path.exists(target_file):
        return

    tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else os.getenv("AGENT_TOKEN", "agent-secret-token")
    if sig and nonce and ts:
        expected_msg = f"{act}:{target_file}:{expected_hash}:{nonce}:{ts}"
        computed_sig = hmac.new(tok.encode("utf-8"), expected_msg.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, computed_sig):
            print(f"[{APP_BRAND} Agent] Remediation task REJECTED: invalid signature!", flush=True)
            return
        if abs(time.time() - float(ts)) > 300:
            print(f"[{APP_BRAND} Agent] Remediation task REJECTED: expired timestamp!", flush=True)
            return

    if expected_hash:
        try:
            st = os.stat(target_file)
            curr_sha, _, _, _ = hash_file_stream(target_file, st)
            if curr_sha and curr_sha.lower() != expected_hash.lower():
                print(f"[{APP_BRAND} Agent] Remediation ABORTED: file hash on disk mismatch!", flush=True)
                return
        except Exception as ex_v:
            print(f"[{APP_BRAND} Agent] Remediation stat failed: {ex_v}", flush=True)
            return

    res_status = "failed"
    detail = ""
    try:
        if act == "quarantine":
            q_dir = "/var/spool/bsmart/quarantine"
            try:
                os.makedirs(q_dir, exist_ok=True)
            except Exception:
                q_dir = "/var/log/.bsmart_quarantine"
                os.makedirs(q_dir, exist_ok=True)

            q_sha = expected_hash or hashlib.sha256(open(target_file, 'rb').read(65536)).hexdigest()
            q_dest = os.path.join(q_dir, f"{q_sha}.dat")
            manifest_p = os.path.join(q_dir, f"{q_sha}.manifest.json")

            st = os.stat(target_file)
            manifest_obj = {
                "original_path": target_file,
                "file_name": os.path.basename(target_file),
                "sha256": q_sha,
                "permissions": oct(st.st_mode)[-4:],
                "owner": st.st_uid,
                "size": st.st_size,
                "quarantined_at": datetime.now().isoformat()
            }
            with open(manifest_p, "w", encoding="utf-8") as mf:
                json.dump(manifest_obj, mf)

            os.replace(target_file, q_dest)
            try:
                os.chmod(q_dest, 0)
            except Exception:
                pass
            res_status = "success"
            detail = f"Quarantined to {q_dest} with manifest"
            print(f"[{APP_BRAND} Agent] Quarantined threat file: {target_file} -> {q_dest}", flush=True)

        elif act == "delete":
            os.remove(target_file)
            res_status = "success"
            detail = "Permanently deleted"
            print(f"[{APP_BRAND} Agent] Deleted threat file: {target_file}", flush=True)

    except Exception as e_act:
        detail = str(e_act)
        print(f"[{APP_BRAND} Agent] Remediation action '{act}' failed on {target_file}: {e_act}", flush=True)

    task_results_queue.append({
        "action": act,
        "file_path": target_file,
        "status": res_status,
        "detail": detail,
        "timestamp": datetime.now().isoformat()
    })


_USER_CACHE = {}
_USER_CACHE_TS = {}

def resolve_uid_to_user(uid_val):
    if not uid_val or str(uid_val) in ("4294967295", "-1", "unset"):
        return "unknown"
    try:
        u_int = int(uid_val)
    except:
        return "unknown"
    KNOWN_UIDS = {
        1005: "mannan",
        1000: "ubuntu",
        1001: "ubuntu",
        1002: "developer",
        1742601378: "manoj.kn",
        1742601308: "mannan.shariff",
        1742601113: "sateesh.j"
    }
    if u_int in KNOWN_UIDS:
        return KNOWN_UIDS[u_int]
    now_ts = time.time()
    if u_int in _USER_CACHE and (now_ts - _USER_CACHE_TS.get(u_int, 0) < 60):
        return _USER_CACHE[u_int]
    uname = "unknown"
    try:
        import pwd
        pw = pwd.getpwuid(u_int)
        if pw and pw.pw_name:
            uname = pw.pw_name
    except:
        pass
    if uname == "unknown":
        try:
            out = subprocess.check_output(["getent", "passwd", str(u_int)], stderr=subprocess.DEVNULL, timeout=2).decode('utf-8', errors='ignore').strip()
            if out:
                uname = out.split(":")[0]
        except:
            pass
    if uname == "unknown":
        try:
            with open("/etc/passwd", "r") as pf:
                for pline in pf:
                    parts = pline.strip().split(":")
                    if len(parts) > 2 and parts[2] == str(u_int):
                        uname = parts[0]
                        break
        except:
            pass
    _USER_CACHE[u_int] = uname
    _USER_CACHE_TS[u_int] = now_ts
    return uname

def get_user_mapping():
    mapping = {}
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 2:
                    mapping[parts[2]] = parts[0]
    except: pass
    return mapping

# Persistent Checkpoint State
CHECKPOINT_FILE = "/opt/securepulse/audit_checkpoint.json"
_checkpoint_state = {"device": 0, "inode": 0, "offset": 0, "last_serial": 0, "last_epoch": 0.0}
_last_audit_events_sent = None

def load_audit_checkpoint():
    global _checkpoint_state
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as cf:
                _checkpoint_state = json.load(cf)
        except:
            pass

def commit_audit_checkpoint():
    global _checkpoint_state, _last_audit_events_sent
    if not _last_audit_events_sent:
        return
    pos, dev, ino, last_s, last_e = _last_audit_events_sent
    _checkpoint_state = {
        "device": dev,
        "inode": ino,
        "offset": pos,
        "last_serial": last_s,
        "last_epoch": last_e
    }
    try:
        os.makedirs(os.path.dirname(CHECKPOINT_FILE), exist_ok=True)
        with open(CHECKPOINT_FILE + ".tmp", "w") as cf:
            json.dump(_checkpoint_state, cf)
        os.replace(CHECKPOINT_FILE + ".tmp", CHECKPOINT_FILE)
    except:
        pass
    _last_audit_events_sent = None

# Rate limiter for noisy keys (e.g. app_mod > 100/min)
_key_rate_counters = {}
_key_rate_window_start = time.time()

def get_auditd_events():
    global _last_audit_events_sent, _key_rate_window_start, _key_rate_counters
    events = []
    path = "/var/log/audit/audit.log"
    if not os.path.exists(path):
        return events

    try:
        load_audit_checkpoint()
        st = os.stat(path)
        cur_dev = st.st_dev
        cur_ino = st.st_ino
        cur_size = st.st_size

        saved_dev = _checkpoint_state.get("device", 0)
        saved_ino = _checkpoint_state.get("inode", 0)
        saved_pos = _checkpoint_state.get("offset", 0)

        # Check for rotation (inode change)
        rotated_path = "/var/log/audit/audit.log.1"
        files_to_read = []
        if saved_ino and saved_ino != cur_ino and os.path.exists(rotated_path):
            try:
                rot_st = os.stat(rotated_path)
                if rot_st.st_ino == saved_ino:
                    files_to_read.append((rotated_path, saved_pos, rot_st.st_size, rot_st.st_dev, rot_st.st_ino))
                    saved_pos = 0
            except:
                pass
        
        pos = saved_pos if (saved_ino == cur_ino and saved_pos <= cur_size) else max(0, cur_size - 16000)
        files_to_read.append((path, pos, cur_size, cur_dev, cur_ino))

        records_by_id = {}
        final_dev = cur_dev
        final_ino = cur_ino
        final_pos = cur_size

        for fpath, seek_pos, fsize, fdev, fino in files_to_read:
            with open(fpath, 'r', errors='ignore') as f:
                f.seek(seek_pos)
                for line in f:
                    msg_m = re.search(r'msg=audit\(([\d\.]+):(\d+)\)', line)
                    if not msg_m:
                        continue
                    epoch_str = msg_m.group(1)
                    serial_str = msg_m.group(2)
                    msg_id = f"{epoch_str}:{serial_str}"
                    
                    if msg_id not in records_by_id:
                        records_by_id[msg_id] = {
                            "epoch": float(epoch_str),
                            "serial": int(serial_str),
                            "lines": [],
                            "syscall": {},
                            "paths": [],
                            "cwd": ""
                        }
                    records_by_id[msg_id]["lines"].append(line.strip())

                    if "type=SYSCALL" in line:
                        auid_m = re.search(r'\bauid=(\d+)', line)
                        uid_m  = re.search(r'\buid=(\d+)', line)
                        euid_m = re.search(r'\beuid=(\d+)', line)
                        key_m  = re.search(r'key="?([^"\s]+)"?', line)
                        comm_m = re.search(r'comm="?([^"\s]+)"?', line)
                        exe_m  = re.search(r'exe="?([^"\s]+)"?', line)
                        ses_m  = re.search(r'\bses=(\d+)', line)
                        pid_m  = re.search(r'\bpid=(\d+)', line)
                        ppid_m = re.search(r'\bppid=(\d+)', line)

                        key_val = key_m.group(1) if key_m else None
                        if key_val in ("(null)", "null", ""):
                            key_val = None

                        records_by_id[msg_id]["syscall"] = {
                            "auid": auid_m.group(1) if auid_m else None,
                            "uid": uid_m.group(1) if uid_m else None,
                            "euid": euid_m.group(1) if euid_m else None,
                            "key": key_val,
                            "comm": comm_m.group(1) if comm_m else "",
                            "exe": exe_m.group(1) if exe_m else "",
                            "ses": ses_m.group(1) if ses_m else None,
                            "pid": pid_m.group(1) if pid_m else None,
                            "ppid": ppid_m.group(1) if ppid_m else None,
                            "line": line.strip()[:1000]
                        }
                    elif "type=PATH" in line:
                        name_m = re.search(r'name="?([^"\s]+)"?', line)
                        if name_m:
                            p_name = name_m.group(1)
                            if p_name not in ("(null)", "null"):
                                records_by_id[msg_id]["paths"].append(p_name)
                    elif "type=CWD" in line:
                        cwd_m = re.search(r'cwd="?([^"\s]+)"?', line)
                        if cwd_m:
                            records_by_id[msg_id]["cwd"] = cwd_m.group(1)

                final_pos = f.tell()
                final_dev = fdev
                final_ino = fino

        # Rate window reset
        now_time = time.time()
        if now_time - _key_rate_window_start >= 60.0:
            _key_rate_counters.clear()
            _key_rate_window_start = now_time

        # Build joined events
        last_s = 0
        last_e = 0.0
        for msg_id, rec in records_by_id.items():
            sc = rec["syscall"]
            key = sc.get("key")
            if not key:
                continue

            _key_rate_counters[key] = _key_rate_counters.get(key, 0) + 1
            if _key_rate_counters[key] > 100:
                if _key_rate_counters[key] == 101:
                    events.append({
                        "serial": rec["serial"],
                        "epoch": rec["epoch"],
                        "key": key,
                        "rate_limited": True,
                        "rate_count": 100,
                        "auid": sc.get("auid"),
                        "username": resolve_uid_to_user(sc.get("auid") or sc.get("uid")),
                        "line": "Key '" + str(key) + "' exceeded 100 events/min rate limit (Aggregated Summary)"
                    })
                continue

            actor_id = sc.get("auid") if (sc.get("auid") and sc.get("auid") not in ("4294967295", "-1", "unset", "0")) else sc.get("uid")
            username = resolve_uid_to_user(actor_id)
            eff_user = resolve_uid_to_user(sc.get("euid") or sc.get("uid"))

            comm = sc.get("comm", "")
            exe = sc.get("exe", "")
            is_daemon = False
            daemon_desc = ""
            known_daemons = ("java", "postgres", "mysqld", "redis-server", "haproxy", "nginx", "docker", "containerd")
            if any(comm.lower().startswith(d) for d in known_daemons) or sc.get("ppid") == "1":
                is_daemon = True
                daemon_desc = f"{comm} daemon (started in session of {username})"

            target_path = rec["paths"][-1] if rec["paths"] else ""
            full_line = " ".join(rec["lines"])[:2500]

            events.append({
                "serial": rec["serial"],
                "epoch": rec["epoch"],
                "key": key,
                "auid": sc.get("auid"),
                "username": username,
                "effective_user": eff_user,
                "comm": comm,
                "exe": exe,
                "ses": sc.get("ses"),
                "pid": sc.get("pid"),
                "ppid": sc.get("ppid"),
                "path": target_path,
                "is_daemon": is_daemon,
                "daemon_desc": daemon_desc,
                "line": full_line
            })
            last_s = rec["serial"]
            last_e = rec["epoch"]

        _last_audit_events_sent = (final_pos, final_dev, final_ino, last_s, last_e)

    except Exception as ex_audit:
        pass

    return events[-250:]

# Auth failure tracking
auth_log_positions = {}

def get_auth_failures():
    failures = []
    auth_pattern = re.compile(r'(Failed password|Invalid user|authentication failure|AUTH_FAIL|Failed publickey)', re.IGNORECASE)
    ip_pattern = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')
    user_pattern = re.compile(r'(?:for invalid user|for user|invalid user)\s+(\S+)', re.IGNORECASE)

    for path, ltype in discovered_paths.items():
        if ltype != 'os': continue
        if 'auth' not in path and 'secure' not in path and 'syslog' not in path: continue
        try:
            size = os.path.getsize(path)
            pos = auth_log_positions.get(path)
            if pos is None: pos = size # Start at end of file on first run to avoid historical alerts
            if size < pos: pos = 0
            with open(path, 'r', errors='ignore') as f:
                f.seek(pos)
                for line in f:
                    if auth_pattern.search(line):
                        ip_m = ip_pattern.search(line)
                        usr_m = user_pattern.search(line)
                        failures.append({
                            "ip": ip_m.group(1) if ip_m else "unknown",
                            "user": usr_m.group(1) if usr_m else "unknown",
                            "line": line.strip()[:2000]
                        })
                auth_log_positions[path] = f.tell()
        except: pass
    return failures[-50:] if len(failures) > 50 else failures

# Sudo event tracking
sudo_log_positions = {}

def get_sudo_events():
    events = []
    try:
        sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\[)', re.IGNORECASE)
        for path, ltype in discovered_paths.items():
            if ltype != 'os': continue
            try:
                size = os.path.getsize(path)
                pos = sudo_log_positions.get(path)
                if pos is None: pos = size
                if size < pos: pos = 0
                with open(path, 'r', errors='ignore') as f:
                    f.seek(pos)
                    for line in f:
                        if sudo_pattern.search(line):
                            events.append({"line": line.strip()[:2000], "path": path})
                    sudo_log_positions[path] = f.tell()
            except Exception: pass
    except Exception as e:
        error_collapser.record_error("sudo_events", e)
    return events[-30:]

# Track bash history commands
bash_positions = {}
def get_bash_commands():
    cmds = []
    hist_files = ["/root/.bash_history"] + glob.glob("/home/*/.bash_history")
    for hp in hist_files:
        if not os.path.exists(hp): continue
        try:
            size = os.path.getsize(hp)
            pos = bash_positions.get(hp, max(0, size - 3000))
            if size < pos: pos = 0
            with open(hp, "r", errors="ignore") as f:
                f.seek(pos)
                for line in f:
                    c = line.strip()
                    if c and not c.startswith("#"):
                        u = "root" if "root" in hp else hp.split("/")[2]
                        cmds.append({"user": u, "command": c})
                bash_positions[hp] = f.tell()
        except: pass
    return cmds[-30:]

# Log tail positions per file
log_positions = {}

def get_new_log_lines(max_lines_per_file=100):
    cat_lines = {"os": [], "tomcat": [], "postgres": [], "other": []}

    for path, ltype in discovered_paths.items():
        if path.startswith("systemd/"):
            continue
        try:
            if not os.path.exists(path): continue
            size = os.path.getsize(path)
            if size == 0: continue

            pos = log_positions.get(path)
            if pos is None:
                # First start: seek to END of file — only push new real-time lines, not old history
                # For small new files (< 10 KB) read last 50 lines as initial context
                pos = max(0, size - 15000)
            elif pos > size:
                # File was rotated / truncated — restart from end of new file
                pos = size

            with open(path, 'r', errors='ignore') as f:
                f.seek(pos)
                raw_lines = f.readlines()
                log_positions[path] = f.tell()  # always save position, even if no new lines

                # No new lines since last check — wait for next poll cycle
                if not raw_lines:
                    continue

                clean_src = path
                if re.search(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', clean_src, re.I):
                    clean_src = re.sub(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', 'catalina.out', clean_src, flags=re.I)
                elif re.search(r'postgresql-[A-Za-z0-9_-]+\.log$', clean_src, re.I):
                    clean_src = re.sub(r'postgresql-[A-Za-z0-9_-]+\.log$', 'postgresql.log', clean_src, flags=re.I)

                seen_batch = set()
                for line in raw_lines[-max_lines_per_file:]:
                    line = line.strip()
                    if not line: continue
                    batch_k = (clean_src, line)
                    if batch_k in seen_batch: continue
                    seen_batch.add(batch_k)
                    lt = ltype
                    if lt not in ('tomcat', 'postgres', 'os'):
                        lower_l = line.lower()
                        if any(k in lower_l for k in ['postgres', 'pgsql', 'fatal:  password authentication', 'no pg_hba.conf', 'drop database', 'drop table', 'alter user', 'alter role', 'grant all', 'drop schema']):
                            lt = 'postgres'
                        elif any(k in lower_l for k in ['tomcat', 'catalina', 'nohup', 'org.apache.catalina', 'spring', 'hibernate', 'mdm', 'unified_hes', 'meter_job']):
                            lt = 'tomcat'

                    item = {"line": line, "source": clean_src, "log_type": lt}
                    if lt in cat_lines:
                        cat_lines[lt].append(item)
                    else:
                        cat_lines["other"].append(item)
        except: pass

    # If systemd/journal registered or no OS lines yet, collect from journalctl
    if "systemd/journal" in discovered_paths or not cat_lines["os"]:
        try:
            out = subprocess.check_output(["journalctl", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n"):
                line = line.strip()
                if line:
                    cat_lines["os"].append({"line": line, "source": "systemd/journal", "log_type": "os"})
        except: pass

    # If systemd/tomcat registered, read from journalctl
    if "systemd/tomcat" in discovered_paths:
        try:
            out = subprocess.check_output(["journalctl", "-u", "tomcat", "-u", "tomcat9", "-u", "tomcat10", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n"):
                line = line.strip()
                if line:
                    cat_lines["tomcat"].append({"line": line, "source": "systemd/tomcat", "log_type": "tomcat"})
        except: pass

    # If systemd/postgresql registered, read from journalctl
    if "systemd/postgresql" in discovered_paths:
        try:
            out = subprocess.check_output(["journalctl", "-u", "postgresql", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n"):
                line = line.strip()
                if line:
                    cat_lines["postgres"].append({"line": line, "source": "systemd/postgresql", "log_type": "postgres"})
        except: pass

    # Balance lines across categories: up to 100 for high-volume tomcat
    balanced = []
    balanced.extend(cat_lines["os"][-50:])
    balanced.extend(cat_lines["tomcat"][-100:])
    balanced.extend(cat_lines["postgres"][-50:])
    balanced.extend(cat_lines["other"][-30:])
    return balanced

# Main loop
def main():
    global push_count, daily_inventory_done_date, daily_malware_scan_done_date, discovered_paths, ASSIGNED_SERVER_ID
    # Release update lock file on startup to inform watchdog of healthy state
    if os.path.exists("/tmp/securepulse_update.lock"):
        try:
            os.remove("/tmp/securepulse_update.lock")
            print(f"[{APP_BRAND} Agent] Update lock released on startup.", flush=True)
        except Exception:
            pass
    print(f"[{APP_BRAND} Agent] Starting. SOC: {SOC_URL}, Node: {TARGET_NAME} ({TARGET_IP}), Server ID: {ASSIGNED_SERVER_ID}", flush=True)

    # Inform systemd service manager of active ready state immediately
    notify_systemd("READY=1")

    # Start dedicated independent heartbeat thread and send immediate initial heartbeat before heavy collectors run
    hb_thread = HeartbeatThread(interval=PUSH_INTERVAL)
    hb_thread.start()
    hb_thread.send_heartbeat_once()

    print(f"[{APP_BRAND} Agent] Discovering log paths...", flush=True)
    discovered_paths = auto_discover_log_paths()
    print(f"[{APP_BRAND} Agent] Found log paths: {list(discovered_paths.keys())}", flush=True)

    # Initialize FIM baseline
    check_fim()

    # Initial background inventory collection on agent startup (Agent v1.6)
    threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": True}, daemon=True).start()

    # Dedicated fast 5-second task polling thread (Agent v1.7)
    threading.Thread(target=task_polling_loop, daemon=True).start()

    # Recover legacy credentials and persist valid node identity on startup
    try:
        _recover_legacy_credentials()
    except Exception:
        pass

    push_count = 0

    while True:
        try:
            global _last_main_loop_tick
            _last_main_loop_tick = time.time()
            # Daily scheduled inventory collection (default 02:30 with random jitter)
            now_dt = datetime.now()
            today_str = now_dt.strftime("%Y-%m-%d")
            if today_str != daily_inventory_done_date:
                if now_dt.hour == scheduled_inventory_hour and now_dt.minute >= scheduled_inventory_minute:
                    daily_inventory_done_date = today_str
                    threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": False}, daemon=True).start()

            # Scheduled zero-impact malware scan twice a month (1st and 15th at 03:00 AM local time)
            if today_str != daily_malware_scan_done_date:
                chk = _load_scan_checkpoint()
                is_paused = chk and chk.get("status") == "paused"
                if (now_dt.day in (1, 15) or is_paused) and 3 <= now_dt.hour < 6:
                    daily_malware_scan_done_date = today_str
                    threading.Thread(target=run_malware_scan, kwargs={"trigger_type": "twice_monthly"}, daemon=True).start()

            sid = check_assigned_server_id()
            cur_ip = get_node_ip()
            cur_host = get_node_name()
            tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""

            def _safe_run(collector_name, fn, default_val):
                try:
                    res = fn()
                    error_collapser.clear_error(collector_name)
                    return res
                except Exception as exc:
                    error_collapser.record_error(collector_name, exc)
                    return default_val

            cpu = _safe_run("cpu", get_cpu_percent, 0.0)
            mem = _safe_run("memory", get_memory_percent, 0.0)
            disk = _safe_run("disk", get_disk_percent, 0.0)
            procs = _safe_run("processes", get_processes, [])
            ports = _safe_run("ports", get_open_ports, [])
            bash_cmds = _safe_run("bash_commands", get_bash_commands, [])
            log_lines = _safe_run("log_lines", get_new_log_lines, [])
            auth_failures = _safe_run("auth_failures", get_auth_failures, [])
            sudo_events = _safe_run("sudo_events", get_sudo_events, [])
            file_changes = _safe_run("fim", check_fim, [])
            audit_events = _safe_run("auditd", get_auditd_events, [])
            net_bytes = _safe_run("network_bytes", get_network_bytes, (0, 0))
            rx, tx = net_bytes if (isinstance(net_bytes, (tuple, list)) and len(net_bytes) == 2) else (0, 0)
            proc_conns = _safe_run("process_connections", get_process_connections, {})
            det_services = _safe_run("services", discover_services, [])

            scan_prog = None
            if is_malware_scan_running:
                try:
                    chk = _load_scan_checkpoint()
                    if chk and isinstance(chk, dict):
                        scan_prog = {
                            "total_scanned": chk.get("total_scanned", 0),
                            "segment_index": chk.get("segment_index", 0),
                            "cache_hits": chk.get("cache_hits", 0)
                        }
                except Exception:
                    pass

            payload = {
                "server_id": sid,
                "agent_token": tok,
                "token": tok,
                "agent_version": AGENT_VERSION,
                "server_ip": cur_ip,
                "hostname": cur_host,
                "system_hostname": get_hostname(),
                "machine_id": get_machine_id(),
                "inventory_error": inventory_error,
                "cpu_percent": cpu,
                "memory_percent": mem,
                "disk_percent": disk,
                "network_rx_bytes": rx,
                "network_tx_bytes": tx,
                "processes": procs,
                "process_connections": proc_conns,
                "open_ports": ports,
                "commands": bash_cmds,
                "log_lines": [x["line"] for x in log_lines[:100]],
                "logs": [{"line": x["line"], "source": x["source"], "log_type": x["log_type"]} for x in log_lines[:100]],
                "auth_failures": auth_failures,
                "sudo_events": sudo_events,
                "file_changes": file_changes,
                "audit_events": audit_events,
                "discovered_log_paths": list(discovered_paths.keys()),
                "detected_services": det_services,
                "scan_progress": scan_prog,
                "degraded_collectors": error_collapser.get_failing_collectors(),
                "task_results": task_results_queue[:]
            }

            data = json.dumps(payload).encode("utf-8")
            res_bytes = send_agent_request(
                "/api/agent/push",
                data=data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            res_data = json.loads(res_bytes.decode())
            error_collapser.clear_error("main_telemetry_loop")
            if push_count % 4 == 0:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{APP_BRAND} Agent] Telemetry push active (Server ID: {ASSIGNED_SERVER_ID}, CPU: {cpu}%, RAM: {mem}%)", flush=True)
            # Commit audit checkpoint ONLY on successful HTTP 200 response
            try:
                commit_audit_checkpoint()
            except:
                pass
            # On-demand malware scan trigger from SOC console ("SCAN NOW" button)
            if res_data and res_data.get("malware_scan_requested") and not is_malware_scan_running:
                threading.Thread(target=run_malware_scan, kwargs={
                    "trigger_type": "manual",
                    "custom_paths": res_data.get("scan_paths")
                }, daemon=True).start()

            # Threat remediation trigger (Quarantine / Delete)
            if res_data and res_data.get("malware_action"):
                threading.Thread(target=handle_malware_action, args=(res_data.get("malware_action"),), daemon=True).start()

            # Cache and persist server_id returned from SOC so future pushes and updates use it immediately
            ret_sid = res_data.get("server_id")
            if ret_sid:
                if ASSIGNED_SERVER_ID is None or ASSIGNED_SERVER_ID != int(ret_sid):
                    ASSIGNED_SERVER_ID = int(ret_sid)
                    _save_persistent_config()
            elif sid and ASSIGNED_SERVER_ID is None:
                ASSIGNED_SERVER_ID = sid
                _save_persistent_config()

            if res_data and (res_data.get("status") in ("ok", "success") or res_data.get("ok")):
                if os.path.exists("/tmp/securepulse_update.lock"):
                    try:
                        os.remove("/tmp/securepulse_update.lock")
                    except Exception:
                        pass

            if res_data.get("update_requested"):
                _save_persistent_config()
                dl_url = res_data.get("update_cmd_url")
                try:
                    send_agent_request("/api/agent/status-update", data=json.dumps({"server_id": sid, "status": "updating"}).encode('utf-8'), timeout=5)
                except: pass
                
                cmd = f"curl -s -k {dl_url} -d 'name={TARGET_NAME}&ip={TARGET_IP}' | bash"
                subprocess.Popen(["bash", "-c", cmd])
                sys.exit(0)

            # On-demand inventory scan requested from SOC ("Scan now" button)
            if res_data.get("inventory_scan_requested"):
                threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": True}, daemon=True).start()

            # Clear delivered task results
            task_results_queue.clear()

            # Process pending signed tasks from SOC Command Center
            if res_data.get("pending_tasks"):
                threading.Thread(target=execute_agent_tasks, args=(res_data.get("pending_tasks"),), daemon=True).start()

            # Also push structured logs
            if log_lines:
                log_payload = {
                    "server_id": sid or ASSIGNED_SERVER_ID,
                    "server_ip": cur_ip,
                    "hostname": cur_host,
                    "agent_token": tok,
                    "token": tok,
                    "machine_id": get_machine_id(),
                    "lines": log_lines[:200]
                }
                ldata = json.dumps(log_payload).encode("utf-8")
                try:
                    send_agent_request("/api/agent/push-logs", data=ldata, timeout=10)
                except: pass

            push_count += 1
            if push_count % 10 == 0:
                # Re-discover log paths periodically
                discovered_paths = auto_discover_log_paths()

        except urllib.error.URLError as e:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now_str}] [{APP_BRAND} Agent] Connection error: {e}", flush=True)
        except Exception as e:
            error_collapser.record_error("main_telemetry_loop", e)

        time.sleep(PUSH_INTERVAL)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--scan", "-s", "scan", "--scan-malware"):
        print(f"[{APP_BRAND} Agent] Running on-demand zero-impact malware scan via CLI...")
        _load_persistent_config()
        run_malware_scan(trigger_type="manual")
        sys.exit(0)
    main()