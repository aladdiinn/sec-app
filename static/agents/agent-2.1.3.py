import os, sys, time, json, socket, subprocess, glob, re, hashlib, gzip, threading, random, platform, zipfile, hmac, ssl
import urllib.request, urllib.error
from datetime import datetime

AGENT_VERSION = "2.1.3"
APP_BRAND = "BSMART SOC"
SOC_URL = "https://192.168.10.201:3443".rstrip("/")
TARGET_IP = "$NODE_IP"
TARGET_NAME = "$NODE_NAME"
AGENT_TOKEN = "$TOKEN"
ASSIGNED_SERVER_ID = int("$ASSIGNED_ID") if "$ASSIGNED_ID".isdigit() else None

CONFIG_FILE = os.environ.get("SECUREPULSE_CONFIG", "/opt/securepulse/config.json")
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
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cdata = json.load(f)
                if cdata.get("SOC_URL") and not str(cdata["SOC_URL"]).startswith("$"):
                    SOC_URL = str(cdata["SOC_URL"]).rstrip("/")
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

    backup_candidates = [
        "/opt/securepulse/node_push_agent.py.backup",
        "/opt/securepulse/node_push_agent.py"
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
            if m_soc and not m_soc.group(1).startswith("$"):
                SOC_URL = m_soc.group(1).rstrip("/")
        except Exception:
            pass

    get_node_ip()
    get_node_name()
    _save_persistent_config()


# Load dynamic persistent configuration if present (preserves node identity across updates)
try:
    _recover_legacy_credentials()
except Exception:
    pass

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
for _candidate in ["http://127.0.0.1:8001", "https://192.168.10.201:3443", "https://127.0.0.1:3443", "http://127.0.0.1:8000"]:
    if _candidate not in CANDIDATE_SOC_URLS:
        CANDIDATE_SOC_URLS.append(_candidate)

def send_agent_request(endpoint, data=None, headers=None, timeout=10):
    global SOC_URL
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
        except Exception as e:
            last_err = e
            continue
    raise last_err

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
    try:
        docker_out = subprocess.check_output(
            ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
            stderr=subprocess.DEVNULL, timeout=8
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
    except Exception:
        pass

    # 4. Handle vanished services: mark as stopped instead of deleting
    for sid, sdata in list(known_services.items()):
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
                    m = re.search(r'-Dcatalina\\.(?:home|base)=([^\\0\\s]+)', cmd_str)
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
                            m = re.search(r'Apache Tomcat Version\\s+([0-9\\.]+)', line, re.I)
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
                        m = re.search(r'version\\s+"([^"]+)"', out)
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

def get_cpu_percent():
    try:
        with open("/proc/stat") as f: t1 = f.readline().split()
        time.sleep(0.5)
        with open("/proc/stat") as f: t2 = f.readline().split()
        idle1 = int(t1[4]) + int(t1[5])
        total1 = sum(int(x) for x in t1[1:])
        idle2 = int(t2[4]) + int(t2[5])
        total2 = sum(int(x) for x in t2[1:])
        dt = float(total2 - total1)
        di = float(idle2 - idle1)
        return round((1.0 - di/dt) * 100.0, 1) if dt > 0 else 0.0
    except: return 0.0

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
        for line in out.strip().split("\\n"):
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
        for line in out.strip().split("\\n"):
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
            
            m = re.search(r':(\\d+)$', local_addr_str)
            if not m:
                m = re.search(r':(\\d+)\\s*', local_addr_str)
            
            if m:
                port = int(m.group(1))
                proc_name = "unknown"
                pid = None
                user_name = "unknown"
                cmdline = ""
                
                # users:(("nginx",pid=123,fd=5))
                proc_m = re.search(r'users:\\s*\\(\\s*\\(\\s*"([^"]+)"\\s*,\\s*pid=(\\d+)', line)
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
                            raw_cmd = cf.read().replace("\\x00", " ").strip()
                            # Mask secrets
                            raw_cmd = re.sub(r'(--password|-p|token|secret|key)[=\\s]+[^\\s]+', r'\\1 *****', raw_cmd, flags=re.IGNORECASE)
                            cmdline = raw_cmd[:120] + ("..." if len(raw_cmd) > 120 else "")
                    except Exception:
                        pass
                
                ports.append({"port": port, "proto": proto, "process": proc_name, "pid": pid, "user": user_name, "cmdline": cmdline})
    except Exception as e:
        try:
            out = subprocess.check_output(["netstat", "-tulnp"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
                m = re.search(r':(\\d+)\\s+', line)
                if m:
                    port = int(m.group(1))
                    proc = re.search(r'\\s+\\d+/([^ \\n]+)', line)
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
        for line in out.strip().split("\\n")[1:]:
            if "ESTAB" in line or "SYN-RECV" in line:
                m = re.search(r'users:\\(\\("([^"]+)",pid=(\\d+)', line)
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
        if re.search(r'\\.(gz|bz2|zip|tar|1|2|3|4|5|bak|old|swp)$', filename, re.IGNORECASE):
            return True
        # Keep active current-day log or recently updated log files
        m = re.search(r'(\\d{4}-\\d{2}-\\d{2})', filename)
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
        if re.search(r'\\.\\d{8}\\.log$', filename, re.IGNORECASE):
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
        for line in out.split("\\n"):
            line_l = line.lower()
            if "catalina" in line_l or "tomcat" in line_l:
                dirs_to_check = []
                m = re.search(r'-Dcatalina\\.home=([^\\s]+)', line)
                if m: dirs_to_check.append(m.group(1).strip())
                m_base = re.search(r'-Dcatalina\\.base=([^\\s]+)', line)
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
                m2 = re.search(r'-classpath\\s+([^\\s]+)', line)
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
        for line in out.split("\\n"):
            if 'postgres' in line.lower() and ('-D' in line or 'cluster' in line):
                m = re.search(r'-D\\s+([^\\s]+)', line)
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
                    msg_m = re.search(r'msg=audit\\(([\\d\\.]+):(\\d+)\\)', line)
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
                        auid_m = re.search(r'\\bauid=(\\d+)', line)
                        uid_m  = re.search(r'\\buid=(\\d+)', line)
                        euid_m = re.search(r'\\beuid=(\\d+)', line)
                        key_m  = re.search(r'key="?([^"\\s]+)"?', line)
                        comm_m = re.search(r'comm="?([^"\\s]+)"?', line)
                        exe_m  = re.search(r'exe="?([^"\\s]+)"?', line)
                        ses_m  = re.search(r'\\bses=(\\d+)', line)
                        pid_m  = re.search(r'\\bpid=(\\d+)', line)
                        ppid_m = re.search(r'\\bppid=(\\d+)', line)

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
                        name_m = re.search(r'name="?([^"\\s]+)"?', line)
                        if name_m:
                            p_name = name_m.group(1)
                            if p_name not in ("(null)", "null"):
                                records_by_id[msg_id]["paths"].append(p_name)
                    elif "type=CWD" in line:
                        cwd_m = re.search(r'cwd="?([^"\\s]+)"?', line)
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
    ip_pattern = re.compile(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)')
    user_pattern = re.compile(r'(?:for invalid user|for user|invalid user)\\s+(\\S+)', re.IGNORECASE)

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
    sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\\[)', re.IGNORECASE)
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
        except: pass
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
                if re.search(r'(catalina|localhost|manager|host-manager)\\.\\d{4}-\\d{2}-\\d{2}\\.log$', clean_src, re.I):
                    clean_src = re.sub(r'(catalina|localhost|manager|host-manager)\\.\\d{4}-\\d{2}-\\d{2}\\.log$', 'catalina.out', clean_src, flags=re.I)
                elif re.search(r'postgresql-[A-Za-z0-9_-]+\\.log$', clean_src, re.I):
                    clean_src = re.sub(r'postgresql-[A-Za-z0-9_-]+\\.log$', 'postgresql.log', clean_src, flags=re.I)

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
            for line in out.strip().split("\\n"):
                line = line.strip()
                if line:
                    cat_lines["os"].append({"line": line, "source": "systemd/journal", "log_type": "os"})
        except: pass

    # If systemd/tomcat registered, read from journalctl
    if "systemd/tomcat" in discovered_paths:
        try:
            out = subprocess.check_output(["journalctl", "-u", "tomcat", "-u", "tomcat9", "-u", "tomcat10", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
                line = line.strip()
                if line:
                    cat_lines["tomcat"].append({"line": line, "source": "systemd/tomcat", "log_type": "tomcat"})
        except: pass

    # If systemd/postgresql registered, read from journalctl
    if "systemd/postgresql" in discovered_paths:
        try:
            out = subprocess.check_output(["journalctl", "-u", "postgresql", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
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

# ══════════════════════════════════════════════════════════════════════════
# EMBEDDED CRYPTOGRAPHIC SIGNATURE VERIFIER & AUTONOMOUS UPDATER
# ══════════════════════════════════════════════════════════════════════════
AGENT_ED25519_PUBLIC_KEY_HEX = "e35f2ca46d8d1d6d0af3152e5a324dd56196dbdd69ca30af06461f24cbd9c970"



import hashlib
import base64
from typing import Dict, Any, Optional

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493

def _expmod(base, exp, mod):
    return pow(base, exp, mod)

def _inv(x):
    return _expmod(x, _q - 2, _q)

_d = -121665 * _inv(121666)
_I = _expmod(2, (_q - 1) // 4, _q)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x

_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]

def _edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]

def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q

def _decodeint(s):
    return int.from_bytes(s, "little")

def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _q - x
    return [x, y]

def _Hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")

def verify_ed25519_pure(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Verifies Ed25519 signature in pure Python with zero external libraries."""
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    Rraw = sig[:32]
    Sraw = sig[32:]
    S = _decodeint(Sraw)
    if S >= _l:
        return False
    try:
        A = _decodepoint(pubkey)
        R = _decodepoint(Rraw)
        h = _Hint(Rraw + pubkey + msg)
        ra = _edwards(R, _scalarmult(A, h))
        sb = _scalarmult(_B, S)
        return ra == sb
    except Exception:
        return False

def verify_manifest(agent_bytes: bytes, manifest: Dict[str, Any], pubkey_hex: Optional[str] = None) -> bool:
    """
    Validates agent artifact against an update manifest:
    1. Size match
    2. SHA-256 match
    3. Ed25519 digital signature
    """
    if not manifest:
        return False

    expected_sha = manifest.get("sha256", "").strip().lower()
    actual_sha = hashlib.sha256(agent_bytes).hexdigest().lower()

    # Robust line ending check: if CRLF/LF platform checkout differs, test canonical LF
    if expected_sha and actual_sha != expected_sha:
        lf_bytes = agent_bytes.replace(b"\r\n", b"\n")
        if hashlib.sha256(lf_bytes).hexdigest().lower() == expected_sha:
            agent_bytes = lf_bytes
            actual_sha = expected_sha
        else:
            return False

    # 1. Size check
    expected_size = manifest.get("size")
    if expected_size and len(agent_bytes) != expected_size:
        return False

    # 2. SHA-256 Digest check
    if expected_sha and actual_sha != expected_sha:
        return False

    # 3. Ed25519 Signature check
    sig_b64 = manifest.get("signature", "")
    key_hex = pubkey_hex or manifest.get("public_key")
    if not sig_b64 or not key_hex:
        return False

    try:
        sig_bytes = base64.b64decode(sig_b64)
        pub_bytes = bytes.fromhex(key_hex)
        return verify_ed25519_pure(agent_bytes, sig_bytes, pub_bytes)
    except Exception:
        return False


def _cleanup_lock(lock_file):
    try:
        if os.path.exists(lock_file): os.remove(lock_file)
    except Exception: pass

def _report_update_failure(sid, target_ver, reason, lock_file, tmp_file=None):
    print(f"[SecurePulse Agent] UPDATE FAILED: {reason}", flush=True)
    _cleanup_lock(lock_file)
    if tmp_file:
        try:
            if os.path.exists(tmp_file): os.remove(tmp_file)
        except Exception: pass
    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "failed",
            "from_version": AGENT_VERSION,
            "to_version": target_ver,
            "error": reason
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

def _spawn_restart_watchdog(sid, target_ver):
    watchdog_script = "/opt/securepulse/update_watchdog.sh"
    try:
        with open(watchdog_script, "w") as f:
            f.write(f"""#!/bin/bash
sleep 2
echo "[WATCHDOG] Restarting SecurePulse agent service after update to v{target_ver}..." >> /var/log/securepulse_agent.log
systemctl restart securepulse 2>/dev/null || systemctl restart securepulse-agent 2>/dev/null || nohup python3 /opt/securepulse/node_push_agent.py >> /var/log/securepulse_agent.log 2>&1 &

HEALTHY=0
CONSECUTIVE_CRASHES=0

for i in $(seq 1 24); do
    sleep 5
    # 1. Check if healthy: agent startup removes the lock file
    if [ ! -f /tmp/securepulse_update.lock ]; then
        HEALTHY=1
        echo "[WATCHDOG] Agent v{target_ver} healthy and update lock released." >> /var/log/securepulse_agent.log
        break
    fi

    # 2. Rapid crash-loop detection: check systemd state
    if command -v systemctl >/dev/null 2>&1; then
        SUBSTATE=$(systemctl show -p SubState securepulse 2>/dev/null | cut -d'=' -f2 || echo "")
        ACTIVE=$(systemctl is-active securepulse 2>/dev/null || echo "")
        if [ "$SUBSTATE" = "auto-restart" ] || [ "$SUBSTATE" = "failed" ] || [ "$ACTIVE" = "failed" ]; then
            CONSECUTIVE_CRASHES=$((CONSECUTIVE_CRASHES+1))
            echo "[WATCHDOG] Warning: service in $SUBSTATE state (count: $CONSECUTIVE_CRASHES)..." >> /var/log/securepulse_agent.log
            if [ $CONSECUTIVE_CRASHES -ge 3 ]; then
                echo "[WATCHDOG] Rapid crash-loop detected ($CONSECUTIVE_CRASHES failures). Triggering immediate rollback!" >> /var/log/securepulse_agent.log
                HEALTHY=0
                break
            fi
        fi
    fi
done

if [ $HEALTHY -eq 0 ]; then
    echo "[WATCHDOG] Agent health check failed! Rolling back to backup..." >> /var/log/securepulse_agent.log
    if [ -f /opt/securepulse/node_push_agent.py.backup ]; then
        cp -f /opt/securepulse/node_push_agent.py.backup /opt/securepulse/node_push_agent.py
        chmod 750 /opt/securepulse/node_push_agent.py
        systemctl restart securepulse 2>/dev/null || systemctl restart securepulse-agent 2>/dev/null || true
        echo "[WATCHDOG] Rollback to backup complete." >> /var/log/securepulse_agent.log
    else
        echo "[WATCHDOG] ERROR: No backup file found to rollback to!" >> /var/log/securepulse_agent.log
    fi
    rm -f /tmp/securepulse_update.lock
fi
rm -f {watchdog_script}
""")
        os.chmod(watchdog_script, 0o750)
        subprocess.Popen(["/bin/bash", watchdog_script], close_fds=True)
    except Exception as e:
        print(f"Watchdog spawn error: {e}", flush=True)
    sys.exit(0)

def check_and_apply_update(manifest, sid):
    lock_file = "/tmp/securepulse_update.lock"
    if os.path.exists(lock_file):
        try:
            mtime = os.path.getmtime(lock_file)
            if time.time() - mtime < 300:
                print(f"[SecurePulse Agent] Update already in progress (lock active).", flush=True)
                return
        except Exception:
            pass
    try:
        with open(lock_file, "w") as f:
            f.write(f"{os.getpid()}:{time.time()}\n")
    except Exception:
        pass

    target_ver = manifest.get("version") or manifest.get("target_version")
    if not target_ver:
        _cleanup_lock(lock_file)
        return

    allow_rollback = manifest.get("allow_rollback", False)
    if not allow_rollback:
        cur_sem = [int(x) for x in re.findall(r'\d+', str(AGENT_VERSION))]
        tgt_sem = [int(x) for x in re.findall(r'\d+', str(target_ver))]
        if tgt_sem <= cur_sem:
            print(f"[SecurePulse Agent] Skipping update: target {target_ver} is not newer than current {AGENT_VERSION}.", flush=True)
            _cleanup_lock(lock_file)
            return

    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "downloading",
            "from_version": AGENT_VERSION,
            "to_version": target_ver
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

    dl_url = manifest.get("download_url")
    if not dl_url:
        _report_update_failure(sid, target_ver, "Missing download_url in manifest", lock_file)
        return

    tmp_file = "/opt/securepulse/node_push_agent.py.tmp"
    backup_file = "/opt/securepulse/node_push_agent.py.backup"
    current_file = "/opt/securepulse/node_push_agent.py"

    try:
        req = urllib.request.Request(dl_url, headers={"User-Agent": f"SecurePulse-Agent/{AGENT_VERSION}"})
        ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
        if ca_bundle and os.path.isfile(ca_bundle):
            ctx = ssl.create_default_context(cafile=ca_bundle)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        proxy_handler = urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=30) as resp:
            artifact_bytes = resp.read()
    except Exception as e_dl:
        _report_update_failure(sid, target_ver, f"Download failed: {e_dl}", lock_file)
        return

    expected_size = manifest.get("size")
    if expected_size and len(artifact_bytes) != expected_size:
        _report_update_failure(sid, target_ver, f"Size mismatch: expected {expected_size}, got {len(artifact_bytes)}", lock_file)
        return

    expected_sha = manifest.get("sha256", "").strip().lower()
    actual_sha = hashlib.sha256(artifact_bytes).hexdigest().lower()
    if expected_sha and actual_sha != expected_sha:
        _report_update_failure(sid, target_ver, f"SHA-256 mismatch: expected {expected_sha}, got {actual_sha}", lock_file)
        return

    sig_b64 = manifest.get("signature", "")
    pubkey_hex = manifest.get("public_key") or AGENT_ED25519_PUBLIC_KEY_HEX
    try:
        sig_bytes = base64.b64decode(sig_b64)
        pub_bytes = bytes.fromhex(pubkey_hex)
        if not verify_ed25519_pure(artifact_bytes, sig_bytes, pub_bytes):
            _report_update_failure(sid, target_ver, "Ed25519 digital signature verification failed: untrusted artifact", lock_file)
            return
    except Exception as e_sig:
        _report_update_failure(sid, target_ver, f"Signature verification error: {e_sig}", lock_file)
        return

    try:
        with open(tmp_file, "wb") as f:
            f.write(artifact_bytes)
        import py_compile
        py_compile.compile(tmp_file, doraise=True)
    except Exception as e_comp:
        _report_update_failure(sid, target_ver, f"Syntax verification failed: {e_comp}", lock_file, tmp_file)
        return

    try:
        st_proc = subprocess.run([sys.executable, tmp_file, "--selftest"], capture_output=True, text=True, timeout=10)
        if st_proc.returncode != 0 or "SELFTEST_OK" not in st_proc.stdout:
            _report_update_failure(sid, target_ver, f"Self-test failed (exit {st_proc.returncode}): {st_proc.stderr[:200]}", lock_file, tmp_file)
            return
    except Exception as e_st:
        _report_update_failure(sid, target_ver, f"Self-test invocation failed: {e_st}", lock_file, tmp_file)
        return

    # Persist config before replacement
    try:
        cfg_file = "/opt/securepulse/config.json"
        cfg_data = {
            "SOC_URL": SOC_URL,
            "TARGET_IP": get_node_ip(),
            "TARGET_NAME": get_node_name(),
            "AGENT_TOKEN": str(AGENT_TOKEN) if not str(AGENT_TOKEN).startswith("$") else "",
            "ASSIGNED_SERVER_ID": ASSIGNED_SERVER_ID
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f, indent=2)
        os.chmod(cfg_file, 0o600)
    except Exception:
        pass

    try:
        import shutil
        if os.path.exists(current_file):
            shutil.copy2(current_file, backup_file)
    except Exception as e_bak:
        print(f"[SecurePulse Agent] Warning: backup copy failed: {e_bak}", flush=True)

    try:
        os.replace(tmp_file, current_file)
        os.chmod(current_file, 0o750)
    except Exception as e_swap:
        _report_update_failure(sid, target_ver, f"Atomic replacement failed: {e_swap}", lock_file, tmp_file)
        return

    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "updating",
            "from_version": AGENT_VERSION,
            "to_version": target_ver
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

    print(f"[SecurePulse Agent] Successfully applied update to {target_ver}. Spawning watchdog restart...", flush=True)
    _spawn_restart_watchdog(sid, target_ver)

def main():
    global push_count, daily_inventory_done_date, discovered_paths, ASSIGNED_SERVER_ID
    print(f"[{APP_BRAND} Agent] Starting. SOC: {SOC_URL}, Node: {TARGET_NAME} ({TARGET_IP}), Server ID: {ASSIGNED_SERVER_ID}")
    print(f"[{APP_BRAND} Agent] Discovering log paths...")
    discovered_paths = auto_discover_log_paths()
    print(f"[{APP_BRAND} Agent] Found log paths: {list(discovered_paths.keys())}")

    # Initialize FIM baseline
    check_fim()

    # Initial background inventory collection on agent startup (Agent v1.6)
    threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": True}, daemon=True).start()

    # Dedicated fast 5-second task polling thread (Agent v1.7)
    # Task polling disabled by security policy

    # Recover legacy credentials and persist valid node identity on startup
    try:
        _recover_legacy_credentials()
    except Exception:
        pass

    push_count = 0
    while True:
        try:
            # Daily scheduled inventory collection (default 02:30 with random jitter)
            now_dt = datetime.now()
            today_str = now_dt.strftime("%Y-%m-%d")
            if today_str != daily_inventory_done_date:
                if now_dt.hour == scheduled_inventory_hour and now_dt.minute >= scheduled_inventory_minute:
                    daily_inventory_done_date = today_str
                    threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": False}, daemon=True).start()

            sid = check_assigned_server_id()
            cur_ip = get_node_ip()
            cur_host = get_node_name()
            tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""

            cpu = get_cpu_percent()
            mem = get_memory_percent()
            disk = get_disk_percent()
            procs = get_processes()
            ports = get_open_ports()
            bash_cmds = get_bash_commands()
            log_lines = get_new_log_lines()
            auth_failures = get_auth_failures()
            sudo_events = get_sudo_events()
            file_changes = check_fim()
            audit_events = get_auditd_events()
            rx, tx = get_network_bytes()
            proc_conns = get_process_connections()

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
                "detected_services": discover_services(),
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
            # Commit audit checkpoint ONLY on successful HTTP 200 response
            try:
                commit_audit_checkpoint()
            except:
                pass
            # Cache and persist server_id returned from SOC so future pushes and updates use it immediately
            ret_sid = res_data.get("server_id")
            if ret_sid:
                if ASSIGNED_SERVER_ID is None or ASSIGNED_SERVER_ID != int(ret_sid):
                    ASSIGNED_SERVER_ID = int(ret_sid)
                    _save_persistent_config()
            elif sid and ASSIGNED_SERVER_ID is None:
                ASSIGNED_SERVER_ID = sid
                _save_persistent_config()

            # Autonomous Signed Self-Update (Zero Remote Commands)
            if res_data.get("update_available") and res_data.get("update_manifest"):
                manifest = res_data.get("update_manifest")
                try:
                    threading.Thread(target=check_and_apply_update, args=(manifest, sid), daemon=True).start()
                except Exception as _ex_up:
                    print(f"[SecurePulse Agent] Auto-update trigger error: {_ex_up}", flush=True)

            # On-demand inventory scan requested from SOC ("Scan now" button)
            if res_data.get("inventory_scan_requested"):
                threading.Thread(target=collect_and_send_inventory, kwargs={"force_full": True}, daemon=True).start()

            # Clear delivered task results
            task_results_queue.clear()

            # Process pending signed tasks from SOC Command Center
            # Remote command execution disabled by security policy

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
            print(f"[{APP_BRAND} Agent] Connection error: {e}")
        except Exception as e:
            print(f"[{APP_BRAND} Agent] Error: {e}")

        time.sleep(PUSH_INTERVAL)


def run_selftest():
    import traceback
    print(f"[SELFTEST] Initiating verification for {AGENT_VERSION} ({APP_BRAND})...", flush=True)
    try:
        # 1. Global constants check
        assert globals().get("APP_BRAND") == "BSMART SOC", f"Invalid APP_BRAND: {globals().get('APP_BRAND')}"
        assert globals().get("AGENT_VERSION") == AGENT_VERSION, f"Invalid AGENT_VERSION: {globals().get('AGENT_VERSION')}"
        assert globals().get("SOC_URL"), "SOC_URL must be defined"
        
        # 2. Config & credential recovery dry-run
        _recover_legacy_credentials()
        
        # 3. Core system collectors dry-run
        hn = get_hostname()
        assert hn, "get_hostname() returned empty"
        mid = get_machine_id()
        assert mid, "get_machine_id() returned empty"
        os_inf = get_os_info()
        assert isinstance(os_inf, dict), "get_os_info() must return dict"
        cpu_val = get_cpu_percent()
        assert isinstance(cpu_val, (int, float)), "get_cpu_percent() invalid"
        mem_val = get_memory_percent()
        assert isinstance(mem_val, (int, float)), "get_memory_percent() invalid"
        disk_val = get_disk_percent()
        assert isinstance(disk_val, (int, float)), "get_disk_percent() invalid"
        fim_changes = check_fim()
        assert isinstance(fim_changes, list), "check_fim() must return list"
        
        # 4. Telemetry payload generation & JSON serialization
        cur_ip = get_node_ip()
        cur_host = get_node_name()
        tok = str(AGENT_TOKEN) if (AGENT_TOKEN and not str(AGENT_TOKEN).startswith("$")) else ""
        test_payload = {
            "server_id": ASSIGNED_SERVER_ID,
            "agent_token": tok,
            "token": tok,
            "agent_version": AGENT_VERSION,
            "server_ip": cur_ip,
            "hostname": cur_host,
            "system_hostname": hn,
            "machine_id": mid,
            "cpu_percent": cpu_val,
            "memory_percent": mem_val,
            "disk_percent": disk_val,
            "auth_failures": 0,
            "sudo_events": 0,
            "file_changes": fim_changes,
            "audit_events": [],
            "discovered_log_paths": [],
            "detected_services": []
        }
        serialized = json.dumps(test_payload)
        assert len(serialized) > 10, "Payload serialization failed"
        
        # 5. Request builder check
        test_hdrs = {}
        if tok:
            test_hdrs["X-Agent-Token"] = tok
            test_hdrs["Authorization"] = f"Bearer {tok}"
        test_hdrs["X-Machine-ID"] = mid
        test_req = urllib.request.Request(f"{SOC_URL}/api/agent/push", data=serialized.encode('utf-8'), headers=test_hdrs)
        assert test_req.get_header("X-machine-id") == mid, "Header generation failed"

        # 6. Live server probe if specified
        test_server = os.environ.get("TEST_SOC_URL")
        if test_server:
            try:
                live_req = urllib.request.Request(f"{test_server.rstrip('/')}/api/version", headers={"User-Agent": f"Selftest/{AGENT_VERSION}"})
                with urllib.request.urlopen(live_req, timeout=3, context=_ssl_ctx) as resp:
                    pass
                print(f"[SELFTEST] Server probe passed against {test_server}", flush=True)
            except Exception as e_srv:
                print(f"[SELFTEST] Server probe note: {e_srv}", flush=True)

        print(f"[SELFTEST] Verification successful: APP_BRAND='{APP_BRAND}', version={AGENT_VERSION}", flush=True)
        print("SELFTEST_OK", flush=True)
        return True
    except Exception as e:
        print(f"[SELFTEST_FAILED] Error: {e}", file=sys.stderr, flush=True)
        traceback.print_exc(file=sys.stderr)
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        ok = run_selftest()
        sys.exit(0 if ok else 1)
    main()