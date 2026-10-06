import os, sys, time, json, socket, subprocess, glob, re, hashlib
import urllib.request, urllib.error
from datetime import datetime

AGENT_VERSION = "0.5"
SOC_URL = "".rstrip("/")
TARGET_IP = "$NODE_IP"
TARGET_NAME = "$NODE_NAME"
ASSIGNED_SERVER_ID = int("$ASSIGNED_ID") if "$ASSIGNED_ID".isdigit() else None
PUSH_INTERVAL = 30  # seconds

def get_hostname():
    try: return socket.gethostname()
    except: return TARGET_NAME

def check_assigned_server_id():
    global ASSIGNED_SERVER_ID, _config_id_map
    if ASSIGNED_SERVER_ID is not None:
        return ASSIGNED_SERVER_ID
    try:
        url = f"{SOC_URL}/api/agent/status?ip={TARGET_IP}&hostname={get_hostname()}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.loads(r.read().decode())
            sid = res.get("server_id")
            configs = res.get("log_configs", {})
            if configs:
                _config_id_map.update(configs)
            if sid:
                ASSIGNED_SERVER_ID = int(sid)
                return ASSIGNED_SERVER_ID
    except Exception: pass
    return ASSIGNED_SERVER_ID

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
        for line in out.strip().split("\n"):
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
        out = subprocess.check_output(["ss", "-tlnp"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.strip().split("\n")[1:]:
            m = re.search(r':(\d+)\s+', line)
            if m:
                port = int(m.group(1))
                proc = re.search(r'users:\(\("([^"]+)"', line)
                ports.append({"port": port, "process": proc.group(1) if proc else "unknown"})
    except:
        try:
            out = subprocess.check_output(["netstat", "-tlnp"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
            for line in out.strip().split("\n"):
                m = re.search(r':(\d+)\s+', line)
                if m: ports.append({"port": int(m.group(1)), "process": "unknown"})
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
        for line in out.strip().split("\n")[1:]:
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
        if re.search(r'\.\d{4}-\d{2}-\d{2}\.log$', filename, re.IGNORECASE): return True
        if re.search(r'\.\d{8}\.log$', filename, re.IGNORECASE): return True
        if re.search(r'\.(gz|bz2|zip|tar|1|2|3|4|5|bak|old|swp)$', filename, re.IGNORECASE): return True
        if re.search(r'^(localhost|manager|host-manager)\.', filename, re.IGNORECASE): return True
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
        "/opt/tomcat/logs/catalina.out",
        "/opt/tomcat*/logs/catalina.out",
        "/var/log/tomcat*/catalina.out",
        "/usr/local/tomcat/logs/catalina.out",
        "/opt/apache-tomcat*/logs/catalina.out",
        "/data/tomcat*/logs/catalina.out",
        "/data/MDM/apache-tomcat*/logs/catalina.out",
        "/data/logs/catalina.out",
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

    # Find tomcat / Java / Spring / MDM from running processes
    try:
        out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
        for line in out.split("\n"):
            line_l = line.lower()
            if "catalina" in line_l or "tomcat" in line_l:
                m = re.search(r'-Dcatalina\.home=([^\s]+)', line)
                if m:
                    cat_log = os.path.join(m.group(1), "logs", "catalina.out")
                    if os.path.exists(cat_log): paths[cat_log] = "tomcat"
                m_base = re.search(r'-Dcatalina\.base=([^\s]+)', line)
                if m_base:
                    cat_log = os.path.join(m_base.group(1), "logs", "catalina.out")
                    if os.path.exists(cat_log): paths[cat_log] = "tomcat"
                m2 = re.search(r'-classpath\s+([^\s]+)', line)
                if m2:
                    nohup_dir = os.path.dirname(m2.group(1))
                    nohup_path = os.path.join(nohup_dir, "nohup.out")
                    if os.path.exists(nohup_path): paths[nohup_path] = "tomcat"
    except: pass

    # If no catalina.out found yet for tomcat, pick ONLY the single newest .log file in tomcat log directory
    has_tomcat = any(lt == 'tomcat' for lt in paths.values())
    if not has_tomcat:
        fallback_globs = ["/data/MDM/apache-tomcat*/logs/*.log", "/opt/tomcat*/logs/*.log", "/var/log/tomcat*/*.log", "/data/logs/*.log"]
        for fg in fallback_globs:
            matches = [p for p in glob.glob(fg) if os.path.exists(p) and not is_rotated_archive(p)]
            if matches:
                matches.sort(key=os.path.getmtime, reverse=True)
                paths[matches[0]] = "tomcat"
                break

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
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/var/spool/cron",
    "/application", "/data", "/home"
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

# Auditd event tracking
audit_log_positions = {}
def get_auditd_events():
    events = []
    path = "/var/log/audit/audit.log"
    if not os.path.exists(path): return events
    try:
        user_mapping = get_user_mapping()
        size = os.path.getsize(path)
        pos = audit_log_positions.get(path, max(0, size - 8000))
        if size < pos: pos = 0
        with open(path, 'r', errors='ignore') as f:
            f.seek(pos)
            for line in f:
                if "type=SYSCALL" in line or "type=PATH" in line:
                    auid_m = re.search(r'auid=(\d+)', line)
                    key_m = re.search(r'key="?([^"\s]+)"?', line)
                    if auid_m and auid_m.group(1) != "4294967295":
                        auid = auid_m.group(1)
                        uname = user_mapping.get(auid, "unknown")
                        key = key_m.group(1) if key_m else "unknown"
                        if key != "unknown":
                            events.append({"auid": auid, "username": uname, "key": key, "line": line.strip()[:2000]})
            audit_log_positions[path] = f.tell()
    except: pass
    return events[-200:]

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
            pos = auth_log_positions.get(path, max(0, size - 8000))
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
    sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\[)', re.IGNORECASE)
    for path, ltype in discovered_paths.items():
        if ltype != 'os': continue
        try:
            size = os.path.getsize(path)
            pos = sudo_log_positions.get(path, max(0, size - 4000))
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
# File state: {path: {"offset": int, "inode": int, "config_id": int|None}}
_file_state = {}
_config_id_map = {}  # path -> config_id (populated from server registration response)

def _get_config_id(path):
    return _config_id_map.get(path)

def _fetch_baseline(path, config_id):
    """Ask the SOC backend for the stored baseline offset for this file, or record current EOF."""
    import json
    import urllib.request
    try:
        import os
        stat = os.stat(path)
        current_size = stat.st_size
        current_inode = stat.st_ino
        if config_id:
            data = json.dumps({"config_id": config_id, "file_path": path, "inode": current_inode, "byte_offset": current_size}).encode("utf-8")
            req = urllib.request.Request(
                SOC_URL + "/api/logs/baseline",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    res = json.loads(r.read().decode())
                    stored_offset = res.get("byte_offset", current_size)
                    return stored_offset, current_inode
            except Exception:
                pass
        # No config_id or request failed: start from current EOF (no history)
        return current_size, current_inode
    except Exception:
        return 0, 0

def get_new_log_lines(max_lines_per_file=50):
    cat_lines = {"os": [], "tomcat": [], "postgres": [], "other": []}

    for path, ltype in discovered_paths.items():
        if path.startswith("systemd/"):
            continue
        # Skip rotated/compressed files
        import re
        if re.search(r'\.\d{4}-\d{2}-\d{2}(\.log|\.txt)?$', path) or re.search(r'\.(gz|bz2|zip|\d+|bak|old)$', path, re.I):
            continue
        try:
            import os
            if not os.path.exists(path): continue
            stat = os.stat(path)
            size = stat.st_size
            inode = stat.st_ino
            if size == 0: continue

            config_id = _get_config_id(path)
            state = _file_state.get(path)

            if state is None:
                # First time seeing this file - get baseline from SOC (or record EOF)
                baseline_offset, baseline_inode = _fetch_baseline(path, config_id)
                _file_state[path] = {"offset": baseline_offset, "inode": baseline_inode, "config_id": config_id}
                # Nothing to read on first cycle (we start at baseline)
                continue

            stored_inode = state.get("inode", inode)
            stored_offset = state.get("offset", size)

            # Rotation detection: inode changed or file shrank
            if inode != stored_inode or size < stored_offset:
                # File was rotated or truncated - reopen from byte 0
                stored_offset = 0
                _file_state[path] = {"offset": 0, "inode": inode, "config_id": config_id}

            if stored_offset >= size:
                # No new bytes
                continue

            with open(path, 'r', errors='ignore') as f:
                f.seek(stored_offset)
                raw_lines = f.readlines()
                new_offset = f.tell()

            _file_state[path] = {"offset": new_offset, "inode": inode, "config_id": config_id}

            if not raw_lines:
                continue

            clean_src = path
            if re.search(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', clean_src, re.I):
                clean_src = re.sub(r'(catalina|localhost|manager|host-manager)\.\d{4}-\d{2}-\d{2}\.log$', 'catalina.out', clean_src, flags=re.I)
            elif re.search(r'postgresql-[A-Za-z0-9_-]+\.log$', clean_src, re.I):
                clean_src = re.sub(r'postgresql-[A-Za-z0-9_-]+\.log$', 'postgresql.log', clean_src, flags=re.I)

            for line in raw_lines[-max_lines_per_file:]:
                line = line.strip()
                if not line: continue
                lt = ltype
                if lt not in ('tomcat', 'postgres', 'os'):
                    lower_l = line.lower()
                    if any(k in lower_l for k in ['postgres', 'pgsql', 'fatal:  password authentication', 'no pg_hba.conf', 'drop database', 'drop table', 'alter user', 'alter role', 'grant all', 'drop schema']):
                        lt = 'postgres'
                    elif any(k in lower_l for k in ['tomcat', 'catalina', 'nohup', 'org.apache.catalina', 'spring', 'hibernate', 'mdm', 'unified_hes', 'meter_job']):
                        lt = 'tomcat'

                item = {"line": line, "source": clean_src, "log_type": lt}
                if config_id:
                    item["config_id"] = config_id
                if lt in cat_lines:
                    cat_lines[lt].append(item)
                else:
                    cat_lines["other"].append(item)
        except Exception: pass

    # If systemd/journal registered or no OS lines yet, collect from journalctl
    if "systemd/journal" in discovered_paths or not cat_lines["os"]:
        try:
            import subprocess
            out = subprocess.check_output(["journalctl", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
                line = line.strip()
                if line:
                    cat_lines["os"].append({"line": line, "source": "systemd/journal", "log_type": "os"})
        except Exception: pass

    # If systemd/tomcat registered, read from journalctl
    if "systemd/tomcat" in discovered_paths:
        try:
            import subprocess
            out = subprocess.check_output(["journalctl", "-u", "tomcat", "-u", "tomcat9", "-u", "tomcat10", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
                line = line.strip()
                if line:
                    cat_lines["tomcat"].append({"line": line, "source": "systemd/tomcat", "log_type": "tomcat"})
        except Exception: pass

    # If systemd/postgresql registered, read from journalctl
    if "systemd/postgresql" in discovered_paths:
        try:
            import subprocess
            out = subprocess.check_output(["journalctl", "-u", "postgresql", "-n", "35", "--no-pager", "-o", "short-iso"], stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.strip().split("\\n"):
                line = line.strip()
                if line:
                    cat_lines["postgres"].append({"line": line, "source": "systemd/postgresql", "log_type": "postgres"})
        except Exception: pass

    # Balance lines across categories: up to 40 each so no single source starves the rest
    balanced = []
    balanced.extend(cat_lines["os"][-40:])
    balanced.extend(cat_lines["tomcat"][-40:])
    balanced.extend(cat_lines["postgres"][-40:])
    balanced.extend(cat_lines["other"][-20:])
    return balanced
# Main loop
print(f"[SecurePulse Agent] Starting. SOC: {SOC_URL}, Node: {TARGET_NAME} ({TARGET_IP}), Server ID: {ASSIGNED_SERVER_ID}")
print("[SecurePulse Agent] Discovering log paths...")
discovered_paths = auto_discover_log_paths()
print(f"[SecurePulse Agent] Found log paths: {list(discovered_paths.keys())}")

# Initialize FIM baseline
check_fim()

push_count = 0
while True:
    try:
        sid = check_assigned_server_id()
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
            "agent_version": AGENT_VERSION,
            "server_ip": TARGET_IP,
            "hostname": get_hostname(),
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
            "discovered_log_paths": list(discovered_paths.keys())
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            SOC_URL + "/api/agent/push",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            res_data = json.loads(r.read().decode())
            if res_data.get("update_requested"):
                dl_url = res_data.get("update_cmd_url")
                try:
                    ureq = urllib.request.Request(f"{SOC_URL}/api/agent/status-update", data=json.dumps({"server_id": sid, "status": "updating"}).encode('utf-8'), headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(ureq, timeout=5)
                except: pass
                
                cmd = f"curl -s {dl_url} -d 'name={TARGET_NAME}&ip={TARGET_IP}' | bash"
                subprocess.Popen(["bash", "-c", cmd])
                sys.exit(0)

        # Also push structured logs
        if log_lines:
            log_payload = {
                "server_id": sid,
                "server_ip": TARGET_IP,
                "hostname": get_hostname(),
                "lines": log_lines[:200]
            }
            ldata = json.dumps(log_payload).encode("utf-8")
            lreq = urllib.request.Request(
                SOC_URL + "/api/agent/push-logs",
                data=ldata,
                headers={"Content-Type": "application/json"}
            )
            try: urllib.request.urlopen(lreq, timeout=10)
            except: pass

        push_count += 1
        if push_count % 10 == 0:
            # Re-discover log paths periodically
            discovered_paths = auto_discover_log_paths()

    except urllib.error.URLError as e:
        print(f"[SecurePulse Agent] Connection error: {e}")
    except Exception as e:
        print(f"[SecurePulse Agent] Error: {e}")

    time.sleep(PUSH_INTERVAL)
