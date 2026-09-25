#!/bin/bash
set -e

# Self-elevation check
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "[SECUREPULSE] Elevating privileges via sudo..."
        exec sudo bash "$0" "$@"
    fi
fi

echo "============================================================"
echo " SecurePulse SOC Command Center — Target Node Push Agent"
echo "============================================================"
echo "[SECUREPULSE] SOC Server URL : http://localhost"
echo "[SECUREPULSE] (Zero SSH Credentials Stored / Pure Outbound Push)"

# 0. Auto-detect real Outward IP and Hostname on the target machine
DETECTED_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7}' || hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$DETECTED_IP" ] || [ "$DETECTED_IP" = "127.0.0.1" ]; then
    DETECTED_IP=$(curl -s --connect-timeout 2 http://checkip.amazonaws.com 2>/dev/null || hostname -i 2>/dev/null | awk '{print $1}')
fi

NODE_IP="127.0.0.1"
if [ -n "$DETECTED_IP" ] && ([ "$NODE_IP" = "127.0.0.1" ] || [ -z "$NODE_IP" ]); then
    NODE_IP="$DETECTED_IP"
fi

DETECTED_HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "")
NODE_NAME="Target-Node"
if [ -n "$DETECTED_HOST" ] && ([ "$NODE_NAME" = "Target-Node" ] || [ -z "$NODE_NAME" ]); then
    NODE_NAME="$DETECTED_HOST"
fi

echo "[SECUREPULSE] Target Node IP   : $NODE_IP"
echo "[SECUREPULSE] Target Hostname  : $NODE_NAME"

# 1. Submit Onboarding Approval Request
echo "[SECUREPULSE] Submitting onboarding approval request for $NODE_NAME ($NODE_IP)..."

PAYLOAD_JSON=$(cat << JSON_EOF
{
  "hostname": "$NODE_NAME",
  "ip_address": "$NODE_IP"
}
JSON_EOF
)

REQ_RES=$(curl -s -X POST "http://localhost/api/approvals/request" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD_JSON" || echo '{"ok": false}')

TOKEN=$(echo "$REQ_RES" | grep -o '"token":"[^"]*' | cut -d'"' -f4 || echo "sp-token-$NODE_NAME")
if [ -z "$TOKEN" ]; then TOKEN="sp-token-$NODE_NAME"; fi

echo ""
echo "[PENDING] Onboarding request submitted to SOC Command Center!"
echo "[PENDING] Waiting for SOC Administrator approval in Dashboard... (Token: $TOKEN)"

STATUS="pending"
MAX_WAIT=300
WAITED=0
ASSIGNED_ID=""

while [ "$STATUS" = "pending" ] && [ $WAITED -lt $MAX_WAIT ]; do
    sleep 3
    WAITED=$((WAITED+3))
    CHECK_RES=$(curl -s -G "http://localhost/api/agent/status" --data-urlencode "token=$TOKEN" --data-urlencode "hostname=$NODE_NAME" --data-urlencode "ip=$NODE_IP" || echo '{"status":"pending"}')
    STATUS=$(echo "$CHECK_RES" | grep -o '"status":"[^"]*' | cut -d'"' -f4 || echo "pending")
    ASSIGNED_ID=$(echo "$CHECK_RES" | grep -o '"server_id":[0-9]*' | cut -d':' -f2 || echo "")
    if [ "$STATUS" = "pending" ]; then
        echo -n "."
    fi
done

echo ""

if [ "$STATUS" = "rejected" ]; then
    echo "============================================================"
    echo " [REJECTED] Onboarding request was rejected by SOC Administrator."
    echo " Target Node installation aborted."
    echo "============================================================"
    exit 1
fi

if [ "$STATUS" != "approved" ]; then
    echo "============================================================"
    echo " [TIMED OUT] Approval not received within $MAX_WAIT seconds."
    echo " Please approve under 'SERVER APPROVALS' in SOC Dashboard and re-run."
    echo "============================================================"
    exit 1
fi

echo "============================================================"
echo " [SUCCESS] Approval Granted by SOC Administrator!"
echo " Asset Node $NODE_NAME ($NODE_IP) Onboarded & Active (Server ID: ${ASSIGNED_ID:-auto})!"
echo "============================================================"

# Ensure readable permissions for log files
chmod +r /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null || true
chmod -R +r /var/log/postgresql /var/lib/pgsql /var/lib/postgresql /opt/postgresql* /opt/pgsql* 2>/dev/null || true
chmod -R +r /var/log/tomcat* /opt/tomcat* 2>/dev/null || true

# 1.5 Setup auditd safely (Cross-platform)
echo "[SECUREPULSE] Configuring auditd security policies..."
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq auditd </dev/null >/dev/null 2>&1 || echo "[SECUREPULSE] Failed to install auditd, continuing..."
elif command -v yum >/dev/null 2>&1; then
    yum install -y audit </dev/null >/dev/null 2>&1 || echo "[SECUREPULSE] Failed to install audit, continuing..."
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y audit </dev/null >/dev/null 2>&1 || echo "[SECUREPULSE] Failed to install audit, continuing..."
fi

if [ -d /etc/audit/rules.d/ ]; then
    cat << 'AUDIT_EOF' > /etc/audit/rules.d/securepulse.rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/ssh/sshd_config -p wa -k remote_access
AUDIT_EOF
    augenrules --load >/dev/null 2>&1 || true
    systemctl restart auditd >/dev/null 2>&1 || true
fi

# 2. Setup background Python Push Agent Daemon
mkdir -p /opt/securepulse

cat << PY_EOF > /opt/securepulse/node_push_agent.py
import os, sys, time, json, socket, subprocess, glob, re, hashlib
import urllib.request, urllib.error
from datetime import datetime

SOC_URL = "http://localhost".rstrip("/")
TARGET_IP = "$NODE_IP"
TARGET_NAME = "$NODE_NAME"
ASSIGNED_SERVER_ID = int("$ASSIGNED_ID") if "$ASSIGNED_ID".isdigit() else None
PUSH_INTERVAL = 30  # seconds

def get_hostname():
    try: return socket.gethostname()
    except: return TARGET_NAME

def check_assigned_server_id():
    global ASSIGNED_SERVER_ID
    if ASSIGNED_SERVER_ID is not None:
        return ASSIGNED_SERVER_ID
    try:
        url = f"{SOC_URL}/api/agent/status?ip={TARGET_IP}&hostname={get_hostname()}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.loads(r.read().decode())
            sid = res.get("server_id")
            if sid:
                ASSIGNED_SERVER_ID = int(sid)
                return ASSIGNED_SERVER_ID
    except: pass
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
            elif any(k in line_l for k in ["java", "spring", "mdm", "jar"]):
                parts = line.split(None, 10)
                if len(parts) > 1:
                    pid = parts[1]
                    fd_dir = f"/proc/{pid}/fd"
                    if os.path.exists(fd_dir):
                        try:
                            for fd in os.listdir(fd_dir):
                                target = os.readlink(os.path.join(fd_dir, fd))
                                if (target.endswith(".log") or target.endswith(".out")) and not is_rotated_archive(target):
                                    if os.path.exists(target):
                                        paths[target] = "tomcat"
                        except: pass
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
            fim_state[path] = sig
        except: pass
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
                    key_m = re.search(r'key="([^"]+)"', line)
                    if auid_m and auid_m.group(1) != "4294967295":
                        auid = auid_m.group(1)
                        uname = user_mapping.get(auid, "unknown")
                        key = key_m.group(1) if key_m else "unknown"
                        if key != "unknown":
                            events.append({"auid": auid, "username": uname, "key": key, "line": line.strip()[:300]})
            audit_log_positions[path] = f.tell()
    except: pass
    return events[-30:]

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
                            "line": line.strip()[:300]
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
                        events.append({"line": line.strip()[:300], "path": path})
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

def get_new_log_lines(max_lines_per_file=50):
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
                pos = size if size > 10240 else max(0, size - 5000)
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

        payload = {
            "server_id": sid,
            "server_ip": TARGET_IP,
            "hostname": get_hostname(),
            "cpu_percent": cpu,
            "memory_percent": mem,
            "disk_percent": disk,
            "processes": procs,
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
        urllib.request.urlopen(req, timeout=10)

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
PY_EOF

chmod +x /opt/securepulse/node_push_agent.py
pkill -f node_push_agent.py 2>/dev/null || true
pkill -f node_push_agent.sh 2>/dev/null || true

# Register as systemd service so systemctl restart/status/stop securepulse works
if command -v systemctl >/dev/null 2>&1; then
    cat << 'SERVICE_EOF' > /etc/systemd/system/securepulse.service
[Unit]
Description=SecurePulse SOC Node Agent Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/securepulse
ExecStart=/usr/bin/python3 /opt/securepulse/node_push_agent.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/securepulse_agent.log
StandardError=append:/var/log/securepulse_agent.log

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable securepulse 2>/dev/null || true
    systemctl restart securepulse 2>/dev/null || nohup python3 /opt/securepulse/node_push_agent.py > /var/log/securepulse_agent.log 2>&1 &
else
    nohup python3 /opt/securepulse/node_push_agent.py > /var/log/securepulse_agent.log 2>&1 &
fi

echo "[SUCCESS] SecurePulse Agent Daemon is active & streaming telemetry!"
echo "[INFO] Manage service: systemctl restart securepulse | systemctl status securepulse"
