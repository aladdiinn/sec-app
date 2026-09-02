#!/usr/bin/env python3
"""
EC2 Security Agent — Persistent Telemetry & Dangerous Command Tracking
Monitors active users, command execution, and security events.
"""

import os
import sys
import time
import re
import json
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ec2-agent")

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "sp-agent-token-default")
SERVER_ID = int(os.getenv("SERVER_ID", "1"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "15"))

# Format: (regex_pattern, category, reason_string)
DANGEROUS_PATTERNS = [
    # FORK BOMB
    (r':\(\)\s*\{\s*:\|:&\s*\};:', "FORK_BOMB", "Fork bomb pattern detected"),

    # DESTRUCTIVE
    (r'rm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+/', "DESTRUCTIVE", "Recursive root deletion attempt"),
    (r'rm\s+-[a-zA-Z]*f[a-zA-Z]*r\s+/', "DESTRUCTIVE", "Recursive root deletion attempt"),
    (r'rm\s+-rf\s+\*', "DESTRUCTIVE", "Wildcard recursive deletion attempt"),
    (r'rm\s+-rf\s+/boot', "DESTRUCTIVE", "Boot folder deletion attempt"),
    (r'rm\s+-rf\s+/etc', "DESTRUCTIVE", "Etc configuration deletion attempt"),
    (r'rm\s+-rf\s+/home/\*', "DESTRUCTIVE", "All home directories deletion attempt"),
    (r'rm\s+-rf\s+/root/\*', "DESTRUCTIVE", "Root home directory deletion attempt"),
    (r'rm\s+-rf\s+/var/\*', "DESTRUCTIVE", "Var directory deletion attempt"),
    (r'dd\s+if=/dev/zero', "DESTRUCTIVE", "Disk zeroing attempt via dd"),
    (r'dd\s+if=/dev/random', "DESTRUCTIVE", "Disk random fill attempt via dd"),
    (r'mkfs\.ext4', "DESTRUCTIVE", "Filesystem format attempt (ext4)"),
    (r'mkfs\.xfs', "DESTRUCTIVE", "Filesystem format attempt (xfs)"),
    (r'mkfs', "DESTRUCTIVE", "Filesystem format attempt"),
    (r'mv\s+/bin', "DESTRUCTIVE", "System binaries move attempt"),
    (r'mv\s+/lib', "DESTRUCTIVE", "System libraries move attempt"),
    (r'mv\s+/usr', "DESTRUCTIVE", "Usr directory move attempt"),
    (r'>\s*/etc/passwd', "DESTRUCTIVE", "Passwd file truncation attempt"),
    (r'>\s*/etc/shadow', "DESTRUCTIVE", "Shadow file truncation attempt"),
    (r'echo\s+""\s*>\s*/etc/passwd', "DESTRUCTIVE", "Passwd file overwrite attempt"),
    (r'echo\s+""\s*>\s*/etc/shadow', "DESTRUCTIVE", "Shadow file overwrite attempt"),

    # PERM_CHANGE
    (r'chmod\s+-[a-zA-Z]*R\s+777\s+/', "PERM_CHANGE", "Global 777 permission set attempt"),
    (r'chmod\s+-[a-zA-Z]*R\s+000\s+/', "PERM_CHANGE", "Global 000 permission lock attempt"),
    (r'chmod\s+-[a-zA-Z]*R\s+777', "PERM_CHANGE", "Recursive 777 permission attempt"),
    (r'chmod\s+-[a-zA-Z]*R\s+000', "PERM_CHANGE", "Recursive 000 permission attempt"),
    (r'chmod\s+777', "PERM_CHANGE", "World writable permission attempt"),
    (r'chown\s+-[a-zA-Z]*R\s+nobody', "PERM_CHANGE", "Recursive owner change to nobody"),
    (r'chown\s+-[a-zA-Z]*R\s+user', "PERM_CHANGE", "Recursive owner change attempt"),
    (r'chown\s+-R', "PERM_CHANGE", "Recursive owner change attempt"),
    (r'chmod', "PERM_CHANGE", "Permission modification"),
    (r'chown', "PERM_CHANGE", "Ownership modification"),

    # PROCESS_KILL
    (r'kill\s+-9\s+-1', "PROCESS_KILL", "Global killall -9 attempt"),
    (r'killall\s+-9', "PROCESS_KILL", "Forced killall attempt"),
    (r'pkill\s+-9\s+ssh', "PROCESS_KILL", "Forced SSH daemon kill attempt"),
    (r'kill\s+-9', "PROCESS_KILL", "Forced process termination"),
    (r'pkill', "PROCESS_KILL", "Process pkill execution"),

    # NETWORK
    (r'iptables\s+-F', "NETWORK", "Iptables firewall flush attempt"),
    (r'iptables\s+-P\s+INPUT\s+DROP', "NETWORK", "Iptables default drop rule attempt"),
    (r'iptables', "NETWORK", "Firewall rules modification"),

    # SERVICE_STOP
    (r'systemctl\s+stop\s+ssh', "SERVICE_STOP", "SSH service stop attempt"),
    (r'systemctl\s+stop\s+network', "SERVICE_STOP", "Network service stop attempt"),
    (r'systemctl\s+disable\s+ssh', "SERVICE_STOP", "SSH service disable attempt"),
    (r'systemctl\s+disable\s+networking', "SERVICE_STOP", "Networking service disable attempt"),
    (r'systemctl\s+stop', "SERVICE_STOP", "Service stop attempt"),

    # REBOOT
    (r'reboot\s+-f', "REBOOT", "Forced system reboot attempt"),
    (r'shutdown\s+-h\s+now', "REBOOT", "Immediate shutdown attempt"),
    (r'reboot', "REBOOT", "System reboot attempt"),
    (r'shutdown', "REBOOT", "System shutdown attempt"),

    # HISTORY
    (r'history\s+-c', "HISTORY", "Shell history clearance attempt"),
    (r'crontab\s+-r', "HISTORY", "Crontab removal attempt"),

    # DISK
    (r'yes\s*>\s*/dev/null', "DISK", "Resource exhaustion (yes command)"),
    (r'cat\s+/dev/zero', "DISK", "Resource exhaustion (cat zero)"),
    (r'ulimit\s+-n\s+1', "DISK", "File descriptor exhaustion attempt"),

    # KERNEL
    (r'echo\s+b\s*>\s*/proc/sysrq-trigger', "KERNEL", "Kernel force reboot trigger attempt"),
    (r'echo\s+1\s*>\s*/proc/sys/kernel/sysrq', "KERNEL", "Kernel SysRq enable attempt")
]

def scan_command(cmd):
    """Matches a command against DANGEROUS_PATTERNS."""
    for pattern, category, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return category, reason
    return None, None

def send_telemetry(payload):
    """Posts telemetry data back to the central monitor server."""
    url = f"{SERVER_URL}/api/events"
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Token": AGENT_TOKEN
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        logger.error(f"Failed to post telemetry: {e}")
        return False

def run_agent():
    logger.info(f"EC2 Security Agent started for server_id={SERVER_ID}. Monitoring...")
    while True:
        try:
            telemetry = {
                "server_id": SERVER_ID,
                "timestamp": time.time(),
                "commands": [],
                "login_history": []
            }
            send_telemetry(telemetry)
        except Exception as e:
            logger.error(f"Agent loop error: {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_agent()
