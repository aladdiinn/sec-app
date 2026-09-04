#!/usr/bin/env python3
"""
SecurePulse Real-Time SOC Endpoint Agent
Monitors:
1. /var/log/auth.log for real SSH failed logins, invalid users, and sudo commands
2. Bash command history from all active users (/root/.bash_history, /home/*/.bash_history)
3. Forwards real-time security events to the SOC backend (/api/agent/push)
"""

import os
import sys
import time
import re
import json
import glob
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("soc-agent")

SOC_URL = os.getenv("SOC_URL", "http://localhost:8000")
SERVER_ID = int(os.getenv("SERVER_ID", "1"))
POLL_INTERVAL = 2.0  # Poll every 2 seconds for real-time responsiveness

AUTH_LOG = "/var/log/auth.log"
auth_file_pos = 0
history_file_positions = {}

def get_server_id():
    """Dynamically fetch our registered server ID from SOC backend if available."""
    try:
        req = urllib.request.Request(f"{SOC_URL}/api/servers", headers={"User-Agent": "SecurePulse-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            servers = data if isinstance(data, list) else data.get("items", [])
            if servers:
                return servers[0].get("id", SERVER_ID)
    except Exception:
        pass
    return SERVER_ID

def send_telemetry(payload):
    """Post security events to SOC backend."""
    url = f"{SOC_URL}/api/agent/push"
    headers = {"Content-Type": "application/json", "User-Agent": "SecurePulse-Agent/1.0"}
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status == 200
    except Exception as e:
        logger.debug(f"Failed to post telemetry to {url}: {e}")
        return False

def scan_auth_log():
    """Read new lines from /var/log/auth.log and extract SSH failures and sudo commands."""
    global auth_file_pos
    events = []
    commands = []

    if not os.path.exists(AUTH_LOG):
        log_path = "/var/log/syslog" if os.path.exists("/var/log/syslog") else None
    else:
        log_path = AUTH_LOG

    if not log_path:
        return events, commands

    try:
        file_size = os.path.getsize(log_path)
        if auth_file_pos == 0:
            auth_file_pos = max(0, file_size - 15000)

        if file_size < auth_file_pos:
            auth_file_pos = 0

        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(auth_file_pos)
            lines = f.readlines()
            auth_file_pos = f.tell()

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Match SSH Failed Password or Invalid User (e.g. MobaXterm wrong user login)
            fail_match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line_str)
            if fail_match:
                user = fail_match.group(1)
                ip = fail_match.group(2)
                events.append({
                    "type": "AUTH_FAIL",
                    "user": user,
                    "ip": ip,
                    "message": line_str,
                    "count": 1
                })
                logger.info(f"[DETECTED] SSH Failed login: user={user}, ip={ip}")
                continue

            # 2. Match Invalid User without password attempt
            inv_match = re.search(r'Invalid user (\S+) from (\S+)', line_str)
            if inv_match:
                user = inv_match.group(1)
                ip = inv_match.group(2)
                events.append({
                    "type": "AUTH_FAIL",
                    "user": user,
                    "ip": ip,
                    "message": line_str,
                    "count": 1
                })
                logger.info(f"[DETECTED] SSH Invalid user attempt: user={user}, ip={ip}")
                continue

            # 3. Match Sudo Command Execution
            sudo_match = re.search(r'sudo:\s+(\S+)\s+:.*?COMMAND=(.+)$', line_str)
            if sudo_match:
                user = sudo_match.group(1)
                cmd = sudo_match.group(2).strip()
                commands.append({
                    "user": user,
                    "command": cmd,
                    "is_sudo": True
                })
                logger.info(f"[DETECTED] Sudo command: user={user}, cmd={cmd}")
                continue

            # 4. Match SSH Successful Login
            succ_match = re.search(r'Accepted (?:publickey|password) for (\S+) from (\S+)', line_str)
            if succ_match:
                user = succ_match.group(1)
                ip = succ_match.group(2)
                events.append({
                    "type": "LOGIN_SUCCESS",
                    "user": user,
                    "ip": ip,
                    "message": line_str
                })
                logger.info(f"[DETECTED] SSH Successful login: user={user}, ip={ip}")

    except Exception as e:
        logger.debug(f"Error scanning auth log: {e}")

    return events, commands

def scan_bash_histories():
    """Read newly appended commands from bash history files across the system."""
    global history_file_positions
    commands = []

    history_paths = ["/root/.bash_history"] + glob.glob("/home/*/.bash_history")

    for h_path in history_paths:
        if not os.path.exists(h_path):
            continue
        try:
            file_size = os.path.getsize(h_path)
            last_pos = history_file_positions.get(h_path, 0)

            if last_pos == 0:
                last_pos = max(0, file_size - 4000)
                history_file_positions[h_path] = last_pos

            if file_size < last_pos:
                last_pos = 0

            if file_size > last_pos:
                with open(h_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    history_file_positions[h_path] = f.tell()

                user = "root" if "/root/" in h_path else h_path.split("/home/")[1].split("/")[0]
                for raw_line in lines:
                    cmd_line = raw_line.strip()
                    if not cmd_line or cmd_line.startswith("#"):
                        continue
                    commands.append({
                        "user": user,
                        "command": cmd_line,
                        "is_sudo": "sudo" in cmd_line
                    })
                    logger.info(f"[DETECTED] Shell history command ({user}): {cmd_line}")
        except Exception as e:
            logger.debug(f"Error scanning history file {h_path}: {e}")

    return commands

def main():
    logger.info("==============================================================")
    logger.info("  SecurePulse SOC Endpoint Agent Started")
    logger.info(f"  Target Server ID : {SERVER_ID}")
    logger.info(f"  SOC Endpoint URL : {SOC_URL}")
    logger.info("  Monitoring: /var/log/auth.log + user bash histories in real time")
    logger.info("==============================================================")

    scan_auth_log()
    scan_bash_histories()

    while True:
        try:
            auth_events, auth_commands = scan_auth_log()
            hist_commands = scan_bash_histories()

            all_commands = auth_commands + hist_commands

            if auth_events or all_commands:
                current_server_id = get_server_id()
                payload = {
                    "server_id": current_server_id,
                    "events": auth_events,
                    "commands": all_commands
                }
                send_telemetry(payload)

        except Exception as e:
            logger.error(f"Agent loop error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
