"""
agent/login_monitor.py — SecurePulse Agent
Tails /var/log/auth.log (or journalctl output) to detect:
  - ssh_login      (Accepted password/publickey)
  - failed_login   (Failed password / Invalid user)
  - logout         (Disconnected / session closed)

Change-detection only — tracks file position to avoid re-reading old lines.
"""

import re
import os
import time
import logging
import threading
import subprocess

from sender import send_event

logger = logging.getLogger("sp_agent.login_monitor")

AUTH_LOG  = "/var/log/auth.log"
SYSLOG    = "/var/log/syslog"
POLL_SEC  = 1   # tail poll interval in seconds

# Regex patterns
RE_SSH_OK  = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
RE_SSH_FAIL= re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
RE_INV_USR = re.compile(r"Invalid user (\S+) from ([\d.]+)")
RE_LOGOUT  = re.compile(r"(?:Disconnected from|session closed for user) (\S+)")


def _pick_log_file() -> str | None:
    for path in (AUTH_LOG, SYSLOG):
        if os.path.exists(path) and os.access(path, os.R_OK):
            return path
    return None


def _parse_line(line: str, cfg: dict):
    """Parse a single auth log line and emit event if matched."""
    if m := RE_SSH_OK.search(line):
        user, ip = m.group(1), m.group(2)
        send_event(cfg, "ssh_login",
                   f"SSH login: user={user} from={ip}",
                   severity="info", source="auth.log",
                   raw_data={"user": user, "ip": ip})

    elif m := RE_SSH_FAIL.search(line):
        user, ip = m.group(1), m.group(2)
        send_event(cfg, "failed_login",
                   f"Failed SSH login: user={user} from={ip}",
                   severity="warning", source="auth.log",
                   raw_data={"user": user, "ip": ip})

    elif m := RE_INV_USR.search(line):
        user, ip = m.group(1), m.group(2)
        send_event(cfg, "failed_login",
                   f"Invalid user login attempt: user={user} from={ip}",
                   severity="warning", source="auth.log",
                   raw_data={"user": user, "ip": ip})

    elif m := RE_LOGOUT.search(line):
        user = m.group(1)
        send_event(cfg, "logout",
                   f"User logged out: {user}",
                   severity="info", source="auth.log",
                   raw_data={"user": user})


def _tail_file(path: str, cfg: dict, stop_event: threading.Event):
    """Tail a file from end, emitting events for new lines."""
    logger.info(f"Tailing log file: {path}")
    with open(path, "r", errors="replace") as f:
        f.seek(0, 2)   # seek to end
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                stop_event.wait(POLL_SEC)
                continue
            line = line.rstrip()
            if line:
                _parse_line(line, cfg)


def _tail_journalctl(cfg: dict, stop_event: threading.Event):
    """Fallback: use journalctl -f for systems without readable auth.log."""
    logger.info("Tailing journalctl -u ssh (no auth.log found)")
    try:
        proc = subprocess.Popen(
            ["journalctl", "-f", "-u", "ssh", "--no-pager", "-o", "short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if line:
                _parse_line(line.rstrip(), cfg)
            else:
                time.sleep(POLL_SEC)
        proc.terminate()
    except FileNotFoundError:
        logger.error("journalctl not found. Login monitoring unavailable.")


class LoginMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="login_monitor", daemon=True)
        self.cfg   = cfg
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        log_path = _pick_log_file()
        if log_path:
            _tail_file(log_path, self.cfg, self._stop)
        else:
            _tail_journalctl(self.cfg, self._stop)
        logger.info("Login monitor stopped")
