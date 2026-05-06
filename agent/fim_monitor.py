"""
agent/fim_monitor.py — SecurePulse Agent
File Integrity Monitor (FIM).
Watches critical files and directories for:
- Content changes (hash)
- Permission changes (chmod)
- Ownership changes (chown)
"""

import os
import time
import hashlib
import logging
import threading
import platform

from sender import send_event

logger = logging.getLogger("sp_agent.fim_monitor")

# Critical targets to monitor
if platform.system() == "Windows":
    FIM_TARGETS = [
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32\\drivers\\etc\\hosts"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32\\drivers\\etc\\networks"),
        # Add local config if exists
        "securepulse-agent.conf",
    ]
else:
    FIM_TARGETS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
    ]

POLL_INTERVAL = 15  # seconds


def _sha256(path: str) -> str:
    """Return SHA-256 hex digest of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return ""


def _get_file_metadata(path: str) -> dict:
    """Returns metadata (hash, mode, uid, gid) for a file."""
    try:
        st = os.stat(path)
        return {
            "hash": _sha256(path) if os.path.isfile(path) else "directory",
            "mode": _get_mode_string(st.st_mode),
            "uid":  getattr(st, "st_uid", 0),
            "gid":  getattr(st, "st_gid", 0),
        }
    except (OSError, IOError):
        return {}


def _get_mode_string(st_mode):
    """Platform-independent mode string."""
    if platform.system() == "Windows":
        # Windows doesn't use octal permissions the same way
        return "win_attr_" + str(st_mode)
    return oct(st_mode & 0o777)


def _collect_fim_snapshot(targets: list[str]) -> dict[str, dict]:
    """
    Collects metadata for all targets.
    Recursively scans directories if needed (limited depth for performance).
    """
    snapshot = {}
    for target in targets:
        if not os.path.exists(target):
            continue
            
        if os.path.isfile(target):
            snapshot[target] = _get_file_metadata(target)
        elif os.path.isdir(target):
            # For directories, we watch the directory itself and its immediate children
            snapshot[target] = _get_file_metadata(target)
            try:
                for fname in os.listdir(target):
                    fpath = os.path.join(target, fname)
                    if os.path.isfile(fpath):
                        snapshot[fpath] = _get_file_metadata(fpath)
            except OSError:
                continue
    return snapshot


class FIMMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="fim_monitor", daemon=True)
        self.cfg      = cfg
        self.interval = POLL_INTERVAL
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info(f"FIM monitor started (poll every {self.interval}s)")
        previous = _collect_fim_snapshot(FIM_TARGETS)
        logger.info(f"FIM baseline: {len(previous)} items indexed")

        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break

            current = _collect_fim_snapshot(FIM_TARGETS)
            
            all_keys = set(previous) | set(current)
            for path in all_keys:
                if path not in previous:
                    self._report_change(path, "created", None, current[path])
                elif path not in current:
                    self._report_change(path, "deleted", previous[path], None)
                else:
                    p = previous[path]
                    c = current[path]
                    changes = []
                    if p["hash"] != c["hash"]: changes.append("content")
                    if p["mode"] != c["mode"]: changes.append("permissions")
                    if p["uid"] != c["uid"] or p["gid"] != c["gid"]: changes.append("ownership")
                    
                    if changes:
                        self._report_change(path, "modified", p, c, changes)

            previous = current

        logger.info("FIM monitor stopped")

    def _report_change(self, path, change_type, old, new, changes=None):
        desc = f"File Integrity: {path} was {change_type}"
        if changes:
            desc += f" ({', '.join(changes)})"
            
        severity = "warning"
        # Escalate for highly sensitive files
        if platform.system() == "Windows":
            CRITICAL_FILES = ["hosts", "SAM", "SYSTEM"]
        else:
            CRITICAL_FILES = ["/etc/shadow", "/etc/sudoers", "/etc/passwd"]
            
        if any(cf in path for cf in CRITICAL_FILES):
            severity = "critical"

        send_event(
            self.cfg,
            event_type="file_change",
            description=desc,
            severity=severity,
            source="fim_monitor",
            raw_data={
                "path": path,
                "change_type": change_type,
                "changes": changes,
                "old": old,
                "new": new,
            }
        )
        logger.info(f"FIM {change_type}: {path} ({changes})")
