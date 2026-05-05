"""
agent/cron_monitor.py — SecurePulse Agent
Watches cron directories and files for changes using SHA-256 hashes.
Sends a cron_change event only when a file is added, removed, or modified.
"""

import os
import time
import hashlib
import logging
import threading

from sender import send_event

logger = logging.getLogger("sp_agent.cron_monitor")

# Directories and files to watch
WATCH_TARGETS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
]

POLL_SECONDS = 10  # check every 10 seconds


def _sha256(path: str) -> str:
    """Return SHA-256 hex digest of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return ""


def _collect_snapshot(targets: list[str]) -> dict[str, str]:
    """
    Walk all watch targets.
    Returns {absolute_path: sha256_hash} for every readable file found.
    """
    snapshot: dict[str, str] = {}
    for target in targets:
        if not os.path.exists(target):
            continue
        if os.path.isfile(target):
            snapshot[target] = _sha256(target)
        elif os.path.isdir(target):
            for fname in os.listdir(target):
                fpath = os.path.join(target, fname)
                if os.path.isfile(fpath):
                    snapshot[fpath] = _sha256(fpath)
    return snapshot


def _diff_snapshots(
    old: dict[str, str],
    new: dict[str, str],
) -> list[tuple[str, str]]:
    """
    Compare two snapshots.
    Returns list of (change_type, path):
      - "modified" — file exists in both, hash changed
      - "added"    — new file
      - "removed"  — file deleted
    """
    changes = []
    all_keys = set(old) | set(new)
    for path in all_keys:
        if path not in old:
            changes.append(("added", path))
        elif path not in new:
            changes.append(("removed", path))
        elif old[path] != new[path]:
            changes.append(("modified", path))
    return changes


class CronMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="cron_monitor", daemon=True)
        self.cfg      = cfg
        self.interval = POLL_SECONDS
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info(f"Cron monitor started (poll every {self.interval}s)")
        previous = _collect_snapshot(WATCH_TARGETS)
        logger.info(f"Cron baseline: {len(previous)} files indexed")

        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break

            current = _collect_snapshot(WATCH_TARGETS)
            changes = _diff_snapshots(previous, current)

            for change_type, path in changes:
                logger.info(f"Cron {change_type}: {path}")
                send_event(
                    self.cfg,
                    event_type="cron_change",
                    description=f"Cron job {change_type}: {path}",
                    severity="warning",
                    source="cron_monitor",
                    raw_data={
                        "change_type": change_type,
                        "path":        path,
                        "old_hash":    previous.get(path, ""),
                        "new_hash":    current.get(path, ""),
                    },
                )

            previous = current

        logger.info("Cron monitor stopped")
