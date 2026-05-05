"""
agent/process_monitor.py — SecurePulse Agent
Monitors running processes using psutil.
Detects NEW processes only (not constant spam).
Sends a new_process event for each newly appeared PID.
"""

import time
import logging
import threading

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from sender import send_event

logger = logging.getLogger("sp_agent.process_monitor")

POLL_SECONDS = 5   # process snapshot interval

# Processes to ignore (very noisy / expected)
IGNORE_NAMES = {
    "kworker", "kthread", "ksoftirqd", "rcu_sched",
    "migration", "cpuhp", "watchdog", "idle",
}


def _get_snapshot() -> dict[int, dict]:
    """Return {pid: {name, cmdline, username}} for all running processes."""
    snap = {}
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            if any(name.startswith(ign) for ign in IGNORE_NAMES):
                continue
            snap[info["pid"]] = {
                "name":     name,
                "cmdline":  " ".join(info.get("cmdline") or [])[:200],
                "username": info.get("username") or "unknown",
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return snap


class ProcessMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="process_monitor", daemon=True)
        self.cfg      = cfg
        self.interval = POLL_SECONDS
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        if not HAS_PSUTIL:
            logger.error("psutil not installed — process monitor disabled. Run: pip install psutil")
            return

        logger.info(f"Process monitor started (poll every {self.interval}s)")
        previous_pids = set(_get_snapshot().keys())
        logger.info(f"Process baseline: {len(previous_pids)} PIDs")

        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break

            current = _get_snapshot()
            current_pids = set(current.keys())

            new_pids = current_pids - previous_pids
            for pid in new_pids:
                proc = current[pid]
                name     = proc["name"]
                cmdline  = proc["cmdline"]
                username = proc["username"]

                logger.info(f"New process: PID={pid} name={name} user={username}")
                send_event(
                    self.cfg,
                    event_type="new_process",
                    description=f"New process detected: {name} (PID {pid}) by {username}",
                    severity="info",
                    source="process_monitor",
                    raw_data={
                        "pid":      pid,
                        "name":     name,
                        "cmdline":  cmdline,
                        "username": username,
                    },
                )

            previous_pids = current_pids

        logger.info("Process monitor stopped")
