"""
agent/heartbeat.py — SecurePulse Agent
Sends a heartbeat event at a fixed interval so the dashboard
knows the agent is alive.
"""

import time
import logging
import threading

from sender import send_event

logger = logging.getLogger("sp_agent.heartbeat")


class HeartbeatMonitor(threading.Thread):
    """Daemon thread — fires a heartbeat event every N seconds."""

    def __init__(self, cfg: dict):
        super().__init__(name="heartbeat", daemon=True)
        self.cfg      = cfg
        self.interval = cfg.get("heartbeat_interval", 60)
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info(f"Heartbeat started (every {self.interval}s)")
        while not self._stop.is_set():
            ok = send_event(
                self.cfg,
                event_type="heartbeat",
                description="Agent heartbeat — server is online",
                severity="info",
                source="heartbeat",
            )
            if not ok:
                logger.warning("Heartbeat failed to send (backend may be down)")
            self._stop.wait(self.interval)
        logger.info("Heartbeat stopped")
