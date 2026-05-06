"""
agent/heartbeat_monitor.py — SecurePulse Agent
Sends periodic heartbeats to the backend to keep the server status 'online'.
"""

import time
import logging
import threading
from sender import send_event

logger = logging.getLogger("sp_agent.heartbeat")

class HeartbeatMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="heartbeat_monitor", daemon=True)
        self.cfg      = cfg
        self.interval = int(cfg.get("heartbeat_interval", 60))
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        logger.info(f"Heartbeat monitor started (interval: {self.interval}s)")
        
        while not self._stop.is_set():
            # Send heartbeat event
            # We use a special event type that just updates last_seen but might not show in feeds
            success = send_event(
                self.cfg,
                event_type="heartbeat",
                description=f"Agent heartbeat from {self.cfg.get('hostname', 'unknown')}",
                severity="info",
                source="heartbeat_monitor"
            )
            
            if success:
                logger.debug("Heartbeat sent successfully")
            else:
                logger.warning("Failed to send heartbeat")

            self._stop.wait(self.interval)

        logger.info("Heartbeat monitor stopped")
