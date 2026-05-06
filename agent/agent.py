#!/usr/bin/env python3
"""
agent/agent.py — SecurePulse Agent
Main entry point. Loads config, registers with backend,
then starts all monitor threads.

Usage:
    python3 agent.py

Environment / config file variables:
    SP_BACKEND_URL        — http://your-server:5000
    SP_AGENT_TOKEN        — token returned at registration
    SP_HEARTBEAT_INTERVAL — seconds between heartbeats (default 60)
    SP_POLL_INTERVAL      — seconds between process polls (default 5)
    SP_LOG_LEVEL          — DEBUG | INFO | WARNING (default INFO)
    SP_CONFIG_FILE        — path to config file (default /etc/securepulse-agent.conf)
"""

import os
import sys
import time
import signal
import logging

# ── Allow imports from this directory ──────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config          import load_config
from config          import load_config
from login_monitor   import LoginMonitor
from cron_monitor    import CronMonitor
from process_monitor import ProcessMonitor
from fim_monitor     import FIMMonitor
from heartbeat_monitor import HeartbeatMonitor


def setup_logging(level_name: str):
    level = getattr(logging, level_name.upper(), logging.INFO)
    log_path = "/var/log/securepulse-agent.log"
    if not os.path.exists(os.path.dirname(log_path)):
        log_path = "securepulse-agent.log"  # Fallback to current directory

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_path, mode="a"),
        ],
    )


def main():
    # ── Load config ─────────────────────────────────────────
    try:
        cfg = load_config()
    except ValueError as e:
        print(f"[FATAL] Config error: {e}", file=sys.stderr)
        sys.exit(1)

    setup_logging(cfg["log_level"])
    logger = logging.getLogger("sp_agent")
    logger.info("=" * 60)
    logger.info(f"  Backend : {cfg['backend_url']}")
    logger.info("=" * 60)

    # ── Check connectivity ──────────────────────────────────
    from sender import check_connectivity
    if not check_connectivity(cfg):
        logger.warning("Agent may not be able to reach backend! Check SP_BACKEND_URL.")

    # ── Start monitor threads ───────────────────────────────
    monitors = [
        LoginMonitor(cfg),
        CronMonitor(cfg),
        ProcessMonitor(cfg),
        FIMMonitor(cfg),
        HeartbeatMonitor(cfg),
    ]

    for m in monitors:
        m.start()
        logger.info(f"Started: {m.name}")

    # ── Graceful shutdown on SIGTERM / SIGINT ───────────────
    def shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping monitors…")
        for m in monitors:
            m.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT,  shutdown)

    logger.info("All monitors running. Press Ctrl+C to stop.")

    # ── Keep main thread alive ──────────────────────────────
    while True:
        alive = [m.name for m in monitors if m.is_alive()]
        dead  = [m.name for m in monitors if not m.is_alive()]
        if dead:
            logger.warning(f"Dead monitors: {dead}")
        time.sleep(30)


if __name__ == "__main__":
    main()
