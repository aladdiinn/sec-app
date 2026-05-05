"""
agent/config.py — SecurePulse Agent
Loads configuration from /etc/securepulse-agent.conf or environment variables.
"""

import os
import configparser
import logging

logger = logging.getLogger("sp_agent.config")

CONFIG_FILE = os.getenv("SP_CONFIG_FILE", "/etc/securepulse-agent.conf")


def load_config() -> dict:
    """
    Load agent config. Priority:
    1. Environment variables (highest)
    2. /etc/securepulse-agent.conf
    3. Defaults (lowest)
    """
    cfg = {
        "backend_url":        "http://localhost:5000",
        "agent_token":        "",
        "heartbeat_interval": 60,
        "poll_interval":      5,
        "log_level":          "INFO",
    }

    # Read from config file if it exists
    if os.path.exists(CONFIG_FILE):
        parser = configparser.ConfigParser()
        parser.read(CONFIG_FILE)
        section = "agent" if parser.has_section("agent") else "DEFAULT"
        cfg["backend_url"]        = parser.get(section, "backend_url",        fallback=cfg["backend_url"])
        cfg["agent_token"]        = parser.get(section, "agent_token",        fallback=cfg["agent_token"])
        cfg["heartbeat_interval"] = int(parser.get(section, "heartbeat_interval", fallback=cfg["heartbeat_interval"]))
        cfg["poll_interval"]      = int(parser.get(section, "poll_interval",      fallback=cfg["poll_interval"]))
        cfg["log_level"]          = parser.get(section, "log_level",           fallback=cfg["log_level"])
        logger.info(f"Loaded config from {CONFIG_FILE}")

    # Environment variables override config file
    cfg["backend_url"]        = os.getenv("SP_BACKEND_URL",        cfg["backend_url"])
    cfg["agent_token"]        = os.getenv("SP_AGENT_TOKEN",        cfg["agent_token"])
    cfg["heartbeat_interval"] = int(os.getenv("SP_HEARTBEAT_INTERVAL", cfg["heartbeat_interval"]))
    cfg["poll_interval"]      = int(os.getenv("SP_POLL_INTERVAL",       cfg["poll_interval"]))
    cfg["log_level"]          = os.getenv("SP_LOG_LEVEL",          cfg["log_level"])

    if not cfg["agent_token"]:
        raise ValueError(
            "SP_AGENT_TOKEN is not set. "
            "Set it in /etc/securepulse-agent.conf or as an environment variable."
        )

    # Normalize URL
    cfg["backend_url"] = cfg["backend_url"].rstrip("/")

    return cfg
