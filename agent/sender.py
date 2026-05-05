"""
agent/sender.py — SecurePulse Agent
Sends events to the backend API with exponential-backoff retry.
"""

import time
import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger("sp_agent.sender")

MAX_RETRIES = 5
BASE_DELAY  = 2   # seconds


def send_event(
    cfg: dict,
    event_type: str,
    description: str,
    severity: str = "info",
    source: str | None = None,
    raw_data: dict | None = None,
) -> bool:
    """
    POST an event to /events on the backend.
    Returns True on success, False after all retries exhausted.
    """
    payload = {
        "event_type":  event_type,
        "description": description,
        "severity":    severity,
        "source":      source,
        "raw_data":    raw_data or {},
    }
    data    = json.dumps(payload).encode("utf-8")
    url     = cfg["backend_url"] + "/api/events"
    token   = cfg["agent_token"]

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                method="POST",
                headers={
                    "Content-Type":  "application/json",
                    "X-Agent-Token": token,
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
                logger.debug(f"Event sent → id={body.get('id')} type={event_type}")
                return True

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            logger.warning(f"[attempt {attempt}] HTTP {e.code} posting event: {body}")
            if e.code in (400, 401, 403):
                # Non-retriable errors
                return False

        except Exception as exc:
            logger.warning(f"[attempt {attempt}] Failed to send event: {exc}")

        if attempt < MAX_RETRIES:
            delay = BASE_DELAY * (2 ** (attempt - 1))
            logger.info(f"Retrying in {delay}s…")
            time.sleep(delay)

    logger.error(f"Gave up sending event after {MAX_RETRIES} attempts: {event_type}")
    return False
