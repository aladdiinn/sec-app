#!/usr/bin/env python3
"""
BSmart SOC — Suricata EVE JSON Sensor Forwarder
================================================
Streams real-time Network IDS (NIDS) alerts from /var/log/suricata/eve.json
to BSmart SOC API (/api/nids/events).

FEATURES:
  - Global multi-firewall support (AWS VPC, FortiGate SPAN, GlobalProtect, any)
  - Interface-to-project mapping via --iface-map (reads in_iface from EVE JSON)
  - Automatic log rotation detection and byte-offset state persistence
  - Batching with configurable size and flush interval
  - Retry with exponential backoff on API errors
  - Structured startup banner and per-event verbose logging

USAGE EXAMPLES:
  # Single firewall (default):
  python3 suricata_forwarder.py \\
      --soc-url https://soc.yourcompany.com \\
      --sensor-name "AWS-VPC-East" \\
      --project-id 1 \\
      --token bsmart_secret_token

  # Multi-firewall on 1 sensor (EC2 monitoring both AWS eth0 and FortiGate eth1):
  python3 suricata_forwarder.py \\
      --soc-url https://soc.yourcompany.com \\
      --token bsmart_secret_token \\
      --iface-map "eth0:1:AWS-VPC-East,eth1:2:FortiGate-HQ-Perimeter"

  # Via environment variables (recommended for systemd):
  SOC_URL=https://soc.example.com SOC_TOKEN=secret PROJECT_ID=1 \\
  SENSOR_NAME=AWS-VPC-East python3 suricata_forwarder.py
"""

import os
import sys
import time
import json
import socket
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_EVE_PATH       = "/var/log/suricata/eve.json"
DEFAULT_STATE_PATH     = "/tmp/bsmart_suricata_fwd.state"
DEFAULT_BATCH_SIZE     = 25
DEFAULT_FLUSH_INTERVAL = 3.0    # seconds
DEFAULT_RETRY_BACKOFF  = 5.0    # seconds initial retry wait
MAX_RETRY_BACKOFF      = 60.0   # seconds max retry wait
RETRY_MULTIPLIER       = 2.0
VERSION                = "2.0.0"


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(level: str, msg: str):
    print(f"[{ts()}] [{level:5s}] {msg}", flush=True)


def parse_args():
    parser = argparse.ArgumentParser(
        description="BSmart SOC — Suricata EVE JSON Forwarder v" + VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--soc-url",     default=os.getenv("SOC_URL", "http://127.0.0.1:8000"),
                        help="BSmart SOC Base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--sensor-name", default=os.getenv("SENSOR_NAME", socket.gethostname()),
                        help="Sensor label (e.g. AWS-VPC-01, FortiGate-WAN). Default: hostname")
    parser.add_argument("--project-id",  type=int, default=int(os.getenv("PROJECT_ID", 0)) or None,
                        help="Project ID to associate all events with (overridden per-iface by --iface-map)")
    parser.add_argument("--eve-path",    default=os.getenv("EVE_PATH", DEFAULT_EVE_PATH),
                        help="Path to Suricata eve.json (default: /var/log/suricata/eve.json)")
    parser.add_argument("--token",       default=os.getenv("SOC_TOKEN", ""),
                        help="BSmart SOC API Bearer Token")
    parser.add_argument("--iface-map",   default=os.getenv("IFACE_MAP", ""),
                        help=(
                            "Map Suricata in_iface to project+sensor. Format: "
                            "'eth0:PROJECT_ID:SENSOR_NAME,eth1:PROJECT_ID:SENSOR_NAME,...' "
                            "Example: 'eth0:1:AWS-VPC-East,eth1:2:FortiGate-HQ'"
                        ))
    parser.add_argument("--batch-size",  type=int, default=int(os.getenv("BATCH_SIZE", DEFAULT_BATCH_SIZE)),
                        help=f"Events per API call (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--flush-secs",  type=float, default=float(os.getenv("FLUSH_SECS", DEFAULT_FLUSH_INTERVAL)),
                        help=f"Max seconds between flushes (default: {DEFAULT_FLUSH_INTERVAL})")
    parser.add_argument("--verbose",     action="store_true", default=os.getenv("VERBOSE", "").lower() in ("1","true","yes"),
                        help="Print each event as it is read")
    return parser.parse_args()


def parse_iface_map(raw: str) -> dict:
    """
    Parse --iface-map string into:
      { 'eth0': (project_id, 'SENSOR-NAME'), 'eth1': (project_id, 'SENSOR-NAME'), ... }
    """
    result = {}
    if not raw:
        return result
    for item in raw.split(","):
        parts = [p.strip() for p in item.strip().split(":")]
        if len(parts) >= 3:
            iface, proj_str, sensor_name = parts[0], parts[1], ":".join(parts[2:])
            try:
                result[iface] = (int(proj_str), sensor_name)
            except ValueError:
                log("WARN", f"Invalid iface-map entry (bad project_id): '{item.strip()}'")
        else:
            log("WARN", f"Invalid iface-map entry (need iface:pid:name): '{item.strip()}'")
    return result


# ── State persistence ─────────────────────────────────────────────────────────
def load_state(state_file: str) -> tuple:
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                data = json.load(f)
                return data.get("inode", 0), data.get("offset", 0)
        except Exception:
            pass
    return 0, 0


def save_state(state_file: str, inode: int, offset: int):
    try:
        with open(state_file, "w") as f:
            json.dump({"inode": inode, "offset": offset, "updated_at": time.time()}, f)
    except Exception as e:
        log("WARN", f"Could not save state: {e}")


# ── API Transmission ──────────────────────────────────────────────────────────
def send_batch(soc_url: str, sensor_name: str, project_id, token: str, batch: list, retry_wait: float = DEFAULT_RETRY_BACKOFF) -> bool:
    """POST a batch of EVE JSON events to BSmart SOC. Returns True on success."""
    if not batch:
        return True
    url = f"{soc_url.rstrip('/')}/api/nids/events"
    payload = {
        "sensor_name": sensor_name,
        "project_id":  project_id,
        "events":      batch
    }
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
            "X-Sensor-Name": sensor_name,
            "X-Forwarder":   f"BSmart-Forwarder/{VERSION}",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            ok = resp.status in (200, 201)
            if ok:
                log("OK", f"Sent {len(batch)} events → {url} (HTTP {resp.status})")
            else:
                log("WARN", f"Unexpected HTTP {resp.status} from {url}")
            return ok
    except urllib.error.HTTPError as e:
        log("ERROR", f"HTTP {e.code} from {url}: {e.reason}")
        return False
    except Exception as e:
        log("ERROR", f"Transmission error to {url}: {e}")
        return False


# ── Main Loop ─────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    iface_map = parse_iface_map(args.iface_map)

    print("=" * 65)
    print(f"  BSmart SOC — Suricata EVE Network IDS Forwarder v{VERSION}")
    print("=" * 65)
    print(f"  SOC URL       : {args.soc_url}")
    print(f"  Default Sensor: {args.sensor_name}")
    print(f"  Default Proj  : {args.project_id or '(auto / global)'}")
    print(f"  EVE JSON Path : {args.eve_path}")
    print(f"  Batch Size    : {args.batch_size}")
    print(f"  Flush Interval: {args.flush_secs}s")
    if iface_map:
        print(f"  Interface Map :")
        for iface, (pid, sname) in iface_map.items():
            print(f"    {iface:10s} → Project {pid} / Sensor '{sname}'")
    else:
        print(f"  Interface Map : (none — single sensor mode)")
    print("=" * 65)

    saved_inode, file_offset = load_state(DEFAULT_STATE_PATH)
    batch:  list  = []
    last_flush    = time.time()
    retry_wait    = DEFAULT_RETRY_BACKOFF
    consecutive_fails = 0

    while True:
        if not os.path.exists(args.eve_path):
            log("WAIT", f"Waiting for {args.eve_path} to appear...")
            time.sleep(2)
            continue

        try:
            st = os.stat(args.eve_path)
            curr_inode = getattr(st, "st_ino", 0)

            # Detect log rotation (inode changed or file shrank)
            if curr_inode != saved_inode or st.st_size < file_offset:
                log("INFO", f"Log rotation detected (inode {saved_inode}→{curr_inode}). Resetting offset.")
                file_offset  = 0
                saved_inode  = curr_inode

            with open(args.eve_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(file_offset)
                new_events = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Only forward alert or drop events
                    if record.get("event_type") not in ("alert", "drop"):
                        continue

                    # Apply interface mapping if configured
                    in_iface = record.get("in_iface")
                    if in_iface and in_iface in iface_map:
                        proj_id, sens_name = iface_map[in_iface]
                        record["project_id"]   = proj_id
                        record["sensor_name"]  = sens_name
                    # else leave record as-is; the API will use the top-level sensor_name/project_id

                    batch.append(record)
                    new_events += 1
                    if args.verbose:
                        sig = record.get("alert", {}).get("signature", "?")
                        log("EVT", f"[{record.get('sensor_name', args.sensor_name)}] {sig} "
                                   f"{record.get('src_ip','?')} → {record.get('dest_ip','?')}")

                file_offset = f.tell()
                save_state(DEFAULT_STATE_PATH, saved_inode, file_offset)

        except Exception as ex:
            log("ERROR", f"Read error on {args.eve_path}: {ex}")

        # ── Flush decision ────────────────────────────────────────────────────
        now = time.time()
        should_flush = (
            len(batch) >= args.batch_size or
            (batch and (now - last_flush) >= args.flush_secs)
        )

        if should_flush and batch:
            # Snapshot current batch to send, keep remainder if partial (future)
            to_send = batch[:]
            success = send_batch(
                args.soc_url, args.sensor_name, args.project_id, args.token, to_send, retry_wait
            )
            if success:
                batch.clear()
                last_flush         = now
                retry_wait         = DEFAULT_RETRY_BACKOFF
                consecutive_fails  = 0
            else:
                consecutive_fails += 1
                log("WARN", f"Failed to send (attempt {consecutive_fails}). Retrying in {retry_wait:.0f}s...")
                time.sleep(retry_wait)
                retry_wait = min(retry_wait * RETRY_MULTIPLIER, MAX_RETRY_BACKOFF)
        else:
            time.sleep(0.5)


if __name__ == "__main__":
    main()
