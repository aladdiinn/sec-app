#!/usr/bin/env python3
"""
BSmart SOC - Suricata EVE JSON Sensor Forwarder
Streams real-time Network IDS (NIDS) alerts from /var/log/suricata/eve.json
to BSmart SOC API (/api/nids/events).
Supports automatic log rotation detection, byte-offset persistence, and batching.
"""

import os
import sys
import time
import json
import socket
import argparse
import urllib.request
import urllib.error

DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"
DEFAULT_STATE_PATH = "/tmp/suricata_fwd.state"
DEFAULT_BATCH_SIZE = 25
DEFAULT_FLUSH_INTERVAL = 2.0  # seconds

def parse_args():
    parser = argparse.ArgumentParser(description="BSmart SOC Suricata EVE JSON Forwarder")
    parser.add_argument("--soc-url", default=os.getenv("SOC_URL", "http://127.0.0.1:8000"), help="BSmart SOC Base URL")
    parser.add_argument("--sensor-name", default=os.getenv("SENSOR_NAME", socket.gethostname()), help="Sensor Name (e.g. AWS-VPC-SENSOR or FORTIGATE-PERIMETER)")
    parser.add_argument("--project-id", type=int, default=os.getenv("PROJECT_ID"), help="Project ID to associate events with")
    parser.add_argument("--eve-path", default=os.getenv("EVE_PATH", DEFAULT_EVE_PATH), help="Path to Suricata eve.json")
    parser.add_argument("--token", default=os.getenv("SOC_TOKEN", "sp-sensor-token"), help="SOC API Ingestion Token")
    parser.add_argument("--iface-map", default=os.getenv("IFACE_MAP", ""), help="Interface mapping, e.g. 'eth0:1:AWS-Firewall,eth1:2:FortiGate-Firewall'")
    return parser.parse_args()

def load_state(state_file):
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                data = json.load(f)
                return data.get("inode", 0), data.get("offset", 0)
        except Exception:
            pass
    return 0, 0

def save_state(state_file, inode, offset):
    try:
        with open(state_file, "w") as f:
            json.dump({"inode": inode, "offset": offset, "updated_at": time.time()}, f)
    except Exception:
        pass

def send_batch(soc_url, sensor_name, project_id, token, batch):
    if not batch:
        return True
    url = f"{soc_url.rstrip('/')}/api/nids/events"
    payload = {
        "sensor_name": sensor_name,
        "project_id": project_id,
        "events": batch
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Sensor-Name": sensor_name
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except Exception as e:
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Forwarder transmission error: {e}\n")
        return False

def main():
    args = parse_args()
    print(f"============================================================")
    print(f" BSmart SOC - Suricata EVE Network IDS Forwarder Started")
    print(f" Target SOC URL : {args.soc_url}")
    print(f" Sensor Name    : {args.sensor_name}")
    print(f" Project ID     : {args.project_id or 'Auto / Global'}")
    print(f" EVE JSON Path  : {args.eve_path}")
    print(f"============================================================")

    iface_lookup = {}
    if args.iface_map:
        for item in args.iface_map.split(","):
            parts = item.strip().split(":")
            if len(parts) >= 3:
                try:
                    iface_lookup[parts[0].strip()] = (int(parts[1].strip()), parts[2].strip())
                except ValueError:
                    pass
        print(f" Interface Map  : {iface_lookup}")

    saved_inode, file_offset = load_state(DEFAULT_STATE_PATH)
    batch = []
    last_flush = time.time()

    while True:
        if not os.path.exists(args.eve_path):
            time.sleep(1)
            continue

        try:
            st = os.stat(args.eve_path)
            curr_inode = getattr(st, 'st_ino', 0)

            # Check if file rotated (inode changed or truncated)
            if curr_inode != saved_inode or st.st_size < file_offset:
                file_offset = 0
                saved_inode = curr_inode

            with open(args.eve_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(file_offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("event_type") in ("alert", "drop"):
                            iface = record.get("in_iface")
                            if iface and iface in iface_lookup:
                                proj_id, sens_name = iface_lookup[iface]
                                record["project_id"] = proj_id
                                record["sensor_name"] = sens_name
                            batch.append(record)
                    except Exception:
                        continue

                file_offset = f.tell()
                save_state(DEFAULT_STATE_PATH, saved_inode, file_offset)

        except Exception as ex:
            sys.stderr.write(f"Read error: {ex}\n")

        # Flush batch when size threshold or interval is reached
        now = time.time()
        if batch and (len(batch) >= DEFAULT_BATCH_SIZE or (now - last_flush) >= DEFAULT_FLUSH_INTERVAL):
            if send_batch(args.soc_url, args.sensor_name, args.project_id, args.token, batch):
                batch.clear()
                last_flush = now
            else:
                # Retain in memory and retry after backoff
                time.sleep(2)

        time.sleep(0.5)

if __name__ == "__main__":
    main()
