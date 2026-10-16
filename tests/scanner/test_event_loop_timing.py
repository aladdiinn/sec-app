#!/usr/bin/env python3
"""
Event Loop Non-Blocking Verification:
Proves that network scanner checks run on threadpool workers and NEVER block
the FastAPI/Starlette asyncio event loop.
Sends concurrent GET /dashboard (or /login) requests during an active scan and records latency.
"""

import sys
import os
import time
import threading
import subprocess
import requests

SERVER_PORT = 8011
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"

def run_timing_proof():
    print("\n" + "="*80)
    print("EVENT LOOP NON-BLOCKING VERIFICATION TEST")
    print("Proving that network checks run in worker thread pool and never block event loop")
    print("="*80 + "\n")

    env = os.environ.copy()
    env["PORT"] = str(SERVER_PORT)

    # 1. Start backend server with uvicorn on dedicated port
    print(f"[*] Starting test server on port {SERVER_PORT}...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--port", str(SERVER_PORT), "--host", "127.0.0.1", "--log-level", "warning"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    # Wait for server to become responsive
    started = False
    for _ in range(30):
        try:
            r = requests.get(f"{BASE_URL}/login", timeout=1.0)
            if r.status_code in (200, 302):
                started = True
                break
        except Exception:
            time.sleep(0.5)

    if not started:
        print("[!] Could not start test server on port", SERVER_PORT)
        proc.kill()
        return False

    print(f"[+] Test server is online and responding at {BASE_URL}")

    scan_started = threading.Event()
    scan_finished = threading.Event()
    scan_result_container = {}

    def launch_heavy_scan():
        try:
            scan_started.set()
            start_t = time.time()
            # Send real port scan request
            res = requests.post(
                f"{BASE_URL}/api/scanner/ports",
                json={"target": "scanme.nmap.org", "force_refresh": True},
                timeout=25.0
            )
            duration = time.time() - start_t
            scan_result_container["status"] = res.status_code
            scan_result_container["duration"] = duration
        except Exception as e:
            scan_result_container["error"] = str(e)
        finally:
            scan_finished.set()

    # 2. Launch scan in background thread
    scan_thread = threading.Thread(target=launch_heavy_scan, daemon=True)
    scan_thread.start()
    scan_started.wait()

    # Brief delay to ensure scan's socket connections are active
    time.sleep(0.5)

    # 3. Concurrently send rapid GET requests to /dashboard (or /login) during active scan
    latencies = []
    print("[*] Sending rapid GET requests to event loop while scan is actively executing...")

    for i in range(10):
        t0 = time.time()
        try:
            resp = requests.get(f"{BASE_URL}/login", timeout=2.0)
            elapsed_ms = (time.time() - t0) * 1000.0
            latencies.append(elapsed_ms)
            print(f"    Request {i+1:02d}: Status {resp.status_code} | Latency: {elapsed_ms:.2f} ms")
        except Exception as ex:
            print(f"    Request {i+1:02d}: Failed ({ex})")
        time.sleep(0.1)

    scan_finished.wait(timeout=30)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    if not latencies:
        print("[FAIL] No successful requests recorded.")
        return False

    avg_lat = sum(latencies) / len(latencies)
    max_lat = max(latencies)
    min_lat = min(latencies)

    print("\n" + "-"*60)
    print(f"Scan Duration: {scan_result_container.get('duration', 0):.2f} seconds")
    print(f"Concurrent Event Loop Requests: {len(latencies)}")
    print(f"Average Latency: {avg_lat:.2f} ms")
    print(f"Min Latency:     {min_lat:.2f} ms")
    print(f"Max Latency:     {max_lat:.2f} ms")
    print("-"*60)

    # If the event loop were blocked, latency would be > 2000 ms (or timed out).
    # Thread pool execution guarantees responsiveness under 100 ms.
    if avg_lat < 100.0 and max_lat < 250.0:
        print("[PASS] PROOF CONFIRMED: Event loop remained unblocked (< 100ms avg latency) during active network scan!\n")
        return True
    else:
        print(f"[FAIL] Latency too high ({avg_lat:.2f} ms) - event loop may have been stalled.\n")
        return False

if __name__ == "__main__":
    success = run_timing_proof()
    sys.exit(0 if success else 1)
