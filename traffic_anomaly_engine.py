import math
import time
import logging
from datetime import datetime, timedelta, timezone
import statistics

logger = logging.getLogger("traffic_anomaly")
logger.setLevel(logging.INFO)

# In-memory tracking of consecutive windows and active anomaly state
# {server_id: {"consecutive_windows": int, "first_seen": float, "last_seen": float, "active_incident_id": int, "peak_bytes": int, "total_bytes": int}}
_ANOMALY_TRACKER = {}

def format_bytes(b: int) -> str:
    """Formats byte counts cleanly as B, KB, MB, GB, or TB."""
    if not b or b <= 0:
        return "0.00 MB"
    mb = b / (1024 * 1024)
    if mb < 1024:
        return f"{mb:.2f} MB"
    gb = mb / 1024
    if gb < 1024:
        return f"{gb:.2f} GB"
    return f"{gb/1024:.2f} TB"

def calculate_robust_baseline(values: list):
    """
    Computes robust statistical metrics:
    - Median
    - Median Absolute Deviation (MAD * 1.4826)
    """
    if not values:
        return {"median": 0.0, "mad": 0.0, "count": 0}
    
    med = float(statistics.median(values))
    if len(values) == 1:
        return {"median": med, "mad": 1.0, "count": 1}

    deviations = [abs(x - med) for x in values]
    mad_val = float(statistics.median(deviations)) * 1.4826
    # Avoid zero deviation to prevent division-by-zero or zero-width bands
    mad_val = max(mad_val, 1024.0 * 1024.0) # at least 1 MB deviation floor

    return {
        "median": med,
        "mad": mad_val,
        "count": len(values)
    }

def detect_traffic_anomaly(
    server_id: int,
    delta_tx: int,
    delta_rx: int,
    history_samples: list,
    active_conns: list = None,
    config: dict = None,
    current_time: datetime = None
):
    """
    Evaluates 30s outbound traffic against a 7-day robust baseline.
    Returns:
    {
        "is_anomaly": bool,
        "severity": "low" | "medium" | "high" | "critical" | None,
        "title": str,
        "message": str,
        "evidence": dict,
        "signals": list,
        "action": "create" | "update" | "ignore"
    }
    """
    if current_time is None:
        current_time = datetime.now(timezone.utc)

    # Configuration with defaults
    cfg = config or {}
    k = float(cfg.get("k_multiplier", 4.0))
    floor_bytes = int(cfg.get("floor_bytes", 50 * 1024 * 1024)) # 50 MB
    sustain_required = int(cfg.get("sustain_windows", 2))
    shadow_mode = bool(cfg.get("shadow_mode", False))

    current_hour = current_time.hour
    curr_tx = max(0, delta_tx)

    # 1. Split historical samples (excluding current window)
    tx_history_all = []
    tx_history_same_hour = {} # {date_str: [samples]}
    distinct_days = set()

    for s in history_samples:
        rec_time = s.get("recorded_at")
        val = s.get("delta_tx_bytes", 0)
        h = s.get("hour_of_day", 0)
        
        if isinstance(rec_time, datetime):
            d_str = rec_time.strftime("%Y-%m-%d")
        else:
            d_str = str(rec_time)[:10]

        distinct_days.add(d_str)
        tx_history_all.append(val)

        if h == current_hour:
            if d_str not in tx_history_same_hour:
                tx_history_same_hour[d_str] = []
            tx_history_same_hour[d_str].append(val)

    days_count = len(distinct_days)
    is_learning = days_count < 7

    # 2. Seasonality check (same-hour baseline if >= 5 of 7 days have data)
    same_hour_days = len(tx_history_same_hour)
    use_seasonality = same_hour_days >= 5

    if use_seasonality:
        # Flatten samples from same hour across days
        season_samples = [item for sublist in tx_history_same_hour.values() for item in sublist]
        baseline_stats = calculate_robust_baseline(season_samples)
        baseline_type = f"Same-Hour ({current_hour}:00 UTC over {same_hour_days} days)"
    else:
        baseline_stats = calculate_robust_baseline(tx_history_all)
        baseline_type = f"7-Day Overall ({days_count} days data)"

    med = baseline_stats["median"]
    dev = baseline_stats["mad"]
    threshold = med + (k * dev)

    # Overall 7-day stats for comparison in evidence
    overall_stats = calculate_robust_baseline(tx_history_all)

    # 3. Check trigger conditions
    is_above_threshold = curr_tx > threshold
    is_above_floor = curr_tx >= floor_bytes
    spike_detected = is_above_threshold and is_above_floor

    # Track consecutive windows
    tracker = _ANOMALY_TRACKER.get(server_id, {
        "consecutive_windows": 0,
        "first_seen": None,
        "last_seen": None,
        "active_incident_id": None,
        "peak_bytes": 0,
        "total_bytes": 0
    })

    now_ts = current_time.timestamp()

    # Reset tracker if quiet for > 10 minutes (600s)
    if tracker["last_seen"] and (now_ts - tracker["last_seen"] > 600):
        tracker = {
            "consecutive_windows": 0,
            "first_seen": None,
            "last_seen": None,
            "active_incident_id": None,
            "peak_bytes": 0,
            "total_bytes": 0
        }

    if not spike_detected:
        _ANOMALY_TRACKER[server_id] = tracker
        return {
            "is_anomaly": False,
            "shadow_mode": shadow_mode,
            "evidence": {
                "volume": curr_tx,
                "baseline_median": med,
                "baseline_deviation": dev,
                "threshold": threshold,
                "floor": floor_bytes,
                "days_count": days_count
            }
        }

    # Anomaly window detected
    tracker["consecutive_windows"] += 1
    tracker["last_seen"] = now_ts
    if not tracker["first_seen"]:
        tracker["first_seen"] = now_ts
    tracker["peak_bytes"] = max(tracker["peak_bytes"], curr_tx)
    tracker["total_bytes"] += curr_tx

    _ANOMALY_TRACKER[server_id] = tracker
    consec = tracker["consecutive_windows"]

    # 4. Determine Secondary Signals for HIGH / CRITICAL
    signals = []
    if active_conns:
        for c in active_conns:
            dest_ip = c.get("remote_ip") or c.get("ip", "")
            port = c.get("remote_port") or c.get("port", 0)
            pname = (c.get("process") or c.get("name") or "").lower()

            # External IP detection
            if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "127.")):
                signals.append(f"External Destination ({dest_ip}:{port})")

            # Unusual process
            if pname in ["nc", "ncat", "bash", "python", "perl", "ruby", "socat", "curl", "wget"]:
                signals.append(f"Suspicious Outbound Process ({pname})")

            # Non-standard outbound ports
            if port in [4444, 1337, 6667, 8888, 9999]:
                signals.append(f"High-Risk Outbound Port ({port})")

    # Off-hours transfer signal (22:00 to 06:00 UTC or weekend)
    is_weekend = current_time.weekday() >= 5
    is_night = current_hour >= 22 or current_hour < 6
    if is_night or is_weekend:
        signals.append("Off-Hours Activity Window")

    signals = list(dict.fromkeys(signals)) # deduplicate

    # 5. Severity Calculation per Rules
    # Rule 3: Learning period (until 7 days exist, max severity is LOW)
    # Rule 4: Single 30s window is at most LOW
    # Rule 5: HIGH/CRITICAL ONLY with independent second signal
    if is_learning:
        severity = "low"
        learning_note = f" (baseline building ({days_count} of 7 days))"
    elif consec < sustain_required:
        severity = "low"
        learning_note = f" (single window: {consec} of {sustain_required} required)"
    else:
        learning_note = ""
        if len(signals) >= 2:
            severity = "critical"
        elif len(signals) == 1:
            severity = "high"
        else:
            severity = "medium"

    ratio = curr_tx / max(med, 1.0)
    duration_secs = int(now_ts - tracker["first_seen"])
    duration_mins = max(1, duration_secs // 60)

    # 6. Message & Evidence construction
    msg = (
        f"Outbound {format_bytes(curr_tx)} / 30s vs 7-day baseline {format_bytes(int(overall_stats['median']))} "
        f"(median {format_bytes(int(med))}, deviation {format_bytes(int(dev))}), "
        f"same-hour baseline {format_bytes(int(baseline_stats['median']))}, {ratio:.1f}x{learning_note}."
    )

    evidence = {
        "baseline_period": f"{days_count} days historical window",
        "baseline_type": baseline_type,
        "method": "Robust Median + MAD (consistent normal scale 1.4826)",
        "measured_volume": curr_tx,
        "baseline_median": int(med),
        "deviation_mad": int(dev),
        "multiplier_k": k,
        "threshold": int(threshold),
        "floor_bytes": floor_bytes,
        "consecutive_windows": consec,
        "duration_minutes": duration_mins,
        "peak_volume": tracker["peak_bytes"],
        "total_volume": tracker["total_bytes"],
        "signals": signals if signals else ["No secondary signals detected (Threshold spike only)"]
    }

    action = "update" if consec > 1 and tracker.get("active_incident_id") else "create"

    return {
        "is_anomaly": True,
        "severity": severity,
        "title": "Network Outbound Traffic Anomaly",
        "message": msg,
        "signals": signals,
        "evidence": evidence,
        "action": action,
        "consecutive_windows": consec,
        "duration_seconds": duration_secs,
        "peak_bytes": tracker["peak_bytes"],
        "total_bytes": tracker["total_bytes"],
        "shadow_mode": shadow_mode
    }

def auto_close_quiet_incidents(db_conn, quiet_minutes: int = 10):
    """
    Closes open network spike incidents that have had no anomalous windows for > 10 minutes.
    """
    if not db_conn:
        return 0
    try:
        with db_conn.cursor() as cur:
            cur.execute("""
                UPDATE incidents
                SET status = 'closed',
                    updated_at = NOW(),
                    description = description || E'\n[AUTO-RESOLVED] Traffic volume normalized; no anomalous spikes detected for 10 consecutive quiet minutes.'
                WHERE title = 'Network Outbound Traffic Anomaly'
                  AND status = 'open'
                  AND updated_at < NOW() - INTERVAL '%s minutes';
            """, (quiet_minutes,))
            closed_count = cur.rowcount
        db_conn.commit()
        return closed_count
    except Exception as e:
        logger.error(f"Error auto-closing quiet traffic incidents: {e}")
        return 0
