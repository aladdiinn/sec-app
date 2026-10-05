import os
import json
import gzip
import logging
import collections
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

import database

load_dotenv()
logger = logging.getLogger("llm_analyzer")
logger.setLevel(logging.INFO)

# ── Configuration ────────────────────────────────────────────────────────────
S3_BUCKET_NAME = os.environ.get("S3_LOG_ARCHIVE_BUCKET", "securepulse-logs-archive-bucket-2026")
AWS_REGION     = os.environ.get("AWS_REGION", "us-east-1")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# ── Gemini Client (new google-genai SDK) ─────────────────────────────────────
_gemini_client = None
_discovered_models = []   # populated lazily on first call

# Preferred model keywords in priority order (flash first = cheaper + faster)
_MODEL_PREFERENCE = [
    "gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-pro",
    "gemini-2.0-pro",   "gemini-1.5-flash", "gemini-1.5-pro",
    "gemini-1.0-pro",   "gemini-pro",
]

def _get_client():
    global _gemini_client
    if _gemini_client is None and GEMINI_API_KEY:
        from google import genai
        # Stable v1 API — v1beta causes 404s on free-tier accounts
        _gemini_client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options={"api_version": "v1"}
        )
    return _gemini_client


def _generate(prompt: str) -> str:
    """Generate content directly using the cheapest/fastest model to save rate limits."""
    client = _get_client()
    if not client:
        raise RuntimeError("GEMINI_API_KEY is not set in .env")

    model_name = "gemini-1.5-flash"
    try:
        logger.info(f"Sending prompt to Gemini model: {model_name}")
        response = client.models.generate_content(model=model_name, contents=prompt)
        logger.info(f"Success with model: {model_name}")
        return response.text
    except Exception as e:
        logger.warning(f"Model {model_name} failed: {e}")
        raise RuntimeError(f"Gemini API request failed: {e}")


# ── S3 helpers ───────────────────────────────────────────────────────────────
def get_s3_client():
    return boto3.client("s3", region_name=AWS_REGION)


def fetch_logs_from_db(server_id: int, log_type: str, start_time: datetime, end_time: datetime):
    """Fetch raw log messages from PostgreSQL pushed_logs table."""
    conn = database.get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            if log_type:
                cur.execute("""
                    SELECT message, log_level, created_at FROM pushed_logs
                    WHERE server_id = %s AND log_type = %s
                      AND created_at >= %s AND created_at <= %s
                    ORDER BY created_at ASC
                    LIMIT 2000
                """, (server_id, log_type, start_time, end_time))
            else:
                cur.execute("""
                    SELECT message, log_level, created_at FROM pushed_logs
                    WHERE server_id = %s
                      AND created_at >= %s AND created_at <= %s
                    ORDER BY created_at ASC
                    LIMIT 2000
                """, (server_id, start_time, end_time))
            rows = cur.fetchall()
            logs = []
            for row in rows:
                if isinstance(row, dict):
                    msg, level, dt = row.get("message",""), row.get("log_level","INFO"), row.get("created_at")
                else:
                    msg, level, dt = row[0], row[1], row[2]
                logs.append({"msg": str(msg), "level": str(level or "INFO"), "time": str(dt)})
            return logs
    except Exception as e:
        logger.error(f"DB fetch error: {e}")
        return []
    finally:
        conn.close()


def fetch_logs_from_s3(server_id: int, server_ip: str, log_type: str,
                       start_time: datetime, end_time: datetime):
    """Fetch compressed logs from S3 for the given time range."""
    s3 = get_s3_client()
    logs = []
    safe_type = (log_type or "system").replace("/", "_").replace("\\", "_")
    current_date = start_time.date()

    while current_date <= end_time.date():
        y, m, d = current_date.year, f"{current_date.month:02d}", f"{current_date.day:02d}"
        prefix = f"{server_ip}/{y}/{m}/{d}/{safe_type}/"
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix):
                for obj in page.get("Contents", []):
                    try:
                        resp = s3.get_object(Bucket=S3_BUCKET_NAME, Key=obj["Key"])
                        data = json.loads(gzip.decompress(resp["Body"].read()).decode("utf-8"))
                        for entry in data:
                            try:
                                log_dt = datetime.strptime(str(entry.get("created_at",""))[:19], "%Y-%m-%d %H:%M:%S")
                                if start_time <= log_dt <= end_time:
                                    logs.append({
                                        "msg":   str(entry.get("message", "")),
                                        "level": str(entry.get("log_level", "INFO")),
                                        "time":  str(entry.get("created_at", ""))
                                    })
                            except Exception:
                                pass
                    except Exception as e:
                        logger.warning(f"S3 object read error {obj['Key']}: {e}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                break
            logger.error(f"S3 list error prefix={prefix}: {e}")
        current_date += timedelta(days=1)
    return logs


# ── Smart Summarizer ─────────────────────────────────────────────────────────
def _build_digest(logs: list, max_sample: int = 300) -> str:
    """
    Converts thousands of raw log lines into a compact structured digest.
    This is what we actually send to Gemini — NOT the raw logs.
    Sending 300 lines of smart summary is 30x faster and gives better analysis
    than dumping 10,000 raw lines.
    """
    total = len(logs)
    level_counts = collections.Counter(l["level"].upper() for l in logs)

    # Collect unique error/warning messages (deduped)
    error_msgs  = []
    seen_errors = set()
    warn_msgs   = []
    seen_warns  = set()
    for l in logs:
        lvl = l["level"].upper()
        msg = l["msg"][:200]  # truncate very long lines
        key = msg[:80]
        if lvl in ("ERROR", "CRITICAL", "FATAL", "CRIT", "SEVERE") and key not in seen_errors:
            seen_errors.add(key)
            error_msgs.append(f"  [{l['time'][:19]}] {msg}")
            if len(error_msgs) >= 60:
                break
        elif lvl in ("WARN", "WARNING") and key not in seen_warns:
            seen_warns.add(key)
            warn_msgs.append(f"  [{l['time'][:19]}] {msg}")
            if len(warn_msgs) >= 40:
                break

    # Evenly sampled INFO lines for context
    info_logs = [l for l in logs if l["level"].upper() not in
                 ("ERROR","CRITICAL","FATAL","CRIT","SEVERE","WARN","WARNING")]
    step = max(1, len(info_logs) // max(1, max_sample - len(error_msgs) - len(warn_msgs)))
    info_sample = [f"  [{l['time'][:19]}] {l['msg'][:200]}" for l in info_logs[::step]][:max_sample]

    time_range = f"{logs[0]['time'][:19]} → {logs[-1]['time'][:19]}" if logs else "N/A"

    digest = f"""=== LOG DIGEST ===
Total lines analysed : {total}
Time range           : {time_range}

Level breakdown:
{chr(10).join(f'  {k}: {v}' for k, v in level_counts.most_common())}

=== ERRORS & CRITICALS ({len(error_msgs)} unique) ===
{chr(10).join(error_msgs) if error_msgs else '  None found'}

=== WARNINGS ({len(warn_msgs)} unique) ===
{chr(10).join(warn_msgs) if warn_msgs else '  None found'}

=== SAMPLED INFO LINES (representative {len(info_sample)} of {len(info_logs)}) ===
{chr(10).join(info_sample) if info_sample else '  None'}
"""
    return digest


# ── Main entry point ─────────────────────────────────────────────────────────
def analyze_logs(server_id: int, server_ip: str, log_type: str, time_period_str: str):
    """Gather logs (DB + S3), build smart digest, send to Gemini, return HTML analysis."""

    # Check API key first — fail fast with a clear message
    if not GEMINI_API_KEY:
        return {"error": "GEMINI_API_KEY is missing from your .env file. Add it and restart the app."}

    now = datetime.now()
    period_map = {
        "1hr": timedelta(hours=1),   "3hr": timedelta(hours=3),
        "10hr": timedelta(hours=10), "1day": timedelta(days=1),
        "3day": timedelta(days=3),   "1week": timedelta(days=7),
        "15days": timedelta(days=15),"1month": timedelta(days=30),
    }
    start_time = now - period_map.get(time_period_str, timedelta(hours=1))
    db_cutoff  = now - timedelta(hours=1)

    # Fetch from DB (hot tier) and S3 (cold tier) as needed
    all_logs = []
    if start_time < db_cutoff:
        all_logs.extend(fetch_logs_from_s3(server_id, server_ip, log_type, start_time, db_cutoff))
    all_logs.extend(fetch_logs_from_db(server_id, log_type, max(start_time, db_cutoff), now))

    if not all_logs:
        return {"analysis": "<div style='color:#8b949e;padding:20px'>No logs found for the selected time period and server.</div>",
                "count": 0, "start": str(start_time), "end": str(now)}

    # Build a smart digest — DO NOT send raw logs to Gemini
    digest = _build_digest(all_logs)

    prompt = f"""You are an expert Security Analyst and DevOps Engineer reviewing a server log digest.
The digest below is a pre-processed summary of {len(all_logs)} log lines — NOT raw logs.
Analyse it for security threats, errors, anomalies, and performance issues.
Be specific: reference actual error messages and timestamps you see.
Be concise: maximum 8 bullet points per section.

Output STRICT HTML (no markdown, no backticks):

<div style="color: #c9d1d9; font-family: sans-serif; font-size: 13px; line-height: 1.7;">
    <h4 style="color: #58a6ff; margin-bottom: 5px; margin-top: 0;">🔍 Key Observations</h4>
    <ul style="margin-top: 5px; padding-left: 20px;">
        <li>...</li>
    </ul>

    <h4 style="color: #ff7b72; margin-bottom: 5px; margin-top: 15px;">⚠️ Security & Risk Findings</h4>
    <p style="margin-top: 5px;">...</p>

    <h4 style="color: #d2a8ff; margin-bottom: 5px; margin-top: 15px;">🔥 Critical Log Snippets (Evidence)</h4>
    <div style="background: rgba(0,0,0,0.3); padding: 8px; border-left: 3px solid #d2a8ff; font-family: monospace; font-size: 11px; margin-top: 5px;">
        Quote the 1 to 3 most critical exact log lines here, including timestamps. If none, say "No critical errors found."
    </div>

    <h4 style="color: #3fb950; margin-bottom: 5px; margin-top: 15px;">✅ Recommendations</h4>
    <ul style="margin-top: 5px; padding-left: 20px;">
        <li>...</li>
    </ul>
</div>

LOG DIGEST:
{digest}
"""

    try:
        raw_text = _generate(prompt)
        html_content = raw_text.replace("```html", "").replace("```", "").strip()
        return {
            "analysis": html_content,
            "count": len(all_logs),
            "start": str(start_time)[:19],
            "end": str(now)[:19]
        }
    except Exception as e:
        logger.error(f"Gemini analysis failed: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}
