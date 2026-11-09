import os
import time
import json
import gzip
import logging
import threading
import re
from datetime import datetime, timedelta, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("s3_archiver")
logger.setLevel(logging.INFO)

# Default to a specific bucket name. You can override this via ENV variables.
S3_BUCKET_NAME = os.environ.get("AWS_S3_BUCKET_NAME") or os.environ.get("S3_BUCKET_NAME") or os.environ.get("S3_LOG_ARCHIVE_BUCKET") or "bsmart-sentinel"
AWS_REGION = os.environ.get("AWS_S3_REGION") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")

# Direct in-memory streaming buffer for routine logs (2xx/3xx access & repetitive warnings)
_s3_stream_buffer = []
_s3_stream_lock = threading.Lock()
_s3_flusher_thread_started = False

# Regex for Apache / Tomcat / Nginx access log lines
TOMCAT_ACCESS_RE = re.compile(
    r'^(?P<ip>[^ ]+)\s+(?P<ident>[^ ]+)\s+(?P<user>[^ ]+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>.+?)\s+HTTP/[0-9\.]+"\s+(?P<status>\d+)\s+(?P<bytes>[^ ]+)(?:\s+.*)?$'
)
GENERIC_ACCESS_RE = re.compile(
    r'"[A-Z]+\s+(?P<path>.+?)\s+HTTP/[0-9\.]+"\s+(?P<status>\d{3})\b'
)

import urllib.parse

def is_routine_access_log(message: str):
    """
    Returns (is_routine, status_code, path).
    True if line is a standard 2xx/3xx HTTP access log line without security attack payloads.
    """
    msg_str = str(message or "").strip()
    if not msg_str:
        return False, 0, ""

    m = TOMCAT_ACCESS_RE.match(msg_str)
    if m:
        try:
            status = int(m.group("status"))
            path = m.group("path")
            if 200 <= status < 400:
                p_unquoted = urllib.parse.unquote_plus(path).lower()
                p_raw = path.lower()
                # If it contains active attack payloads, do NOT treat as routine
                attack_tokens = (
                    "union select", "' or '", "script>", "<script", "../", "..\\",
                    "/etc/passwd", "cmd.exe", "exec(", "benchmark(", "sleep(",
                    "xp_cmdshell", "drop table", "information_schema"
                )
                if not any(atk in p_unquoted or atk in p_raw for atk in attack_tokens):
                    return True, status, path
        except Exception:
            pass

    m2 = GENERIC_ACCESS_RE.search(msg_str)
    if m2:
        try:
            status = int(m2.group("status"))
            path = m2.group("path")
            if 200 <= status < 400:
                p_unquoted = urllib.parse.unquote_plus(path).lower()
                p_raw = path.lower()
                attack_tokens = (
                    "union select", "' or '", "script>", "<script", "../", "..\\",
                    "/etc/passwd", "cmd.exe", "exec(", "benchmark(", "sleep(",
                    "xp_cmdshell", "drop table", "information_schema"
                )
                if not any(atk in p_unquoted or atk in p_raw for atk in attack_tokens):
                    return True, status, path
        except Exception:
            pass

    return False, 0, ""

def is_repetitive_app_warning(message: str, source: str = "", log_type: str = "") -> bool:
    """
    Returns True if log line is a repetitive application warning or generic exception
    WITHOUT a user or IP attribution (i.e. background framework/app noise).
    These are filtered out of PostgreSQL and streamed directly to S3.
    """
    msg_str = str(message or "").strip()
    if not msg_str:
        return False

    msg_low = msg_str.lower()
    src_low = (source or "").lower()
    lt_low = (log_type or "").lower()

    # Is it from an application or tomcat/catalina source?
    is_app_src = any(k in src_low for k in ["tomcat", "catalina", "app", "nohup", "stdout", "stderr"]) or lt_low in ("tomcat", "catalina", "app")

    # Is it a warning, info log, or generic exception?
    has_warn_or_exc = any(k in msg_low for k in [
        "warn", "warning", "exception", "severe", "app_warn", "app_exception"
    ])

    if not (is_app_src or has_warn_or_exc):
        return False

    # Security exception checks - must NOT be filtered if it's an attack, auth violation, or SQL injection
    if any(k in msg_low for k in [
        "auth_failure", "authentication failed", "invalid password", "bad credentials",
        "login failed", "privilege_violation", "restricted admin access", "sqlexception",
        "syntax error at or near", "sql injection", "unauthorized", "brute force", "attack"
    ]):
        return False

    # Check for presence of an authenticated user
    m_user = re.search(r'(?:user|username|user_id|login_id|usr):\s*[\'"]?([^\s\'",]+)[\'"]?', msg_str, re.IGNORECASE)
    if m_user and m_user.group(1).strip() not in ("-", "null", "none", "unknown"):
        return False  # Has user, keep in DB

    # Check for presence of a real remote client IP
    m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg_str)
    if m_ip:
        ip_val = m_ip.group(0)
        if not ip_val.startswith("127.") and ip_val != "0.0.0.0":
            return False  # Has remote IP, keep in DB

    return True

def get_s3_client():
    """Initializes the boto3 S3 client supporting both AWS_S3_* and standard AWS_* env variables."""
    key_id = os.environ.get("AWS_S3_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_S3_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_S3_REGION") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    if key_id and secret_key:
        return boto3.client('s3', region_name=region, aws_access_key_id=key_id, aws_secret_access_key=secret_key)
    return boto3.client('s3', region_name=region)

def ensure_bucket_exists(s3_client):
    """Verifies access to the S3 bucket; gracefully proceeds if bucket already exists."""
    try:
        s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
        logger.debug(f"Bucket {S3_BUCKET_NAME} accessible.")
    except ClientError as e:
        error_code = str(e.response.get('Error', {}).get('Code', ''))
        if error_code in ('404', 'NoSuchBucket'):
            logger.info(f"Bucket {S3_BUCKET_NAME} does not exist. Creating it now...")
            try:
                if AWS_REGION == "us-east-1":
                    s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
                else:
                    s3_client.create_bucket(
                        Bucket=S3_BUCKET_NAME,
                        CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
                    )
                logger.info(f"Successfully created bucket {S3_BUCKET_NAME}")
            except Exception as create_e:
                logger.warning(f"Bucket creation note (proceeding): {create_e}")
        else:
            logger.debug(f"Bucket check note for {S3_BUCKET_NAME} (proceeding): {e}")

def enqueue_direct_log_to_s3(server_id=None, application_id=None, log_type="system", source="unknown", message="", server_ip=None, hostname=None):
    """
    Buffers routine logs (2xx/3xx access, repetitive warnings) in-memory to stream DIRECTLY to S3,
    completely bypassing PostgreSQL tables to prevent database disk exhaustion.
    Note: S3 is strictly used for log streams (under /logs/ prefixes).
    """
    global _s3_stream_buffer, _s3_flusher_thread_started
    if not message:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    entry = {
        "server_id": server_id,
        "application_id": application_id,
        "log_type": log_type or "system",
        "source": source or "unknown",
        "message": message,
        "created_at": now_iso,
        "server_ip": server_ip,
        "hostname": hostname
    }

    should_flush_now = False
    with _s3_stream_lock:
        _s3_stream_buffer.append(entry)
        if len(_s3_stream_buffer) >= 1000:
            should_flush_now = True

    if not _s3_flusher_thread_started:
        _start_flusher_thread()

    if should_flush_now:
        # Trigger background flush if buffer exceeds 1000 lines
        threading.Thread(target=flush_direct_s3_stream, daemon=True).start()

def _start_flusher_thread():
    global _s3_flusher_thread_started
    with _s3_stream_lock:
        if _s3_flusher_thread_started:
            return
        _s3_flusher_thread_started = True

    def _loop():
        while True:
            time.sleep(20)  # Flush every 20 seconds
            try:
                flush_direct_s3_stream()
            except Exception as e:
                logger.debug(f"[S3-DIRECT-STREAM] Flusher loop note: {e}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

_SERVER_META_CACHE = {}
_APP_META_CACHE = {}

def get_server_meta(server_id):
    """Fetches and caches (machine_id, server_ip) for a given server_id."""
    if not server_id:
        return None, None
    if server_id in _SERVER_META_CACHE:
        return _SERVER_META_CACHE[server_id]
    try:
        import database as db
        conn = db.get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT ip, machine_id, name, hostname FROM servers WHERE id = %s", (server_id,))
                    row = cur.fetchone()
                    if row:
                        ip = row.get("ip") if isinstance(row, dict) else row[0]
                        name = row.get("name") or row.get("hostname") or row.get("machine_id") if isinstance(row, dict) else (row[2] or row[1] or row[3] if len(row) > 3 else row[1])
                        s_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(name or f"server-{server_id}"))
                        _SERVER_META_CACHE[server_id] = (s_name, ip or f"server-{server_id}")
                        return _SERVER_META_CACHE[server_id]
            finally:
                conn.close()
    except Exception:
        pass
    return None, None

def get_app_meta(application_id):
    """Fetches and caches (app_name, app_key) for a given application_id."""
    if not application_id:
        return None, None
    if application_id in _APP_META_CACHE:
        return _APP_META_CACHE[application_id]
    try:
        import database as db
        conn = db.get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT name FROM applications WHERE id = %s", (application_id,))
                    row = cur.fetchone()
                    if row:
                        name = row.get("name") if isinstance(row, dict) else row[0]
                        a_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(name or f"app-{application_id}"))
                        _APP_META_CACHE[application_id] = (a_name, f"app-{application_id}")
                        return _APP_META_CACHE[application_id]
            finally:
                conn.close()
    except Exception:
        pass
    return None, None

def flush_direct_s3_stream():
    """
    Drains the in-memory log buffer, groups logs by server/app and stream,
    compresses into .jsonl.gz, and puts directly into S3. Zero SQL database writes!
    Note: S3 is strictly used for log streams under /{machine_id}/{server_ip}/logs/...
    """
    global _s3_stream_buffer
    with _s3_stream_lock:
        if not _s3_stream_buffer:
            return
        batch = _s3_stream_buffer
        _s3_stream_buffer = []

    s3_client = get_s3_client()
    try:
        ensure_bucket_exists(s3_client)
    except Exception:
        pass

    # Group by (server_id, application_id, log_type, source)
    groups = {}
    for item in batch:
        key = (item["server_id"], item["application_id"], item["log_type"], item["source"])
        if key not in groups:
            groups[key] = {
                "server_id": item.get("server_id"),
                "application_id": item.get("application_id"),
                "server_ip": item.get("server_ip"),
                "hostname": item.get("hostname"),
                "logs": []
            }
        groups[key]["logs"].append(item)

    now = datetime.now()
    year = str(now.year)
    month = f"{now.month:02d}"
    day = f"{now.day:02d}"
    hour = f"{now.hour:02d}"
    timestamp_str = now.strftime("%H_%M_%S")

    total_uploaded = 0

    for (sid, app_id, l_type, src), grp in groups.items():
        logs_list = grp["logs"]
        if not logs_list:
            continue

        safe_log_type = (l_type or "system").replace("/", "_").replace("\\", "_")
        file_id = (src or "unknown").strip().replace("/", "_").replace("\\", "_")
        if file_id.startswith("_"):
            file_id = file_id[1:]

        # Derive S3 prefix: S3 is strictly for logs
        srv_ip = grp.get("server_ip")
        machine_id = grp.get("hostname")

        if not srv_ip or not machine_id:
            if sid:
                cached_mid, cached_ip = get_server_meta(sid)
                machine_id = machine_id or cached_mid or f"server-{sid}"
                srv_ip = srv_ip or cached_ip or f"server-{sid}"
            elif app_id:
                cached_app, cached_ip = get_app_meta(app_id)
                machine_id = machine_id or cached_app or f"app-{app_id}"
                srv_ip = srv_ip or cached_ip or f"app-{app_id}"
            else:
                machine_id = machine_id or "unknown-host"
                srv_ip = srv_ip or "unknown-ip"

        machine_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(machine_id))
        srv_ip = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(srv_ip))

        # S3 Key Format: {machine_id}/{server_ip}/logs/{safe_log_type}/{file_id}/{yyyy}/{mm}/{dd}/{hh}/{timestamp_str}.jsonl.gz
        s3_key = f"{machine_id}/{srv_ip}/logs/{safe_log_type}/{file_id}/{year}/{month}/{day}/{hour}/{timestamp_str}_{len(logs_list)}.jsonl.gz"

        try:
            json_data = json.dumps(logs_list, default=str)
            compressed_data = gzip.compress(json_data.encode('utf-8'))

            s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_key,
                Body=compressed_data,
                ContentType='application/x-gzip'
            )
            total_uploaded += len(logs_list)
        except Exception as up_err:
            logger.debug(f"[S3-DIRECT-STREAM] PutObject note for {s3_key}: {up_err}")

    if total_uploaded > 0:
        logger.info(f"[S3-DIRECT-STREAM] Streamed {total_uploaded} routine logs directly to S3 (0 bytes written to PostgreSQL).")

def archive_logs_to_s3(db_conn):
    """
    Finds all logs in the eviction queue, batches them by server_id and source (file_id),
    uploads them to S3, and then deletes them from the queue.
    """
    s3_client = get_s3_client()
    try:
        ensure_bucket_exists(s3_client)
    except Exception:
        logger.error("Could not ensure S3 bucket exists. Aborting archival.")
        return

    logger.info("Starting S3 log archival from eviction queue.")

    try:
        with db_conn.cursor() as cur:
            # 1. Group eviction logs by server_id, log_type, and source
            cur.execute("""
                SELECT server_id, log_type, source, DATE(created_at) as log_date, COUNT(*) as count 
                FROM logs_eviction_queue 
                GROUP BY server_id, log_type, source, DATE(created_at)
            """)
            
            batches = cur.fetchall()
            
            if not batches:
                logger.info("No logs in eviction queue to archive.")
                return

            for batch in batches:
                server_id = batch["server_id"] if isinstance(batch, dict) else batch[0]
                log_type = batch["log_type"] if isinstance(batch, dict) else batch[1]
                source = batch["source"] if isinstance(batch, dict) else batch[2]
                log_date = batch["log_date"] if isinstance(batch, dict) else batch[3]
                
                safe_log_type = (log_type or "system").replace("/", "_").replace("\\", "_")
                
                # Sanitize source path to act as file_id in S3 key (replace slashes with underscores)
                file_id = (source or "unknown_file").strip().replace("/", "_").replace("\\", "_")
                if file_id.startswith("_"):
                    file_id = file_id[1:]
                
                cur.execute("SELECT ip, machine_id, name, hostname FROM servers WHERE id = %s", (server_id,))
                server_row = cur.fetchone()
                if server_row and isinstance(server_row, dict):
                    server_ip = server_row.get("ip") or f"unknown-ip-{server_id}"
                    raw_name = server_row.get("name") or server_row.get("hostname") or server_row.get("machine_id") or f"server-{server_id}"
                    machine_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(raw_name))
                elif server_row:
                    server_ip = server_row[0] or f"unknown-ip-{server_id}"
                    raw_name = server_row[2] if len(server_row) > 2 and server_row[2] else server_row[1] if server_row[1] else f"server-{server_id}"
                    machine_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(raw_name))
                else:
                    server_ip = f"unknown-ip-{server_id}"
                    machine_id = f"server-{server_id}"

                # 2. Fetch the actual logs for this specific batch
                cur.execute("""
                    SELECT id, log_type, source, message, created_at 
                    FROM logs_eviction_queue 
                    WHERE server_id = %s AND DATE(created_at) = %s AND (log_type = %s OR (log_type IS NULL AND %s IS NULL)) AND (source = %s OR (source IS NULL AND %s IS NULL))
                """, (server_id, log_date, log_type, log_type, source, source))
                logs = cur.fetchall()
                
                if not logs:
                    continue

                log_dicts = []
                log_ids_to_delete = []
                for row in logs:
                    if isinstance(row, dict):
                        log_dicts.append(dict(row))
                        log_ids_to_delete.append(row["id"])
                    else:
                        log_dicts.append({
                            "id": row[0], "log_type": row[1], "source": row[2], 
                            "message": row[3], "created_at": str(row[4])
                        })
                        log_ids_to_delete.append(row[0])

                json_data = json.dumps(log_dicts, default=str)
                compressed_data = gzip.compress(json_data.encode('utf-8'))

                dt_obj = log_date if isinstance(log_date, datetime) else datetime.strptime(str(log_date), "%Y-%m-%d")
                year, month, day = str(dt_obj.year), f"{dt_obj.month:02d}", f"{dt_obj.day:02d}"
                now = datetime.now()
                hour = f"{now.hour:02d}"
                timestamp_str = now.strftime("%H_%M_%S")
                
                # S3 Key: strictly for logs
                s3_key = f"{machine_id}/{server_ip}/logs/{safe_log_type}/{file_id}/{year}/{month}/{day}/{hour}/{timestamp_str}.jsonl.gz"

                # 5. Upload to S3
                logger.info(f"Uploading {len(log_dicts)} evicted logs to s3://{S3_BUCKET_NAME}/{s3_key}")
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=compressed_data,
                    ContentType='application/x-gzip'
                )

                # 6. Delete the uploaded logs from the local eviction queue
                chunk_size = 1000
                for i in range(0, len(log_ids_to_delete), chunk_size):
                    chunk = log_ids_to_delete[i:i + chunk_size]
                    cur.execute("DELETE FROM logs_eviction_queue WHERE id = ANY(%s)", (chunk,))
                
                db_conn.commit()
                logger.info(f"Successfully archived and deleted {len(log_dicts)} evicted logs for file {file_id}.")

            # If eviction queue is now completely drained, TRUNCATE to reclaim 100% of table disk space
            try:
                cur.execute("SELECT COUNT(*) FROM logs_eviction_queue;")
                cnt_row = cur.fetchone()
                rem = cnt_row["count"] if isinstance(cnt_row, dict) else cnt_row[0] if cnt_row else 0
                if rem == 0:
                    cur.execute("TRUNCATE TABLE logs_eviction_queue;")
                    db_conn.commit()
                    logger.info("[S3-ARCHIVER] Queue fully drained. Truncated logs_eviction_queue to 0 bytes.")
            except Exception as tr_e:
                logger.debug(f"Queue truncate note: {tr_e}")

    except Exception as e:
        logger.error(f"Error during S3 archival: {e}")
        db_conn.rollback()

def purge_older_s3_logs(retention_days=90):
    """
    Automatically deletes S3 archived logs older than retention_days (default 90 days / 3 months).
    Runs using standard s3:DeleteObject / s3:ListBucket permissions without requiring s3:PutLifecycleConfiguration.
    """
    s3_client = get_s3_client()
    cutoff_time = datetime.now(timezone.utc) - timedelta(days=retention_days)
    logger.info(f"[S3-RETENTION] Checking for logs older than {retention_days} days in s3://{S3_BUCKET_NAME}/...")
    
    deleted_count = 0
    paginator = s3_client.get_paginator('list_objects_v2')
    
    try:
        for page in paginator.paginate(Bucket=S3_BUCKET_NAME):
            contents = page.get('Contents', [])
            keys_to_delete = []
            for obj in contents:
                k = obj.get('Key', '')
                # Ensure we strictly target log archives under /logs/ or *.gz, never non-log data
                if '/logs/' not in k and not k.endswith('.jsonl.gz') and not k.endswith('.log.gz'):
                    continue
                last_mod = obj.get('LastModified')
                if last_mod:
                    # Ensure timezone awareness
                    if last_mod.tzinfo is None:
                        last_mod = last_mod.replace(tzinfo=timezone.utc)
                    if last_mod < cutoff_time:
                        keys_to_delete.append({'Key': k})
                    
            if keys_to_delete:
                for i in range(0, len(keys_to_delete), 1000):
                    batch = keys_to_delete[i:i + 1000]
                    s3_client.delete_objects(
                        Bucket=S3_BUCKET_NAME,
                        Delete={'Objects': batch, 'Quiet': True}
                    )
                    deleted_count += len(batch)
        if deleted_count > 0:
            logger.info(f"[S3-RETENTION] Cleaned up {deleted_count} older log object(s) from s3://{S3_BUCKET_NAME}/.")
        else:
            logger.info(f"[S3-RETENTION] Bucket clean. Zero objects older than {retention_days} days found.")
    except Exception as e:
        logger.warning(f"[S3-RETENTION] S3 retention check note: {e}")
    return deleted_count

if __name__ == "__main__":
    # Test script standalone
    import database
    logging.basicConfig(level=logging.INFO)
    conn = database.get_db_connection()
    if conn:
        archive_logs_to_s3(conn)
        conn.close()
