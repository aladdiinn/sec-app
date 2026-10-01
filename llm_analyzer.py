import os
import json
import gzip
import logging
import google.generativeai as genai
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError
import database

logger = logging.getLogger("llm_analyzer")
logger.setLevel(logging.INFO)

from dotenv import load_dotenv
load_dotenv()

# Configuration
S3_BUCKET_NAME = os.environ.get("S3_LOG_ARCHIVE_BUCKET", "securepulse-logs-archive-bucket-2026")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Initialize Gemini
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    llm_model = genai.GenerativeModel('gemini-1.5-flash-latest')
else:
    llm_model = None

def get_s3_client():
    return boto3.client('s3', region_name=AWS_REGION)

def fetch_logs_from_db(server_id: int, log_type: str, start_time: datetime, end_time: datetime):
    """Fetches logs directly from PostgreSQL."""
    conn = database.get_db_connection()
    if not conn:
        return []
    
    try:
        with conn.cursor() as cur:
            if log_type:
                cur.execute("""
                    SELECT message, created_at FROM pushed_logs 
                    WHERE server_id = %s AND log_type = %s AND created_at >= %s AND created_at <= %s
                    ORDER BY created_at ASC
                """, (server_id, log_type, start_time, end_time))
            else:
                cur.execute("""
                    SELECT message, created_at FROM pushed_logs 
                    WHERE server_id = %s AND created_at >= %s AND created_at <= %s
                    ORDER BY created_at ASC
                """, (server_id, start_time, end_time))
            
            rows = cur.fetchall()
            logs = []
            for row in rows:
                msg = row["message"] if isinstance(row, dict) else row[0]
                dt = row["created_at"] if isinstance(row, dict) else row[1]
                logs.append(f"[{dt}] {msg}")
            return logs
    except Exception as e:
        logger.error(f"Error fetching logs from DB: {e}")
        return []
    finally:
        conn.close()

def fetch_logs_from_s3(server_id: int, server_ip: str, log_type: str, start_time: datetime, end_time: datetime):
    """Fetches compressed logs from S3 for the given time range. Limits to last 5 files to stay fast."""
    s3_client = get_s3_client()
    logs = []
    all_keys = []
    
    # Generate list of days we need to query
    current_date = start_time.date()
    end_date = end_time.date()
    
    safe_log_type = (log_type or "system").replace("/", "_").replace("\\", "_")

    while current_date <= end_date:
        year, month, day = str(current_date.year), f"{current_date.month:02d}", f"{current_date.day:02d}"
        prefix = f"{server_ip}/{year}/{month}/{day}/{safe_log_type}/"
        
        try:
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix)
            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        all_keys.append(obj['Key'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                logger.warning(f"S3 Bucket {S3_BUCKET_NAME} does not exist yet.")
                break
            else:
                logger.error(f"S3 Error listing prefix {prefix}: {e}")
        
        current_date += timedelta(days=1)
    
    # Only fetch the 5 most recent files to avoid multi-file serial download lag
    for key in sorted(all_keys)[-5:]:
        try:
            response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=key)
            compressed_data = response['Body'].read()
            json_data = gzip.decompress(compressed_data).decode('utf-8')
            file_logs = json.loads(json_data)
            for log_entry in file_logs:
                try:
                    log_dt_str = log_entry['created_at'].split("+")[0].split(".")[0]
                    log_dt = datetime.strptime(log_dt_str, "%Y-%m-%d %H:%M:%S")
                    if start_time.replace(tzinfo=None) <= log_dt <= end_time.replace(tzinfo=None):
                        logs.append(f"[{log_entry['created_at']}] {log_entry['message']}")
                except Exception:
                    logs.append(f"[unknown] {log_entry.get('message', '')}")
        except Exception as e:
            logger.error(f"S3 Error fetching file {key}: {e}")
        
    return logs

def analyze_logs(server_id: int, server_ip: str, log_type: str, time_period_str: str):
    """Main function to gather logs (DB + S3) and send to Gemini."""
    if not llm_model:
        return {"error": "Gemini API key is missing. Please add GEMINI_API_KEY to your .env file."}
        
    now = datetime.now()
    
    # Calculate timeframe
    if time_period_str == "1hr":
        start_time = now - timedelta(hours=1)
    elif time_period_str == "3hr":
        start_time = now - timedelta(hours=3)
    elif time_period_str == "10hr":
        start_time = now - timedelta(hours=10)
    elif time_period_str == "1day":
        start_time = now - timedelta(days=1)
    elif time_period_str == "3day":
        start_time = now - timedelta(days=3)
    elif time_period_str == "1week":
        start_time = now - timedelta(days=7)
    elif time_period_str == "15days":
        start_time = now - timedelta(days=15)
    elif time_period_str == "1month":
        start_time = now - timedelta(days=30)
    else:
        start_time = now - timedelta(hours=1)
        
    # The archiver leaves the last 1 hour in the DB.
    # So if the start_time is older than 1 hour ago, we need to fetch from S3 as well.
    db_cutoff = now - timedelta(hours=1)
    
    all_logs = []
    
    if start_time < db_cutoff:
        # Fetch older part from S3
        s3_logs = fetch_logs_from_s3(server_id, server_ip, log_type, start_time, db_cutoff)
        all_logs.extend(s3_logs)
        # Fetch the newest hour from DB
        db_logs = fetch_logs_from_db(server_id, log_type, db_cutoff, now)
        all_logs.extend(db_logs)
    else:
        # Entire timeframe is within the last hour, just use DB
        all_logs = fetch_logs_from_db(server_id, log_type, start_time, now)
        
    if not all_logs:
        return {"analysis": "No logs found for the selected time period.", "risk_level": "none", "count": 0}
    
    total_count = len(all_logs)
    
    # Sample evenly across the window — Gemini quality doesn't improve past 500 lines.
    # Sending 10k lines takes 30s+; 500 sampled lines takes 3-5s with same insight.
    MAX_LINES = 500
    if len(all_logs) > MAX_LINES:
        step = len(all_logs) / MAX_LINES
        all_logs = [all_logs[int(i * step)] for i in range(MAX_LINES)]
        
    logs_text = "\n".join(all_logs)
    
    prompt = f"""
    You are an expert Security Analyst and DevOps Engineer. Analyze the following SAMPLED system logs from a server.
    These are {MAX_LINES} representative lines sampled evenly from {total_count} total log lines in the selected window.
    Look for security threats, errors, anomalies, and performance issues. 
    
    Output your analysis in STRICT HTML matching this structure (DO NOT use markdown backticks, just output raw HTML):
    
    <div style="color: #c9d1d9; font-family: sans-serif;">
        <h4 style="color: #58a6ff; margin-bottom: 5px;">Analysis / Observation</h4>
        <ul style="margin-top: 5px; padding-left: 20px;">
            <li>Point 1...</li>
            <li>Point 2...</li>
        </ul>
        
        <h4 style="color: #ff7b72; margin-bottom: 5px; margin-top: 15px;">Potential Risk</h4>
        <p style="margin-top: 5px;">Describe the risk here...</p>
        
        <h4 style="color: #3fb950; margin-bottom: 5px; margin-top: 15px;">Recommendations</h4>
        <ul style="margin-top: 5px; padding-left: 20px;">
            <li>Recommendation 1...</li>
        </ul>
    </div>
    
    LOGS TO ANALYZE:
    {logs_text}
    """
    
    # 60-second timeout: if Gemini hangs longer, raise so we return a clean error
    import signal
    def _timeout_handler(signum, frame):
        raise TimeoutError("Gemini API timed out after 60 seconds")
    
    try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(60)
    except (AttributeError, OSError):
        pass  # Windows doesn't support SIGALRM — skip gracefully
    
    try:
        response = llm_model.generate_content(prompt)
    except TimeoutError as te:
        return {"error": "Analysis timed out. Gemini took too long to respond. Try again or select a shorter time window."}
    except Exception as e:
        if "404" in str(e) or "not found" in str(e).lower():
            # Fallback 1: gemini-1.5-pro-latest
            try:
                fallback_model = genai.GenerativeModel('gemini-1.5-pro-latest')
                response = fallback_model.generate_content(prompt)
            except Exception as e2:
                if "404" in str(e2) or "not found" in str(e2).lower():
                    # Fallback 2: Legacy gemini-pro
                    legacy_model = genai.GenerativeModel('gemini-pro')
                    response = legacy_model.generate_content(prompt)
                else:
                    raise e2
        else:
            raise e
            
    try:
        try:
            signal.alarm(0)  # Cancel the timeout alarm
        except (AttributeError, OSError):
            pass
        # Strip any markdown code blocks if the model ignores the strict instruction
        html_content = response.text.replace("```html", "").replace("```", "").strip()
        
        return {
            "analysis": html_content,
            "count": total_count,
            "sampled": len(all_logs),
            "start": str(start_time),
            "end": str(now)
        }
    except Exception as e:
        logger.error(f"Gemini API Error: {e}")
        return {"error": f"Failed to analyze logs with Gemini: {str(e)}"}
