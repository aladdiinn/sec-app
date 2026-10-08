import os
import time
import json
import gzip
import logging
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("s3_archiver")
logger.setLevel(logging.INFO)

# Default to a specific bucket name. You can override this via ENV variables.
S3_BUCKET_NAME = os.environ.get("S3_LOG_ARCHIVE_BUCKET", "securepulse-logs-archive-bucket-2026")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

def get_s3_client():
    """Initializes the boto3 S3 client."""
    # Note: Boto3 will automatically use IAM roles if deployed on EC2, 
    # or ~/.aws/credentials if running locally.
    return boto3.client('s3', region_name=AWS_REGION)

def ensure_bucket_exists(s3_client):
    """Creates the S3 bucket if it doesn't already exist."""
    try:
        s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
        logger.debug(f"Bucket {S3_BUCKET_NAME} already exists.")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
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
                logger.error(f"Failed to create bucket: {create_e}")
                raise
        else:
            logger.error(f"Unexpected error checking bucket: {e}")
            raise

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
                
                cur.execute("SELECT ip, machine_id FROM servers WHERE id = %s", (server_id,))
                server_row = cur.fetchone()
                if server_row and isinstance(server_row, dict):
                    server_ip = server_row.get("ip") or f"unknown-ip-{server_id}"
                    machine_id = server_row.get("machine_id") or f"unknown-machine-{server_id}"
                elif server_row:
                    server_ip = server_row[0] or f"unknown-ip-{server_id}"
                    machine_id = server_row[1] or f"unknown-machine-{server_id}"
                else:
                    server_ip = f"unknown-ip-{server_id}"
                    machine_id = f"unknown-machine-{server_id}"

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

                # logs/{machine_id}/{server_ip}/{type}/{file_id}/{yyyy}/{mm}/{dd}/{hh}/{ts}.jsonl.gz
                dt_obj = log_date if isinstance(log_date, datetime) else datetime.strptime(str(log_date), "%Y-%m-%d")
                year, month, day = str(dt_obj.year), f"{dt_obj.month:02d}", f"{dt_obj.day:02d}"
                now = datetime.now()
                hour = f"{now.hour:02d}"
                timestamp_str = now.strftime("%H_%M_%S")
                
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

    except Exception as e:
        logger.error(f"Error during S3 archival: {e}")
        db_conn.rollback()

if __name__ == "__main__":
    # Test script standalone
    import database
    logging.basicConfig(level=logging.INFO)
    conn = database.get_db_connection()
    if conn:
        archive_logs_to_s3(conn)
        conn.close()
