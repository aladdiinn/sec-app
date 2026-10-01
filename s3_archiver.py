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
    Finds all logs in the DB older than 1 hour, uploads them to S3, 
    and then deletes them from the local database.
    """
    s3_client = get_s3_client()
    try:
        ensure_bucket_exists(s3_client)
    except Exception:
        logger.error("Could not ensure S3 bucket exists. Aborting archival.")
        return

    # Calculate the cutoff time (1 hour ago)
    cutoff_time = datetime.now() - timedelta(hours=1)
    cutoff_timestamp = cutoff_time.timestamp()

    logger.info(f"Starting S3 log archival. Cutoff time: {cutoff_time}")

    try:
        with db_conn.cursor() as cur:
            # 1. Group old logs by server_id, day, and log_type
            cur.execute("""
                SELECT server_id, DATE(created_at) as log_date, log_type, COUNT(*) as count 
                FROM logs 
                WHERE created_at < %s
                GROUP BY server_id, DATE(created_at), log_type
            """, (cutoff_time,))
            
            batches = cur.fetchall()
            
            if not batches:
                logger.info("No logs older than 1 hour found to archive.")
                return

            # Process each batch (per server, per day, per log_type)
            for batch in batches:
                server_id = batch["server_id"] if isinstance(batch, dict) else batch[0]
                log_date = batch["log_date"] if isinstance(batch, dict) else batch[1]
                log_type = batch["log_type"] if isinstance(batch, dict) else batch[2]
                
                # Default log type folder if null
                safe_log_type = (log_type or "system").replace("/", "_").replace("\\", "_")
                
                # Get the server IP to use in the S3 path
                cur.execute("SELECT ip FROM servers WHERE id = %s", (server_id,))
                server_row = cur.fetchone()
                server_ip = server_row["ip"] if server_row and isinstance(server_row, dict) else (server_row[0] if server_row else f"unknown-server-{server_id}")

                # 2. Fetch the actual logs for this specific type
                cur.execute("""
                    SELECT id, log_type, source, message, created_at 
                    FROM logs 
                    WHERE server_id = %s AND DATE(created_at) = %s AND (log_type = %s OR (log_type IS NULL AND %s IS NULL)) AND created_at < %s
                """, (server_id, log_date, log_type, log_type, cutoff_time))
                logs = cur.fetchall()
                
                if not logs:
                    continue

                # Convert to dicts for JSON serialization
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

                # 3. Create compressed JSON payload
                json_data = json.dumps(log_dicts, default=str)
                compressed_data = gzip.compress(json_data.encode('utf-8'))

                # 4. Determine S3 Path Structure
                # Format: s3://bucket/server_ip/YYYY/MM/DD/log_type/logs_HH_MM_SS.json.gz
                dt_obj = log_date if isinstance(log_date, datetime) else datetime.strptime(str(log_date), "%Y-%m-%d")
                year, month, day = str(dt_obj.year), f"{dt_obj.month:02d}", f"{dt_obj.day:02d}"
                timestamp_str = datetime.now().strftime("%H_%M_%S")
                
                s3_key = f"{server_ip}/{year}/{month}/{day}/{safe_log_type}/logs_{timestamp_str}.json.gz"

                # 5. Upload to S3
                logger.info(f"Uploading {len(log_dicts)} logs to s3://{S3_BUCKET_NAME}/{s3_key}")
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=compressed_data,
                    ContentType='application/x-gzip'
                )

                # 6. Delete the uploaded logs from the local database
                # Delete in chunks to avoid locking issues
                chunk_size = 1000
                for i in range(0, len(log_ids_to_delete), chunk_size):
                    chunk = log_ids_to_delete[i:i + chunk_size]
                    cur.execute("DELETE FROM logs WHERE id = ANY(%s)", (chunk,))
                
                db_conn.commit()
                logger.info(f"Successfully archived and deleted {len(log_dicts)} logs for {server_ip}.")

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
