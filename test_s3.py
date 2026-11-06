#!/usr/bin/env python3
"""
Test AWS S3 connection and bucket access using configured environment variables.
Usage:
    python test_s3.py
"""
import os
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError

load_dotenv()

S3_REGION = os.environ.get("AWS_S3_REGION") or os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET = os.environ.get("AWS_S3_BUCKET_NAME") or os.environ.get("S3_LOG_ARCHIVE_BUCKET")
KEY_ID = os.environ.get("AWS_S3_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
SECRET_KEY = os.environ.get("AWS_S3_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")

print("=== AWS S3 Config Check ===")
print(f"Region: {S3_REGION}")
print(f"Bucket: {S3_BUCKET}")
print(f"Access Key ID: {KEY_ID[:6]}... (length: {len(KEY_ID)})" if KEY_ID else "Access Key ID: None")

if not S3_BUCKET:
    print("❌ ERROR: AWS_S3_BUCKET_NAME is missing in .env")
    exit(1)

if not KEY_ID or not SECRET_KEY:
    print("❌ ERROR: AWS_S3_ACCESS_KEY_ID or AWS_S3_SECRET_ACCESS_KEY is missing in .env")
    exit(1)

try:
    print("\nAttempting to connect to AWS S3...")
    client = boto3.client(
        's3',
        region_name=S3_REGION,
        aws_access_key_id=KEY_ID,
        aws_secret_access_key=SECRET_KEY
    )
    
    print(f"Verifying access to bucket '{S3_BUCKET}'...")
    client.head_bucket(Bucket=S3_BUCKET)
    print(f"✅ SUCCESS! Connected to bucket '{S3_BUCKET}' in region '{S3_REGION}'.")
except ClientError as e:
    code = e.response.get('Error', {}).get('Code', 'Unknown')
    print(f"❌ S3 Error ({code}): {e}")
except Exception as e:
    print(f"❌ Unexpected Error: {e}")
