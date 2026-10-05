import os
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError

load_dotenv()

AWS_REGION = os.environ.get("SES_AWS_REGION") or os.environ.get("AWS_REGION", "us-east-1")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL")
SES_RECIPIENT_EMAIL = os.environ.get("SES_RECIPIENT_EMAIL")

print("=== AWS SES Config Check ===")
print(f"Region: {AWS_REGION}")
print(f"Sender: {SES_SENDER_EMAIL}")
print(f"Recipient: {SES_RECIPIENT_EMAIL}")

if not SES_SENDER_EMAIL or not SES_RECIPIENT_EMAIL:
    print("❌ ERROR: SES_SENDER_EMAIL or SES_RECIPIENT_EMAIL is missing in .env")
    exit(1)

try:
    print("\nAttempting to connect to AWS SES...")
    # Explicitly pull keys in case Boto3 is missing them
    key_id = os.environ.get("SES_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("SES_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    
    if not key_id or not secret_key:
        print("❌ ERROR: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY is missing in .env")
        exit(1)
        
    client = boto3.client(
        'ses',
        region_name=AWS_REGION,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret_key
    )
    
    print("Connected! Attempting to send a test email...")
    
    recipients = [r.strip() for r in SES_RECIPIENT_EMAIL.replace(";", ",").split(",") if r.strip()]
    
    response = client.send_email(
        Source=SES_SENDER_EMAIL,
        Destination={'ToAddresses': recipients},
        Message={
            'Subject': {'Data': 'SOC Dashboard - SES Test'},
            'Body': {'Text': {'Data': 'If you receive this, SES is configured correctly!'}}
        }
    )
    print(f"✅ SUCCESS! Email sent. Message ID: {response['MessageId']}")

except ClientError as e:
    error_code = e.response['Error']['Code']
    error_msg = e.response['Error']['Message']
    print(f"❌ AWS SES ERROR: {error_code}")
    print(f"Details: {error_msg}")
    if error_code == 'MessageRejected':
        print("👉 FIX: Your email addresses are not verified in AWS SES. Since your AWS account is in the 'Sandbox', BOTH the sender and recipient emails must be verified in the AWS Console before you can send emails.")
    elif error_code == 'InvalidClientTokenId' or error_code == 'SignatureDoesNotMatch':
        print("👉 FIX: Your AWS Access Key or Secret Key is incorrect.")
except Exception as e:
    print(f"❌ UNEXPECTED ERROR: {e}")
