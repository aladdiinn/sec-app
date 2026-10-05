import os
import logging
import boto3
from botocore.exceptions import ClientError
try:
    from google import genai
except ImportError:
    genai = None

logger = logging.getLogger("ses_mailer")
logger.setLevel(logging.INFO)

AWS_REGION = os.environ.get("SES_AWS_REGION") or os.environ.get("AWS_REGION", "us-east-1")
# For SES to work, the sender email MUST be verified in the AWS SES console.
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "security@yourcompany.com")
# Where the alerts should be sent
SES_RECIPIENT_EMAIL = os.environ.get("SES_RECIPIENT_EMAIL", "soc-team@yourcompany.com")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

_gemini_client = None
if GEMINI_API_KEY and genai:
    try:
        # Use stable v1 API for Free Tier accounts
        _gemini_client = genai.Client(api_key=GEMINI_API_KEY, http_options={"api_version": "v1"})
    except Exception as e:
        logger.error(f"Failed to configure Gemini Client: {e}")

def get_ses_client():
    key_id = os.environ.get("SES_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("SES_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    if key_id and secret_key:
        return boto3.client('ses', region_name=AWS_REGION, aws_access_key_id=key_id, aws_secret_access_key=secret_key)
    else:
        return boto3.client('ses', region_name=AWS_REGION)

def generate_alert_analysis(alert_title: str, alert_type: str, message: str, server_ip: str, username: str = "root"):
    """Uses Gemini to generate the Analysis, Risk, and Recommendation for the email."""
    if not _gemini_client:
        return {
            "analysis": "LLM API Key missing. Analysis unavailable.",
            "risk": "Unknown",
            "recommendations": "Please configure GEMINI_API_KEY to enable smart analysis."
        }
    
    prompt = f"""
    You are an expert SOC Analyst. Analyze this specific security alert that just occurred on a Linux server.
    
    Alert Title: {alert_title}
    Alert Type: {alert_type}
    Server IP: {server_ip}
    Username involved: {username}
    Raw Message/Event: {message}
    
    Output your response STRICTLY as a JSON object with exactly these three keys:
    "analysis" (A concise, numbered list summarizing what happened, formatted in HTML `<li>` tags)
    "risk" (A concise paragraph explaining the potential risk in HTML `<p>` tags)
    "recommendations" (A concise, numbered list of actions to take, formatted in HTML `<li>` tags)
    
    Do NOT wrap the response in markdown code blocks. Output pure JSON only.
    """
    
    try:
        response = _gemini_client.models.generate_content(model='gemini-3.8-flash', contents=prompt)
        text = response.text.replace("```json", "").replace("```", "").strip()
        import json
        data = json.loads(text)
        return data
    except Exception as e:
        logger.error(f"Gemini API Error during alert analysis: {e}")
        return {
            "analysis": f"<li>Failed to analyze alert using AI. Error: {str(e)}</li>",
            "risk": "<p>Unable to determine risk due to AI failure.</p>",
            "recommendations": "<li>Investigate manually via the dashboard.</li>"
        }

def send_smart_alert_email(alert_id: int, alert_title: str, alert_type: str, message: str, severity: str, timestamp: str, server_ip: str, hostname: str):
    """Constructs the HTML template and sends it via AWS SES."""
    
    # 1. Filter out noisy alerts as requested by the user
    noisy_types = ["sudo su", "session open", "uncoded", "session_opened"]
    if any(noisy in alert_type.lower() or noisy in message.lower() or noisy in alert_title.lower() for noisy in noisy_types):
        logger.info(f"Skipping email for noisy alert: {alert_title}")
        return False
        
    # 2. Get LLM Analysis
    llm_data = generate_alert_analysis(alert_title, alert_type, message, server_ip)
    
    # 3. Construct the exact HTML table requested by the user
    # Using a red header block and clean table rows
    html_body = f"""
    <html>
    <head></head>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
        <div style="max-width: 900px; margin: 0 auto; background: white; border: 1px solid #ccc;">
            <!-- Red Header -->
            <div style="background-color: #ff0000; color: white; text-align: center; font-weight: bold; padding: 10px; font-size: 16px;">
                Alert Name: "{alert_title}"
            </div>
            
            <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; width: 25%; font-weight: bold;">Event Time Stamp</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{timestamp}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Alert ID</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{alert_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Event Generator</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{alert_type}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Host Name</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{hostname}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Host IP</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{server_ip}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Severity</td>
                    <td style="padding: 8px; border: 1px solid #ccc; color: red;">{severity.upper()}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold;">Raw Message</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">{message}</td>
                </tr>
                
                <!-- LLM Analysis Section -->
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold; vertical-align: top;">Analysis/Observation</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">
                        <ol style="margin: 0; padding-left: 20px;">
                            {llm_data.get('analysis', '')}
                        </ol>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold; vertical-align: top;">Potential Risk</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">
                        {llm_data.get('risk', '')}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ccc; font-weight: bold; vertical-align: top;">Recommendations</td>
                    <td style="padding: 8px; border: 1px solid #ccc;">
                        <ol style="margin: 0; padding-left: 20px;">
                            {llm_data.get('recommendations', '')}
                        </ol>
                    </td>
                </tr>
            </table>
        </div>
    </body>
    </html>
    """
    
    subject = f"[SOC ALERT] {severity.upper()} - {alert_title} on {hostname}"
    
    # Parse multiple comma-separated recipients
    recipient_str = os.environ.get("SES_RECIPIENT_EMAIL", "soc-team@yourcompany.com")
    recipients = [r.strip() for r in recipient_str.replace(";", ",").split(",") if r.strip()]
    
    try:
        ses = get_ses_client()
        response = ses.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={'ToAddresses': recipients},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': html_body}}
            }
        )
        logger.info(f"Smart Alert Email sent! Message ID: {response['MessageId']}")
        return True
    except ClientError as e:
        logger.error(f"Failed to send SES email: {e.response['Error']['Message']}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False
