import os
import html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

import logging
import boto3
from botocore.exceptions import ClientError
try:
    from google import genai
    _sdk = "new"
except ImportError:
    try:
        import google.generativeai as genai
        _sdk = "old"
    except ImportError:
        genai = None
        _sdk = None

logger = logging.getLogger("ses_mailer")
logger.setLevel(logging.INFO)

AWS_REGION = os.environ.get("SES_AWS_REGION") or os.environ.get("AWS_REGION", "us-east-1")
# For SES to work, the sender email MUST be verified in the AWS SES console.
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL", "security@yourcompany.com")
# Where the alerts should be sent
SES_RECIPIENT_EMAIL = os.environ.get("SES_RECIPIENT_EMAIL", "soc-team@yourcompany.com")

import gemini_client

def get_ses_client():
    key_id = os.environ.get("SES_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("SES_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    if key_id and secret_key:
        return boto3.client('ses', region_name=AWS_REGION, aws_access_key_id=key_id, aws_secret_access_key=secret_key)
    else:
        return boto3.client('ses', region_name=AWS_REGION)

def generate_alert_analysis(alert_title: str, alert_type: str, message: str, server_ip: str, username: str = "root"):
    """Uses Gemini to generate the Analysis, Risk, and Recommendation for the email."""
    prompt = f"""
    You are an expert SOC Analyst. Analyze this specific security alert that just occurred on a Linux server.
    
    Alert Title: {alert_title}
    Alert Type: {alert_type}
    Server IP: {server_ip}
    Username involved: {username}
    Raw Message/Event: {message}
    
    Output your response STRICTLY as a JSON object with exactly these three keys:
    "analysis" (A concise, numbered list summarizing what happened, formatted in HTML <li> tags)
    "risk" (A concise paragraph explaining the potential risk in HTML <p> tags)
    "recommendations" (A concise, numbered list of actions to take, formatted in HTML <li> tags)
    
    Do NOT wrap the response in markdown code blocks. Output pure JSON only.
    """
    
    try:
        text = gemini_client.generate_content(prompt)
        text = text.replace("```json", "").replace("```", "").strip()
        import json
        data = json.loads(text)
        return data
    except Exception as e:
        logger.error(f"Gemini API Error during alert analysis: {e}")
        # Graceful fallback to rule-based description if AI fails
        return {
            "analysis": f"<li>Event Type: {alert_type}</li><li>Target Server: {server_ip}</li><li>User: {username}</li><li>Raw Event: {message}</li>",
            "risk": f"<p>A security event matching rule '{alert_title}' was triggered. Immediate manual review is recommended.</p>",
            "recommendations": "<li>Investigate the raw event logs via the SecurePulse dashboard.</li><li>Verify the user's authorization to perform this action.</li><li>Check the affected server for related anomalous activity.</li>"
        }

def send_smart_alert_email(alert_id: int, alert_title: str, alert_type: str, message: str, severity: str, timestamp: str, server_ip: str, hostname: str):
    """Constructs the HTML template and sends it via AWS SES."""
    
    # 1. Filter out noisy alerts
    noisy_types = ["sudo su", "session open", "uncoded", "session_opened"]
    if any(noisy in alert_type.lower() or noisy in message.lower() or noisy in alert_title.lower() for noisy in noisy_types):
        logger.info(f"Skipping email for noisy alert: {alert_title}")
        return False
        
    # 2. Get LLM Analysis
    llm_data = generate_alert_analysis(alert_title, alert_type, message, server_ip)
    
    # Escape dynamic values
    safe_title = html.escape(str(alert_title))
    safe_id = html.escape(str(alert_id))
    safe_type = html.escape(str(alert_type))
    safe_msg = html.escape(str(message))
    safe_sev = html.escape(str(severity)).upper()
    safe_time = html.escape(str(timestamp))
    safe_ip = html.escape(str(server_ip))
    safe_host = html.escape(str(hostname))
    
    sev_color = "red" if safe_sev in ["HIGH", "CRITICAL", "WARNING"] else "#333"

    html_body = f"""
    <html>
    <head></head>
    <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; border: 1px solid #e0e0e0;">
            <div style="padding: 10px 15px; font-size: 12px; color: #666; border-bottom: 1px solid #e0e0e0; background-color: #f0f0f0;">
                BSMART SOC Alert
            </div>
            
            <!-- Dark Banner -->
            <table style="width: 100%; background-color: #0a0e17; color: white; border-collapse: collapse; margin: 0; padding: 0;">
                <tr>
                    <td style="padding: 15px 15px 15px 15px; width: 80px; vertical-align: middle; text-align: center;">
                        <img src="cid:soc_logo" alt="BSMART SOC" style="width: 70px; max-width: 70px; height: auto; display: block; border: 0; margin: 0 auto;" />
                    </td>
                    <td style="padding: 15px 15px 15px 10px; vertical-align: middle; text-align: left;">
                        <span style="color: #0088ff; font-weight: bold; font-size: 20px; display: inline-block; vertical-align: middle;">ALERT:</span>
                        <span style="font-weight: bold; font-size: 20px; margin-left: 5px; display: inline-block; vertical-align: middle;">{safe_title}</span>
                    </td>
                </tr>
            </table>
            
            <!-- Table -->
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; width: 35%; font-weight: bold; background-color: #fbfbfb;">Event Time Stamp</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">{safe_time}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Alert ID</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">{safe_id}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Event Generator</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">{safe_type}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Host Name</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">{safe_host}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Host IP</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">{safe_ip}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Severity</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; color: {sev_color};">{safe_sev}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb;">Raw Message</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; word-break: break-all; word-wrap: break-word;">{safe_msg}</td>
                </tr>
                
                <!-- LLM Analysis Section -->
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb; vertical-align: top;">Analysis/Observation</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">
                        <ol style="margin: 0; padding-left: 20px;">
                            {llm_data.get('analysis', '')}
                        </ol>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb; vertical-align: top;">Potential Risk</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">
                        {llm_data.get('risk', '')}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #e0e0e0; font-weight: bold; background-color: #fbfbfb; vertical-align: top;">Recommendations</td>
                    <td style="padding: 10px; border: 1px solid #e0e0e0;">
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
    
    subject = f"[BSMART SOC] {safe_sev} - {safe_title} on {safe_host}"
    
    # Parse multiple comma-separated recipients
    recipient_str = os.environ.get("SES_RECIPIENT_EMAIL", "soc-team@yourcompany.com")
    recipients = [r.strip() for r in recipient_str.replace(";", ",").split(",") if r.strip()]
    
    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = SES_SENDER_EMAIL
        msg['To'] = ", ".join(recipients)

        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)

        msg_html = MIMEText(html_body, 'html')
        msg_alternative.attach(msg_html)

        # Attach CID image
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, 'rb') as f:
                img_data = f.read()
            msg_image = MIMEImage(img_data)
            msg_image.add_header('Content-ID', '<soc_logo>')
            msg_image.add_header('Content-Disposition', 'inline')
            msg.attach(msg_image)
            
        ses = get_ses_client()
        response = ses.send_raw_email(
            Source=SES_SENDER_EMAIL,
            Destinations=recipients,
            RawMessage={'Data': msg.as_string()}
        )
        logger.info(f"Smart Alert Email sent! Message ID: {response['MessageId']}")
        return True
    except ClientError as e:
        logger.error(f"Failed to send SES email: {e.response['Error']['Message']}")
        return False
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
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
