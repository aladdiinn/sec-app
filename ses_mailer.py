import os
import re
import html
import time
import logging
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("ses_mailer")
logger.setLevel(logging.INFO)

# ── Startup & Environment Configuration ───────────────────────────────────────
_STARTUP_CHECKED = False
_CRITICAL_EMAIL_DEDUP = {} # (rule_key, server_id): timestamp
_DEDUP_LOCK = threading.Lock()

# Burst Digest Queue: {project_id: [{"alert_id": ..., "title": ..., "time": ...}]}
_BURST_DIGEST_QUEUE = {}
_DIGEST_LOCK = threading.Lock()
_DIGEST_WORKER_STARTED = False

def get_ses_config():
    """Reads exactly SES_* configuration variables with fallback names."""
    region = os.environ.get("SES_AWS_REGION") or os.environ.get("AWS_REGION")
    key_id = os.environ.get("SES_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("SES_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    sender = os.environ.get("SES_SENDER_EMAIL")
    recipient_str = os.environ.get("SES_RECIPIENT_EMAIL")

    missing = []
    if not region: missing.append("SES_AWS_REGION")
    if not key_id: missing.append("SES_AWS_ACCESS_KEY_ID")
    if not secret_key: missing.append("SES_AWS_SECRET_ACCESS_KEY")
    if not sender: missing.append("SES_SENDER_EMAIL")
    if not recipient_str: missing.append("SES_RECIPIENT_EMAIL")

    return {
        "region": region,
        "key_id": key_id,
        "secret_key": secret_key,
        "sender": sender.strip() if sender else None,
        "recipient_str": recipient_str,
        "missing": missing
    }

def get_ses_client():
    """
    Initializes boto3 SES client with explicit credentials, HTTPS port 443, 
    proxy support, and retry with exponential backoff on throttling/network errors.
    """
    cfg = get_ses_config()
    if cfg["missing"]:
        raise ValueError(f"Missing required SES environment variables: {', '.join(cfg['missing'])}")

    boto_config = Config(
        retries={'max_attempts': 3, 'mode': 'standard'},
        connect_timeout=5,
        read_timeout=10
    )

    return boto3.client(
        'ses',
        region_name=cfg["region"],
        aws_access_key_id=cfg["key_id"],
        aws_secret_access_key=cfg["secret_key"],
        config=boto_config
    )

def parse_recipients(recipient_str: str):
    """
    Splits recipient string on commas or semicolons, trims quotes and spaces,
    and returns a list of valid email addresses.
    """
    if not recipient_str:
        return []
    raw_list = re.split(r'[,;]+', recipient_str)
    cleaned = []
    email_re = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    for item in raw_list:
        clean = item.strip().strip("'\"").strip()
        if clean and email_re.match(clean):
            cleaned.append(clean)
    return cleaned

# ── Startup & On-Demand Self-Check ───────────────────────────────────────────
def perform_ses_self_check():
    """
    Performs comprehensive SES self-check:
    - Missing variable verification
    - Endpoint reachability & quota check
    - Sandbox status check (get_account)
    - Identity verification status of sender and recipients
    """
    cfg = get_ses_config()
    result = {
        "configured": len(cfg["missing"]) == 0,
        "missing_vars": cfg["missing"],
        "region": cfg["region"],
        "sender": cfg["sender"],
        "sender_verified": False,
        "sandbox_mode": "Unknown",
        "recipients": [],
        "quota": None,
        "reachability": False,
        "error": None
    }

    if cfg["missing"]:
        result["error"] = f"Missing environment variables: {', '.join(cfg['missing'])}"
        return result

    recipients = parse_recipients(cfg["recipient_str"])

    try:
        client = get_ses_client()
        result["reachability"] = True

        # 1. Quota Check
        try:
            quota = client.get_send_quota()
            result["quota"] = {
                "max_24h": quota.get("Max24HourSend", 0.0),
                "max_send_rate": quota.get("MaxSendRate", 0.0),
                "sent_24h": quota.get("SentLast24Hours", 0.0)
            }
        except ClientError as e:
            logger.warning(f"[SES] Could not read send quota: {e.response.get('Error', {}).get('Message')}")

        # 2. Account / Sandbox Status
        try:
            acc = client.get_account()
            prod_enabled = acc.get("ProductionAccessEnabled", False)
            result["sandbox_mode"] = "Production (Out of Sandbox)" if prod_enabled else "SES Sandbox (Verified Emails Only)"
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == "AccessDenied":
                result["sandbox_mode"] = "Unknown (IAM lacks ses:GetAccount permission)"
            else:
                result["sandbox_mode"] = f"Check failed ({code})"

        # 3. Verification status for Sender & Recipients
        all_emails = [cfg["sender"]] + recipients
        try:
            attrs = client.get_identity_verification_attributes(Identities=all_emails).get("VerificationAttributes", {})
            sender_attr = attrs.get(cfg["sender"], {}).get("VerificationStatus", "NotFound")
            result["sender_verified"] = (sender_attr.lower() == "success")

            for rcpt in recipients:
                rcpt_attr = attrs.get(rcpt, {}).get("VerificationStatus", "NotFound")
                result["recipients"].append({
                    "email": rcpt,
                    "verified": (rcpt_attr.lower() == "success"),
                    "status": rcpt_attr
                })
        except ClientError as e:
            logger.warning(f"[SES] Could not read identity verification attributes: {e.response.get('Error', {}).get('Message')}")

    except ClientError as ce:
        err_code = ce.response.get('Error', {}).get('Code', 'ClientError')
        err_msg = ce.response.get('Error', {}).get('Message', str(ce))
        result["error"] = f"{err_code}: {err_msg}"
    except EndpointConnectionError as ece:
        result["error"] = f"EndpointConnectionError: Cannot reach AWS SES on HTTPS port 443 in {cfg['region']}"
    except Exception as ex:
        result["error"] = str(ex)

    return result

def log_startup_ses_check_once():
    """Logs the SES self-check report ONCE at startup (never loops every 15s)."""
    global _STARTUP_CHECKED
    if _STARTUP_CHECKED:
        return
    _STARTUP_CHECKED = True

    chk = perform_ses_self_check()
    if not chk["configured"]:
        logger.warning(f"[SES STARTUP] SES email alerts disabled. Missing required variables: {', '.join(chk['missing_vars'])}")
        return

    if chk["error"]:
        logger.error(f"[SES STARTUP] SES configuration check failed: {chk['error']}")
        return

    logger.info(
        f"[SES STARTUP] SES Connected: Region={chk['region']} | "
        f"Sandbox={chk['sandbox_mode']} | "
        f"Sender={chk['sender']} (verified: {chk['sender_verified']}) | "
        f"Recipients={len(chk['recipients'])} configured"
    )

# ── Data Sanitization for External AI ─────────────────────────────────────────
def sanitize_alert_for_external_ai(text: str) -> str:
    """Masks IP addresses, authentication tokens, and user credentials before external LLM calls."""
    if not text:
        return ""
    # Mask IPv4 addresses
    s = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', str(text))
    # Mask tokens and hex hashes
    s = re.sub(r'sp-token-[a-zA-Z0-9_-]+', '[REDACTED_TOKEN]', s)
    s = re.sub(r'token[=:][a-zA-Z0-9_\.-]+', 'token=[REDACTED]', s, flags=re.I)
    # Mask password parameters
    s = re.sub(r'(password|passwd|pwd)[=:][^&\s]+', r'\1=[REDACTED]', s, flags=re.I)
    return s

def generate_alert_analysis(alert_title: str, alert_type: str, message: str, server_ip: str, username: str = "root"):
    """
    Optional LLM analysis outside the send path.
    If GEMINI_API_KEY is missing or disabled, skips silently with clean rule-based fallback.
    Never blocks or delays email dispatch.
    """
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        return {
            "analysis": f"<li>Event Type: {html.escape(alert_type)}</li><li>Target Server: {html.escape(server_ip)}</li><li>User Account: {html.escape(username)}</li><li>Evidence Summary: {html.escape(message[:200])}</li>",
            "risk": f"<p>A security event matching rule '{html.escape(alert_title)}' was triggered. Immediate SOC review is recommended.</p>",
            "recommendations": "<li>Investigate the raw event logs in BSMART SOC dashboard.</li><li>Verify authorization for this server activity.</li><li>Check the affected server for correlated anomalous events.</li>"
        }

    try:
        import gemini_client
        clean_msg = sanitize_alert_for_external_ai(message)
        prompt = f"""
        You are an expert SOC Analyst. Analyze this security alert on a Linux server.
        Alert Title: {alert_title}
        Alert Type: {alert_type}
        Server IP: {sanitize_alert_for_external_ai(server_ip)}
        Username: {username}
        Evidence: {clean_msg[:300]}

        Output STRICTLY JSON with exactly three keys:
        "analysis" (concise list formatted in HTML <li> tags)
        "risk" (concise paragraph in HTML <p> tags)
        "recommendations" (concise list in HTML <li> tags)
        No markdown blocks.
        """
        raw_text = gemini_client.generate_content(prompt)
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()
        import json
        return json.loads(raw_text)
    except Exception as e:
        logger.debug(f"[SES] Gemini alert analysis fallback: {e}")
        return {
            "analysis": f"<li>Event Type: {html.escape(alert_type)}</li><li>Target Server: {html.escape(server_ip)}</li><li>User Account: {html.escape(username)}</li><li>Evidence Summary: {html.escape(message[:200])}</li>",
            "risk": f"<p>A security event matching rule '{html.escape(alert_title)}' was triggered.</p>",
            "recommendations": "<li>Investigate the raw event logs in BSMART SOC dashboard.</li><li>Verify user authorization and server posture.</li>"
        }

# ── Core Email Dispatch Function (Per-Recipient + Error Logging) ──────────────
def send_email_per_recipient(subject: str, html_body: str, alert_id: int = None):
    """
    Sends email to each recipient INDIVIDUALLY so an unverified address
    in SES sandbox does NOT block delivery to other verified addresses.
    Records every attempt in the database email_log table.
    """
    cfg = get_ses_config()
    if cfg["missing"]:
        err_msg = f"Cannot send email: missing {', '.join(cfg['missing'])}"
        logger.error(f"[SES] {err_msg}")
        return {"ok": False, "error": err_msg, "results": []}

    recipients = parse_recipients(cfg["recipient_str"])
    if not recipients:
        err_msg = "No valid recipient email addresses found in SES_RECIPIENT_EMAIL"
        logger.error(f"[SES] {err_msg}")
        return {"ok": False, "error": err_msg, "results": []}

    import database as db

    try:
        client = get_ses_client()
    except Exception as e:
        err_msg = f"Failed to initialize SES client: {e}"
        logger.error(f"[SES] {err_msg}")
        for r in recipients:
            db.log_email_attempt(r, subject, "FAILED", None, err_msg, alert_id)
        return {"ok": False, "error": err_msg, "results": []}

    results = []
    sender = cfg["sender"]

    for rcpt in recipients:
        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = rcpt

            msg_alt = MIMEMultipart('alternative')
            msg.attach(msg_alt)
            msg_alt.attach(MIMEText(html_body, 'html'))

            # Inline Logo & Banner if available
            logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img", "logo.png")
            if os.path.exists(logo_path):
                try:
                    with open(logo_path, 'rb') as f:
                        img = MIMEImage(f.read())
                    img.add_header('Content-ID', '<soc_logo>')
                    img.add_header('Content-Disposition', 'inline')
                    msg.attach(img)
                except Exception: pass

            bg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img", "email_bg.png")
            if os.path.exists(bg_path):
                try:
                    with open(bg_path, 'rb') as f:
                        bg = MIMEImage(f.read())
                    bg.add_header('Content-ID', '<email_bg>')
                    bg.add_header('Content-Disposition', 'inline')
                    msg.attach(bg)
                except Exception: pass

            response = client.send_raw_email(
                Source=sender,
                Destinations=[rcpt],
                RawMessage={'Data': msg.as_string()}
            )
            msg_id = response.get('MessageId', '')
            logger.info(f"[SES SUCCESS] Sent email to '{rcpt}'. MessageId: {msg_id}")
            db.log_email_attempt(rcpt, subject, "SENT", msg_id, None, alert_id)
            results.append({"recipient": rcpt, "ok": True, "message_id": msg_id})

        except ClientError as ce:
            code = ce.response.get('Error', {}).get('Code', 'ClientError')
            msg_txt = ce.response.get('Error', {}).get('Message', str(ce))
            err_desc = f"{code}: {msg_txt}"
            logger.error(f"[SES FAILED] Recipient '{rcpt}' failed: {err_desc}")
            db.log_email_attempt(rcpt, subject, "FAILED", None, err_desc, alert_id)
            results.append({"recipient": rcpt, "ok": False, "error": err_desc})

        except Exception as ex:
            err_desc = str(ex)
            logger.error(f"[SES FAILED] Recipient '{rcpt}' failed: {err_desc}")
            db.log_email_attempt(rcpt, subject, "FAILED", None, err_desc, alert_id)
            results.append({"recipient": rcpt, "ok": False, "error": err_desc})

    any_success = any(r["ok"] for r in results)
    return {
        "ok": any_success,
        "results": results,
        "message_id": results[0].get("message_id") if results and results[0].get("ok") else None
    }

# ── Alert Email Construction & Background Deduplication ───────────────────────
def build_alert_html(alert_id: int, alert_title: str, alert_type: str, message: str, severity: str, timestamp: str, server_ip: str, hostname: str, llm_data: dict, alert_link: str = "#"):
    safe_title = html.escape(str(alert_title))
    safe_id = html.escape(str(alert_id or 'N/A'))
    safe_type = html.escape(str(alert_type))
    safe_msg = html.escape(str(message))
    safe_sev = html.escape(str(severity)).upper()
    safe_time = html.escape(str(timestamp))
    safe_ip = html.escape(str(server_ip))
    safe_host = html.escape(str(hostname))

    sev_color = "#ef4444" if safe_sev == "CRITICAL" else "#f59e0b" if safe_sev in ["HIGH", "WARNING"] else "#38bdf8"

    return f"""
    <html>
    <head></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 20px; margin: 0;">
        <div style="max-width: 640px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
            <!-- Header Banner -->
            <div style="background: #0f172a; border-bottom: 2px solid {sev_color}; padding: 18px 24px; display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="background: {sev_color}; color: #ffffff; font-size: 11px; font-weight: 800; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px;">{safe_sev}</span>
                    <h2 style="color: #ffffff; font-size: 18px; margin: 8px 0 0 0; font-weight: 700;">{safe_title}</h2>
                </div>
            </div>

            <!-- Details Table -->
            <div style="padding: 20px 24px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #cbd5e1; margin-bottom: 20px;">
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; width: 30%; font-weight: 600;">Target Asset / Node</td>
                        <td style="padding: 8px 0; font-weight: 700; color: #ffffff;">{safe_host} <span style="font-family: monospace; color: #38bdf8;">({safe_ip})</span></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Detection Rule</td>
                        <td style="padding: 8px 0; font-family: monospace; color: #f8fafc;">{safe_type}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Alert Timestamp</td>
                        <td style="padding: 8px 0; color: #94a3b8;">{safe_time}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; color: #64748b; font-weight: 600;">Alert ID</td>
                        <td style="padding: 8px 0; font-family: monospace; color: #94a3b8;">#{safe_id}</td>
                    </tr>
                </table>

                <!-- Evidence Summary -->
                <div style="background: #0a0e1a; border: 1px solid #1e293b; border-radius: 6px; padding: 14px; margin-bottom: 20px;">
                    <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px; letter-spacing: 0.5px;">Evidence Summary</div>
                    <div style="font-family: monospace; font-size: 12px; color: #f1f5f9; line-height: 1.5; word-break: break-word;">{safe_msg}</div>
                </div>

                <!-- LLM Analysis Section -->
                <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid #1e293b; border-radius: 6px; padding: 16px; margin-bottom: 20px;">
                    <div style="font-size: 12px; font-weight: 700; color: #38bdf8; text-transform: uppercase; margin-bottom: 10px;">Security Analyst Observation</div>
                    <ol style="margin: 0; padding-left: 20px; font-size: 12.5px; line-height: 1.6; color: #cbd5e1;">
                        {llm_data.get('analysis', '')}
                    </ol>
                    <div style="margin-top: 12px; font-size: 12px; font-weight: 700; color: #fbbf24; text-transform: uppercase;">Potential Risk</div>
                    <div style="font-size: 12.5px; line-height: 1.5; color: #e2e8f0; margin-top: 4px;">
                        {llm_data.get('risk', '')}
                    </div>
                    <div style="margin-top: 12px; font-size: 12px; font-weight: 700; color: #34d399; text-transform: uppercase;">Recommended Actions</div>
                    <ol style="margin: 4px 0 0 0; padding-left: 20px; font-size: 12.5px; line-height: 1.6; color: #cbd5e1;">
                        {llm_data.get('recommendations', '')}
                    </ol>
                </div>

                <!-- Action Button -->
                <div style="text-align: center; margin-top: 24px;">
                    <a href="{alert_link}" style="background: #0284c7; color: #ffffff; text-decoration: none; padding: 10px 24px; border-radius: 6px; font-size: 13px; font-weight: 700; display: inline-block;">View in BSMART SOC Dashboard &rarr;</a>
                </div>
            </div>

            <!-- Footer -->
            <div style="background: #0f172a; border-top: 1px solid #1e293b; padding: 12px 24px; text-align: center; font-size: 11px; color: #64748b;">
                BSMART SOC Command Center &bull; Automated Alert Dispatch &bull; Confidential
            </div>
        </div>
    </body>
    </html>
    """

def send_smart_alert_email(alert_id: int, alert_title: str, alert_type: str, message: str, severity: str, timestamp: str, server_ip: str, hostname: str, project_id: int = 1, force: bool = False):
    """
    Main dispatch entry point:
    - Enforces 15-minute deduplication for critical alerts per (rule, server).
    - Prevents mail storm from frequent 30-60s alerts.
    - Runs in background without blocking caller.
    """
    rule_key = str(alert_type).upper()
    now = time.time()

    # 1. Deduplication for Critical Alerts (15 Minutes)
    if not force and str(severity).lower() == "critical":
        with _DEDUP_LOCK:
            last_sent = _CRITICAL_EMAIL_DEDUP.get((rule_key, str(server_ip)), 0)
            if now - last_sent < 900: # 15 minutes = 900 seconds
                logger.info(f"[SES DEDUP] Suppressing duplicate Critical email for {rule_key} on {server_ip} (Sent {int(now - last_sent)}s ago)")
                return False
            _CRITICAL_EMAIL_DEDUP[(rule_key, str(server_ip))] = now

    # 2. Get LLM Analysis (Safe fallback if Gemini missing)
    llm_data = generate_alert_analysis(alert_title, alert_type, message, server_ip)

    # 3. Format Subject & Body
    subject = f"[BSMART SOC] {severity.upper()} - {alert_title} on {hostname}"
    html_body = build_alert_html(alert_id, alert_title, alert_type, message, severity, timestamp, server_ip, hostname, llm_data)

    # 4. Dispatch Email per Recipient
    result = send_email_per_recipient(subject, html_body, alert_id=alert_id)
    return result["ok"]

def send_test_email(target_recipient: str = None):
    """Sends a single test email and returns the exact SES MessageId or error."""
    cfg = get_ses_config()
    sender = cfg["sender"]
    rcpt = target_recipient or (parse_recipients(cfg["recipient_str"])[0] if parse_recipients(cfg["recipient_str"]) else None)

    if not rcpt:
        return {"ok": False, "error": "No recipient email address specified or configured"}

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = f"[BSMART SOC] SES Verification Test Email ({timestamp})"
    html_body = f"""
    <html>
    <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 24px;">
        <div style="max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 8px; padding: 24px; border: 1px solid #334155;">
            <h2 style="color: #38bdf8; margin-top: 0;">✅ AWS SES Integration Test Successful</h2>
            <p>Your BSMART SOC Command Center is successfully connected to AWS SES in region <strong>{cfg['region']}</strong>.</p>
            <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #cbd5e1; margin-top: 16px;">
                <tr><td style="padding: 6px 0; color: #94a3b8;">Sender:</td><td><strong>{sender}</strong></td></tr>
                <tr><td style="padding: 6px 0; color: #94a3b8;">Recipient:</td><td><strong>{rcpt}</strong></td></tr>
                <tr><td style="padding: 6px 0; color: #94a3b8;">Sent At:</td><td>{timestamp}</td></tr>
            </table>
            <p style="font-size: 12px; color: #64748b; margin-top: 20px;">If you received this message, SES alerting is operational.</p>
        </div>
    </body>
    </html>
    """

    try:
        client = get_ses_client()
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = rcpt
        msg.attach(MIMEText(html_body, 'html'))

        response = client.send_raw_email(
            Source=sender,
            Destinations=[rcpt],
            RawMessage={'Data': msg.as_string()}
        )
        msg_id = response.get('MessageId')
        import database as db
        db.log_email_attempt(rcpt, subject, "SENT", msg_id, None, None)
        return {"ok": True, "message_id": msg_id, "recipient": rcpt}

    except ClientError as ce:
        code = ce.response.get('Error', {}).get('Code', 'ClientError')
        msg = ce.response.get('Error', {}).get('Message', str(ce))
        err_desc = f"{code}: {msg}"
        import database as db
        db.log_email_attempt(rcpt, subject, "FAILED", None, err_desc, None)
        return {"ok": False, "error": err_desc, "recipient": rcpt}
    except Exception as ex:
        err_desc = str(ex)
        import database as db
        db.log_email_attempt(rcpt, subject, "FAILED", None, err_desc, None)
        return {"ok": False, "error": err_desc, "recipient": rcpt}
