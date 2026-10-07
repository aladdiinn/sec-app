import os
# Mock env variables if needed, or rely on system
import ses_mailer

success = ses_mailer.send_smart_alert_email(
    alert_id=999,
    alert_title="Commands Detected - root",
    alert_type="AUDIT_commands_0",
    message="[Commands] User 'root' executed a monitored command using `debian-sa1`.",
    severity="WARNING",
    timestamp="2026-10-05 05:25:07+00:00",
    server_ip="10.0.0.21",
    hostname="bscom wfm tnd"
)

if success:
    print("Test email sent successfully!")
else:
    print("Failed to send test email. Check SES credentials and verified identities.")
