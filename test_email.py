import os
import sys
from dotenv import load_dotenv

load_dotenv()

import ses_mailer
import database as db

settings = db.get_settings()
raw_val = settings.get("email_notifications_enabled", "true")
is_enabled = ses_mailer.is_email_dispatch_enabled()

print("====================================================================")
print("  BSMART SOC — AWS SES EMAIL ALERT DISPATCH VERIFICATION")
print("====================================================================")
print(f"[*] Setting 'email_notifications_enabled' in DB : '{raw_val}'")
print(f"[*] Current Dispatch Mode                       : {'✅ ENABLED' if is_enabled else '🛑 DISABLED (Suppressed)'}")

# Allow passing --force to bypass the disabled setting if intentionally testing SES connection
force_flag = "--force" in sys.argv

print("\n[*] Simulating Security Alert Dispatch (Critical Audit Event)...")
success = ses_mailer.send_smart_alert_email(
    alert_id=999,
    alert_title="Test Security Alert - SES Verification",
    alert_type="AUDIT_commands_0",
    message="[Security Test] Verification event generated to test SES alert email delivery.",
    severity="CRITICAL",
    timestamp="2026-11-06 13:45:00 UTC",
    server_ip="192.168.10.201",
    hostname="bsmart-soc-production",
    force=force_flag
)

print("--------------------------------------------------------------------")
if success:
    print("✅ RESULT: Alert email was DISPATCHED via AWS SES!")
    print("👉 Check your recipient email inbox to verify delivery.")
else:
    if not is_enabled and not force_flag:
        print("🛑 RESULT: Alert email was SUPPRESSED as expected!")
        print("👉 Reason: 'Global Alert Dispatch' is DISABLED in Settings.")
        print("👉 Zero emails sent to AWS SES. Disabling mail in UI is VERIFIED working!")
    else:
        print("ℹ️ RESULT: Alert email was NOT sent.")
        print("👉 Reason: Either suppressed by 15-minute deduplication for this asset/rule,")
        print("   or AWS SES credentials error. Pass --force to test bypassing dedup.")
print("====================================================================")
