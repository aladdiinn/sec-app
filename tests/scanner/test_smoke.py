#!/usr/bin/env python3
"""
Production Smoke Test for Security Scanner & Domain VAPT (SHCHECK).
Executes exactly one real scan per tab across all 7 tabs and outputs PASS or FAIL.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import scanner_engine as se
import database as db

def run_smoke_test():
    print("\n" + "="*70)
    print("PRODUCTION SMOKE TEST: SECURITY SCANNER & DOMAIN VAPT (SHCHECK)")
    print("="*70 + "\n")

    db.init_db()
    tabs_status = {}

    # 1. HTTP Headers
    try:
        res = se.analyze_http_headers("https://example.com", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and "grade" in res and res.get("score") is not None
        tabs_status["Tab 1: HTTP Headers"] = ("PASS" if passed else "FAIL", f"Grade: {res.get('grade')}, Score: {res.get('score')}")
    except Exception as e:
        tabs_status["Tab 1: HTTP Headers"] = ("FAIL", f"Exception: {e}")

    # 2. Domain VAPT
    try:
        res = se.run_full_domain_vapt("example.com", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and "findings" in res and res.get("vapt_score") is not None
        tabs_status["Tab 2: Domain VAPT"] = ("PASS" if passed else "FAIL", f"Score: {res.get('vapt_score')}, Findings: {len(res.get('findings', []))}")
    except Exception as e:
        tabs_status["Tab 2: Domain VAPT"] = ("FAIL", f"Exception: {e}")

    # 3. SSL / TLS
    try:
        res = se.analyze_ssl_certificate("example.com:443", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and "cipher" in res and res.get("valid") is True
        tabs_status["Tab 3: SSL / TLS"] = ("PASS" if passed else "FAIL", f"Valid: {res.get('valid')}, Grade: {res.get('grade')}, Protocol: {res.get('protocol')}")
    except Exception as e:
        tabs_status["Tab 3: SSL / TLS"] = ("FAIL", f"Exception: {e}")

    # 4. Port Scan
    try:
        res = se.scan_common_ports("scanme.nmap.org", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and len(res.get("ports", [])) > 0
        open_p = [p["port"] for p in res.get("ports", []) if p["status"] == "open"]
        tabs_status["Tab 4: Port Scan"] = ("PASS" if passed else "FAIL", f"Open ports: {open_p}")
    except Exception as e:
        tabs_status["Tab 4: Port Scan"] = ("FAIL", f"Exception: {e}")

    # 5. DNS Lookup
    try:
        res = se.lookup_dns_records("example.com", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and len(res.get("records", [])) > 0
        tabs_status["Tab 5: DNS Lookup"] = ("PASS" if passed else "FAIL", f"Records: {len(res.get('records', []))}, Security checks: {len(res.get('security', []))}")
    except Exception as e:
        tabs_status["Tab 5: DNS Lookup"] = ("FAIL", f"Exception: {e}")

    # 6. WHOIS / RDAP
    try:
        res = se.lookup_whois_rdap("example.com", force_refresh=True)
        passed = res.get("status") == "COMPLETED" and bool(res.get("registrar"))
        tabs_status["Tab 6: WHOIS / RDAP"] = ("PASS" if passed else "FAIL", f"Registrar: {res.get('registrar')}, Days left: {res.get('days_left')}")
    except Exception as e:
        tabs_status["Tab 6: WHOIS / RDAP"] = ("FAIL", f"Exception: {e}")

    # 7. Tech Stack
    try:
        res = se.fingerprint_technologies("https://example.com", force_refresh=True)
        passed = res.get("status") == "COMPLETED"
        tabs_status["Tab 7: Tech Stack"] = ("PASS" if passed else "FAIL", f"Shielded: {res.get('is_shielded')}, Tech count: {len(res.get('technologies', []))}")
    except Exception as e:
        tabs_status["Tab 7: Tech Stack"] = ("FAIL", f"Exception: {e}")

    # Output Results
    all_passed = True
    for tab, (status, detail) in tabs_status.items():
        print(f"[{status}] {tab:<24} | {detail}")
        if status != "PASS":
            all_passed = False

    print("\n" + "-"*70)
    if all_passed:
        print("ALL 7 TABS SMOKE TEST: PASS (Production Ready)")
    else:
        print("SMOKE TEST FAILED")
    print("-"*70 + "\n")

    return all_passed

if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
