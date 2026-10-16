#!/usr/bin/env python3
"""
Live Ground-Truth Regression Verification Script for Security Scanner & Domain VAPT.
Tests live reference targets across all 7 tabs and outputs an accuracy table:
(Tab, Target / Test, Expected, Got, PASS/FAIL).
"""

import sys
import os
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import scanner_engine as se
import database as db

def run_ground_truth_tests():
    # Ensure DB tables are initialized
    db.init_db()

    results = []

    def record(tab, test, expected, got, passed):
        status = "PASS" if passed else "FAIL"
        results.append({
            "tab": tab,
            "test": test,
            "expected": expected,
            "got": str(got),
            "status": status
        })
        print(f"[{status}] {tab} | {test} -> Expected: {expected} | Got: {got}")

    print("\n" + "="*80)
    print("RUNNING LIVE GROUND-TRUTH ACCURACY REGRESSION SUITE")
    print("="*80 + "\n")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 1: HTTP HEADERS
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 1: HTTP HEADERS ---")
    try:
        gh_h = se.analyze_http_headers("https://github.com", force_refresh=True)
        # GitHub has strict HSTS max-age 31536000, preload, CSP unsafe-inline (deduction -12), score 80 (Grade B)
        grade = gh_h.get("grade", "")
        hsts_valid = gh_h.get("hsts_valid", False)
        record("HTTP Headers", "github.com Grade (Observatory Formula)", "Grade A/B (Score >= 80)", f"Grade: {grade} (Score: {gh_h.get('score')})", grade in ("A", "A+", "B", "B+"))
        record("HTTP Headers", "github.com HSTS Validity", "True", str(hsts_valid), hsts_valid is True)
    except Exception as e:
        record("HTTP Headers", "github.com", "Grade A/B", f"Exception: {e}", False)

    try:
        ex_h = se.analyze_http_headers("http://example.com", force_refresh=True)
        redirect_chain = ex_h.get("redirect_chain", [])
        final_url = ex_h.get("final_url", "")
        record("HTTP Headers", "example.com Redirect Chain & URL", "Tracked chain and final URL", f"{len(redirect_chain)} hops, final: {final_url}", len(redirect_chain) > 0 and bool(final_url))
    except Exception as e:
        record("HTTP Headers", "example.com", "Tracked chain", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 2: DOMAIN VAPT AUDIT
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 2: DOMAIN VAPT AUDIT ---")
    try:
        vapt_res = se.run_full_domain_vapt("example.com", force_refresh=True)
        status = vapt_res.get("status", "")
        findings = vapt_res.get("findings", [])
        has_evidence = all("evidence" in f and f["evidence"] for f in findings)
        no_banner_cve = all("CVE-" not in f["title"] or "CONFIRMED" in f.get("confidence", "") for f in findings)
        record("Domain VAPT", "example.com Execution", "COMPLETED", status, status == "COMPLETED")
        record("Domain VAPT", "All Findings Have Real Evidence", "True", str(has_evidence), has_evidence)
        record("Domain VAPT", "Zero Banner-Guessed CVEs", "True", str(no_banner_cve), no_banner_cve)
    except Exception as e:
        record("Domain VAPT", "example.com", "Completed with evidence", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 3: SSL / TLS INSPECTION (badssl.com ground truth & production targets)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 3: SSL / TLS INSPECTION ---")
    # 1. Expired cert
    try:
        exp_res = se.analyze_ssl_certificate("expired.badssl.com:443", force_refresh=True)
        valid = exp_res.get("valid", True)
        grade = exp_res.get("grade", "")
        record("SSL / TLS", "expired.badssl.com (valid=False, grade=F)", "valid: False, grade: F", f"valid: {valid}, grade: {grade}", (valid is False and grade == "F"))
    except Exception as e:
        record("SSL / TLS", "expired.badssl.com", "valid: False, grade: F", f"Exception: {e}", False)

    # 2. Wrong host cert
    try:
        wh_res = se.analyze_ssl_certificate("wrong.host.badssl.com:443", force_refresh=True)
        valid = wh_res.get("valid", True)
        grade = wh_res.get("grade", "")
        san_match = wh_res.get("hostname_match", True)
        record("SSL / TLS", "wrong.host.badssl.com (hostname_match=False)", "valid: False, hostname_match: False", f"valid: {valid}, hostname_match: {san_match}", (valid is False and san_match is False))
    except Exception as e:
        record("SSL / TLS", "wrong.host.badssl.com", "valid: False, hostname_match: False", f"Exception: {e}", False)

    # 3. Self-signed cert
    try:
        ss_res = se.analyze_ssl_certificate("self-signed.badssl.com:443", force_refresh=True)
        valid = ss_res.get("valid", True)
        grade = ss_res.get("grade", "")
        record("SSL / TLS", "self-signed.badssl.com (self_signed=True, grade=F)", "valid: False, grade: F", f"valid: {valid}, grade: {grade}", (valid is False and grade == "F"))
    except Exception as e:
        record("SSL / TLS", "self-signed.badssl.com", "valid: False, grade: F", f"Exception: {e}", False)

    # 4. Untrusted root cert
    try:
        ur_res = se.analyze_ssl_certificate("untrusted-root.badssl.com:443", force_refresh=True)
        valid = ur_res.get("valid", True)
        grade = ur_res.get("grade", "")
        record("SSL / TLS", "untrusted-root.badssl.com (untrusted=True, grade=F)", "valid: False, grade: F", f"valid: {valid}, grade: {grade}", (valid is False and grade in ("F", "N/A")))
    except Exception as e:
        record("SSL / TLS", "untrusted-root.badssl.com", "valid: False, grade: F", f"Exception: {e}", False)

    # 5. github.com cert (valid reference)
    try:
        gh_tls = se.analyze_ssl_certificate("github.com:443", force_refresh=True)
        valid = gh_tls.get("valid", False)
        grade = gh_tls.get("grade", "")
        tls13 = gh_tls.get("protocols_supported", {}).get("TLSv1.3", False)
        record("SSL / TLS", "github.com:443 (valid=True, grade=A/A+)", "valid: True, grade: A/A+", f"valid: {valid}, grade: {grade}, TLS1.3: {tls13}", (valid is True and grade in ("A", "A+")))
    except Exception as e:
        record("SSL / TLS", "github.com:443", "valid: True, grade: A/A+", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 4: PORT SCANNER
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 4: PORT SCANNER ---")
    # SSRF Protection
    try:
        ssrf_res = se.scan_common_ports("127.0.0.1")
        ssrf_ok = ssrf_res.get("status") == "NOT CHECKED" and "SSRF Blocked" in ssrf_res.get("reason", "")
        record("Port Scan", "SSRF Rejection (127.0.0.1)", "NOT CHECKED (SSRF Blocked)", f"{ssrf_res.get('status')}: {ssrf_res.get('reason')}", ssrf_ok)
    except Exception as e:
        record("Port Scan", "SSRF Rejection (127.0.0.1)", "NOT CHECKED", f"Exception: {e}", False)

    # Unapproved host rejection
    try:
        unapp_res = se.scan_common_ports("example.org")
        unapp_ok = unapp_res.get("status") == "NOT CHECKED" and "Authorization required" in unapp_res.get("reason", "")
        record("Port Scan", "Unapproved Target Rejection (example.org)", "NOT CHECKED (Authorization Required)", f"{unapp_res.get('status')}: {unapp_res.get('reason')}", unapp_ok)
    except Exception as e:
        record("Port Scan", "Unapproved Target Rejection", "NOT CHECKED", f"Exception: {e}", False)

    # Approved target scan (scanme.nmap.org)
    try:
        nmap_res = se.scan_common_ports("scanme.nmap.org", force_refresh=True)
        status = nmap_res.get("status", "")
        ports = nmap_res.get("ports", [])
        open_ports = [p["port"] for p in ports if p["status"] == "open"]
        # nmap scanme.nmap.org typically has 22 or 80 open
        has_standard_port = any(p in open_ports for p in [22, 80])
        record("Port Scan", "scanme.nmap.org (Match Reference Nmap)", "Open port 22 or 80 detected", f"Open ports: {open_ports}", has_standard_port)
    except Exception as e:
        record("Port Scan", "scanme.nmap.org", "Open port 22 or 80", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 5: DNS LOOKUP
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 5: DNS LOOKUP ---")
    try:
        dns_res = se.lookup_dns_records("example.com", force_refresh=True)
        records = dns_res.get("records", [])
        has_a = any(r.get("type") == "A" for r in records)
        has_ns = any(r.get("type") == "NS" for r in records) or len(dns_res.get("nameservers", [])) > 0
        dnssec_entry = next((s for s in dns_res.get("security", []) if "DNSSEC" in s.get("name", "")), {})
        dnssec = dnssec_entry.get("value", "")
        record("DNS Lookup", "example.com A & NS Records", "Resolved", f"A: {has_a}, NS: {has_ns}", (has_a and has_ns))
        record("DNS Lookup", "example.com DNSSEC Cryptographic Validation", "SECURE / VALIDATED", dnssec, "SECURE" in dnssec)
    except Exception as e:
        record("DNS Lookup", "example.com", "Resolved with DNSSEC", f"Exception: {e}", False)

    try:
        gh_dns = se.lookup_dns_records("github.com", force_refresh=True)
        spf_entry = next((s for s in gh_dns.get("security", []) if "SPF" in s.get("name", "")), {})
        has_spf = spf_entry.get("status") == "present"
        record("DNS Lookup", "github.com SPF Record Parsing", "Configured (True)", f"configured: {has_spf}, record: {spf_entry.get('value', '')[:40]}", has_spf)
    except Exception as e:
        record("DNS Lookup", "github.com", "SPF Configured", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 6: WHOIS / RDAP
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 6: WHOIS / RDAP ---")
    try:
        whois_res = se.lookup_whois_rdap("example.com", force_refresh=True)
        registrar = whois_res.get("registrar", "")
        created = whois_res.get("created", "")
        days_left = whois_res.get("days_left") or whois_res.get("days_to_expiry") or 0
        source = whois_res.get("source", "")
        # example.com is registered by IANA
        iana_match = "IANA" in registrar or "Internet Assigned Numbers Authority" in registrar or "ICANN" in registrar
        record("WHOIS / RDAP", "example.com Registrar via IANA RDAP", "IANA / ICANN", f"Registrar: {registrar} (Source: {source})", iana_match)
        record("WHOIS / RDAP", "example.com Days to Expiry Calculation", "days > 0", f"Days left: {days_left}, Created: {created}", (days_left is not None and days_left > 0))
    except Exception as e:
        record("WHOIS / RDAP", "example.com", "IANA RDAP data", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 7: TECH STACK FINGERPRINTING
    # ══════════════════════════════════════════════════════════════════════════
    print("\n--- TAB 7: TECH STACK ---")
    try:
        cf_tech = se.fingerprint_technologies("https://cloudflare.com", force_refresh=True)
        is_shielded = cf_tech.get("is_shielded", False)
        tech_names = [t["name"] for t in cf_tech.get("technologies", [])]
        record("Tech Stack", "cloudflare.com Shield & CDN Detection", "Cloudflare detected, is_shielded: True", f"is_shielded: {is_shielded}, Tech: {tech_names}", (is_shielded is True and any("Cloudflare" in n for n in tech_names)))
    except Exception as e:
        record("Tech Stack", "cloudflare.com", "Cloudflare shield", f"Exception: {e}", False)

    try:
        gh_tech = se.fingerprint_technologies("https://github.com", force_refresh=True)
        tech_list = gh_tech.get("technologies", [])
        evidence_intact = all("evidence" in t and t["evidence"] for t in tech_list)
        record("Tech Stack", "github.com Fingerprint Evidence Integrity", "All evidence verifiable", f"Count: {len(tech_list)}, evidence intact: {evidence_intact}", evidence_intact and len(tech_list) > 0)
    except Exception as e:
        record("Tech Stack", "github.com", "Evidence verified", f"Exception: {e}", False)

    # ══════════════════════════════════════════════════════════════════════════
    # PRINT ACCURACY TABLE
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("LIVE GROUND-TRUTH ACCURACY TABLE")
    print("="*80)
    col_tab = 16
    col_test = 36
    col_exp = 30
    col_got = 35
    col_stat = 8

    header = f"| {'Tab':<{col_tab}} | {'Test Case':<{col_test}} | {'Expected':<{col_exp}} | {'Got':<{col_got}} | {'Status':<{col_stat}} |"
    sep = f"|{'-'*(col_tab+2)}|{'-'*(col_test+2)}|{'-'*(col_exp+2)}|{'-'*(col_got+2)}|{'-'*(col_stat+2)}|"
    print(header)
    print(sep)

    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")

    for r in results:
        t = (r["tab"][:col_tab-2] + "..") if len(r["tab"]) > col_tab else r["tab"]
        test = (r["test"][:col_test-2] + "..") if len(r["test"]) > col_test else r["test"]
        exp = (r["expected"][:col_exp-2] + "..") if len(r["expected"]) > col_exp else r["expected"]
        got = (r["got"][:col_got-2] + "..") if len(r["got"]) > col_got else r["got"]
        print(f"| {t:<{col_tab}} | {test:<{col_test}} | {exp:<{col_exp}} | {got:<{col_got}} | {r['status']:<{col_stat}} |")

    print(sep)
    print(f"\nTOTAL TESTS: {len(results)} | PASSED: {pass_count} | FAILED: {fail_count}")
    if fail_count == 0:
        print(">> REGRESSION SUITE: 100% PASS <<\n")
    else:
        print(f">> REGRESSION SUITE: {fail_count} FAILED <<\n")

    return fail_count == 0

if __name__ == "__main__":
    success = run_ground_truth_tests()
    sys.exit(0 if success else 1)
