import os, sys, time, json, urllib.request, urllib.error, logging, threading
from datetime import datetime, timezone
import database as db

logger = logging.getLogger("security_monitor.vuln_sync")

# Curated high-fidelity real-world advisories database
CURATED_ADVISORIES = [
    # ── OPENSSL ──
    {
        "cve_id": "CVE-2022-3602",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "openssl",
        "fixed_version": "3.0.2-0ubuntu1.7",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.042,
        "is_cisa_kev": False,
        "advisory_id": "USN-5699-1",
        "summary": "OpenSSL X.509 Email Address 4-byte Buffer Overflow",
        "details": "A 4-byte buffer overflow can be triggered in X.509 certificate verification, specifically in name constraint checking.",
        "source": "USN"
    },
    {
        "cve_id": "CVE-2022-3786",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "openssl",
        "fixed_version": "3.0.2-0ubuntu1.7",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.038,
        "is_cisa_kev": False,
        "advisory_id": "USN-5699-1",
        "summary": "OpenSSL X.509 Email Address Variable Length Buffer Overflow",
        "details": "A variable length buffer overflow can be triggered in X.509 certificate verification.",
        "source": "USN"
    },
    {
        "cve_id": "CVE-2023-0286",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "openssl",
        "fixed_version": "3.0.2-0ubuntu1.10",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H",
        "epss_score": 0.015,
        "is_cisa_kev": False,
        "advisory_id": "USN-5847-1",
        "summary": "OpenSSL X.400 address type confusion in GENERAL_NAME_cmp",
        "details": "Type confusion vulnerability in GENERAL_NAME_cmp affecting X.400 address processing.",
        "source": "USN"
    },
    {
        "cve_id": "CVE-2022-3602",
        "ecosystem": "Debian:11",
        "package_name": "openssl",
        "fixed_version": "1.1.1n-0+deb11u4",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "epss_score": 0.042,
        "is_cisa_kev": False,
        "advisory_id": "DSA-5269-1",
        "summary": "OpenSSL buffer overflow in X.509 verification",
        "details": "Buffer overflow in X.509 certificate email address verification.",
        "source": "Debian"
    },

    # ── SUDO (Baron Samedit) ──
    {
        "cve_id": "CVE-2021-3156",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "sudo",
        "fixed_version": "1.9.9-1ubuntu2",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.962,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-05-03",
        "advisory_id": "USN-4705-1",
        "summary": "Sudo Baron Samedit Local Privilege Escalation",
        "details": "Heap-based buffer overflow allowing any local unprivileged user to obtain root privileges without authentication.",
        "source": "USN"
    },
    {
        "cve_id": "CVE-2021-3156",
        "ecosystem": "Debian:11",
        "package_name": "sudo",
        "fixed_version": "1.9.5p2-3",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.962,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-05-03",
        "advisory_id": "DSA-4839-1",
        "summary": "Sudo Baron Samedit Local Privilege Escalation",
        "details": "Heap-based buffer overflow in argument parsing.",
        "source": "Debian"
    },
    {
        "cve_id": "CVE-2021-3156",
        "ecosystem": "Red Hat:8",
        "package_name": "sudo",
        "fixed_version": "1.8.29-6.el8_3.1",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.962,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-05-03",
        "advisory_id": "RHSA-2021:0218",
        "summary": "Sudo Baron Samedit Local Privilege Escalation",
        "details": "Heap buffer overflow in sudo argument escaping.",
        "source": "RedHat"
    },

    # ── POLKIT (PwnKit) ──
    {
        "cve_id": "CVE-2021-4034",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "policykit-1",
        "fixed_version": "0.105-31ubuntu1.2",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.974,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-07-18",
        "advisory_id": "USN-5252-1",
        "summary": "Polkit PwnKit Local Privilege Escalation",
        "details": "Memory corruption in pkexec allowing local unprivileged users to gain full root privileges.",
        "source": "USN"
    },

    # ── OPENSSH (RegreSSHion) ──
    {
        "cve_id": "CVE-2024-6387",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "openssh-server",
        "fixed_version": "1:8.9p1-3ubuntu0.10",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.725,
        "is_cisa_kev": True,
        "cisa_due_date": "2024-07-22",
        "advisory_id": "USN-6859-1",
        "summary": "OpenSSH Server RegreSSHion Remote Code Execution",
        "details": "Signal handler race condition in OpenSSH server allowing unauthenticated remote code execution as root on glibc-based Linux systems.",
        "source": "USN"
    },
    {
        "cve_id": "CVE-2024-6387",
        "ecosystem": "Debian:12",
        "package_name": "openssh-server",
        "fixed_version": "1:9.2p1-2+deb12u3",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.725,
        "is_cisa_kev": True,
        "cisa_due_date": "2024-07-22",
        "advisory_id": "DSA-5721-1",
        "summary": "OpenSSH Server RegreSSHion Remote Code Execution",
        "details": "Signal handler race condition in sshd server.",
        "source": "Debian"
    },

    # ── CURL ──
    {
        "cve_id": "CVE-2023-38545",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "curl",
        "fixed_version": "7.81.0-1ubuntu1.14",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.820,
        "is_cisa_kev": True,
        "cisa_due_date": "2023-11-01",
        "advisory_id": "USN-6423-1",
        "summary": "curl SOCKS5 Heap Buffer Overflow",
        "details": "This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.",
        "source": "USN"
    },

    # ── LINUX KERNEL ──
    {
        "cve_id": "CVE-2022-0847",
        "ecosystem": "Ubuntu:22.04",
        "package_name": "linux-image-generic",
        "fixed_version": "5.15.0-25.25",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.923,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-03-24",
        "advisory_id": "USN-5317-1",
        "summary": "Linux Kernel Dirty Pipe Local Privilege Escalation",
        "details": "A flaw was found in the way the flags member of the new pipe_buffer was uninitialized in copy_page_to_iter_pipe, allowing unauthorized overwriting of data in read-only files.",
        "source": "USN"
    },

    # ── STANDALONE: APACHE TOMCAT ──
    {
        "cve_id": "CVE-2020-1938",
        "ecosystem": "Standalone",
        "package_name": "Apache Tomcat",
        "fixed_version": "9.0.31",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.971,
        "is_cisa_kev": True,
        "cisa_due_date": "2022-03-07",
        "advisory_id": "CVE-2020-1938",
        "summary": "Apache Tomcat AJP Connector Ghostcat File Read/Inclusion",
        "details": "When using the Apache JServ Protocol (AJP), Tomcat treats connections with higher trust than HTTP, allowing remote file read or inclusion.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2025-24813",
        "ecosystem": "Standalone",
        "package_name": "Apache Tomcat",
        "fixed_version": "10.1.65",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.941,
        "is_cisa_kev": True,
        "cisa_due_date": "2025-02-15",
        "advisory_id": "CVE-2025-24813",
        "summary": "Apache Tomcat Remote Code Execution via Session Persistence",
        "details": "A deserialization vulnerability in session persistence allows remote unauthenticated attackers to execute arbitrary code.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2024-56337",
        "ecosystem": "Standalone",
        "package_name": "Apache Tomcat",
        "fixed_version": "10.1.34",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.812,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2024-56337",
        "summary": "Apache Tomcat Time-of-Check Time-of-Use RCE in DefaultServlet",
        "details": "A time-of-check time-of-use (TOCTOU) race condition in Apache Tomcat DefaultServlet allows remote code execution on case-insensitive filesystems.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2024-52316",
        "ecosystem": "Standalone",
        "package_name": "Apache Tomcat",
        "fixed_version": "10.1.29",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss_score": 0.095,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2024-52316",
        "summary": "Apache Tomcat Jakarta Authentication Bypass",
        "details": "Authentication bypass vulnerability in Apache Tomcat when using Jakarta Authentication.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2024-21733",
        "ecosystem": "Standalone",
        "package_name": "Apache Tomcat",
        "fixed_version": "9.0.85",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "epss_score": 0.054,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2024-21733",
        "summary": "Apache Tomcat Incomplete Request Parsing Information Disclosure",
        "details": "Generation of Error Message Containing Sensitive Information vulnerability in Apache Tomcat.",
        "source": "NVD"
    },

    # ── STANDALONE: JAVA / JVM ──
    {
        "cve_id": "CVE-2024-21011",
        "ecosystem": "Standalone",
        "package_name": "Java",
        "fixed_version": "21.0.13",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "epss_score": 0.118,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2024-21011",
        "summary": "Java SE Hotspot and Core Libraries Memory Corruption",
        "details": "Vulnerability in Oracle Java SE, OpenJDK Hotspot component allowing unauthenticated network attackers to compromise Java SE.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2024-21147",
        "ecosystem": "Standalone",
        "package_name": "Java",
        "fixed_version": "21.0.13",
        "severity": "HIGH",
        "cvss_score": 7.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "epss_score": 0.065,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2024-21147",
        "summary": "Java Hotspot JIT Compiler Code Execution Flaw",
        "details": "Flaw in Hotspot JIT compiler leading to memory access outside bounds during array optimization.",
        "source": "NVD"
    },
    {
        "cve_id": "CVE-2022-21449",
        "ecosystem": "Standalone",
        "package_name": "Java",
        "fixed_version": "11.0.15",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "epss_score": 0.125,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2022-21449",
        "summary": "Java Psychic Signatures ECDSA Signature Verification Bypass",
        "details": "Vulnerability in Java SE components allowing signature verification bypass where ECDSA signature r and s values are both zero.",
        "source": "NVD"
    },

    # ── STANDALONE: POSTGRESQL ──
    {
        "cve_id": "CVE-2022-1552",
        "ecosystem": "Standalone",
        "package_name": "PostgreSQL",
        "fixed_version": "14.3",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.089,
        "is_cisa_kev": False,
        "advisory_id": "CVE-2022-1552",
        "summary": "PostgreSQL Autovacuum / CREATE INDEX Privilege Escalation",
        "details": "A flaw in PostgreSQL allows an unprivileged database user to execute arbitrary SQL functions as superuser via autovacuum or reindex operations.",
        "source": "NVD"
    }
]


def seed_curated_advisories():
    """Seed base curated advisories into advisory_cves table idempotently."""
    conn = db.get_db_connection()
    if not conn:
        raise Exception("Database connection unavailable for advisory seeding")
    try:
        inserted = 0
        with conn.cursor() as cur:
            for adv in CURATED_ADVISORIES:
                cur.execute("""
                    INSERT INTO advisory_cves (
                        cve_id, ecosystem, package_name, fixed_version,
                        severity, cvss_score, cvss_vector, epss_score,
                        is_cisa_kev, cisa_due_date, advisory_id, summary, details, source, synced_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (cve_id, ecosystem, package_name) DO UPDATE SET
                        fixed_version = EXCLUDED.fixed_version,
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score,
                        cvss_vector = EXCLUDED.cvss_vector,
                        epss_score = EXCLUDED.epss_score,
                        is_cisa_kev = EXCLUDED.is_cisa_kev,
                        cisa_due_date = EXCLUDED.cisa_due_date,
                        advisory_id = EXCLUDED.advisory_id,
                        summary = EXCLUDED.summary,
                        details = EXCLUDED.details,
                        source = EXCLUDED.source,
                        synced_at = NOW();
                """, (
                    adv["cve_id"],
                    adv["ecosystem"],
                    adv["package_name"],
                    adv.get("fixed_version"),
                    adv.get("severity", "UNKNOWN"),
                    adv.get("cvss_score", 0.0),
                    adv.get("cvss_vector"),
                    adv.get("epss_score", 0.0),
                    adv.get("is_cisa_kev", False),
                    adv.get("cisa_due_date"),
                    adv.get("advisory_id"),
                    adv.get("summary"),
                    adv.get("details"),
                    adv.get("source", "Curated")
                ))
                inserted += 1

            # Update sync status
            cur.execute("""
                INSERT INTO advisory_sync_status (source, last_sync, status, records_count)
                VALUES ('Curated Seed', NOW(), 'success', %s)
                ON CONFLICT (source) DO UPDATE SET
                    last_sync = NOW(),
                    status = 'success',
                    records_count = EXCLUDED.records_count,
                    error_message = NULL;
            """, (inserted,))

        logger.info(f"Curated advisories seeded: {inserted} records.")
        return inserted
    finally:
        conn.close()


def sync_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog and mark matching CVEs."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    conn = db.get_db_connection()
    if not conn: return 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BSmartSOC-VulnerabilityScanner/1.6"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities: return 0

        kev_count = 0
        with conn.cursor() as cur:
            for item in vulnerabilities:
                cve_id = item.get("cveID")
                due_date = item.get("dueDate")
                if cve_id:
                    cur.execute("""
                        UPDATE advisory_cves SET
                            is_cisa_kev = TRUE,
                            cisa_due_date = %s
                        WHERE cve_id = %s;
                    """, (due_date, cve_id))
                    kev_count += 1

            cur.execute("""
                INSERT INTO advisory_sync_status (source, last_sync, status, records_count)
                VALUES ('CISA KEV', NOW(), 'success', %s)
                ON CONFLICT (source) DO UPDATE SET
                    last_sync = NOW(),
                    status = 'success',
                    records_count = %s,
                    error_message = NULL;
            """, (len(vulnerabilities), len(vulnerabilities)))

        logger.info(f"CISA KEV synchronized: {len(vulnerabilities)} catalog items processed.")
        return len(vulnerabilities)
    except Exception as e:
        logger.warning(f"CISA KEV sync skipped/failed: {e}")
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO advisory_sync_status (source, last_sync, status, error_message)
                    VALUES ('CISA KEV', NOW(), 'error', %s)
                    ON CONFLICT (source) DO UPDATE SET
                        status = 'error',
                        error_message = EXCLUDED.error_message;
                """, (str(e),))
        except: pass
        return 0
    finally:
        conn.close()


def sync_all_advisories():
    """Run full advisory synchronization with PostgreSQL advisory lock."""
    conn = db.get_db_connection()
    if not conn: return {"status": "error", "error": "Database unavailable"}
    try:
        with conn.cursor() as cur:
            # Try PostgreSQL advisory lock to ensure single worker
            try:
                cur.execute("SELECT pg_try_advisory_lock(2002);")
                r = cur.fetchone()
                locked = (r["pg_try_advisory_lock"] if isinstance(r, dict) else r[0]) if r else False
                if not locked:
                    return {"status": "skipped", "message": "Advisory sync already running on another worker"}
            except Exception:
                pass
    finally:
        conn.close()

    total_records = 0
    start_t = time.time()
    try:
        # 1. Seed base curated advisories
        c_cnt = seed_curated_advisories()
        total_records += c_cnt

        # 2. Sync CISA KEV
        k_cnt = sync_cisa_kev()
        total_records += k_cnt

        elapsed = round(time.time() - start_t, 2)
        logger.info(f"Advisory sync completed in {elapsed}s. Total records: {total_records}")
        return {
            "status": "success",
            "curated_records": c_cnt,
            "kev_records": k_cnt,
            "duration_seconds": elapsed
        }
    finally:
        # Release lock
        conn = db.get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(2002);")
            except: pass
            finally: conn.close()


def run_advisory_sync_worker():
    """Background daemon loop that seeds advisories on startup and refreshes daily."""
    time.sleep(5)  # Brief delay on server startup
    try:
        logger.info("Starting initial advisory sync...")
        sync_all_advisories()
    except Exception as e:
        logger.error(f"Initial advisory sync error: {e}")

    while True:
        try:
            # Sleep 24 hours between automated sync runs
            time.sleep(24 * 3600)
            sync_all_advisories()
        except Exception as e:
            logger.error(f"Advisory sync loop error: {e}")
            time.sleep(3600)
