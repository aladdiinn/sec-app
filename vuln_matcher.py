import os, sys, time, logging, json
import database as db
import vuln_version

logger = logging.getLogger("security_monitor.vuln_matcher")

def scan_server_vulnerabilities(server_id: int) -> dict:
    """
    Run vulnerability matching for a single server.
    Compares installed packages and standalone software against advisory database.
    Distro-aware version comparison handles security backports correctly.
    """
    conn = db.get_db_connection()
    if not conn:
        return {"status": "error", "error": "Database unavailable"}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, hostname, os_info, agent_version, reboot_required, reboot_reasons FROM servers WHERE id = %s;", (server_id,))
            server = cur.fetchone()
            if not server:
                return {"status": "error", "error": f"Server {server_id} not found"}

            agent_ver = (server.get("agent_version") or "").strip()
            # Rule: Agent version check
            # For older agents show "Agent v1.5: inventory not supported, update the agent" instead of "0 vulnerabilities"
            try:
                ver_float = float(agent_ver)
            except ValueError:
                ver_float = 0.0

            if ver_float < 1.6:
                status_msg = f"Agent v{agent_ver}: inventory not supported, update the agent"
                cur.execute("""
                    UPDATE servers SET
                        vuln_scan_status = %s,
                        vuln_critical = 0,
                        vuln_high = 0,
                        vuln_medium = 0,
                        vuln_low = 0,
                        last_vuln_scan = NOW()
                    WHERE id = %s;
                """, (status_msg, server_id))
                return {
                    "server_id": server_id,
                    "status": "unsupported_agent",
                    "scan_status": status_msg,
                    "findings_count": 0,
                    "findings": []
                }

            # Fetch OS info
            cur.execute("SELECT * FROM server_os_info WHERE server_id = %s;", (server_id,))
            os_info = cur.fetchone()
            if not os_info:
                status_msg = "NOT CHECKED (no inventory received yet)"
                cur.execute("UPDATE servers SET vuln_scan_status = %s, last_vuln_scan = NOW() WHERE id = %s;", (status_msg, server_id))
                return {
                    "server_id": server_id,
                    "status": "no_inventory",
                    "scan_status": status_msg,
                    "findings_count": 0,
                    "findings": []
                }

            os_id = (os_info.get("os_id") or "").lower()
            os_ver = (os_info.get("os_version_id") or "").lower()
            kernel_release = (os_info.get("kernel_release") or "").strip()
            reboot_req = bool(os_info.get("reboot_required") or server.get("reboot_required"))

            # Rule: Unsupported / End-of-Life OS check
            is_eol = bool(os_info.get("is_eol"))
            eol_reason = os_info.get("eol_reason") or ""
            if not is_eol:
                if "ubuntu" in os_id:
                    try:
                        v_num = float(os_ver[:5])
                        if v_num < 20.04:
                            is_eol = True
                            eol_reason = f"Ubuntu {os_ver} reached end of standard support"
                    except: pass
                elif "centos" in os_id:
                    try:
                        if int(os_ver.split('.')[0]) <= 7:
                            is_eol = True
                            eol_reason = f"CentOS {os_ver} reached end of life"
                    except: pass
                elif "debian" in os_id:
                    try:
                        if int(os_ver.split('.')[0]) < 10:
                            is_eol = True
                            eol_reason = f"Debian {os_ver} reached end of life"
                    except: pass

            if is_eol:
                status_msg = f"No security data for this OS (reason: {eol_reason or 'End of standard support'})"
                cur.execute("UPDATE servers SET vuln_scan_status = %s, last_vuln_scan = NOW() WHERE id = %s;", (status_msg, server_id))
                return {
                    "server_id": server_id,
                    "status": "unsupported_os",
                    "scan_status": status_msg,
                    "findings_count": 0,
                    "findings": []
                }

            # Determine ecosystem for matching
            if "ubuntu" in os_id:
                ecosystem = f"Ubuntu:{os_ver}"
            elif "debian" in os_id:
                ecosystem = f"Debian:{os_ver.split('.')[0] if '.' in os_ver else os_ver}"
            elif "rhel" in os_id or "red hat" in os_id:
                ecosystem = f"Red Hat:{os_ver.split('.')[0] if '.' in os_ver else os_ver}"
            elif "rocky" in os_id:
                ecosystem = f"Rocky Linux:{os_ver.split('.')[0] if '.' in os_ver else os_ver}"
            elif "centos" in os_id:
                ecosystem = f"CentOS:{os_ver.split('.')[0] if '.' in os_ver else os_ver}"
            else:
                # Rule: Unknown or unsupported OS
                status_msg = f"No security data for this OS ({os_id} {os_ver})"
                cur.execute("UPDATE servers SET vuln_scan_status = %s, last_vuln_scan = NOW() WHERE id = %s;", (status_msg, server_id))
                return {
                    "server_id": server_id,
                    "status": "unsupported_os",
                    "scan_status": status_msg,
                    "findings_count": 0,
                    "findings": []
                }

            # Fetch installed packages for server
            cur.execute("SELECT name, version, arch, source_name, source_version FROM server_packages WHERE server_id = %s;", (server_id,))
            packages = cur.fetchall() or []

            # Fetch standalone software for server
            cur.execute("SELECT product, version, path, detection_evidence FROM server_software WHERE server_id = %s;", (server_id,))
            software = cur.fetchall() or []

            # Fetch applicable advisories from database
            cur.execute("""
                SELECT * FROM advisory_cves 
                WHERE ecosystem IN (%s, 'Standalone', 'Ubuntu:22.04', 'Debian:11', 'Red Hat:8');
            """, (ecosystem,))
            advisories = cur.fetchall() or []

            findings = []
            pkgs_by_name = {}
            for p in packages:
                pkgs_by_name[p["name"]] = p
                if p.get("source_name") and p["source_name"] != p["name"]:
                    pkgs_by_name[p["source_name"]] = p

            # 1. Match Packages
            for adv in advisories:
                adv_pkg = adv["package_name"]
                if adv_pkg in pkgs_by_name:
                    pkg = pkgs_by_name[adv_pkg]
                    inst_v = pkg["version"]
                    fix_v = adv.get("fixed_version")
                    if vuln_version.is_package_vulnerable(inst_v, fix_v, ecosystem):
                        # Check if kernel package is affected
                        is_kernel = "linux-image" in adv_pkg or "kernel" in adv_pkg
                        running_kernel_aff = False
                        if is_kernel and kernel_release:
                            running_kernel_aff = reboot_req or (kernel_release not in inst_v)

                        findings.append({
                            "cve_id": adv["cve_id"],
                            "package_name": adv_pkg,
                            "installed_version": inst_v,
                            "fixed_version": fix_v or "None",
                            "severity": (adv.get("severity") or "UNKNOWN").upper(),
                            "cvss_score": adv.get("cvss_score") or 0.0,
                            "epss_score": adv.get("epss_score") or 0.0,
                            "is_cisa_kev": bool(adv.get("is_cisa_kev", False)),
                            "reboot_required": reboot_req or running_kernel_aff,
                            "running_kernel_affected": running_kernel_aff,
                            "advisory_id": adv.get("advisory_id") or adv["cve_id"],
                            "summary": adv.get("summary") or ""
                        })

            # 2. Match Standalone Software
            for sw in software:
                prod = sw["product"]
                ver = sw["version"]
                for adv in advisories:
                    if adv["ecosystem"] == "Standalone" and adv["package_name"].lower() == prod.lower():
                        fix_v = adv.get("fixed_version")
                        if vuln_version.compare_semver(ver, fix_v) < 0:
                            findings.append({
                                "cve_id": adv["cve_id"],
                                "package_name": prod,
                                "installed_version": ver,
                                "fixed_version": fix_v,
                                "severity": (adv.get("severity") or "UNKNOWN").upper(),
                                "cvss_score": adv.get("cvss_score") or 0.0,
                                "epss_score": adv.get("epss_score") or 0.0,
                                "is_cisa_kev": bool(adv.get("is_cisa_kev", False)),
                                "reboot_required": False,
                                "running_kernel_affected": False,
                                "advisory_id": adv.get("advisory_id") or adv["cve_id"],
                                "summary": f"{adv.get('summary', '')} (Found at {sw.get('path', '')})"
                            })

            # 3. Atomically update server_vulnerabilities table
            cur.execute("DELETE FROM server_vulnerabilities WHERE server_id = %s;", (server_id,))
            crit_cnt, high_cnt, med_cnt, low_cnt = 0, 0, 0, 0

            for f in findings:
                sev = f["severity"].upper()
                if sev == "CRITICAL": crit_cnt += 1
                elif sev == "HIGH": high_cnt += 1
                elif sev == "MEDIUM": med_cnt += 1
                elif sev == "LOW": low_cnt += 1

                cur.execute("""
                    INSERT INTO server_vulnerabilities (
                        server_id, cve_id, package_name, installed_version, fixed_version,
                        fix_state, severity, cvss_score, epss_score, is_cisa_kev,
                        reboot_required, running_kernel_affected, advisory_id, summary,
                        detected_at, status
                    ) VALUES (%s, %s, %s, %s, %s, 'needed', %s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'active')
                    ON CONFLICT (server_id, cve_id, package_name) DO UPDATE SET
                        installed_version = EXCLUDED.installed_version,
                        fixed_version = EXCLUDED.fixed_version,
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score,
                        epss_score = EXCLUDED.epss_score,
                        is_cisa_kev = EXCLUDED.is_cisa_kev,
                        reboot_required = EXCLUDED.reboot_required,
                        running_kernel_affected = EXCLUDED.running_kernel_affected,
                        summary = EXCLUDED.summary,
                        status = 'active';
                """, (
                    server_id,
                    f["cve_id"],
                    f["package_name"],
                    f["installed_version"],
                    f["fixed_version"],
                    sev,
                    f["cvss_score"],
                    f["epss_score"],
                    f["is_cisa_kev"],
                    f["reboot_required"],
                    f["running_kernel_affected"],
                    f["advisory_id"],
                    f["summary"]
                ))

            # Update servers table summary
            cur.execute("""
                UPDATE servers SET
                    vuln_critical = %s,
                    vuln_high = %s,
                    vuln_medium = %s,
                    vuln_low = %s,
                    vuln_scan_status = 'scanned',
                    last_vuln_scan = NOW()
                WHERE id = %s;
            """, (crit_cnt, high_cnt, med_cnt, low_cnt, server_id))

            # Step 6: Alerts & Audit Log for Critical vulnerabilities
            server_name = server.get("hostname") or server.get("name") or f"Server #{server_id}"
            for f in findings:
                if f["severity"] == "CRITICAL" and (f["is_cisa_kev"] or f["cvss_score"] >= 9.0) and f["fixed_version"] and f["fixed_version"] != "None":
                    try:
                        cur.execute("""
                            SELECT id FROM alerts 
                            WHERE server_id = %s AND alert_type = 'VULNERABILITY_CRITICAL' 
                              AND title LIKE %s AND is_resolved IS NOT TRUE;
                        """, (server_id, f"%{f['cve_id']}%"))
                        if not cur.fetchone():
                            alert_title = f"CRITICAL CVE DETECTED: {f['cve_id']} on {server_name}"
                            alert_msg = f"Package {f['package_name']} ({f['installed_version']}) is vulnerable to {f['cve_id']} (CVSS {f['cvss_score']:.1f}). Fixed in {f['fixed_version']}."
                            db.log_alert(
                                server_id=server_id,
                                alert_type="VULNERABILITY_CRITICAL",
                                message=alert_msg,
                                severity="critical",
                                title=alert_title
                            )
                    except Exception as ex_a:
                        logger.error(f"Failed to log vulnerability alert: {ex_a}")

            try:
                db.log_audit(
                    username="system",
                    action="VULN_SCAN_DETECTED",
                    target_type="server",
                    target_id=str(server_id),
                    detail=f"Detected {len(findings)} vulnerabilities ({crit_cnt} critical, {high_cnt} high)"
                )
            except Exception as ex_aud:
                logger.error(f"Failed to log audit entry: {ex_aud}")

            logger.info(f"Server {server_id} scanned: {len(findings)} findings (C:{crit_cnt} H:{high_cnt} M:{med_cnt} L:{low_cnt})")
            return {
                "server_id": server_id,
                "status": "success",
                "scan_status": "scanned",
                "findings_count": len(findings),
                "critical": crit_cnt,
                "high": high_cnt,
                "medium": med_cnt,
                "low": low_cnt,
                "findings": findings
            }
    finally:
        conn.close()


def scan_all_servers_vulnerabilities() -> dict:
    """Scan all registered servers fleet-wide in background."""
    conn = db.get_db_connection()
    if not conn: return {"status": "error", "error": "Database unavailable"}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, hostname, agent_version FROM servers ORDER BY id ASC;")
            servers = cur.fetchall() or []
    finally:
        conn.close()

    results = []
    for srv in servers:
        sid = srv["id"]
        res = scan_server_vulnerabilities(sid)
        results.append(res)

    return {
        "status": "success",
        "scanned_count": len(results),
        "results": results
    }
