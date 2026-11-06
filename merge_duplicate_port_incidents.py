#!/usr/bin/env python3
"""
BSMART SOC — Duplicate Port Incident Consolidation Tool
Consolidates duplicate rapid-fire port/exposed service incidents (e.g. INC-534, 535, 536)
into a single primary open incident, marking duplicates as 'merged' with an audit log.

Zero data loss: audit entries and history are preserved.
"""

import sys
import os
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()
import database as db

def merge_port_duplicates():
    print("=" * 72)
    print(" BSMART SOC — DUPLICATE PORT INCIDENT MERGE TOOL")
    print("=" * 72)

    conn = db.get_db_connection()
    if not conn:
        print("[!] ERROR: Unable to connect to PostgreSQL database.")
        return

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, severity, description, status, server_id, created_at
                FROM incidents
                WHERE (title ILIKE '%port%' OR title ILIKE '%exposed%')
                  AND status IN ('open', 'active')
                ORDER BY server_id ASC, created_at ASC;
            """)
            rows = [dict(r) if isinstance(r, dict) else {
                "id": r[0], "title": r[1], "severity": r[2], "description": r[3],
                "status": r[4], "server_id": r[5], "created_at": r[6]
            } for r in cur.fetchall()]

            if not rows:
                print("[*] No open duplicate port incidents found to merge.")
                return

            print(f"[*] Found {len(rows)} open port/exposed service incidents. Analyzing clusters...")

            # Group by server_id and port number
            clusters = {}
            for r in rows:
                desc = r.get("description", "")
                m = re.search(r'port\s+(\d+)', desc, re.I)
                port = m.group(1) if m else "general"
                key = (r["server_id"], port)
                if key not in clusters:
                    clusters[key] = []
                clusters[key].append(r)

            merged_total = 0
            for (srv_id, port), cluster in clusters.items():
                if len(cluster) <= 1:
                    continue

                primary = cluster[0]
                duplicates = cluster[1:]
                dup_ids = [d["id"] for d in duplicates]

                print(f"\n[+] Merging cluster for Server #{srv_id} (Port {port}):")
                print(f"    Primary Incident   : #{primary['id']} ({primary['title']} at {primary['created_at']})")
                print(f"    Duplicate Incidents: {dup_ids} ({len(duplicates)} records)")

                window_count = len(cluster)
                merge_note = (
                    f"\n\n[CONSOLIDATED EXPOSED PORT EVENT] Aggregated {window_count} occurrences of Port {port} exposure. "
                    f"Consolidated duplicate incident records: {dup_ids} into Primary Incident #{primary['id']}."
                )

                cur.execute("""
                    UPDATE incidents
                    SET description = description || %s,
                        updated_at = NOW()
                    WHERE id = %s;
                """, (merge_note, primary["id"]))

                cur.execute("""
                    UPDATE incidents
                    SET status = 'merged',
                        updated_at = NOW(),
                        description = description || %s
                    WHERE id = ANY(%s);
                """, (f"\n[MERGED into primary Incident #{primary['id']}]", dup_ids))

                audit_details = (
                    f"Merged {len(duplicates)} duplicate port incidents {dup_ids} into "
                    f"Primary Incident #{primary['id']} for Server #{srv_id} (Port {port})."
                )
                cur.execute("""
                    INSERT INTO audit_logs (user_id, action, target, target_type, target_id, detail, timestamp)
                    VALUES (1, 'MERGE_DUPLICATE_PORT_INCIDENTS', 'incidents', 'incident', %s, %s, NOW());
                """, (primary["id"], audit_details))

                merged_total += len(duplicates)

            conn.commit()
            print(f"\n[✓] Successfully merged {merged_total} duplicate port incidents into primary incident records.")
            print("[✓] Reversible audit trail entries logged in audit_logs.")

    except Exception as e:
        print(f"[!] Error during port incident merge: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    merge_port_duplicates()
