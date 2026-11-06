#!/usr/bin/env python3
"""
BSMART SOC — Duplicate Incident Consolidation Tool
Merges duplicate rapid-fire traffic incidents (e.g. INC-307, 308, 312) into
a single consolidated incident, recording a reversible audit entry in audit_logs.

NEVER bulk-closes without a full audit log.
"""

import sys
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

import database as db

def merge_duplicates():
    print("=" * 72)
    print(" BSMART SOC — DUPLICATE TRAFFIC INCIDENT MERGE TOOL")
    print("=" * 72)

    conn = db.get_db_connection()
    if not conn:
        print("[!] ERROR: Unable to connect to PostgreSQL database.")
        return

    try:
        with conn.cursor() as cur:
            # Find open traffic spike incidents
            cur.execute("""
                SELECT id, title, severity, description, status, server_id, created_at
                FROM incidents
                WHERE (title ILIKE '%traffic%' OR title ILIKE '%spike%')
                  AND status IN ('open', 'active')
                ORDER BY server_id ASC, created_at ASC;
            """)
            rows = [dict(r) if isinstance(r, dict) else {
                "id": r[0], "title": r[1], "severity": r[2], "description": r[3],
                "status": r[4], "server_id": r[5], "created_at": r[6]
            } for r in cur.fetchall()]

            if not rows:
                print("[*] No open duplicate traffic incidents found to merge.")
                return

            print(f"[*] Found {len(rows)} open traffic incidents. Analyzing clusters...")

            # Group into clusters per server where incidents are within 15 minutes of each other
            clusters = []
            current_cluster = []

            for r in rows:
                if not current_cluster:
                    current_cluster.append(r)
                else:
                    last = current_cluster[-1]
                    time_diff = (r["created_at"] - last["created_at"]).total_seconds()
                    same_server = (r["server_id"] == last["server_id"])

                    if same_server and time_diff <= 900: # 15 minutes
                        current_cluster.append(r)
                    else:
                        clusters.append(current_cluster)
                        current_cluster = [r]

            if current_cluster:
                clusters.append(current_cluster)

            merged_total = 0
            for cluster in clusters:
                if len(cluster) <= 1:
                    continue

                primary = cluster[0]
                duplicates = cluster[1:]
                dup_ids = [d["id"] for d in duplicates]

                print(f"\n[+] Merging cluster for Server #{primary['server_id']}:")
                print(f"    Primary Incident: #{primary['id']} ({primary['title']} at {primary['created_at']})")
                print(f"    Duplicate Incidents ({len(duplicates)}): {dup_ids}")

                # Update primary incident with consolidated window summary
                window_count = len(cluster)
                merge_note = (
                    f"\n\n[CONSOLIDATED TRAFFIC EVENT] Aggregated {window_count} consecutive anomalous windows "
                    f"spanning {(cluster[-1]['created_at'] - primary['created_at']).total_seconds() / 60:.1f} minutes. "
                    f"Merged duplicate incident records: {dup_ids}."
                )

                cur.execute("""
                    UPDATE incidents
                    SET description = description || %s,
                        updated_at = NOW()
                    WHERE id = %s;
                """, (merge_note, primary["id"]))

                # Mark duplicates as merged
                cur.execute("""
                    UPDATE incidents
                    SET status = 'merged',
                        updated_at = NOW(),
                        description = description || %s
                    WHERE id = ANY(%s);
                """, (f"\n[MERGED into primary Incident #{primary['id']}]", dup_ids))

                # Reversible Audit Trail Log
                audit_details = (
                    f"Merged {len(duplicates)} duplicate traffic incidents {dup_ids} into "
                    f"Primary Incident #{primary['id']} for Server #{primary['server_id']}."
                )
                cur.execute("""
                    INSERT INTO audit_logs (user_id, action, target, target_type, target_id, detail, timestamp)
                    VALUES (1, 'MERGE_DUPLICATE_INCIDENTS', 'incidents', 'incident', %s, %s, NOW());
                """, (primary["id"], audit_details))

                merged_total += len(duplicates)

            conn.commit()
            print(f"\n[✓] Successfully merged {merged_total} duplicate incidents into consolidated master records.")
            print("[✓] Reversible audit trail entries recorded in audit_logs.")

    except Exception as e:
        print(f"[!] Error during incident merge: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    merge_duplicates()
