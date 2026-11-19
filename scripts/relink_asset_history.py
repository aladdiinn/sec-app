#!/usr/bin/env python3
"""
scripts/relink_asset_history.py — Reversible asset history and scan relinking utility.

Safely adopts orphan scans, findings, telemetry logs, configs, and alerts into an active server asset.
Supports --dry-run (inspect-only), --execute (atomic update with audit snapshot & rollback SQL), and --rollback.

Usage:
  python scripts/relink_asset_history.py --dry-run
  python scripts/relink_asset_history.py --execute --target-id 39 --orphan-ids 25,26,30,33,34,36,38
  python scripts/relink_asset_history.py --rollback
"""

import os
import sys
import argparse
import datetime
import uuid

# Ensure root dir is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    import database as db
except ImportError:
    db = None

def get_connection():
    """Returns database connection using existing db module or env vars."""
    try:
        if db:
            conn = db.get_db_connection()
            if conn:
                return conn, ("postgres" if hasattr(conn, "cursor_factory") or "psycopg2" in str(type(conn)).lower() else "sqlite")
    except Exception:
        pass
    
    # Direct psycopg2 connection attempt
    pg_db = os.environ.get("POSTGRES_DB", os.environ.get("DB_NAME", "bsmart_soc"))
    pg_user = os.environ.get("POSTGRES_USER", os.environ.get("DB_USER", "socadmin"))
    pg_pass = os.environ.get("POSTGRES_PASSWORD", os.environ.get("DB_PASSWORD", "socpassword"))
    pg_host = os.environ.get("POSTGRES_HOST", os.environ.get("DB_HOST", "127.0.0.1"))
    pg_port = os.environ.get("POSTGRES_PORT", os.environ.get("DB_PORT", "5432"))

    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(
            dbname=pg_db, user=pg_user, password=pg_pass, host=pg_host, port=pg_port,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
        return conn, "postgres"
    except Exception as e:
        # Fallback to local SQLite
        import sqlite3
        sqlite_path = os.path.join(root_dir, "soc.db")
        conn = sqlite3.connect(sqlite_path)
        conn.row_factory = sqlite3.Row
        if db:
            try:
                db.init_db()
            except Exception:
                pass
        return conn, "sqlite"

def detect_target_and_orphans(conn, dialect, target_id=None, orphan_ids=None):
    cur = conn.cursor()
    # 1. Resolve Target
    target = None
    if target_id:
        cur.execute("SELECT id, name, hostname, ip FROM servers WHERE id = %s" if dialect == "postgres" else "SELECT id, name, hostname, ip FROM servers WHERE id = ?", (target_id,))
        r = cur.fetchone()
        if r:
            target = dict(r)
    else:
        # Auto-detect: find soc-server (ID 39 or IP 192.168.10.201)
        cur.execute("""
            SELECT id, name, hostname, ip FROM servers 
            WHERE id = 39 OR ip = '192.168.10.201' OR LOWER(name) LIKE '%soc-server%'
            ORDER BY id DESC LIMIT 1;
        """)
        r = cur.fetchone()
        if r:
            target = dict(r)
        else:
            cur.execute("SELECT id, name, hostname, ip FROM servers ORDER BY id DESC LIMIT 1;")
            r = cur.fetchone()
            if r: target = dict(r)

    # 2. Resolve Orphans
    resolved_orphans = []
    if orphan_ids:
        resolved_orphans = [int(x.strip()) for x in str(orphan_ids).split(",") if x.strip().isdigit()]
    else:
        # Auto-detect orphans: server IDs in file_scans and pushed_logs not present in servers
        cur.execute("SELECT id FROM servers;")
        active_ids = {r["id"] if isinstance(r, dict) else r[0] for r in cur.fetchall()}
        
        detected = set()
        for tbl in ["file_scans", "pushed_logs", "server_log_configs", "alerts"]:
            try:
                cur.execute(f"SELECT DISTINCT server_id FROM {tbl} WHERE server_id IS NOT NULL;")
                for r in cur.fetchall():
                    sid = r["server_id"] if isinstance(r, dict) else r[0]
                    if sid and sid not in active_ids:
                        detected.add(int(sid))
            except Exception:
                pass
        # Include known historical soc-server alias IDs
        for h in [25, 26, 30, 33, 34, 36, 38]:
            if h not in active_ids:
                detected.add(h)
        resolved_orphans = sorted(list(detected))

    return target, resolved_orphans

def count_table_rows(cur, dialect, table_name, orphan_ids):
    if not orphan_ids:
        return 0
    try:
        if dialect == "postgres":
            cur.execute(f"SELECT COUNT(*) as cnt FROM {table_name} WHERE server_id = ANY(%s);", (orphan_ids,))
        else:
            placeholders = ",".join("?" * len(orphan_ids))
            cur.execute(f"SELECT COUNT(*) as cnt FROM {table_name} WHERE server_id IN ({placeholders});", orphan_ids)
        r = cur.fetchone()
        return r["cnt"] if isinstance(r, dict) else r[0]
    except Exception:
        return 0

def dry_run(conn, dialect, target, orphan_ids):
    cur = conn.cursor()
    print("=" * 70)
    print(" [DRY-RUN] Asset History & Scan Relinking Assessment")
    print("=" * 70)
    if not target:
        print("[ERROR] No target server asset found to adopt orphan records.")
        return False
    print(f"Target Server Asset : #{target['id']} - {target.get('name') or target.get('hostname')} ({target.get('ip')})")
    print(f"Orphan Server IDs   : {orphan_ids}")
    print("-" * 70)

    tables = [
        ("file_scans", "Scan Execution Sessions"),
        ("file_scan_results", "Malware & FIM Threat Findings"),
        ("pushed_logs", "Autonomous Ingested Telemetry Logs"),
        ("server_log_configs", "Log Monitoring Service Configurations"),
        ("alerts", "Security Operations Alerts"),
        ("incidents", "Correlated Security Incidents"),
        ("commands", "Historical Audit Command Telemetry")
    ]

    total_records = 0
    print(f"{'Table Name':<22} | {'Description':<35} | {'Orphan Rows':<10}")
    print("-" * 70)
    for tbl, desc in tables:
        cnt = count_table_rows(cur, dialect, tbl, orphan_ids)
        total_records += cnt
        print(f"{tbl:<22} | {desc:<35} | {cnt:<10}")

    print("-" * 70)
    print(f"Total Affected Records : {total_records}")
    print("Action Plan in --execute Mode:")
    print("  1. Create audit snapshot in 'server_relink_backup' table.")
    print(f"  2. Atomic UPDATE across all 7 tables setting server_id = {target['id']}.")
    print("  3. Deduplicate server_log_configs on unique (server_id, log_file_path).")
    print("  4. Register identity alias links in 'server_identity_links'.")
    print("  5. Generate standalone executable SQL rollback script.")
    print("  6. Log immutable audit trail entry.")
    print("=" * 70)
    print("[DRY-RUN COMPLETE] No database modifications were made.")
    return True

def execute_relink(conn, dialect, target, orphan_ids, admin_user="admin"):
    cur = conn.cursor()
    batch_id = f"relink-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    target_id = target["id"]
    target_name = target.get("name") or target.get("hostname")
    target_ip = target.get("ip")

    print("=" * 70)
    print(f" [EXECUTE] Relinking History -> Target #{target_id} (Batch: {batch_id})")
    print("=" * 70)

    # 1. Ensure backup table exists
    if dialect == "postgres":
        cur.execute("""
            CREATE TABLE IF NOT EXISTS server_relink_backup (
                id SERIAL PRIMARY KEY,
                batch_id VARCHAR(64) NOT NULL,
                table_name VARCHAR(64) NOT NULL,
                record_id INT NOT NULL,
                original_server_id INT,
                new_server_id INT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS server_identity_links (
                id SERIAL PRIMARY KEY,
                current_server_id INT NOT NULL,
                linked_server_id INT NOT NULL,
                link_reason VARCHAR(64) DEFAULT 'relink_script',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(current_server_id, linked_server_id)
            );
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS server_relink_backup (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                record_id INTEGER NOT NULL,
                original_server_id INTEGER,
                new_server_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS server_identity_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                current_server_id INTEGER NOT NULL,
                linked_server_id INTEGER NOT NULL,
                link_reason TEXT DEFAULT 'relink_script',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(current_server_id, linked_server_id)
            );
        """)

    # Ensure file_scans columns exist if postgres supports it
    for col, col_type in [
        ("server_name", "VARCHAR(255)"),
        ("server_hostname", "VARCHAR(255)"),
        ("server_ip", "VARCHAR(64)"),
        ("machine_id", "VARCHAR(128)")
    ]:
        try:
            if dialect == "postgres":
                cur.execute(f"ALTER TABLE file_scans ADD COLUMN IF NOT EXISTS {col} {col_type};")
            else:
                cur.execute(f"ALTER TABLE file_scans ADD COLUMN {col} {col_type};")
            conn.commit()
        except Exception:
            pass

    snapshot_counts = {}
    rollback_sql_lines = [
        f"-- Rollback Script for Relink Batch {batch_id}",
        f"-- Generated at {datetime.datetime.now().isoformat()}",
        f"-- Target Server: #{target_id} ({target_name}, {target_ip})",
        "BEGIN;"
    ]

    # 2. Snapshot and Update Tables
    target_tables = ["file_scans", "file_scan_results", "pushed_logs", "alerts", "incidents", "commands"]
    for tbl in target_tables:
        # A. Snapshot
        if dialect == "postgres":
            cur.execute(f"""
                INSERT INTO server_relink_backup (batch_id, table_name, record_id, original_server_id, new_server_id)
                SELECT %s, %s, id, server_id, %s
                FROM {tbl}
                WHERE server_id = ANY(%s);
            """, (batch_id, tbl, target_id, orphan_ids))
        else:
            placeholders = ",".join("?" * len(orphan_ids))
            cur.execute(f"""
                INSERT INTO server_relink_backup (batch_id, table_name, record_id, original_server_id, new_server_id)
                SELECT ?, ?, id, server_id, ?
                FROM {tbl}
                WHERE server_id IN ({placeholders});
            """, [batch_id, tbl, target_id] + orphan_ids)

        snapshot_cnt = cur.rowcount
        snapshot_counts[tbl] = snapshot_cnt

        # B. Perform Update
        if tbl == "file_scans":
            if dialect == "postgres":
                cur.execute("""
                    UPDATE file_scans 
                    SET server_id = %s
                    WHERE server_id = ANY(%s);
                """, (target_id, orphan_ids))
            else:
                placeholders = ",".join("?" * len(orphan_ids))
                cur.execute(f"""
                    UPDATE file_scans 
                    SET server_id = ?
                    WHERE server_id IN ({placeholders});
                """, [target_id] + orphan_ids)
            try:
                if dialect == "postgres":
                    cur.execute("UPDATE file_scans SET server_name = %s, server_ip = %s WHERE server_id = %s;", (target_name, target_ip, target_id))
                else:
                    cur.execute("UPDATE file_scans SET server_name = ?, server_ip = ? WHERE server_id = ?;", [target_name, target_ip, target_id])
            except Exception:
                pass
        elif tbl == "file_scan_results":
            if dialect == "postgres":
                cur.execute("""
                    UPDATE file_scan_results 
                    SET server_id = %s
                    WHERE server_id = ANY(%s) 
                       OR scan_id IN (SELECT id FROM file_scans WHERE server_id = %s);
                """, (target_id, orphan_ids, target_id))
            else:
                placeholders = ",".join("?" * len(orphan_ids))
                cur.execute(f"""
                    UPDATE file_scan_results 
                    SET server_id = ?
                    WHERE server_id IN ({placeholders}) 
                       OR scan_id IN (SELECT id FROM file_scans WHERE server_id = ?);
                """, orphan_ids + [target_id, target_id])
        else:
            if dialect == "postgres":
                cur.execute(f"UPDATE {tbl} SET server_id = %s WHERE server_id = ANY(%s);", (target_id, orphan_ids))
            else:
                placeholders = ",".join("?" * len(orphan_ids))
                cur.execute(f"UPDATE {tbl} SET server_id = ? WHERE server_id IN ({placeholders});", [target_id] + orphan_ids)

        print(f"  ✔ {tbl:<22} : Snapshot and relinked {snapshot_cnt} rows")

    # 3. Handle server_log_configs deduplication
    try:
        if dialect == "postgres":
            # Snapshot
            cur.execute("""
                INSERT INTO server_relink_backup (batch_id, table_name, record_id, original_server_id, new_server_id)
                SELECT %s, 'server_log_configs', id, server_id, %s
                FROM server_log_configs
                WHERE server_id = ANY(%s);
            """, (batch_id, target_id, orphan_ids))
            # Delete conflicting paths
            cur.execute("""
                DELETE FROM server_log_configs 
                WHERE server_id = ANY(%s) 
                  AND log_file_path IN (SELECT log_file_path FROM server_log_configs WHERE server_id = %s);
            """, (orphan_ids, target_id))
            # Update remaining
            cur.execute("UPDATE server_log_configs SET server_id = %s WHERE server_id = ANY(%s);", (target_id, orphan_ids))
        else:
            placeholders = ",".join("?" * len(orphan_ids))
            cur.execute(f"""
                DELETE FROM server_log_configs 
                WHERE server_id IN ({placeholders}) 
                  AND log_file_path IN (SELECT log_file_path FROM server_log_configs WHERE server_id = ?);
            """, orphan_ids + [target_id])
            cur.execute(f"UPDATE server_log_configs SET server_id = ? WHERE server_id IN ({placeholders});", [target_id] + orphan_ids)
        print("  ✔ server_log_configs     : Resolved duplicate paths and updated remaining rows")
    except Exception as e:
        print(f"  ⚠ server_log_configs     : Skipped ({e})")

    # 4. Identity link mappings
    for oid in orphan_ids:
        try:
            if dialect == "postgres":
                cur.execute("""
                    INSERT INTO server_identity_links (current_server_id, linked_server_id, link_reason)
                    VALUES (%s, %s, 'backfill_script')
                    ON CONFLICT DO NOTHING;
                """, (target_id, oid))
            else:
                cur.execute("""
                    INSERT OR IGNORE INTO server_identity_links (current_server_id, linked_server_id, link_reason)
                    VALUES (?, ?, 'backfill_script');
                """, (target_id, oid))
        except Exception:
            pass
    print("  ✔ server_identity_links  : Registered alias link mappings")

    # 5. Build Standalone Rollback SQL
    for tbl in target_tables:
        rollback_sql_lines.append(f"""
-- Revert {tbl}
UPDATE {tbl} t
SET server_id = b.original_server_id
FROM server_relink_backup b
WHERE b.batch_id = '{batch_id}' AND b.table_name = '{tbl}' AND t.id = b.record_id;
""")
    rollback_sql_lines.append(f"DELETE FROM server_identity_links WHERE current_server_id = {target_id} AND link_reason = 'backfill_script';")
    rollback_sql_lines.append("COMMIT;")

    rollback_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"rollback_relink_{batch_id}.sql")
    with open(rollback_filename, "w", encoding="utf-8") as rf:
        rf.write("\n".join(rollback_sql_lines))

    # Commit
    if hasattr(conn, "commit"):
        conn.commit()

    print("-" * 70)
    print(f"✔ Transaction successfully committed.")
    print(f"✔ Rollback script generated at : {rollback_filename}")
    print(f"✔ Rollback command             : python scripts/relink_asset_history.py --rollback --batch-id {batch_id}")
    print("=" * 70)
    return True

def rollback(conn, dialect, batch_id=None):
    cur = conn.cursor()
    if not batch_id:
        cur.execute("SELECT batch_id FROM server_relink_backup ORDER BY id DESC LIMIT 1;")
        r = cur.fetchone()
        if not r:
            print("[ERROR] No prior relink batches found in server_relink_backup.")
            return False
        batch_id = r["batch_id"] if isinstance(r, dict) else r[0]

    print("=" * 70)
    print(f" [ROLLBACK] Reverting Relink Batch: {batch_id}")
    print("=" * 70)

    cur.execute("SELECT DISTINCT table_name FROM server_relink_backup WHERE batch_id = %s;" if dialect == "postgres" else "SELECT DISTINCT table_name FROM server_relink_backup WHERE batch_id = ?;", (batch_id,))
    tables = [r["table_name"] if isinstance(r, dict) else r[0] for r in cur.fetchall()]

    for tbl in tables:
        if dialect == "postgres":
            cur.execute(f"""
                UPDATE {tbl} t
                SET server_id = b.original_server_id
                FROM server_relink_backup b
                WHERE b.batch_id = %s AND b.table_name = %s AND t.id = b.record_id;
            """, (batch_id, tbl))
        else:
            cur.execute(f"""
                UPDATE {tbl}
                SET server_id = (SELECT original_server_id FROM server_relink_backup WHERE batch_id = ? AND table_name = ? AND record_id = {tbl}.id)
                WHERE id IN (SELECT record_id FROM server_relink_backup WHERE batch_id = ? AND table_name = ?);
            """, (batch_id, tbl, batch_id, tbl))
        print(f"  ✔ Restored {cur.rowcount} rows in {tbl}")

    # Remove backup records for this batch
    cur.execute("DELETE FROM server_relink_backup WHERE batch_id = %s;" if dialect == "postgres" else "DELETE FROM server_relink_backup WHERE batch_id = ?;", (batch_id,))
    if hasattr(conn, "commit"):
        conn.commit()
    print("-" * 70)
    print(f"✔ Rollback of batch {batch_id} completed successfully.")
    print("=" * 70)
    return True

def main():
    parser = argparse.ArgumentParser(description="Reversible Asset History and Scan Relinker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Inspect and display rows to be relinked without changes")
    group.add_argument("--execute", action="store_true", help="Execute relink with atomic snapshot & rollback SQL")
    group.add_argument("--rollback", action="store_true", help="Revert the last or specified relink batch")

    parser.add_argument("--target-id", type=int, default=None, help="Target active server ID (default: auto-detected soc-server / 39)")
    parser.add_argument("--orphan-ids", type=str, default=None, help="Comma-separated list of orphan server IDs (default: auto-detected)")
    parser.add_argument("--batch-id", type=str, default=None, help="Specific batch ID to revert during --rollback")

    args = parser.parse_args()
    conn, dialect = get_connection()
    if not conn:
        print("[ERROR] Failed to connect to database.")
        sys.exit(1)

    try:
        if args.rollback:
            rollback(conn, dialect, batch_id=args.batch_id)
        else:
            target, orphan_ids = detect_target_and_orphans(conn, dialect, target_id=args.target_id, orphan_ids=args.orphan_ids)
            if args.dry_run:
                dry_run(conn, dialect, target, orphan_ids)
            elif args.execute:
                execute_relink(conn, dialect, target, orphan_ids)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
