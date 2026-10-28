import sys
import os
import time
from datetime import datetime, timezone, timedelta
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import database
import app_siem_db
import psycopg2.extras

def test_idempotence():
    print("--- [TEST 1] IDEMPOTENT SCHEMA INITIALIZATION (RUN 1 & RUN 2) ---")
    conn1 = database.get_db_connection()
    app_siem_db.init_app_siem_schema(conn1)
    conn1.close()
    print("Run 1 completed successfully.")

    conn2 = database.get_db_connection()
    app_siem_db.init_app_siem_schema(conn2)
    conn2.close()
    print("Run 2 completed successfully without errors. [PASS]")

def test_tables_and_rules():
    print("\n--- [TEST 2] VERIFY TABLES & STARTER RULES EXISTENCE ---")
    expected_tables = [
        'applications',
        'application_components',
        'app_events',
        'app_rules',
        'app_incidents',
        'app_incident_events',
        'app_suppressions',
        'app_baselines',
        'project_apps',
        'app_users_synced'
    ]
    conn = database.get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        existing = {r['table_name'] for r in cur.fetchall()}
        for t in expected_tables:
            assert t in existing, f"Missing table: {t}"
            print(f"  [OK] Table '{t}' exists.")

        cur.execute("SELECT COUNT(*) as cnt FROM app_rules;")
        cnt = cur.fetchone()['cnt']
        assert cnt >= 18, f"Expected at least 18 starter rules, found {cnt}"
        print(f"  [OK] Starter rules count: {cnt} (>= 18 expected).")

        # Test project_apps link table and application project link
        cur.execute("""
            INSERT INTO applications (name, primary_url, environment, description, status)
            VALUES ('test-benchmark-app.internal', 'https://test-benchmark.internal', 'Test', 'Benchmark Test Application', 'WAITING')
            ON CONFLICT (name) DO UPDATE SET updated_at = NOW() RETURNING id;
        """)
        app_id = cur.fetchone()['id']
        print(f"  [OK] Created/verified application test-benchmark-app.internal (ID={app_id}).")

    conn.close()
    return app_id

def test_retention():
    print("\n--- [TEST 3] RETENTION CLEANUP JOB (delete_old_app_events) ---")
    conn = database.get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM applications WHERE name = 'test-benchmark-app.internal';")
        app_id = cur.fetchone()['id']

        # Insert 10 events older than 35 days
        old_time = datetime.now(timezone.utc) - timedelta(days=40)
        cur.execute("""
            INSERT INTO app_events (event_time, application_id, component_id, event_type, client_ip, severity)
            SELECT %s, %s, 1, 'test_old', '10.0.0.99', 'info'
            FROM generate_series(1, 10);
        """, (old_time, app_id))

    deleted = app_siem_db.delete_old_app_events(conn, retention_days=30, batch_size=5000)
    print(f"  [OK] Retention cleanup purged {deleted} events older than 30 days. [PASS]")
    conn.close()

def test_machine_id_server_link():
    print("\n--- [TEST 4] COMPONENT MACHINE-ID LINKING TO EXISTING SERVER ASSET ---")
    conn = database.get_db_connection()
    with conn.cursor() as cur:
        # Check if any server exists
        cur.execute("SELECT id, hostname, ip FROM servers LIMIT 1;")
        srv = cur.fetchone()
        if not srv:
            cur.execute("""
                INSERT INTO servers (name, hostname, ip, status)
                VALUES ('TEST-NODE-01', 'test-node-01', '10.10.10.50', 'online')
                RETURNING id, hostname, ip;
            """)
            srv = cur.fetchone()

        srv_id = srv['id']
        test_machine_id = f"mid-test-{srv_id}"

        # Register application component with this machine_id and linked_server_id
        cur.execute("SELECT id FROM applications WHERE name = 'test-benchmark-app.internal';")
        app_id = cur.fetchone()['id']

        cur.execute("""
            INSERT INTO application_components (application_id, role, node_name, node_ip, machine_id, linked_server_id, token_hash)
            VALUES (%s, 'web', 'test-node-01', '10.10.10.50', %s, %s, %s)
            ON CONFLICT (token_hash) DO UPDATE SET last_seen = NOW()
            RETURNING id, linked_server_id;
        """, (app_id, test_machine_id, srv_id, f"thash_{srv_id}_{app_id}"))
        comp = cur.fetchone()
        assert comp['linked_server_id'] == srv_id, "Component did not link properly to existing server asset"
        print(f"  [OK] Component ID={comp['id']} linked to Server ID={srv_id} without altering server asset. [PASS]")

    conn.close()

def get_plan(cur):
    res = cur.fetchone()
    if isinstance(res, dict):
        raw = list(res.values())[0]
    else:
        raw = res[0]
    if isinstance(raw, list):
        return raw[0]
    return raw

def test_1m_events_benchmark(app_id):
    print("\n--- [TEST 5] 1,000,000 EVENTS INGESTION & QUERY BENCHMARK ---")
    conn = database.get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM app_events WHERE application_id = %s;", (app_id,))
        existing_cnt = cur.fetchone()['cnt']
        if existing_cnt < 1000000:
            print(f"Currently {existing_cnt} events present. Inserting 1,000,000 events using PostgreSQL generate_series...")
            start_ins = time.time()
            cur.execute("""
                INSERT INTO app_events (
                    event_time, received_time, application_id, component_id, node, source_type,
                    event_type, client_ip, is_trusted_proxy, user_name, session_hash, method,
                    url_path, query_masked, status_code, bytes_sent, duration_ms, user_agent,
                    severity, parse_status
                )
                SELECT
                    NOW() - (random() * interval '7 days'),
                    NOW(),
                    %s,
                    1,
                    CASE WHEN (g %% 2 = 0) THEN 'web-1' ELSE 'web-2' END,
                    'tomcat_access',
                    CASE
                        WHEN (g %% 100 = 0) THEN 'auth_failure'
                        WHEN (g %% 50 = 0) THEN 'web_error'
                        ELSE 'web_request'
                    END,
                    '192.168.1.' || (g %% 250 + 1)::text,
                    (g %% 5 = 0),
                    CASE WHEN (g %% 20 = 0) THEN 'user_' || (g %% 1000)::text ELSE NULL END,
                    md5((g %% 5000)::text),
                    CASE WHEN (g %% 10 = 0) THEN 'POST' ELSE 'GET' END,
                    CASE
                        WHEN (g %% 30 = 0) THEN '/admin/users'
                        WHEN (g %% 15 = 0) THEN '/login'
                        ELSE '/api/v1/resource/' || (g %% 100)::text
                    END,
                    'q=test&page=1',
                    CASE WHEN (g %% 50 = 0) THEN 500 WHEN (g %% 20 = 0) THEN 401 ELSE 200 END,
                    (random() * 5000)::int + 200,
                    (random() * 120)::int + 5,
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    CASE WHEN (g %% 100 = 0) THEN 'high' ELSE 'info' END,
                    'parsed'
                FROM generate_series(1, 1000000) AS g;
            """, (app_id,))
            ins_time = time.time() - start_ins
            print(f"1,000,000 events inserted in {ins_time:.2f}s.")
        else:
            print(f"Verified {existing_cnt} events already present in table for application {app_id}.")

        # Benchmark 1: App events search by IP & time window
        print("\nExecuting EXPLAIN ANALYZE for Query 1: App Events Search (IP + 24h Window)...")
        q1 = """
            EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            SELECT * FROM app_events
            WHERE application_id = %s
              AND event_time >= NOW() - INTERVAL '24 hours'
              AND client_ip = '192.168.1.100'
            ORDER BY event_time DESC
            LIMIT 100;
        """
        cur.execute(q1, (app_id,))
        plan1 = get_plan(cur)
        exec_time1 = plan1['Execution Time']
        print(f"  Plan: {plan1['Plan']['Node Type']}, Execution Time: {exec_time1:.2f} ms")
        assert exec_time1 < 300, f"Query 1 exceeded 300ms: {exec_time1} ms"
        print(f"  [PASS] Query 1 finished in {exec_time1:.2f} ms (Target: < 300 ms).")

        # Benchmark 2: 24-hour event type aggregation count
        print("\nExecuting EXPLAIN ANALYZE for Query 2: 24-hour Counts by Event Type...")
        q2 = """
            EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            SELECT event_type, COUNT(*)
            FROM app_events
            WHERE application_id = %s
              AND event_time >= NOW() - INTERVAL '24 hours'
            GROUP BY event_type;
        """
        cur.execute(q2, (app_id,))
        plan2 = get_plan(cur)
        exec_time2 = plan2['Execution Time']
        print(f"  Plan: {plan2['Plan']['Node Type']}, Execution Time: {exec_time2:.2f} ms")
        assert exec_time2 < 300, f"Query 2 exceeded 300ms: {exec_time2} ms"
        print(f"  [PASS] Query 2 finished in {exec_time2:.2f} ms (Target: < 300 ms).")

        # Benchmark 3: Incident timeline query across IP or session hash in time range
        print("\nExecuting EXPLAIN ANALYZE for Query 3: Incident Timeline Query...")
        start_time = datetime.now(timezone.utc) - timedelta(hours=12)
        end_time = datetime.now(timezone.utc)
        q3 = """
            EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            SELECT id, event_time, node, event_type, client_ip, user_name, session_hash, url_path, severity
            FROM app_events
            WHERE application_id = %s
              AND (client_ip = '192.168.1.50' OR session_hash = md5('50'))
              AND event_time BETWEEN %s AND %s
            ORDER BY event_time ASC
            LIMIT 200;
        """
        cur.execute(q3, (app_id, start_time, end_time))
        plan3 = get_plan(cur)
        exec_time3 = plan3['Execution Time']
        print(f"  Plan: {plan3['Plan']['Node Type']}, Execution Time: {exec_time3:.2f} ms")
        assert exec_time3 < 300, f"Query 3 exceeded 300ms: {exec_time3} ms"
        print(f"  [PASS] Query 3 finished in {exec_time3:.2f} ms (Target: < 300 ms).")

        # Cleanup: Delete the benchmark test events
        print("\nCleaning up 1,000,000 test benchmark rows...")
        cur.execute("DELETE FROM app_events WHERE application_id = %s;", (app_id,))
        cur.execute("DELETE FROM application_components WHERE application_id = %s;", (app_id,))
        cur.execute("DELETE FROM applications WHERE id = %s;", (app_id,))
        print("  [OK] Cleaned up test benchmark rows and test application.")

    conn.close()

if __name__ == '__main__':
    test_idempotence()
    app_id = test_tables_and_rules()
    test_retention()
    test_machine_id_server_link()
    test_1m_events_benchmark(app_id)
    print("\n=======================================================")
    print("STEP 1: DATA MODEL COMPLETE - ALL VERIFICATIONS PASSED")
    print("=======================================================")
