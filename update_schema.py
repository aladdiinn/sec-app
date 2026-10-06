import os
from dotenv import load_dotenv
import psycopg2
from urllib.parse import urlparse

load_dotenv()
db_url = os.getenv("DATABASE_URL")
if not db_url:
    print("Error: DATABASE_URL not found in environment.")
    exit(1)

# Ensure SQLAlchemy prefixes are stripped for urlparse
clean_url = db_url.replace("postgresql+psycopg2://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
parsed = urlparse(clean_url)

conn = psycopg2.connect(
    host=parsed.hostname,
    port=parsed.port or 5432,
    user=parsed.username,
    password=parsed.password,
    dbname=parsed.path.lstrip('/')
)

try:
    with conn.cursor() as cur:
        # Ensure notification_routes table exists
        print("Ensuring 'notification_routes' exists...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notification_routes (
                id SERIAL PRIMARY KEY,
                match_type VARCHAR(32) NOT NULL,
                match_value VARCHAR(128),
                recipient_email VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            );
        """)
        conn.commit()
except Exception as e:
    print(f"Error creating notification_routes: {e}")
    conn.rollback()

print("Updating tables and constraints...")
alters = [
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'primary';",
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS site VARCHAR(50) DEFAULT 'DC';",
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS cluster_id VARCHAR(50);",
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE IF EXISTS playbooks ADD COLUMN IF NOT EXISTS description TEXT;",
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE;",
    "ALTER TABLE IF EXISTS servers ADD COLUMN IF NOT EXISTS managed_services TEXT;",
    "ALTER TABLE IF EXISTS alert_rules ADD COLUMN IF NOT EXISTS playbook_id INTEGER REFERENCES playbooks(id);",
    "ALTER TABLE IF EXISTS users ALTER COLUMN email DROP NOT NULL;"
]

alters.extend([
    # Deduplicate detection_rules before adding unique constraint
    """
    DELETE FROM detection_rules
    WHERE id NOT IN (
        SELECT MIN(id)
        FROM detection_rules
        GROUP BY name
    );
    """,
    "ALTER TABLE IF EXISTS detection_rules ADD CONSTRAINT unique_rule_name UNIQUE (name);"
])

for alt_sql in alters:
    try:
        with conn.cursor() as cur:
            cur.execute(alt_sql)
        conn.commit()
    except Exception as e:
        print(f"Skipping alter (maybe table doesn't exist): {e}")
        conn.rollback()

print("Adding performance indexes for dashboard loading...")
indexes = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_server_id_resolved ON alerts(server_id, is_resolved);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity_resolved ON alerts(server_id, severity, is_resolved);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_activity_feed_created_at ON activity_feed(created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_approvals_hostname ON approvals(LOWER(hostname));",
    "CREATE INDEX IF NOT EXISTS idx_approvals_ip ON approvals(ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);"
]
for idx_sql in indexes:
    try:
        with conn.cursor() as cur:
            cur.execute(idx_sql)
        conn.commit()
    except Exception as e:
        print(f"Skipping index creation (maybe table doesn't exist): {e}")
        conn.rollback()

print("Database schema and indexes updated successfully.")
conn.close()
