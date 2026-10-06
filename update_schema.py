import os
from dotenv import load_dotenv
import psycopg

load_dotenv()
db_url = os.getenv("DATABASE_URL")
# Convert SQLAlchemy URL to psycopg connection string
# postgresql+psycopg://user:pass@host:port/db -> host=... user=...
conn_str = db_url.replace("postgresql+psycopg://", "").split("@")
user_pass = conn_str[0].split(":")
host_db = conn_str[1].split("/")
host_port = host_db[0].split(":")

conn = psycopg.connect(
    host=host_port[0],
    port=host_port[1],
    user=user_pass[0],
    password=user_pass[1],
    dbname=host_db[1]
)

try:
    with conn.cursor() as cur:
        # Add missing columns to servers table
        print("Updating tables and constraints...")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'primary';")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS site VARCHAR(50) DEFAULT 'DC';")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS cluster_id VARCHAR(50);")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS description TEXT;")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE;")
        cur.execute("ALTER TABLE servers ADD COLUMN IF NOT EXISTS managed_services TEXT;")
        cur.execute("ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS playbook_id INTEGER REFERENCES playbooks(id);")
        
        # Make email nullable in users table
        cur.execute("ALTER TABLE users ALTER COLUMN email DROP NOT NULL;")
        
        # Ensure notification_routes table exists (handled by app but let's be sure)
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

        print("Adding performance indexes for dashboard loading...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_server_id_resolved ON alerts(server_id, is_resolved);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity_resolved ON alerts(server_id, severity, is_resolved);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_feed_created_at ON activity_feed(created_at DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_approvals_hostname ON approvals(LOWER(hostname));")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_approvals_ip ON approvals(ip_address);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);")

        conn.commit()
        print("Database schema updated successfully.")
except Exception as e:
    print(f"Error updating database: {e}")
finally:
    conn.close()
