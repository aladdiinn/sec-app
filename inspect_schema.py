import os
import psycopg2
import psycopg2.extras

DB_HOST = os.getenv("POSTGRES_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = int(os.getenv("POSTGRES_PORT", os.getenv("DB_PORT", "5432")))
DB_NAME = os.getenv("POSTGRES_DB", os.getenv("DB_NAME", "securepulse_db"))
DB_USER = os.getenv("POSTGRES_USER", os.getenv("DB_USER", "securepulse"))
DB_PASS = os.getenv("POSTGRES_PASSWORD", os.getenv("DB_PASS", "securepulse_pass"))
DATABASE_URL = os.getenv("DATABASE_URL")

try:
    if DATABASE_URL:
        url = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")
        conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASS, cursor_factory=psycopg2.extras.RealDictCursor)

    cur = conn.cursor()
    tables = ["servers", "alerts", "users", "commands", "projects", "approvals"]
    for t in tables:
        cur.execute(f"SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = '{t}';")
        cols = cur.fetchall()
        print(f"=== TABLE: {t} ===")
        for c in cols:
            print(f"  {c['column_name']} ({c['data_type']}) nullable={c['is_nullable']}")
    conn.close()
except Exception as e:
    print(f"ERROR: {e}")
