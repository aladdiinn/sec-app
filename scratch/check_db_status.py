import os
from dotenv import load_dotenv
import psycopg

load_dotenv()
db_url = os.getenv("DATABASE_URL")
conn_str = db_url.replace("postgresql+psycopg://", "postgresql://")

try:
    conn = psycopg.connect(conn_str)
    cur = conn.cursor()
    
    print("--- Existing Tables ---")
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    tables = cur.fetchall()
    for t in tables:
        print(t[0])
    
    print("\n--- Playbooks Table Structure ---")
    try:
        cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'playbooks'")
        columns = cur.fetchall()
        for c in columns:
            print(f"{c[0]}: {c[1]}")
    except Exception as e:
        print(f"Error checking playbooks table: {e}")
        
    print("\n--- Threat Indicators Table Structure ---")
    try:
        cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'threat_indicators'")
        columns = cur.fetchall()
        for c in columns:
            print(f"{c[0]}: {c[1]}")
    except Exception as e:
        print(f"Error checking threat_indicators table: {e}")

    conn.close()
except Exception as e:
    print(f"Connection Error: {e}")
