import psycopg2
import os

DB_HOST = os.getenv("POSTGRES_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = int(os.getenv("POSTGRES_PORT", os.getenv("DB_PORT", "5432")))
DB_NAME = os.getenv("POSTGRES_DB", os.getenv("DB_NAME", "securepulse_db"))
DB_USER = os.getenv("POSTGRES_USER", os.getenv("DB_USER", "postgres"))
DB_PASS = os.getenv("POSTGRES_PASSWORD", os.getenv("DB_PASSWORD", "postgres"))

def run_cleanup():
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    with conn.cursor() as cur:
        # First normalize all paths: trim trailing slashes and multiple slashes
        cur.execute("UPDATE server_log_configs SET log_file_path = regexp_replace(log_file_path, '/+$', '');")
        cur.execute("UPDATE server_log_configs SET log_file_path = regexp_replace(log_file_path, '//+', '/', 'g');")
        
        # Now delete duplicates, keeping only the one with the lowest ID
        cur.execute("""
            DELETE FROM server_log_configs
            WHERE id IN (
                SELECT id FROM (
                    SELECT id, row_number() OVER (PARTITION BY server_id, log_file_path ORDER BY id ASC) as row_num
                    FROM server_log_configs
                ) t WHERE t.row_num > 1
            );
        """)
        conn.commit()
        print("Cleanup successful. Duplicates removed.")
        
        try:
            cur.execute("ALTER TABLE server_log_configs ADD CONSTRAINT unique_server_path UNIQUE (server_id, log_file_path);")
            conn.commit()
            print("Unique constraint added.")
        except Exception as e:
            print("Constraint already exists or failed:", e)

if __name__ == '__main__':
    run_cleanup()
