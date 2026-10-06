from database import get_db_connection

def run_cleanup():
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database.")
        return
        
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
