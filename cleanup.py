import database as db

conn = db.get_db_connection()
if conn:
    try:
        with conn.cursor() as cur:
            cur.execute('''
                DELETE FROM server_log_configs a
                USING server_log_configs b
                WHERE a.id > b.id
                AND a.server_id = b.server_id
                AND a.file_path = b.file_path;
            ''')
            cur.execute('''
                ALTER TABLE server_log_configs
                ADD CONSTRAINT unique_server_file UNIQUE (server_id, file_path);
            ''')
            conn.commit()
            print("Database cleanup and constraint addition successful.")
    except Exception as e:
        print(f"Error during cleanup: {e}")
    finally:
        conn.close()
