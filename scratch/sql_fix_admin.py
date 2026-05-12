import os
from dotenv import load_dotenv
import psycopg

load_dotenv()
db_url = os.getenv("DATABASE_URL")
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
        # Force set the username for the admin email
        cur.execute("UPDATE users SET username = 'admin' WHERE email = 'admin@securepulse.local';")
        conn.commit()
        print("SQL Fix Applied: 'admin@securepulse.local' now has username 'admin'")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
