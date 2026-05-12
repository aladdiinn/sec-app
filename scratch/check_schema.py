import sys
import os
sys.path.append(os.getcwd())
from app import app, db
import psycopg
from dotenv import load_dotenv

load_dotenv()
db_url = os.getenv("DATABASE_URL")
# Simplified parsing for verification
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
        cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'servers';")
        cols = cur.fetchall()
        for col in cols:
            print(f"Column: {col[0]}, Type: {col[1]}")
finally:
    conn.close()
