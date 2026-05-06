import os
import sys
import logging
from flask import Flask
from database import db
from models import User, Server, Event, Alert, AuditLog
from sqlalchemy import text

# Setup minimal app context
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://securepulse:securepulse_pass@localhost:5432/securepulse_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

def check_db():
    print("Checking database connection...")
    try:
        with app.app_context():
            # 1. Test basic connectivity
            db.session.execute(text("SELECT 1"))
            print("  [OK] Connection successful.")
            
            # 2. Check tables
            tables = ["users", "servers", "events", "alerts", "audit_logs"]
            for table in tables:
                res = db.session.execute(text(f"SELECT count(*) FROM {table}"))
                count = res.scalar()
                print(f"  [OK] Table '{table}' exists (count: {count})")
            
            # 3. Check sequences
            res = db.session.execute(text("SELECT relname FROM pg_class WHERE relkind = 'S'"))
            seqs = [r[0] for r in res.fetchall()]
            print(f"  [INFO] Found sequences: {seqs}")
            
    except Exception as e:
        print(f"  [ERROR] Database check failed: {e}")
        print("\nPossible solutions:")
        print("1. Ensure PostgreSQL is running on localhost:5432")
        print("2. Ensure user 'securepulse' exists with password 'securepulse_pass'")
        print("3. Ensure database 'securepulse_db' exists")
        print("4. Check your firewall/NAT if the DB is on another machine")

if __name__ == "__main__":
    check_db()
