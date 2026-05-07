"""
migrate.py — Safe database migration for SecurePulse.
Adds any missing columns to existing tables without data loss.

Usage (on Linux server):
    cd /home/ubuntu/sec-app
    source venv/bin/activate
    python migrate.py
"""

import os
from dotenv import load_dotenv
load_dotenv()

from database import db
from app import app
from sqlalchemy import text

MIGRATIONS = [
    # alerts table — new columns added in v2
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(128)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INTEGER REFERENCES cases(id)",

    # cases table — ensure it exists (created by db.create_all, but just in case)
    """
    CREATE TABLE IF NOT EXISTS cases (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        status VARCHAR(32) DEFAULT 'open',
        priority VARCHAR(16) DEFAULT 'medium',
        assignee_id INTEGER REFERENCES users(id),
        summary TEXT,
        due_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ
    )
    """,

    # threat_indicators table
    """
    CREATE TABLE IF NOT EXISTS threat_indicators (
        id SERIAL PRIMARY KEY,
        indicator_type VARCHAR(32) NOT NULL,
        value VARCHAR(512) NOT NULL,
        source VARCHAR(128),
        severity VARCHAR(16) DEFAULT 'medium',
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # playbooks table
    """
    CREATE TABLE IF NOT EXISTS playbooks (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        actions TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # alert_rules table
    """
    CREATE TABLE IF NOT EXISTS alert_rules (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        event_type VARCHAR(64) NOT NULL,
        threshold INTEGER DEFAULT 1,
        window INTEGER DEFAULT 60,
        severity VARCHAR(16) DEFAULT 'warning',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,
]


def run_migrations():
    with app.app_context():
        # Ensure all base tables exist first
        db.create_all()
        print("[✓] db.create_all() complete")

        with db.engine.connect() as conn:
            for sql in MIGRATIONS:
                sql = sql.strip()
                if not sql:
                    continue
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    # Print first line of statement as label
                    label = sql.splitlines()[0][:80]
                    print(f"[✓] {label}")
                except Exception as e:
                    conn.rollback()
                    print(f"[!] Skipped (likely already exists): {str(e)[:120]}")

        print("\n✅ Migration complete. Restart the app now.")


if __name__ == "__main__":
    run_migrations()
