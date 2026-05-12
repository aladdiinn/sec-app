"""
migrate.py — Safe database migration for SecurePulse.
Adds any missing columns/tables without data loss.

Usage:
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
    # ── alerts table ─────────────────────────────────────────────────────────
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(128)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INTEGER REFERENCES cases(id)",

    # ── users table — RBAC & new fields ──────────────────────────────────────
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(128)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'normal'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64)",

    # Backfill role from is_admin
    """
    UPDATE users SET role = CASE
        WHEN is_admin = TRUE THEN 'superuser'
        ELSE 'normal'
    END
    WHERE role = 'normal' OR role IS NULL
    """,

    # ── audit_logs — extra details field ─────────────────────────────────────
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT",

    # ── cases table ───────────────────────────────────────────────────────────
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

    # ── case_comments table (#34) ──────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS case_comments (
        id SERIAL PRIMARY KEY,
        case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        is_system BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_case_comments_case ON case_comments(case_id)",

    # ── notifications table (#34) ──────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(32) NOT NULL,
        message VARCHAR(512) NOT NULL,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        is_read BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)",

    # ── threat_indicators table ────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS threat_indicators (
        id SERIAL PRIMARY KEY,
        indicator_type VARCHAR(32) NOT NULL,
        value VARCHAR(512) NOT NULL,
        source VARCHAR(128),
        severity VARCHAR(16) DEFAULT 'medium',
        is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    "ALTER TABLE threat_indicators ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE",

    # ── playbooks table ───────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS playbooks (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        actions TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # ── alert_rules table ─────────────────────────────────────────────────
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

    # ── firewall_configs (#25) ────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS firewall_configs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        fw_type VARCHAR(32) NOT NULL,
        api_endpoint VARCHAR(512),
        credentials TEXT,
        default_ttl_hrs INTEGER DEFAULT 168,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # ── blocked_ips (#25) ─────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(64) NOT NULL,
        reason TEXT NOT NULL,
        blocked_by INTEGER REFERENCES users(id),
        blocked_at TIMESTAMPTZ DEFAULT NOW(),
        ttl_hours INTEGER,
        expires_at TIMESTAMPTZ,
        firewalls TEXT,
        status VARCHAR(32) DEFAULT 'active',
        incident_id INTEGER REFERENCES cases(id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)",

    # ── identity_provider_configs (#24/#32) ───────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS identity_provider_configs (
        id SERIAL PRIMARY KEY,
        provider_type VARCHAR(32) NOT NULL,
        is_enabled BOOLEAN DEFAULT FALSE,
        config TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ
    )
    """,

    # ── jira_configs (#35) ────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS jira_configs (
        id SERIAL PRIMARY KEY,
        provider VARCHAR(32) DEFAULT 'jira_cloud',
        base_url VARCHAR(512),
        project_key VARCHAR(64),
        api_token VARCHAR(512),
        user_email VARCHAR(255),
        issue_type VARCHAR(64) DEFAULT 'Bug',
        auto_create VARCHAR(32) DEFAULT 'critical',
        is_enabled BOOLEAN DEFAULT FALSE,
        status_map TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # ── case_tickets (#35) ────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS case_tickets (
        id SERIAL PRIMARY KEY,
        case_id INTEGER NOT NULL UNIQUE REFERENCES cases(id) ON DELETE CASCADE,
        ticket_id VARCHAR(64) NOT NULL,
        ticket_url VARCHAR(512),
        ticket_status VARCHAR(64) DEFAULT 'Open',
        provider VARCHAR(32) DEFAULT 'jira_cloud',
        last_synced TIMESTAMPTZ,
        sync_error TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # ── dr_test_logs (#33) ────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS dr_test_logs (
        id SERIAL PRIMARY KEY,
        run_by INTEGER REFERENCES users(id),
        result VARCHAR(16) NOT NULL,
        details TEXT,
        rto_seconds INTEGER,
        ran_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,

    # ── projects (Part C) ─────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ
    )
    """,

    # ── project_endpoints (Part C) ────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS project_endpoints (
        id SERIAL PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        added_by INTEGER REFERENCES users(id),
        added_at TIMESTAMPTZ DEFAULT NOW(),
        CONSTRAINT uq_project_server UNIQUE (project_id, server_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_project_endpoints_proj ON project_endpoints(project_id)",
    "CREATE INDEX IF NOT EXISTS idx_project_endpoints_srv ON project_endpoints(server_id)",
]


def run_migrations():
    with app.app_context():
        # Ensure all base tables exist first
        db.create_all()
        print("[OK] db.create_all() complete")

        with db.engine.connect() as conn:
            for sql in MIGRATIONS:
                sql = sql.strip()
                if not sql:
                    continue
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    label = sql.splitlines()[0][:80]
                    print(f"[OK] {label}")
                except Exception as e:
                    conn.rollback()
                    print(f"[SKIP] {str(e)[:120]}")

        print("\nMigration complete. Restart the app now.")


if __name__ == "__main__":
    run_migrations()
