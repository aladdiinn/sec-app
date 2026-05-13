from flask import Flask
from flask_sqlalchemy import SQLAlchemy # type: ignore
from sqlalchemy import text

# Initialize the SQLAlchemy object
db = SQLAlchemy()

def init_db(app: Flask):
    """
    Initializes the database schema.
    Ensures all tables defined in models.py are created in PostgreSQL.
    """
    with app.app_context():
        # This will create tables for all models registered with 'db'
        db.create_all()
        
        # Auto-migrate newly added columns
        try:
            # Users
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(128) UNIQUE"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'normal' NOT NULL"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL"))
            db.session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64)"))
            
            # Servers
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'none'"))
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS site VARCHAR(32) DEFAULT 'DC'"))
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS cluster_id VARCHAR(128)"))
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN DEFAULT FALSE NOT NULL"))
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE"))
            db.session.execute(text("ALTER TABLE servers ADD COLUMN IF NOT EXISTS managed_services TEXT"))
            
            # Alerts
            db.session.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128)"))
            db.session.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(128)"))
            db.session.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0 NOT NULL"))
            db.session.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN DEFAULT FALSE NOT NULL"))
            db.session.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INTEGER"))
            
            # Alert Rules
            db.session.execute(text("ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS playbook_id INTEGER"))
            
            db.session.commit()
        except Exception as e:
            print(f"Error during schema migration: {e}")
            db.session.rollback()