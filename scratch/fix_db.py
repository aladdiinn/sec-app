import os
import sys
from sqlalchemy import text
from app import app, db

with app.app_context():
    try:
        # Check users table
        print("Checking users table...")
        db.session.execute(text("SELECT username FROM users LIMIT 1"))
        print("users.username exists")
    except Exception as e:
        print(f"Error in users: {e}")
        db.session.rollback()
        print("Adding users.username...")
        db.session.execute(text("ALTER TABLE users ADD COLUMN username VARCHAR(128) UNIQUE"))
        db.session.commit()

    try:
        # Check servers table
        print("Checking servers table...")
        db.session.execute(text("SELECT is_maintenance, maintenance_until, managed_services, role, site, cluster_id FROM servers LIMIT 1"))
        print("servers columns exist")
    except Exception as e:
        print(f"Error in servers: {e}")
        db.session.rollback()
        
        # We need to add columns one by one in case some exist
        columns_to_add = [
            ("is_maintenance", "BOOLEAN DEFAULT FALSE NOT NULL"),
            ("maintenance_until", "TIMESTAMP WITH TIME ZONE"),
            ("managed_services", "TEXT"),
            ("role", "VARCHAR(32) DEFAULT 'none'"),
            ("site", "VARCHAR(32) DEFAULT 'DC'"),
            ("cluster_id", "VARCHAR(128)")
        ]
        
        for col_name, col_type in columns_to_add:
            try:
                db.session.execute(text(f"SELECT {col_name} FROM servers LIMIT 1"))
            except Exception:
                db.session.rollback()
                print(f"Adding servers.{col_name}...")
                db.session.execute(text(f"ALTER TABLE servers ADD COLUMN {col_name} {col_type}"))
                db.session.commit()
    
    print("Done checking and fixing db.")
