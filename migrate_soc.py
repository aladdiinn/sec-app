from app import app, db
from sqlalchemy import text # type: ignore

def migrate():
    with app.app_context():
        print("Starting SOC database migration...")
        
        # 1. Ensure new tables are created
        db.create_all()
        print("Tables checked/created.")

        # 2. Add missing columns to existing tables
        try:
            with db.engine.connect() as conn:
                # Add case_id to alerts table
                conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INTEGER REFERENCES cases(id)"))
                conn.commit()
                print("Column 'case_id' added to 'alerts' table.")
        except Exception as e:
            print(f"Migration error: {e}")
            
        print("Migration complete!")

if __name__ == "__main__":
    migrate()
