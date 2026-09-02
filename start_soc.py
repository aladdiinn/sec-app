import subprocess
import sys
import os

def start():
    print("🚀 Initializing SecurePulse SOC Platform...")
    
    # 1. Run migrations
    print("\n--- Synchronizing Database ---")
    try:
        subprocess.run([sys.executable, "migrate_soc.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Migration failed: {e}")
        return

    # 2. Start the application
    print("\n--- Starting SOC Command Center ---")
    print("Access the dashboard at http://127.0.0.1:5000")
    try:
        # Use subprocess to run the app.py
        subprocess.run([sys.executable, "app.py"], check=True)
    except KeyboardInterrupt:
        print("\n👋 SOC Platform shutting down.")
    except Exception as e:
        print(f"❌ Application failed to start: {e}")

if __name__ == "__main__":
    start()
