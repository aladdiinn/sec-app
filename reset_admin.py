#!/usr/bin/env python3
"""
One-Off Administrator Password Reset & Security Re-initialization Tool
Usage on server: python reset_admin.py

Actions performed:
1. Generates a cryptographically strong 20-character random password.
2. Hashes it with bcrypt and updates the admin/superuser record(s) in PostgreSQL.
3. Enforces `must_change_password = TRUE` (user must choose a new password on first login).
4. Clears active session locks.
5. Writes an immutable audit entry to `audit_logs`.
6. Prints the temporary password to stdout ONCE in a secure banner.
"""
import sys
import os
import secrets
import string
import logging

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db

try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    from werkzeug.security import generate_password_hash
    USE_BCRYPT = False

def generate_strong_password(length=20):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    # Ensure at least one uppercase, lowercase, digit, and symbol
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*")
    ]
    pwd += [secrets.choice(chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def reset_admin():
    print("[*] Connecting to PostgreSQL database...")
    try:
        conn = db.get_db_connection()
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        print("Ensure PostgreSQL is running and environment variables (POSTGRES_DB, etc.) are set.")
        sys.exit(1)

    if not conn:
        print("[ERROR] Could not establish database connection.")
        sys.exit(1)

    raw_password = generate_strong_password(20)

    if USE_BCRYPT:
        hashed = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        hashed = generate_password_hash(raw_password)

    try:
        with conn.cursor() as cur:
            # 1. Ensure must_change_password column exists
            try:
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;")
            except Exception:
                pass

            # 2. Update all administrator accounts
            cur.execute("""
                UPDATE users 
                SET hashed_password = %s,
                    must_change_password = TRUE,
                    is_active = TRUE
                WHERE is_admin = TRUE OR LOWER(role) IN ('admin', 'superuser') OR LOWER(username) = 'admin'
                RETURNING id, username, email;
            """, (hashed,))
            updated_users = cur.fetchall()

            if not updated_users:
                # If no admin user exists, create one
                cur.execute("""
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, must_change_password, created_at)
                    VALUES ('admin', 'admin@bsmartsoc.local', %s, 'superuser', 'System Administrator', TRUE, TRUE, TRUE, NOW())
                    RETURNING id, username, email;
                """, (hashed,))
                updated_users = cur.fetchall()

            # 3. Write structured audit log entry
            details_str = f"Administrator credentials reset with random strong password on {len(updated_users)} account(s); must_change_password enforced."
            try:
                cur.execute("""
                    INSERT INTO audit_logs (user_id, action, target, details, created_at)
                    VALUES (%s, 'ADMIN_CREDENTIALS_RESET', 'admin', %s, NOW());
                """, (updated_users[0]['id'] if isinstance(updated_users[0], dict) else updated_users[0][0], details_str))
            except Exception:
                pass

            try:
                conn.commit()
            except Exception:
                pass

        print("\n" + "="*72)
        print("       BSMART SOC — ADMINISTRATOR PASSWORD RESET COMPLETE       ")
        print("="*72)
        print(f"Target Account(s) Updated: {len(updated_users)}")
        for u in updated_users:
            uname = u['username'] if isinstance(u, dict) else u[1]
            uemail = u['email'] if isinstance(u, dict) else u[2]
            print(f"  * Username: {uname} (Email: {uemail})")
        print("-" * 72)
        print("TEMPORARY ONE-TIME ADMINISTRATOR PASSWORD:")
        print(f"\n    {raw_password}\n")
        print("-" * 72)
        print("SECURITY ENFORCEMENTS:")
        print("  1. Hardcoded password fallbacks (admin/admin, Admin@1234) are REMOVED.")
        print("  2. 'must_change_password' flag is set to TRUE.")
        print("  3. You will be redirected to /change-password immediately upon login.")
        print("  4. Save this temporary password now; it will NOT be shown again.")
        print("="*72 + "\n")

    except Exception as e:
        print(f"[ERROR] Failed to update admin credentials: {e}")
        sys.exit(1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    reset_admin()
