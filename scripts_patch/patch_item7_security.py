import os

# 1. Update database.py: add must_change_password column and remove password overwrite
with open('database.py', 'r', encoding='utf-8') as f:
    db_text = f.read()

# Add must_change_password column to user columns list
target_cols = '("is_active", "BOOLEAN DEFAULT TRUE"),'
replacement_cols = '("is_active", "BOOLEAN DEFAULT TRUE"),\n                ("must_change_password", "BOOLEAN DEFAULT FALSE"),'

if target_cols in db_text:
    db_text = db_text.replace(target_cols, replacement_cols, 1)
    print("Added must_change_password column to users table definition")

# Remove the forced password overwrite in database.py
target_seed = """            admin_row = cur.fetchone()
            if not admin_row:
                cur.execute(\"\"\"
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, created_at)
                    VALUES (%s, %s, %s, 'superuser', 'System Administrator', TRUE, TRUE, NOW());
                \"\"\", ("admin", "admin@bsmartsoc.local", hashed_admin))
            else:
                cur.execute(\"\"\"
                    UPDATE users SET username = 'admin', email = 'admin@bsmartsoc.local', hashed_password = %s, role = 'superuser', is_admin = TRUE, is_active = TRUE WHERE id = %s;
                \"\"\", (hashed_admin, admin_row["id"]))"""

replacement_seed = """            admin_row = cur.fetchone()
            if not admin_row:
                # Seed super admin ONCE only if not exists, requiring password change on first login
                cur.execute(\"\"\"
                    INSERT INTO users (username, email, hashed_password, role, full_name, is_admin, is_active, must_change_password, created_at)
                    VALUES (%s, %s, %s, 'superuser', 'System Administrator', TRUE, TRUE, TRUE, NOW());
                \"\"\", ("admin", "admin@bsmartsoc.local", hashed_admin))"""

if target_seed in db_text:
    db_text = db_text.replace(target_seed, replacement_seed, 1)
    print("Removed hardcoded password overwrite from database.py init_db")

with open('database.py', 'w', encoding='utf-8', newline='') as f:
    f.write(db_text)

# 2. Update app.py: Remove hardcoded backdoors, enforce DB hash, audit logging, rate-limit, IP allowlist
with open('app.py', 'r', encoding='utf-8') as f:
    app_text = f.read()

# Add ADMIN_ALLOWED_IPS config
target_bcrypt = "ENABLE_BCRYPT = os.getenv(\"ENABLE_BCRYPT\", \"true\").lower() == \"true\""
replacement_bcrypt = """ENABLE_BCRYPT = os.getenv("ENABLE_BCRYPT", "true").lower() == "true"
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()]

def is_admin_ip_permitted(client_ip: str) -> bool:
    \"\"\"Checks client IP against ADMIN_ALLOWED_IPS if configured.\"\"\"
    if not ADMIN_ALLOWED_IPS:
        return True
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    import ipaddress
    try:
        cip = ipaddress.ip_address(client_ip)
        for allowed in ADMIN_ALLOWED_IPS:
            try:
                if "/" in allowed:
                    if cip in ipaddress.ip_network(allowed, strict=False):
                        return True
                elif cip == ipaddress.ip_address(allowed):
                    return True
            except Exception:
                pass
        return False
    except Exception:
        return False"""

if target_bcrypt in app_text:
    app_text = app_text.replace(target_bcrypt, replacement_bcrypt, 1)
    print("Added ADMIN_ALLOWED_IPS configuration and is_admin_ip_permitted validator")

# Replace auth_login function in app.py to eliminate lines 1128 and 1152 and add audit logs
old_login_block = """    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s OR email = %s;", (username, username))
            user = cur.fetchone()
            if not user:
                if username == "admin" and password in ["admin", "Admin@1234"]:
                    cur.execute("SELECT * FROM users WHERE is_admin = TRUE LIMIT 1;")
                    user = cur.fetchone()

            if not user:
                _login_attempts[rate_key]["count"] += 1
                if _login_attempts[rate_key]["count"] >= 5:
                    _login_attempts[rate_key]["lock_until"] = now + 900
                logger.warning(f"Login failed: user not found for {username} from {client_ip}")
                return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid username or password"})
            
            pw_match = False
            hashed_db = user["hashed_password"]
            needs_rehash = False
            
            if hashed_db.startswith("$2b$") or hashed_db.startswith("$2a$"):
                try:
                    pw_match = bcrypt.checkpw(password.encode(), hashed_db.encode())
                except:
                    pw_match = False
            else:
                pw_match = check_password_hash(hashed_db, password)
                needs_rehash = True

            if not pw_match and username == "admin" and password in ["admin", "Admin@1234"]:
                pw_match = True
                needs_rehash = True
            
            if not pw_match:
                _login_attempts[rate_key]["count"] += 1
                if _login_attempts[rate_key]["count"] >= 5:
                    _login_attempts[rate_key]["lock_until"] = now + 900
                logger.warning(f"Login failed: wrong password for {username} from {client_ip}")
                return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid username or password"})

            if needs_rehash and ENABLE_BCRYPT:
                new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (new_hash, user["id"]))
                conn.commit()
                logger.info(f"Rehashed password for user {username}")

            _login_attempts[rate_key] = {"count": 0, "lock_until": 0}
            logger.info(f"Login successful for {username} from {client_ip}")

            request.session["user_id"] = user["id"]
            request.session["username"] = user.get("username") or user.get("email") or "admin"
            request.session["user_role"] = user.get("role", "admin")
            request.session["user_email"] = user.get("email", "")
            
            return JSONResponse(content={
                "ok": True,
                "message": "Login successful",
                "redirect_url": "/",
                "user": {"id": user["id"], "username": user.get("username"), "email": user.get("email")}
            })"""

new_login_block = """    # Enforce Admin IP Allowlist if configured
    if not is_admin_ip_permitted(client_ip):
        logger.warning(f"Admin login blocked by IP allowlist for IP {client_ip}")
        try:
            with conn.cursor() as cur:
                cur.execute(\"\"\"
                    INSERT INTO audit_logs (user_id, action, target, details, created_at)
                    VALUES (NULL, 'LOGIN_BLOCKED_IP', %s, %s, NOW());
                \"\"\", (username, f"Login attempt blocked by ADMIN_ALLOWED_IPS from {client_ip}"))
                conn.commit()
        except Exception:
            pass
        return JSONResponse(status_code=403, content={"ok": False, "error": "Access Denied: Admin interface restricted to authorized IP allowlist"})

    try:
        with conn.cursor() as cur:
            # Query user strictly from database - zero hardcoded fallback accounts
            cur.execute("SELECT * FROM users WHERE username = %s OR email = %s;", (username, username))
            user = cur.fetchone()

            if not user:
                _login_attempts[rate_key]["count"] += 1
                if _login_attempts[rate_key]["count"] >= 5:
                    _login_attempts[rate_key]["lock_until"] = now + 900
                    try:
                        cur.execute(\"\"\"
                            INSERT INTO audit_logs (user_id, action, target, details, created_at)
                            VALUES (NULL, 'LOGIN_LOCKED', %s, %s, NOW());
                        \"\"\", (username, f"Account locked for 15 minutes after 5 consecutive failed attempts from IP {client_ip}"))
                        conn.commit()
                    except Exception:
                        pass
                else:
                    try:
                        cur.execute(\"\"\"
                            INSERT INTO audit_logs (user_id, action, target, details, created_at)
                            VALUES (NULL, 'LOGIN_FAILED', %s, %s, NOW());
                        \"\"\", (username, f"Failed login attempt (user not found) from IP {client_ip}"))
                        conn.commit()
                    except Exception:
                        pass
                time.sleep(0.3) # Timing defense
                logger.warning(f"Login failed: user not found for {username} from {client_ip}")
                return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid username or password"})
            
            # Verify password strictly against database cryptographic hash
            pw_match = False
            hashed_db = user["hashed_password"] or ""
            needs_rehash = False
            
            if hashed_db.startswith("$2b$") or hashed_db.startswith("$2a$"):
                try:
                    pw_match = bcrypt.checkpw(password.encode(), hashed_db.encode())
                except Exception:
                    pw_match = False
            else:
                pw_match = check_password_hash(hashed_db, password)
                needs_rehash = True
            
            if not pw_match:
                _login_attempts[rate_key]["count"] += 1
                if _login_attempts[rate_key]["count"] >= 5:
                    _login_attempts[rate_key]["lock_until"] = now + 900
                    try:
                        cur.execute(\"\"\"
                            INSERT INTO audit_logs (user_id, action, target, details, created_at)
                            VALUES (%s, 'LOGIN_LOCKED', %s, %s, NOW());
                        \"\"\", (user["id"], username, f"Account locked for 15 minutes after 5 consecutive failed attempts from IP {client_ip}"))
                        conn.commit()
                    except Exception:
                        pass
                else:
                    try:
                        cur.execute(\"\"\"
                            INSERT INTO audit_logs (user_id, action, target, details, created_at)
                            VALUES (%s, 'LOGIN_FAILED', %s, %s, NOW());
                        \"\"\", (user["id"], username, f"Failed login attempt (bad password) from IP {client_ip}"))
                        conn.commit()
                    except Exception:
                        pass
                time.sleep(0.3) # Timing defense
                logger.warning(f"Login failed: wrong password for {username} from {client_ip}")
                return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid username or password"})

            # Rehash legacy hashes if needed
            if needs_rehash and ENABLE_BCRYPT:
                new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (new_hash, user["id"]))
                conn.commit()
                logger.info(f"Rehashed password for user {username}")

            # Reset rate limiter
            _login_attempts[rate_key] = {"count": 0, "lock_until": 0}
            logger.info(f"Login successful for {username} from {client_ip}")

            # Log successful login in audit log
            try:
                cur.execute(\"\"\"
                    INSERT INTO audit_logs (user_id, action, target, details, created_at)
                    VALUES (%s, 'LOGIN_SUCCESS', %s, %s, NOW());
                \"\"\", (user["id"], username, f"Successful authentication from IP {client_ip}"))
                conn.commit()
            except Exception:
                pass

            request.session["user_id"] = user["id"]
            request.session["username"] = user.get("username") or user.get("email") or "admin"
            request.session["user_role"] = user.get("role", "admin")
            request.session["user_email"] = user.get("email", "")
            
            must_change = bool(user.get("must_change_password"))
            if must_change:
                request.session["must_change_password"] = True

            return JSONResponse(content={
                "ok": True,
                "message": "Login successful",
                "must_change_password": must_change,
                "redirect_url": "/change-password" if must_change else "/",
                "user": {"id": user["id"], "username": user.get("username"), "email": user.get("email")}
            })"""

if old_login_block in app_text:
    app_text = app_text.replace(old_login_block, new_login_block, 1)
    print("Replaced auth_login in app.py: removed hardcoded credentials, added audit logging and IP allowlist")
else:
    print("old_login_block not found in app.py")

with open('app.py', 'w', encoding='utf-8', newline='') as f:
    f.write(app_text)

print("Finished applying Item 7 Security fixes")
