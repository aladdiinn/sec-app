import re

with open("app.py", "r", encoding="utf-8") as f:
    code = f.read()

# 1. Add RotatingFileHandler
target_log = """# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("security_monitor.app")"""

replacement_log = """# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("security_monitor.app")

# Persistent rotated application log file (Requirement 9)
from logging.handlers import RotatingFileHandler
try:
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "app_security.log")
    file_handler = RotatingFileHandler(log_file, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.getLogger().addHandler(file_handler)
except Exception as _log_e:
    logger.warning(f"Could not initialize RotatingFileHandler: {_log_e}")"""

if "RotatingFileHandler" not in code:
    code = code.replace(target_log, replacement_log)
    print("[+] Added RotatingFileHandler for log persistence")

# 2. Add get_client_ip function and update auth_login
target_helper = """_login_attempts = defaultdict(lambda: {"count": 0, "lock_until": 0})
ENABLE_BCRYPT = os.getenv("ENABLE_BCRYPT", "true").lower() == "true"
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()]

def is_admin_ip_permitted(client_ip: str) -> bool:"""

replacement_helper = """_login_attempts = defaultdict(lambda: {"count": 0, "lock_until": 0})
ENABLE_BCRYPT = os.getenv("ENABLE_BCRYPT", "true").lower() == "true"
ADMIN_ALLOWED_IPS = [ip.strip() for ip in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()]

def get_client_ip(request: Request) -> str:
    \"\"\"Extracts the client IP address, properly inspecting proxy headers when behind reverse proxies.\"\"\"
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    x_real = request.headers.get("x-real-ip")
    if x_real:
        return x_real.strip()
    return request.client.host if request.client else "127.0.0.1"

def is_admin_ip_permitted(client_ip: str) -> bool:"""

if "def get_client_ip(" not in code:
    code = code.replace(target_helper, replacement_helper)
    print("[+] Added get_client_ip function")

# 3. Update client_ip in auth_login
target_auth_head = """async def auth_login(request: Request):
    client_ip = request.client.host if request.client else "unknown\""""

replacement_auth_head = """async def auth_login(request: Request):
    client_ip = get_client_ip(request)"""

code = code.replace(target_auth_head, replacement_auth_head)

# 4. Replace time.sleep(0.3) with await asyncio.sleep(0.3) in auth_login
code = code.replace("time.sleep(0.3) # Timing defense", "await asyncio.sleep(0.3) # Non-blocking async timing defense")

# 5. Ensure rate lock returns 429 and does not lock globally
target_lock_check = """    if _login_attempts[rate_key]["lock_until"] > now:
        logger.warning(f"Login failed: locked out for {username} from {client_ip}")
        return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid username or password"})"""

replacement_lock_check = """    if _login_attempts[rate_key]["lock_until"] > now:
        remaining = int(_login_attempts[rate_key]["lock_until"] - now)
        logger.warning(f"Login throttled: per-IP lockout for {username} from {client_ip} ({remaining}s remaining)")
        return JSONResponse(status_code=429, content={"ok": False, "error": f"Too many failed login attempts from your IP. Account locked for {remaining} seconds."})"""

code = code.replace(target_lock_check, replacement_lock_check)

with open("app.py", "w", encoding="utf-8") as f:
    f.write(code)

print("[+] Updated app.py with async sleep, proxy client IP extraction, and log rotation.")
