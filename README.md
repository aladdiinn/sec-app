# SecurePulse — Server Security Monitoring Platform

A production-style, agent-based security monitoring dashboard built with
**Flask + PostgreSQL + SocketIO + Vanilla JS**.

## Architecture

```
Agent (Linux server)
  └─ login_monitor.py   → tails auth.log (ssh_login / failed_login / logout)
  └─ cron_monitor.py    → SHA-256 hash watch on /etc/cron* (cron_change)
  └─ process_monitor.py → psutil new-PID detection (new_process)
  └─ heartbeat.py       → periodic alive ping (heartbeat)
       │
       │  POST /events  (X-Agent-Token header)
       ▼
Backend (Flask + PostgreSQL)
  └─ app.py             → REST API + SocketIO server
  └─ models.py          → users / servers / events / alerts tables
  └─ database.py        → SQLAlchemy init
       │
       │  WebSocket push  (room: dashboard)
       ▼
Frontend (Jinja2 templates served by Flask)
  └─ dashboard.html     → live feed + stats + open alerts
  └─ servers.html       → server list + status
  └─ events.html        → paginated events + filters
  └─ alerts.html        → alert management + resolve
```

---

## 1. PostgreSQL Setup

### Local (Windows / macOS / Linux)

```sql
-- Run in psql as superuser
CREATE USER securepulse WITH PASSWORD 'securepulse_pass';
CREATE DATABASE securepulse_db OWNER securepulse;
GRANT ALL PRIVILEGES ON DATABASE securepulse_db TO securepulse;
```

### Antigravity Cloud
Create a PostgreSQL service in Antigravity, then copy the connection string:
```
DATABASE_URL=postgresql://USERNAME:PASSWORD@HOST:PORT/DBNAME?sslmode=require
```

---

## 2. Backend Setup

```bash
cd security-dash

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
# .env is already present with default values — edit if needed
# Make sure DATABASE_URL points to your PostgreSQL instance

# Run (tables are created + admin seeded automatically)
python app.py
```

The server starts at **http://localhost:5000**

**Default login:**
- Email: `admin@securepulse.local`
- Password: `Admin@1234`

---

## 3. Frontend

No build step needed. Flask serves all pages from `templets/` and static files
from `static/`. Open http://localhost:5000 in your browser.

---

## 4. Agent Setup (on a Linux server)

### Option A — Install via script (recommended)
```bash
# On the TARGET Linux server you want to monitor:
sudo bash install.sh \
  --backend-url http://YOUR_DASHBOARD_IP:5000 \
  --api-key     sp-agent-key-9f2a8c1b5d3e7f0a4c6b8d2e1f5a9c3b
```

The script will:
1. Install Python3, pip, psutil
2. Copy agent files to `/opt/securepulse-agent/`
3. Register the server → get an `agent_token`
4. Write `/etc/securepulse-agent.conf`
5. Enable `securepulse-agent.service` (auto-start on reboot)

### Option B — Manual run (for testing)
```bash
cd agent

# Set environment variables
export SP_BACKEND_URL=http://localhost:5000
export SP_AGENT_TOKEN=<token-from-registration>

python3 agent.py
```

### Register a server manually (curl)
```bash
curl -X POST http://localhost:5000/agents/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sp-agent-key-9f2a8c1b5d3e7f0a4c6b8d2e1f5a9c3b" \
  -d '{
    "hostname": "test-server-01",
    "ip_address": "192.168.1.100",
    "os_info": "Ubuntu 22.04"
  }'
```
Copy the returned `agent_token` and export it as `SP_AGENT_TOKEN`.

### Send a test event (curl)
```bash
curl -X POST http://localhost:5000/events \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: <your-agent-token>" \
  -d '{
    "event_type": "ssh_login",
    "description": "SSH login: user=admin from=192.168.1.50",
    "severity": "info",
    "source": "auth.log"
  }'
```

---

## 5. Database Schema

| Table     | Purpose                                      |
|-----------|----------------------------------------------|
| `users`   | Dashboard admin accounts (JWT auth)          |
| `servers` | Registered agents (hostname, IP, token)      |
| `events`  | All security events from agents              |
| `alerts`  | Auto-generated alerts for suspicious events  |

---

## 6. API Reference

| Method | Endpoint                    | Auth          | Description                    |
|--------|-----------------------------|---------------|--------------------------------|
| POST   | `/auth/login`               | —             | Login, returns JWT             |
| GET    | `/auth/me`                  | JWT Bearer    | Current user info              |
| POST   | `/agents/register`          | X-API-Key     | Register new agent             |
| POST   | `/events`                   | X-Agent-Token | Ingest event from agent        |
| GET    | `/events`                   | JWT Bearer    | List events (filtered/paged)   |
| GET    | `/servers`                  | JWT Bearer    | List all servers + status      |
| GET    | `/servers/stats`            | JWT Bearer    | Dashboard KPI stats            |
| GET    | `/alerts`                   | JWT Bearer    | List alerts (filtered/paged)   |
| PATCH  | `/alerts/<id>/resolve`      | JWT Bearer    | Resolve an alert               |
| GET    | `/health`                   | —             | Health check                   |

---

## 7. Agent Service Management (Linux)

```bash
# Check status
sudo systemctl status securepulse-agent

# View live logs
sudo journalctl -u securepulse-agent -f

# Restart agent
sudo systemctl restart securepulse-agent

# Stop agent
sudo systemctl stop securepulse-agent

# View config
cat /etc/securepulse-agent.conf
```

---

## 8. Deploying to Cloud (Antigravity / VPS)

### Simple VPS Deployment (no Kubernetes)

```bash
# 1. SSH into your server
ssh user@YOUR_SERVER_IP

# 2. Clone the project
git clone https://github.com/your-org/securepulse.git
cd securepulse

# 3. Set environment variables
cp .env .env.production
# Edit DATABASE_URL, SECRET_KEY, AGENT_API_KEY

# 4. Install + run with gunicorn
pip install -r requirements.txt
gunicorn --worker-class eventlet -w 1 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  "app:app"

# 5. Use nginx as reverse proxy (recommended)
# Point nginx to localhost:5000
# Enable WebSocket upgrade in nginx config
```

### Antigravity Specific
1. Create a PostgreSQL service → copy the `DATABASE_URL`
2. Create a Python service, set env vars in the dashboard
3. Set start command: `gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT "app:app"`
4. Deploy agents on your monitored servers pointing `SP_BACKEND_URL` to your Antigravity URL

---

## 9. Environment Variables Reference

| Variable                  | Required | Default                            | Description                   |
|---------------------------|----------|------------------------------------|-------------------------------|
| `SECRET_KEY`              | Yes      | auto-generated                     | Flask/JWT signing key         |
| `DATABASE_URL`            | Yes      | `postgresql://...localhost...`     | PostgreSQL connection string  |
| `AGENT_API_KEY`           | Yes      | see `.env`                         | Key agents use to register    |
| `DEFAULT_ADMIN_EMAIL`     | No       | `admin@securepulse.local`          | Seeded admin email            |
| `DEFAULT_ADMIN_PASSWORD`  | No       | `Admin@1234`                       | Seeded admin password         |
| `HEARTBEAT_TIMEOUT`       | No       | `120`                              | Seconds before server offline |
| `PORT`                    | No       | `5000`                             | Server port                   |
| `DEBUG`                   | No       | `false`                            | Flask debug mode              |
