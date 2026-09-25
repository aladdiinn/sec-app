# SecurePulse — Server Security Monitoring Platform

A production-style, agent-based security monitoring dashboard built with
**FastAPI + PostgreSQL + Vanilla JS**.

## Architecture

```
Agent (Linux server)
  └─ node_push_agent.py (auto-installed via curl)
       │  Tails auth.log / syslogs / application logs
       │  Scans processes, resources, file modifications (FIM)
       │  POST /api/agent/push
       ▼
Backend (FastAPI + PostgreSQL)
  └─ app.py             → REST API & Backend Engine
  └─ database.py        → PostgreSQL interactions & schema
       │
       │  Serves UI & Responds to API calls
       ▼
Frontend (Jinja2 templates served by FastAPI)
  └─ dashboard.html     → Live feed + stats + alerts
  └─ servers.html       → Server inventory & NOC status
  └─ rules.html         → Detection Rules Engine
  └─ ...
```

---

## 1. PostgreSQL Setup

### Local Setup

```sql
-- Run in psql as superuser
CREATE USER securepulse WITH PASSWORD 'securepulse_pass';
CREATE DATABASE securepulse_db OWNER securepulse;
GRANT ALL PRIVILEGES ON DATABASE securepulse_db TO securepulse;
```

---

## 2. Backend Setup

```bash
cd security-dash

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start everything easily with the script
chmod +x start.sh
./start.sh
```

The server starts at **http://localhost:8000**

**Default login:**
- Email: `admin@securepulse.local`
- Password: `Admin@1234`

---

## 3. Agent Setup (on a Linux server)

On the TARGET Linux server you want to monitor, simply run the autoinstall script from your SOC backend:

```bash
curl -s http://YOUR_DASHBOARD_IP:8000/setup_node.sh -d "name=MyServer&ip=192.168.1.100" | bash
```

The script will:
1. Copy agent files to `/opt/securepulse/node_push_agent.py`
2. Register the server in the Pending Approvals list
3. Create a systemd service `securepulse.service` (auto-start on reboot)

**Important:** After running the script, go to the SOC Dashboard -> Asset Inventory to **Approve** the pending server. Once approved, telemetry will begin appearing.

---

## 4. API Reference

| Method | Endpoint                    | Description                    |
|--------|-----------------------------|--------------------------------|
| POST   | `/api/login`                | Login, stores session cookie   |
| POST   | `/api/servers/add`          | Add a server manually          |
| POST   | `/api/agent/push`           | Ingest telemetry from agents   |
| GET    | `/api/servers`              | List all servers               |
| GET    | `/api/alerts`               | List alerts (filtered)         |
| GET    | `/api/dashboard/counts`     | Dashboard KPI stats            |

---

## 5. Agent Service Management (Linux)

```bash
# Check status
sudo systemctl status securepulse

# View live logs
sudo tail -f /var/log/securepulse_agent.log

# Restart agent
sudo systemctl restart securepulse
```
