# BSmart SOC Command Center — Production Deployment Guide
**Zero-Secret Architecture for Docker on Ubuntu 22.04 LTS**

---

## 1. Security Architecture Principles

1. **Zero Secrets in Git**: No real `.env` file, database passwords, or cryptographic tokens exist in this repository.
2. **Zero Secrets in Docker Images**: `.dockerignore` blocks `.env*`, `.pem`, and keys. Secrets are injected strictly at runtime via Docker Compose `env_file`.
3. **Private Image Registry**: Images are built via GitHub Actions and published to GitHub Container Registry (`ghcr.io`).
4. **Local Host Proxying**: The container binds only to `127.0.0.1:8005` on the loopback interface (preventing collision with existing host services like GitLab Dashboard on port 8000), shielding FastAPI and PostgreSQL from direct internet exposure.

---

## 2. Server Setup Commands (Run on Ubuntu 22.04 LTS)

### Step 1: Create Host Directory Layout
```bash
# Create deployment directories
sudo mkdir -p /application/Soc/logs /application/Soc/data
cd /application/Soc
```

### Step 2: Copy Docker Compose Configuration
Copy [`docker-compose.yml`](file:///c:/Users/Test/Downloads/security-dash/docker-compose.yml) to `/application/Soc/docker-compose.yml`:
```bash
sudo curl -fsSL https://raw.githubusercontent.com/aladdiinn/sec-app/main/docker-compose.yml -o /application/Soc/docker-compose.yml
# Or copy via SCP: scp docker-compose.yml user@server:/application/Soc/
```

### Step 3: Create `/application/Soc/.env` Manually
Create `/application/Soc/.env` from `.env.example`:
```bash
sudo nano /application/Soc/.env
```
Populate the required secrets:
```dotenv
# ── Database Credentials ──
DB_HOST=host.docker.internal
DB_PORT=5432
DB_NAME=bsmart_soc
DB_USER=socadmin
DB_PASSWORD=YOUR_STRONG_DATABASE_PASSWORD_HERE

# ── Application Security ──
# Generate with: openssl rand -hex 32
SECRET_KEY=YOUR_64_CHAR_RANDOM_SECRET_KEY_HERE
SECURE_COOKIES=true
ENABLE_BCRYPT=true
ADMIN_ALLOWED_IPS=
TRUSTED_PROXIES=127.0.0.1,172.17.0.1,172.18.0.1
PORT=8000
ENVIRONMENT=production

# ── Storage & Logging ──
LOG_LEVEL=INFO
LOG_FILE_PATH=/app/logs/app_security.log
GEOIP_DB_PATH=/app/data/GeoLite2-City.mmdb
```

### Step 4: Lock Down Permissions (Root-only read)
```bash
sudo chown -R root:root /application/Soc
sudo chmod 600 /application/Soc/.env
sudo chmod 755 /application/Soc/logs /application/Soc/data
```

### Step 5: Log in to GitHub Container Registry (GHCR)
Generate a GitHub Personal Access Token (Classic) with `read:packages` scope, then log in:
```bash
echo "YOUR_GHCR_PAT_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

### Step 6: Start the SOC Container
```bash
cd /application/Soc
docker compose pull
docker compose up -d
```

### Step 7: Verify Running State
```bash
# Check container status
docker compose ps

# View live application security log
docker compose logs -f soc

# Verify local healthcheck
curl -f http://127.0.0.1:8005/api/version
```

---

## 3. Database Connectivity from Container

### When PostgreSQL runs on the host server:
1. `DB_HOST=host.docker.internal` allows the container to communicate with the host via `extra_hosts: ["host.docker.internal:host-gateway"]`.
2. Configure PostgreSQL to listen on the Docker bridge gateway (`172.17.0.1`):
   Edit `/etc/postgresql/14/main/postgresql.conf`:
   ```ini
   listen_addresses = 'localhost, 172.17.0.1'
   ```
3. Allow container subnet access in `/etc/postgresql/14/main/pg_hba.conf`:
   ```
   # Allow Docker bridge network to connect to bsmart_soc
   host    bsmart_soc    socadmin    172.17.0.0/16    scram-sha-256
   ```
4. Reload PostgreSQL: `sudo systemctl reload postgresql`.

---

## 4. Reverse Proxy Options on Host (Port 80/443 Termination)

Because your server already runs a reverse proxy managing existing services, route traffic to `http://127.0.0.1:8000` using either option below.

### Option A: Using Nginx on the Host
Create `/etc/nginx/sites-available/soc.conf`:
```nginx
server {
    listen 80;
    server_name soc.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/soc.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8005;
        proxy_http_version 1.1;

        # WebSocket & SSE Streaming Support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Proxy IP Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/soc.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option B: Using Existing Host HAProxy
If you already have HAProxy running on the host, append this snippet to `/etc/haproxy/haproxy.cfg`:

```haproxy
frontend https_in
    # Existing bind ...
    acl is_soc hdr(host) -i soc.yourdomain.com
    use_backend soc_backend if is_soc

backend soc_backend
    mode http
    option forwardfor
    timeout tunnel 3600s
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    server soc_app 127.0.0.1:8000 check inter 5s rise 2 fall 3
```
Reload HAProxy:
```bash
sudo systemctl reload haproxy
```

---

## 5. Instant Rollback Procedure

Every build pushed by GitHub Actions is tagged with the short commit SHA (e.g. `ghcr.io/aladdiinn/sec-app:sha-1b05f8d`).

To roll back immediately to a known stable build:
```bash
# Set image to specific commit SHA tag in /application/Soc/.env
echo "DOCKER_IMAGE=ghcr.io/aladdiinn/sec-app:sha-4e804d0" | sudo tee -a /application/Soc/.env

# Pull and restart
cd /application/Soc
docker compose pull soc
docker compose up -d
```

---

## 6. Optional Enterprise Upgrade: AWS SSM Parameter Store

To avoid maintaining `/application/Soc/.env` manually, store secrets in AWS SSM Parameter Store under path `/soc/production/`:
- `/soc/production/DB_PASSWORD` (SecureString)
- `/soc/production/SECRET_KEY` (SecureString)

Attach an IAM Role with `ssm:GetParametersByPath` to the EC2 instance, then generate `/application/Soc/.env` automatically during deployment:

```bash
#!/usr/bin/env bash
# /application/Soc/fetch_env_from_ssm.sh
aws ssm get-parameters-by-path \
  --path "/soc/production/" \
  --with-decryption \
  --query "Parameters[*].[Name,Value]" \
  --output text | awk '{split($1,a,"/"); print a[4]"="$2}' > /application/Soc/.env

chmod 600 /application/Soc/.env
```
