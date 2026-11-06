# BSmart SOC Command Center — Production Deployment Guide
**Zero-Secret Architecture for Docker on Ubuntu 22.04 LTS**

---

## 1. Security Architecture Principles

1. **Zero Secrets in Git**: No real `.env` file, database passwords, or cryptographic tokens exist in this repository.
2. **Zero Secrets in Docker Images**: `.dockerignore` blocks `.env*`, `.pem`, and keys. Secrets are injected strictly at runtime via Docker Compose `env_file`.
3. **Single Authoritative `.env`**: Exactly ONE configuration file located at `/application/Soc/.env`. No second copies inside git clones.
4. **Private Image Registry**: Images are built via GitHub Actions and published to GitHub Container Registry (`ghcr.io`).
5. **Local Host Proxying**: The container binds only to `127.0.0.1:8001` on the loopback interface (preventing collision with existing host services like GitLab Dashboard on port 8000), terminated by HAProxy on HTTPS port 3443 with SSL.

---

## 2. Recommended Production Directory Layout

The deployment host `/application/Soc` is an execution folder, NOT a development repository. It should contain only runtime orchestration files:

```text
/application/Soc/
├── docker-compose.yml     # Multi-container stack (soc-app + soc-db)
├── .env                   # Single production configuration (chmod 600 root:root)
├── logs/                  # Persistent rotated security logs (/app/logs)
├── data/                  # Offline MaxMind GeoIP database & local state (/app/data)
└── SOC-DB/                # Dedicated isolated PostgreSQL 15 database volume
```

### Server Git Repository Cleanup Procedure
If `/application/Soc` was initialized as a git clone that accidentally tracked `.env`:
```bash
cd /application/Soc

# 1. Untrack .env from git index WITHOUT deleting the actual file on disk
git rm --cached .env

# 2. Verify git status (should show .env untracked / ignored)
git status

# 3. Check history to confirm what secret names were exposed (do not print values)
git log -p -1 .env | grep -E "^[+-][A-Z_]+=" | awk -F'=' '{print $1}' | sort -u
```

### Secrets to Rotate Immediately
If `.env` was committed or pushed to any shared repository, immediately rotate:
1. `GEMINI_API_KEY` (Revoke and regenerate in Google AI Studio)
2. `SES_AWS_SECRET_ACCESS_KEY` (Deactivate IAM access key in AWS IAM and issue a new one)
3. `AWS_S3_SECRET_ACCESS_KEY` (Deactivate IAM access key in AWS IAM and issue a new one)
4. `SECRET_KEY` (Regenerate new 64-char key: `openssl rand -hex 32`)
5. `DB_PASSWORD` (Change PostgreSQL password and update `/application/Soc/.env`)

---

## 3. AWS SES Prerequisites & Setup

### A. Region Alignment
- The AWS IAM credentials and `SES_AWS_REGION` MUST match the region where your sender email/domain identity is verified (e.g. `ap-south-1` or `us-east-1`).
- If using separate regions for S3 and SES:
  - `SES_AWS_REGION=ap-south-1`
  - `AWS_S3_REGION=us-east-1`

### B. Sandbox vs Production Mode
- **SES Sandbox**: If your AWS account is in the SES Sandbox, **EVERY recipient address** in `SES_RECIPIENT_EMAIL` must be individually verified in AWS SES Console.
- **Production Mode**: Submit a standard "Request Production Access" in AWS SES Console (typically approved within 24h) to send to unverified recipient emails.

### C. Minimal IAM Policy for SES
Attach this least-privilege IAM policy to the user specified in `SES_AWS_ACCESS_KEY_ID`:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSESSending",
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail",
                "ses:GetSendQuota",
                "ses:GetIdentityVerificationAttributes"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## 4. Applying Changes & Restarting Services

Whenever `/application/Soc/.env` is edited, you MUST force Docker Compose to recreate the container so the new environment variables are loaded:

```bash
cd /application/Soc

# Recreate container with updated environment variables
docker compose up -d --force-recreate soc

# Test SES connection and list available models
docker compose exec soc python check_gemini_models.py
docker compose exec soc python test_ses.py
```

---

## 5. Reverse Proxy Setup (HAProxy on Port 3443)

The SOC container listens on loopback `127.0.0.1:8001`. HAProxy terminates HTTPS on port `3443`:

```haproxy
frontend https_frontend_3443
    bind 192.168.10.201:3443 ssl crt /etc/haproxy/bsmartone.pem
    mode http
    option httplog
    option forwardfor
    acl is_bsmartsoc hdr_beg(host) -i bsmartsoc.bsmartone.com
    use_backend bsmartsoc_backend if is_bsmartsoc
    default_backend bsmartsoc_backend

backend bsmartsoc_backend
    mode http
    option forwardfor
    timeout tunnel 3600s
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Port 3443
    http-request set-header X-Real-IP %[src]
    server soc_app 127.0.0.1:8001 check inter 5s rise 2 fall 3
```

Reload HAProxy:
```bash
sudo systemctl reload haproxy
```
