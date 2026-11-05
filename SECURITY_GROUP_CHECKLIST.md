# AWS EC2 Security Group & Network Hardening Checklist
**Target Host**: `13.232.88.40` (Production BSmart SOC Server)

---

### 1. Inbound Rules Checklist (Ingress)

| Port / Protocol | Service / Purpose | Source IP / CIDR | Action Required | Risk Assessment |
|---|---|---|---|---|
| **TCP 443** (HTTPS) | Web UI Dashboard & Agent Telemetry | **Analyst VPN / Office IPs** (e.g. `203.0.113.0/24`) or `0.0.0.0/0` if protected by `ADMIN_ALLOWED_IPS` | **ALLOW** | Normal operational access. Protected by TLS and IP allowlist. |
| **TCP 80** (HTTP) | ACME Challenge / HTTP Redirect | `0.0.0.0/0` (only for Let's Encrypt renewal) or restricted | **ALLOW (Redirect only)** | Nginx immediately 301-redirects all traffic to 443. |
| **TCP 8000** | Direct FastAPI / Uvicorn Server | **BLOCKED FROM INTERNET** (`127.0.0.1` only) | **REMOVE / BLOCK** | **CRITICAL RISK**: Bypasses Nginx reverse proxy, TLS encryption, and header validation. Must only listen locally on `127.0.0.1:8000`. |
| **TCP 22** (SSH) | Secure Shell Server Administration | **Admin Workstation / Bastion IP strictly** (e.g. `103.116.x.x/32`) | **RESTRICT STRICTLY** | **CRITICAL RISK**: Never expose SSH to `0.0.0.0/0` (prevents brute-force scanning). Use SSH key pairs only; disable password authentication in `sshd_config`. |
| **TCP 5432** (PostgreSQL) | Internal Telemetry Database | **Localhost (`127.0.0.1`) only** or Private VPC Subnet | **BLOCK EXTERNAL** | Database must NEVER be bound to a public IP. Configured in `postgresql.conf` with `listen_addresses = 'localhost'`. |

---

### 2. Outbound Rules Checklist (Egress)

| Port / Protocol | Service / Purpose | Destination | Recommendation |
|---|---|---|---|
| **TCP 443** | AWS SES (Email Alerts) & Package Updates | `0.0.0.0/0` (or AWS IP ranges) | Allow outbound HTTPS. |
| **TCP 53** (UDP/TCP) | DNS Resolution | AWS VPC DNS Resolver (`10.0.0.2` / `169.254.169.253`) | Standard internal DNS resolution. |
| **TCP 123** (UDP) | NTP Time Synchronization | Standard NTP servers | Essential for SIEM event correlation accuracy. |

---

### 3. Verification Commands (Run on Server)

1. **Verify port 8000 is listening locally only:**
   ```bash
   ss -tulpn | grep 8000
   # Expected output: 127.0.0.1:8000 (NOT 0.0.0.0:8000)
   ```
2. **Verify Nginx reverse proxy is active:**
   ```bash
   systemctl status nginx
   ```
3. **Verify TLS certificates:**
   ```bash
   openssl s_client -connect 127.0.0.1:443 -servername soc.bsmartsoc.local
   ```
4. **Run verify_login.sh against localhost and public IP:**
   ```bash
   ./verify_login.sh http://127.0.0.1:8000
   ./verify_login.sh https://13.232.88.40
   ```
