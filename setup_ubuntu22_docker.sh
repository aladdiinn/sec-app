#!/usr/bin/env bash
# ==============================================================================
# BSmart SOC Command Center — Ubuntu 22.04 LTS Host Provisioning Script
# Automated Docker CE, Docker Compose V2, UFW Firewall, HAProxy TLS & Stack Init
# ==============================================================================

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (use sudo)."
  exit 1
fi

SERVER_IP=$(curl -s https://ifconfig.me || curl -s https://api.ipify.org || hostname -I | awk '{print $1}')
INSTALL_DIR="/opt/bsmart-soc"

echo "================================================================================"
echo " Starting BSmart SOC Server Setup on Ubuntu 22.04 LTS"
echo " Detected Server IP: $SERVER_IP"
echo " Target Directory:   $INSTALL_DIR"
echo "================================================================================"

# 1. Update package lists and install essential system tools
echo "[1/7] Installing prerequisite packages..."
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    ufw \
    openssl \
    git \
    net-tools

# 2. Install official Docker Engine & Docker Compose V2
echo "[2/7] Installing official Docker CE & Compose Plugin..."
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

systemctl enable docker
systemctl start docker

# Add sudo user to docker group if running under sudo
if [ -n "${SUDO_USER:-}" ]; then
    usermod -aG docker "$SUDO_USER"
    echo "Added user $SUDO_USER to docker group."
fi

# 3. Create target deployment directory layout
echo "[3/7] Setting up directory structure at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR/certs"
mkdir -p "$INSTALL_DIR/haproxy"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/certs"

# 4. Copy configuration files to /opt/bsmart-soc if running from repository
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
    echo "Copying docker-compose and configs from $SCRIPT_DIR..."
    cp "$SCRIPT_DIR/docker-compose.yml" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/haproxy/haproxy.cfg" "$INSTALL_DIR/haproxy/"
    cp "$SCRIPT_DIR/haproxy/generate_certs.sh" "$INSTALL_DIR/haproxy/"
    chmod +x "$INSTALL_DIR/haproxy/generate_certs.sh"
    
    if [ ! -f "$INSTALL_DIR/.env" ] && [ -f "$SCRIPT_DIR/.env.example" ]; then
        cp "$SCRIPT_DIR/.env.example" "$INSTALL_DIR/.env"
        # Generate random secure passwords for fresh installation
        RAND_DB_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9')
        RAND_SEC_KEY=$(openssl rand -hex 32)
        RAND_STATS_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
        sed -i "s/replace_with_strong_database_password_2026/$RAND_DB_PASS/g" "$INSTALL_DIR/.env"
        sed -i "s/replace_with_random_64_character_secret_key/$RAND_SEC_KEY/g" "$INSTALL_DIR/.env"
        sed -i "s/replace_with_strong_stats_password/$RAND_STATS_PASS/g" "$INSTALL_DIR/.env"
        echo "Generated initial .env file with randomized secrets."
    fi
fi

# 5. Generate TLS Certificate for HAProxy
echo "[4/7] Generating initial TLS certificates for HAProxy..."
cd "$INSTALL_DIR"
if [ ! -f "$INSTALL_DIR/certs/combined.pem" ]; then
    bash "$INSTALL_DIR/haproxy/generate_certs.sh" "$SERVER_IP"
fi

# 6. Configure UFW Host Firewall (Security Hardening)
echo "[5/7] Configuring UFW host firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH Remote Administration"
ufw allow 80/tcp comment "HTTP (HAProxy -> HTTPS Redirect)"
ufw allow 443/tcp comment "HTTPS (HAProxy TLS Termination)"
ufw allow 8404/tcp comment "HAProxy Health & Stats Dashboard"
# Block external access to internal backend and db ports
ufw deny 8000/tcp comment "Block direct FastAPI access (HAProxy only)"
ufw deny 5432/tcp comment "Block direct PostgreSQL access"
ufw --force enable

# 7. Pull and Launch Docker Containers
echo "[6/7] Starting BSmart SOC Docker container stack..."
docker compose pull || true
docker compose up -d

# 8. Verification & Status Report
echo "[7/7] Validating deployment status..."
sleep 5
docker compose ps

echo "================================================================================"
echo " [✓] BSmart SOC Platform Successfully Deployed!"
echo "================================================================================"
echo " Public Access URLs:"
echo "   - Web Console:      https://$SERVER_IP/"
echo "   - HAProxy Stats:    https://$SERVER_IP:8404/stats"
echo ""
echo " Directory Location:   $INSTALL_DIR"
echo " Environment File:     $INSTALL_DIR/.env"
echo " To view live logs:    docker compose -f $INSTALL_DIR/docker-compose.yml logs -f"
echo "================================================================================"
