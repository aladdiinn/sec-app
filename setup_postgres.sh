#!/bin/bash
# ==============================================================================
# SecurePulse PostgreSQL Database Setup Script (Ubuntu/Debian)
# ==============================================================================
# This script installs PostgreSQL, configures it for external access, and sets
# up the exact database credentials expected by the SecurePulse application.
# ==============================================================================

# Exit on error
set -e

echo "[*] Updating package lists..."
sudo apt-get update -y

echo "[*] Installing PostgreSQL..."
sudo apt-get install -y postgresql postgresql-contrib

# ------------------------------------------------------------------------------
# 1. Setup Database and Credentials
# ------------------------------------------------------------------------------
# Default credentials mapped from app.py:
DB_NAME="securepulse_db"
DB_USER="securepulse"
DB_PASS="securepulse_pass"

echo "[*] Creating PostgreSQL User and Database..."
sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" || echo "[!] User may already exist."
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || echo "[!] Database may already exist."
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"
sudo -u postgres psql -c "ALTER USER ${DB_USER} CREATEDB;"

# ------------------------------------------------------------------------------
# 2. Configure PostgreSQL for External Access
# ------------------------------------------------------------------------------
echo "[*] Configuring PostgreSQL to listen on all interfaces..."

# Find the postgresql.conf file dynamically (supports different PG versions like 14, 15, 16)
PG_CONF_FILE=$(sudo find /etc/postgresql -name "postgresql.conf" | head -n 1)
PG_HBA_FILE=$(sudo find /etc/postgresql -name "pg_hba.conf" | head -n 1)

if [ -z "$PG_CONF_FILE" ]; then
    echo "[!] Could not find postgresql.conf. Please configure listen_addresses manually."
else
    # Backup conf
    sudo cp "$PG_CONF_FILE" "${PG_CONF_FILE}.bak"
    # Replace or add listen_addresses
    sudo sed -i "s/^#listen_addresses = 'localhost'/listen_addresses = '*'/g" "$PG_CONF_FILE"
    # If it wasn't uncommented, forcefully append it
    grep -q "^listen_addresses = '*'" "$PG_CONF_FILE" || echo "listen_addresses = '*'" | sudo tee -a "$PG_CONF_FILE"
    echo "[+] Updated ${PG_CONF_FILE}"
fi

if [ -z "$PG_HBA_FILE" ]; then
    echo "[!] Could not find pg_hba.conf. Please configure external IP access manually."
else
    # Backup conf
    sudo cp "$PG_HBA_FILE" "${PG_HBA_FILE}.bak"
    # Add external access rule allowing password auth from ANY IP 
    # (For production, restrict 0.0.0.0/0 to your actual App Server IP)
    echo "host    ${DB_NAME}    ${DB_USER}    0.0.0.0/0    md5" | sudo tee -a "$PG_HBA_FILE"
    echo "[+] Updated ${PG_HBA_FILE}"
fi

# ------------------------------------------------------------------------------
# 3. Open Firewall (Optional but Recommended)
# ------------------------------------------------------------------------------
echo "[*] Checking UFW Firewall rules..."
if command -v ufw > /dev/null; then
    sudo ufw allow 5432/tcp
    echo "[+] Opened port 5432 in UFW."
fi

# ------------------------------------------------------------------------------
# 4. Restart and Verify
# ------------------------------------------------------------------------------
echo "[*] Restarting PostgreSQL service to apply changes..."
sudo systemctl restart postgresql
sudo systemctl enable postgresql

echo ""
echo "========================================================================"
echo "                   DATABASE SETUP COMPLETE!                             "
echo "========================================================================"
echo " Database Name : ${DB_NAME}"
echo " Database User : ${DB_USER}"
echo " Database Pass : ${DB_PASS}"
echo " Port          : 5432"
echo "========================================================================"
echo ""
echo "NEXT STEPS ON YOUR APPLICATION SERVER:"
echo "Update your environment variables or start the SecurePulse app with this"
echo "new external database IP:"
echo ""
echo "export DB_HOST=\"<THIS_NEW_SERVER_IP>\""
echo "export DB_PORT=\"5432\""
echo "export DB_NAME=\"${DB_NAME}\""
echo "export DB_USER=\"${DB_USER}\""
echo "export DB_PASS=\"${DB_PASS}\""
echo "python app.py"
echo "========================================================================"
