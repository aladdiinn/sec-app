#!/usr/bin/env bash
# ==============================================================================
# BSmart SOC — HAProxy Certificate Generator & Manager
# Generates self-signed TLS certificates for bootstrap OR converts Let's Encrypt
# certificates into HAProxy combined PEM format (cert + privkey in one file).
# ==============================================================================

set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../certs" && pwd)"
mkdir -p "$CERTS_DIR"
chmod 700 "$CERTS_DIR"

COMBINED_PEM="$CERTS_DIR/combined.pem"

if [ "$#" -ge 1 ] && [ "$1" == "letsencrypt" ]; then
    DOMAIN="${2:-}"
    if [ -z "$DOMAIN" ]; then
        echo "Error: Domain required. Usage: ./generate_certs.sh letsencrypt <your-domain.com>"
        exit 1
    fi
    LE_PATH="/etc/letsencrypt/live/$DOMAIN"
    if [ ! -f "$LE_PATH/fullchain.pem" ] || [ ! -f "$LE_PATH/privkey.pem" ]; then
        echo "Error: Let's Encrypt files not found at $LE_PATH"
        exit 1
    fi
    echo "[*] Combining Let's Encrypt certificates for HAProxy..."
    cat "$LE_PATH/fullchain.pem" "$LE_PATH/privkey.pem" > "$COMBINED_PEM"
    chmod 600 "$COMBINED_PEM"
    echo "[✓] Successfully installed combined PEM to: $COMBINED_PEM"
    exit 0
fi

SERVER_IP="${1:-127.0.0.1}"

echo "[*] Generating 2048-bit RSA Self-Signed TLS Certificate for HAProxy..."
echo "[*] Subject Alternative Names (SAN): DNS:localhost, IP:127.0.0.1, IP:$SERVER_IP"

TMP_KEY=$(mktemp)
TMP_CRT=$(mktemp)
TMP_CONF=$(mktemp)

cat <<EOF > "$TMP_CONF"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = IN
ST = Maharashtra
L = Mumbai
O = BSmart SOC
OU = Security Operations
CN = ${SERVER_IP}

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ${SERVER_IP}
EOF

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$TMP_KEY" \
    -out "$TMP_CRT" \
    -config "$TMP_CONF" >/dev/null 2>&1

# HAProxy expects the private key and cert concatenated together
cat "$TMP_CRT" "$TMP_KEY" > "$COMBINED_PEM"
chmod 600 "$COMBINED_PEM"

rm -f "$TMP_KEY" "$TMP_CRT" "$TMP_CONF"

echo "[✓] HAProxy TLS certificate ready at: $COMBINED_PEM"
echo "[i] For production domains with Let's Encrypt, run:"
echo "    sudo certbot certonly --standalone -d your-domain.com"
echo "    ./haproxy/generate_certs.sh letsencrypt your-domain.com"
