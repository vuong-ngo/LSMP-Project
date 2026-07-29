#!/usr/bin/env bash
# ============================================================================
# file: database_server/generate_keys.sh
# Description: Standalone script to generate TLS Certificates & Shared Ingest Token
#              for LSMP Ingest Receiver (Server B - Database Server).
#              Can be run independently on Server B in a distributed setup.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"

echo "================================================================="
echo "🔒  LSMP SECURITY: GENERATING DATABASE SERVER KEYS & CERTIFICATES"
echo "================================================================="

mkdir -p "${CERTS_DIR}"

# 1. Generate High-Entropy Shared Token & Redis Password
echo "🔑 Generating secure random INGEST_TOKEN and REDIS_PASSWORD..."
INGEST_TOKEN=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | fold -w 24 | head -n 1)

# 2. Generate Root CA Key and Self-Signed CA Certificate
echo "📜 Generating Root CA Private Key and Certificate (ca.crt)..."
openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" -sha256 -days 3650 \
    -out "${CERTS_DIR}/ca.crt" \
    -subj "/C=VN/ST=Hanoi/L=Hanoi/O=LSMP Security/OU=DB Server/CN=LSMP-Root-CA" 2>/dev/null

# 3. Generate Ingest Server Private Key and CSR Configuration with SAN
echo "🔐 Generating LSMP Ingest Server Private Key (lsmp_ingest.key)..."
openssl genrsa -out "${CERTS_DIR}/lsmp_ingest.key" 2048 2>/dev/null

cat <<EOF > "${CERTS_DIR}/san.cnf"
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[dn]
C  = VN
ST = Hanoi
L  = Hanoi
O  = LSMP Security
OU = Ingest Server
CN = lsmp-ingest

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = lsmp-ingest
IP.1  = 127.0.0.1
IP.2  = 0.0.0.0
EOF

openssl req -new -key "${CERTS_DIR}/lsmp_ingest.key" \
    -out "${CERTS_DIR}/lsmp_ingest.csr" \
    -config "${CERTS_DIR}/san.cnf" 2>/dev/null

# 4. Sign the Server Certificate using the Root CA
echo "🛡️ Signing Server Certificate (lsmp_ingest.crt) with Root CA..."
openssl x509 -req -in "${CERTS_DIR}/lsmp_ingest.csr" \
    -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial \
    -out "${CERTS_DIR}/lsmp_ingest.crt" -days 3650 -sha256 \
    -extfile "${CERTS_DIR}/san.cnf" -extensions req_ext 2>/dev/null

# Clean up temporary CSR & SAN config
rm -f "${CERTS_DIR}/lsmp_ingest.csr" "${CERTS_DIR}/san.cnf" "${CERTS_DIR}/ca.srl"

# Set strict permissions on keys and certificates
chmod 600 "${CERTS_DIR}"/*.key
chmod 644 "${CERTS_DIR}"/*.crt

# 5. Create or Update .env file for Database Server
echo "⚙️  Updating environment file (${ENV_FILE})..."
if [ ! -f "${ENV_FILE}" ]; then
    if [ -f "${ENV_EXAMPLE}" ]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    else
        cat <<EOF > "${ENV_FILE}"
REDIS_PASSWORD=${REDIS_PASSWORD}
INGEST_TOKEN=${INGEST_TOKEN}
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=lsmp_db
USE_TLS=true
EOF
    fi
fi

# Update INGEST_TOKEN, REDIS_PASSWORD, and USE_TLS safely in .env
if grep -q "^INGEST_TOKEN=" "${ENV_FILE}"; then
    sed -i "s|^INGEST_TOKEN=.*|INGEST_TOKEN=${INGEST_TOKEN}|" "${ENV_FILE}"
else
    echo "INGEST_TOKEN=${INGEST_TOKEN}" >> "${ENV_FILE}"
fi

if grep -q "^REDIS_PASSWORD=" "${ENV_FILE}"; then
    sed -i "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=${REDIS_PASSWORD}|" "${ENV_FILE}"
else
    echo "REDIS_PASSWORD=${REDIS_PASSWORD}" >> "${ENV_FILE}"
fi

if grep -q "^USE_TLS=" "${ENV_FILE}"; then
    sed -i "s|^USE_TLS=.*|USE_TLS=true|" "${ENV_FILE}"
else
    echo "USE_TLS=true" >> "${ENV_FILE}"
fi

echo "================================================================="
echo "✅ DATABASE SERVER SECURITY KEYS SUCCESSFULLY GENERATED!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📄 Server Cert     : ${CERTS_DIR}/lsmp_ingest.crt"
echo "🔑 Server Key      : ${CERTS_DIR}/lsmp_ingest.key"
echo "📜 Root CA Cert    : ${CERTS_DIR}/ca.crt"
echo "🔑 Generated Token : ${INGEST_TOKEN}"
echo "================================================================="
echo ""
echo "📋 TO DEPLOY ON REMOTE WAZUH SERVER (SERVER A):"
echo "1. Copy '${CERTS_DIR}/ca.crt' to Server A at: wazuh_server/certs/ca.crt"
echo "2. Set INGEST_TOKEN in Server A's .env file:"
echo "   INGEST_TOKEN=${INGEST_TOKEN}"
echo "================================================================="
