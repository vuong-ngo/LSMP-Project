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

TOKEN_ARG=""
REDIS_PASS_ARG=""
FORCE_REGEN=false

show_help() {
    echo "Usage: bash generate_keys.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --token, -t <TOKEN>         Specify a custom INGEST_TOKEN (64-char hex recommended)"
    echo "  --redis-pass, -r <PASS>     Specify a custom REDIS_PASSWORD"
    echo "  --force, -f                 Force re-generation of TLS certificates and random tokens"
    echo "  --help, -h                  Show this help message"
    exit 0
}

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token|-t)
            TOKEN_ARG="$2"
            shift 2
            ;;
        --redis-pass|-r)
            REDIS_PASS_ARG="$2"
            shift 2
            ;;
        --force|-f)
            FORCE_REGEN=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "Unknown argument: $1"
            show_help
            ;;
    esac
done

echo "================================================================="
echo "🔒  LSMP SECURITY: GENERATING DATABASE SERVER KEYS & CERTIFICATES"
echo "================================================================="

mkdir -p "${CERTS_DIR}"

# 1. Determine INGEST_TOKEN and REDIS_PASSWORD
INGEST_TOKEN=""
REDIS_PASSWORD=""

if [ -n "${TOKEN_ARG}" ]; then
    INGEST_TOKEN="${TOKEN_ARG}"
elif [ "${FORCE_REGEN}" = false ] && [ -f "${ENV_FILE}" ]; then
    EXISTING_TOKEN=$(grep "^INGEST_TOKEN=" "${ENV_FILE}" 2>/dev/null | cut -d '=' -f2-)
    if [ -n "${EXISTING_TOKEN}" ] && [ "${EXISTING_TOKEN}" != "CHANGE_ME_RANDOM_LONG_SECRET" ]; then
        INGEST_TOKEN="${EXISTING_TOKEN}"
        echo "ℹ️  Retaining existing INGEST_TOKEN from ${ENV_FILE}"
    fi
fi

if [ -z "${INGEST_TOKEN}" ]; then
    echo "🔑 Generating secure random INGEST_TOKEN..."
    INGEST_TOKEN=$(openssl rand -hex 32)
fi

if [ -n "${REDIS_PASS_ARG}" ]; then
    REDIS_PASSWORD="${REDIS_PASS_ARG}"
elif [ "${FORCE_REGEN}" = false ] && [ -f "${ENV_FILE}" ]; then
    EXISTING_PASS=$(grep "^REDIS_PASSWORD=" "${ENV_FILE}" 2>/dev/null | cut -d '=' -f2-)
    if [ -n "${EXISTING_PASS}" ] && [ "${EXISTING_PASS}" != "SecretRedisPassword123" ]; then
        REDIS_PASSWORD="${EXISTING_PASS}"
        echo "ℹ️  Retaining existing REDIS_PASSWORD from ${ENV_FILE}"
    fi
fi

if [ -z "${REDIS_PASSWORD}" ]; then
    echo "🔑 Generating secure random REDIS_PASSWORD..."
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24)
fi

# 2. TLS Certificates Generation
if [ "${FORCE_REGEN}" = false ] && [ -f "${CERTS_DIR}/ca.crt" ] && [ -f "${CERTS_DIR}/ca.key" ] && [ -f "${CERTS_DIR}/lsmp_ingest.crt" ] && [ -f "${CERTS_DIR}/lsmp_ingest.key" ]; then
    echo "✅ Existing TLS Certificates found in ${CERTS_DIR}. Skipping certificate generation."
    echo "   (Use --force or -f to regenerate certificates)"
else
    echo "📜 Generating Root CA Private Key and Certificate (ca.crt)..."
    openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" -sha256 -days 3650 \
        -out "${CERTS_DIR}/ca.crt" \
        -subj "/C=VN/ST=Hanoi/L=Hanoi/O=LSMP Security/OU=DB Server/CN=LSMP-Root-CA" 2>/dev/null

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

    echo "🛡️ Signing Server Certificate (lsmp_ingest.crt) with Root CA..."
    openssl x509 -req -in "${CERTS_DIR}/lsmp_ingest.csr" \
        -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial \
        -out "${CERTS_DIR}/lsmp_ingest.crt" -days 3650 -sha256 \
        -extfile "${CERTS_DIR}/san.cnf" -extensions req_ext 2>/dev/null

    rm -f "${CERTS_DIR}/lsmp_ingest.csr" "${CERTS_DIR}/san.cnf" "${CERTS_DIR}/ca.srl"
fi

# Set strict permissions on keys and certificates
chmod 600 "${CERTS_DIR}"/*.key 2>/dev/null || true
chmod 644 "${CERTS_DIR}"/*.crt 2>/dev/null || true

# 3. Create or Update .env file for Database Server
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
echo "✅ DATABASE SERVER SECURITY KEYS SUCCESSFULLY CONFIGURED!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📄 Server Cert     : ${CERTS_DIR}/lsmp_ingest.crt"
echo "🔑 Server Key      : ${CERTS_DIR}/lsmp_ingest.key"
echo "📜 Root CA Cert    : ${CERTS_DIR}/ca.crt"
echo "🔑 Configured Token: ${INGEST_TOKEN}"
echo "================================================================="
echo ""
echo "📋 TO DEPLOY ON REMOTE WAZUH SERVER (SERVER A):"
echo "1. Copy '${CERTS_DIR}/ca.crt' to Server A at: wazuh_server/certs/ca.crt"
echo "2. Set INGEST_TOKEN in Server A's .env file or run:"
echo "   bash generate_keys.sh --token ${INGEST_TOKEN}"
echo "================================================================="
