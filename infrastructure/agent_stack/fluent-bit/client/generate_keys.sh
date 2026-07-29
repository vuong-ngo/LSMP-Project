#!/usr/bin/env bash
# ============================================================================
# file: client/generate_keys.sh
# Description: Standalone script to configure TLS Root CA Certificate and environment
#              for LSMP Client Fluent-Bit Agent.
#              Designed for easy deployment on monitored SME client machines.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
DB_SERVER_CERTS="$(cd "${SCRIPT_DIR}/../server/database_server" 2>/dev/null && pwd)/certs"

echo "================================================================="
echo "🔒  LSMP SECURITY: CONFIGURING CLIENT AGENT TLS & CREDENTIALS"
echo "================================================================="

mkdir -p "${CERTS_DIR}"

# 1. Sync or Verify Root CA Certificate (ca.crt)
if [ -f "${DB_SERVER_CERTS}/ca.crt" ]; then
    echo "📋 Auto-syncing Root CA Certificate (ca.crt) from local database_server..."
    cp "${DB_SERVER_CERTS}/ca.crt" "${CERTS_DIR}/ca.crt"
else
    if [ ! -f "${CERTS_DIR}/ca.crt" ]; then
        echo "⚠️  Root CA certificate (${CERTS_DIR}/ca.crt) not found."
        echo "   Please copy 'ca.crt' generated from Database Server into '${CERTS_DIR}/ca.crt'."
        exit 1
    else
        echo "✅ Existing Root CA certificate found at ${CERTS_DIR}/ca.crt"
    fi
fi

# 2. Create or Update .env file for Client Agent
echo "⚙️  Updating environment file (${ENV_FILE})..."
if [ ! -f "${ENV_FILE}" ]; then
    if [ -f "${ENV_EXAMPLE}" ]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    else
        cat <<EOF > "${ENV_FILE}"
LOKI_HOST=127.0.0.1
LOKI_PORT=3100
LOKI_USER=
LOKI_PASSWORD=
ENABLE_TLS=On
TLS_VERIFY=On
WAZUH_HOST=127.0.0.1
WAZUH_PORT=514
CLIENT_HOSTNAME=$(hostname 2>/dev/null || echo "client-01")
ENV=production
EOF
    fi
fi

# Sync parameters in .env
if grep -q "^ENABLE_TLS=" "${ENV_FILE}"; then
    sed -i "s|^ENABLE_TLS=.*|ENABLE_TLS=On|" "${ENV_FILE}"
else
    echo "ENABLE_TLS=On" >> "${ENV_FILE}"
fi

if grep -q "^TLS_VERIFY=" "${ENV_FILE}"; then
    sed -i "s|^TLS_VERIFY=.*|TLS_VERIFY=On|" "${ENV_FILE}"
else
    echo "TLS_VERIFY=On" >> "${ENV_FILE}"
fi

chmod 644 "${CERTS_DIR}"/*.crt 2>/dev/null || true

echo "================================================================="
echo "✅ LSMP CLIENT FLUENT-BIT TLS SECURITY CONFIGURED!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📜 Root CA File    : ${CERTS_DIR}/ca.crt"
echo "================================================================="
