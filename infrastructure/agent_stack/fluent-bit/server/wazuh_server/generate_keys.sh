#!/usr/bin/env bash
# ============================================================================
# file: wazuh_server/generate_keys.sh
# Description: Standalone script to configure TLS Root CA Certificate and Shared Ingest Token
#              for Fluent-Bit on Server A (Wazuh Server).
#              Designed for easy distributed deployment on independent machines.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
DB_SERVER_CERTS="$(cd "${SCRIPT_DIR}/../database_server" 2>/dev/null && pwd)/certs"
DB_SERVER_ENV="$(cd "${SCRIPT_DIR}/../database_server" 2>/dev/null && pwd)/.env"

TOKEN=""
TARGET_HOST=""
TARGET_PORT=""

# Parse arguments if passed (e.g., --token <TOKEN> --host <HOST>)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token|-t)
            TOKEN="$2"
            shift 2
            ;;
        --host|-h)
            TARGET_HOST="$2"
            shift 2
            ;;
        --port|-p)
            TARGET_PORT="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "================================================================="
echo "🔒  LSMP SECURITY: CONFIGURING WAZUH SERVER KEYS & CERTIFICATES"
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

# 2. Extract, Prompt, or Use Provided INGEST_TOKEN
if [ -z "${TOKEN}" ] && [ -f "${DB_SERVER_ENV}" ]; then
    TOKEN=$(grep "^INGEST_TOKEN=" "${DB_SERVER_ENV}" | cut -d '=' -f2-)
fi

if [ -z "${TOKEN}" ] && [ -f "${ENV_FILE}" ]; then
    EXISTING_TOKEN=$(grep "^INGEST_TOKEN=" "${ENV_FILE}" | cut -d '=' -f2-)
    if [ -n "${EXISTING_TOKEN}" ] && [ "${EXISTING_TOKEN}" != "CHANGE_ME_RANDOM_LONG_SECRET" ]; then
        TOKEN="${EXISTING_TOKEN}"
    fi
fi

if [ -z "${TOKEN}" ] || [ "${TOKEN}" = "CHANGE_ME_RANDOM_LONG_SECRET" ]; then
    if [ -t 0 ]; then
        read -rp "🔑 Enter INGEST_TOKEN generated on Database Server: " TOKEN
    fi
fi

if [ -z "${TOKEN}" ] || [ "${TOKEN}" = "CHANGE_ME_RANDOM_LONG_SECRET" ]; then
    echo "❌ Error: A valid INGEST_TOKEN is required."
    echo "   Usage: bash generate_keys.sh --token <TOKEN>"
    exit 1
fi

# 3. Create or Update .env file for Wazuh Server
echo "⚙️  Updating environment file (${ENV_FILE})..."
if [ ! -f "${ENV_FILE}" ]; then
    if [ -f "${ENV_EXAMPLE}" ]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    else
        cat <<EOF > "${ENV_FILE}"
INGEST_HOST=${TARGET_HOST:-127.0.0.1}
INGEST_PORT=${TARGET_PORT:-8080}
INGEST_TOKEN=${TOKEN}
ENABLE_TLS=On
TLS_VERIFY=On
EOF
    fi
fi

# Sync parameters in .env
if grep -q "^INGEST_TOKEN=" "${ENV_FILE}"; then
    sed -i "s|^INGEST_TOKEN=.*|INGEST_TOKEN=${TOKEN}|" "${ENV_FILE}"
else
    echo "INGEST_TOKEN=${TOKEN}" >> "${ENV_FILE}"
fi

if [ -n "${TARGET_HOST}" ]; then
    if grep -q "^INGEST_HOST=" "${ENV_FILE}"; then
        sed -i "s|^INGEST_HOST=.*|INGEST_HOST=${TARGET_HOST}|" "${ENV_FILE}"
    else
        echo "INGEST_HOST=${TARGET_HOST}" >> "${ENV_FILE}"
    fi
fi

if [ -n "${TARGET_PORT}" ]; then
    if grep -q "^INGEST_PORT=" "${ENV_FILE}"; then
        sed -i "s|^INGEST_PORT=.*|INGEST_PORT=${TARGET_PORT}|" "${ENV_FILE}"
    else
        echo "INGEST_PORT=${TARGET_PORT}" >> "${ENV_FILE}"
    fi
fi

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
echo "✅ WAZUH SERVER FLUENT-BIT TLS SECURITY CONFIGURED!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📜 Root CA File    : ${CERTS_DIR}/ca.crt"
echo "🔑 Configured Token: ${TOKEN}"
echo "================================================================="
