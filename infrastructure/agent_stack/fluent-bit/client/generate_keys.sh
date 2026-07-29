#!/usr/bin/env bash
# ============================================================================
# file: client/generate_keys.sh
# Description: Automated TLS Certificate generator & Grafana Loki connection
#              configurator for LSMP Client Fluent-Bit Agent.
#              Supports auto-syncing CA certs, generating self-signed fallback
#              certs, and setting up secure connections to Grafana Loki.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
DB_SERVER_CERTS="$(cd "${SCRIPT_DIR}/../server/database_server" 2>/dev/null && pwd)/certs"

# Default CLI parameters
ARG_LOKI_HOST=""
ARG_LOKI_PORT=""
ARG_LOKI_USER=""
ARG_LOKI_PASS=""
ARG_CA_CERT=""

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --loki-host)
            ARG_LOKI_HOST="$2"
            shift 2
            ;;
        --loki-port)
            ARG_LOKI_PORT="$2"
            shift 2
            ;;
        --loki-user)
            ARG_LOKI_USER="$2"
            shift 2
            ;;
        --loki-pass)
            ARG_LOKI_PASS="$2"
            shift 2
            ;;
        --ca-cert)
            ARG_CA_CERT="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "================================================================="
echo "🔒  LSMP SECURITY: CONFIGURING CLIENT AGENT TLS & GRAFANA LOKI"
echo "================================================================="

mkdir -p "${CERTS_DIR}"

# 1. Provision Root CA Certificate (ca.crt)
if [ -n "${ARG_CA_CERT}" ] && [ -f "${ARG_CA_CERT}" ]; then
    echo "📋 Copying provided Root CA Certificate from ${ARG_CA_CERT}..."
    cp "${ARG_CA_CERT}" "${CERTS_DIR}/ca.crt"
elif [ -f "${DB_SERVER_CERTS}/ca.crt" ]; then
    echo "📋 Auto-syncing Root CA Certificate from local database_server..."
    cp "${DB_SERVER_CERTS}/ca.crt" "${CERTS_DIR}/ca.crt"
elif [ -f "${CERTS_DIR}/ca.crt" ]; then
    echo "✅ Existing Root CA certificate found at ${CERTS_DIR}/ca.crt"
else
    echo "🔑 Generating self-signed Root CA certificate fallback for TLS..."
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "${CERTS_DIR}/ca.key" \
        -out "${CERTS_DIR}/ca.crt" \
        -days 3650 \
        -subj "/C=VN/ST=Hanoi/L=Hanoi/O=LSMP Security/OU=Client/CN=LSMP-Root-CA" 2>/dev/null
    echo "✅ Self-signed Root CA generated at ${CERTS_DIR}/ca.crt"
fi

# 2. Configure .env File
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

# Override variables if CLI arguments provided
if [ -n "${ARG_LOKI_HOST}" ]; then
    sed -i "s|^LOKI_HOST=.*|LOKI_HOST=${ARG_LOKI_HOST}|" "${ENV_FILE}"
fi
if [ -n "${ARG_LOKI_PORT}" ]; then
    sed -i "s|^LOKI_PORT=.*|LOKI_PORT=${ARG_LOKI_PORT}|" "${ENV_FILE}"
fi
if [ -n "${ARG_LOKI_USER}" ]; then
    sed -i "s|^LOKI_USER=.*|LOKI_USER=${ARG_LOKI_USER}|" "${ENV_FILE}"
fi
if [ -n "${ARG_LOKI_PASS}" ]; then
    sed -i "s|^LOKI_PASSWORD=.*|LOKI_PASSWORD=${ARG_LOKI_PASS}|" "${ENV_FILE}"
fi

# Ensure TLS flags are enabled
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

# Display current configuration summary
CURRENT_LOKI_HOST=$(grep "^LOKI_HOST=" "${ENV_FILE}" | cut -d '=' -f2)
CURRENT_LOKI_PORT=$(grep "^LOKI_PORT=" "${ENV_FILE}" | cut -d '=' -f2)

echo "================================================================="
echo "✅ LSMP CLIENT FLUENT-BIT SECURE CONNECTION CONFIGURED!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📜 Root CA File    : ${CERTS_DIR}/ca.crt"
echo "🌐 Grafana Loki    : https://${CURRENT_LOKI_HOST}:${CURRENT_LOKI_PORT}"
echo "================================================================="
