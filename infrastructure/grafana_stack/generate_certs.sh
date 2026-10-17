#!/usr/bin/env bash
# ============================================================================
# file: grafana_stack/generate_certs.sh
# Description: Generates TLS certificates for Grafana Loki Nginx Gateway
#              signed by the LSMP Root CA, enabling secure end-to-end TLS between
#              log shippers (Fluent-Bit client) and Loki Gateway (:3100).
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
DB_SERVER_CERTS="$(cd "${SCRIPT_DIR}/../agent_stack/fluent-bit/server/database_server" 2>/dev/null && pwd)/certs"

# ====== Default Parameters & State ======
FORCE_REGEN=false
EXTRA_DOMAINS=()
EXTRA_IPS=()

# ====== Help & Usage Information ======
show_help() {
    echo "Usage: bash generate_certs.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --domain, -d <DOMAIN>       Add extra DNS SAN to TLS cert (repeatable)"
    echo "  --extra-ip, -i <IP>         Add extra IP SAN to TLS cert (repeatable)"
    echo "  --force, -f                 Force re-generation of TLS certificates"
    echo "  --help, -h                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  bash generate_certs.sh --domain loki.example.com --extra-ip 192.168.1.100"
    echo "  bash generate_certs.sh -d server-b.local -i 10.0.0.5"
    exit 0
}

# ====== Parse CLI Arguments ======
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE_REGEN=true
            shift
            ;;
        --domain|-d)
            EXTRA_DOMAINS+=("$2")
            shift 2
            ;;
        --extra-ip|-i)
            EXTRA_IPS+=("$2")
            shift 2
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
echo "🔒  LSMP SECURITY: GENERATING TLS CERTS FOR LOKI GATEWAY"
echo "================================================================="

mkdir -p "${CERTS_DIR}"

# Check if certificates already exist and skip unless --force
if [ "${FORCE_REGEN}" = false ] && [ -f "${CERTS_DIR}/loki_gateway.crt" ] && [ -f "${CERTS_DIR}/loki_gateway.key" ] && [ -f "${CERTS_DIR}/ca.crt" ]; then
    echo "ℹ️  Existing Loki Gateway TLS certificates found in ${CERTS_DIR}."
    echo "   Use --force to regenerate new keys and certificates."
    exit 0
fi

# ====== Step 1: Locate or Generate Root CA ======
CA_KEY=""
CA_CRT=""

if [ -f "${CERTS_DIR}/ca.crt" ] && [ -f "${CERTS_DIR}/ca.key" ]; then
    echo "📜 Found existing Root CA at ${CERTS_DIR}"
    CA_KEY="${CERTS_DIR}/ca.key"
    CA_CRT="${CERTS_DIR}/ca.crt"
elif [ -f "${DB_SERVER_CERTS}/ca.crt" ] && [ -f "${DB_SERVER_CERTS}/ca.key" ]; then
    echo "📜 Reusing LSMP Root CA from local database_server (${DB_SERVER_CERTS})..."
    cp -f "${DB_SERVER_CERTS}/ca.crt" "${CERTS_DIR}/ca.crt"
    cp -f "${DB_SERVER_CERTS}/ca.key" "${CERTS_DIR}/ca.key"
    CA_KEY="${CERTS_DIR}/ca.key"
    CA_CRT="${CERTS_DIR}/ca.crt"
else
    echo "🔑 Generating new LSMP Root CA..."
    openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" -sha256 -days 3650 \
        -out "${CERTS_DIR}/ca.crt" \
        -subj "/C=VN/ST=Hanoi/L=Hanoi/O=LSMP Security/OU=Grafana Loki Gateway/CN=LSMP-Root-CA" 2>/dev/null
    CA_KEY="${CERTS_DIR}/ca.key"
    CA_CRT="${CERTS_DIR}/ca.crt"
    echo "✅ Root CA generated at ${CERTS_DIR}/ca.crt"
fi

# ====== Step 2: Auto-detect Host IP Addresses ======
DETECTED_IPS=$(hostname -I 2>/dev/null || ip addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
for ip in ${DETECTED_IPS}; do
    if [[ ! " ${EXTRA_IPS[*]} " =~ " ${ip} " ]] && [[ "${ip}" != "127.0.0.1" ]]; then
        EXTRA_IPS+=("${ip}")
    fi
done

# ====== Step 3: Generate Loki Gateway Server Key & CSR ======
echo "🔐 Generating Loki Gateway Private Key (loki_gateway.key)..."
openssl genrsa -out "${CERTS_DIR}/loki_gateway.key" 2048 2>/dev/null

echo "📝 Preparing Subject Alternative Names (SANs)..."
SAN_CONFIG="[req]
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[req_distinguished_name]
C  = VN
ST = Hanoi
L  = Hanoi
O  = LSMP Security
OU = Grafana Loki Gateway
CN = gateway

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = gateway
DNS.3 = loki
IP.1  = 127.0.0.1
IP.2  = 0.0.0.0"

DNS_IDX=4
for d in "${EXTRA_DOMAINS[@]}"; do
    SAN_CONFIG="${SAN_CONFIG}
DNS.${DNS_IDX} = ${d}"
    DNS_IDX=$((DNS_IDX + 1))
done

IP_IDX=3
for ip_addr in "${EXTRA_IPS[@]}"; do
    SAN_CONFIG="${SAN_CONFIG}
IP.${IP_IDX} = ${ip_addr}"
    IP_IDX=$((IP_IDX + 1))
done

SAN_CONF_FILE="${CERTS_DIR}/san.cnf"
echo "${SAN_CONFIG}" > "${SAN_CONF_FILE}"

echo "🛡️  Signing Loki Gateway Certificate (loki_gateway.crt)..."
openssl req -new -key "${CERTS_DIR}/loki_gateway.key" \
    -out "${CERTS_DIR}/loki_gateway.csr" \
    -config "${SAN_CONF_FILE}" 2>/dev/null

openssl x509 -req -in "${CERTS_DIR}/loki_gateway.csr" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${CERTS_DIR}/loki_gateway.crt" \
    -days 3650 -sha256 \
    -extfile "${SAN_CONF_FILE}" -extensions req_ext 2>/dev/null

rm -f "${CERTS_DIR}/loki_gateway.csr" "${CERTS_DIR}/san.cnf"
chmod 644 "${CERTS_DIR}"/*.crt 2>/dev/null || true
chmod 600 "${CERTS_DIR}"/*.key 2>/dev/null || true

# ====== Step 4: Verification ======
echo "🔍 Verifying generated certificate against Root CA..."
if openssl verify -CAfile "${CA_CRT}" "${CERTS_DIR}/loki_gateway.crt" >/dev/null 2>&1; then
    echo "✅ Certificate chain is 100% VALID!"
else
    echo "❌ Error: Certificate verification failed!"
    exit 1
fi

# ====== Step 5: Output Summary ======
echo "================================================================="
echo "✅ LOKI GATEWAY TLS CERTIFICATES READY!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${CERTS_DIR}"
echo "📄 Server Cert     : ${CERTS_DIR}/loki_gateway.crt"
echo "🔑 Server Key      : ${CERTS_DIR}/loki_gateway.key"
echo "📜 Root CA Cert    : ${CERTS_DIR}/ca.crt"
echo "🌐 SANs included   :"
openssl x509 -in "${CERTS_DIR}/loki_gateway.crt" -noout -ext subjectAltName 2>/dev/null | grep -A5 "Subject Alternative Name" || true
echo "-----------------------------------------------------------------"
echo "📋 Distribution Guide:"
echo "   Copy '${CERTS_DIR}/ca.crt' to client endpoints (e.g. fluent-bit client)"
echo "   to enable secure verification when pushing logs to port 3100 (HTTPS)."
echo "================================================================="
