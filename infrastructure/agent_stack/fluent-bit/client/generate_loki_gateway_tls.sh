#!/usr/bin/env bash
# ============================================================================
# file: agent_stack/fluent-bit/client/generate_loki_gateway_tls.sh
# Description: Generates TLS certificates for Grafana Loki Nginx Gateway
#              signed by the LSMP Root CA, enabling end-to-end TLS between
#              Fluent-Bit client and Loki Gateway.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_CERTS_DIR="${SCRIPT_DIR}/certs"
DB_SERVER_CERTS="$(cd "${SCRIPT_DIR}/../server/database_server" 2>/dev/null && pwd)/certs"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
GRAFANA_STACK_DIR="${PROJECT_ROOT}/grafana_stack"
OUTPUT_CERTS_DIR="${SCRIPT_DIR}/loki_gateway_certs"

# ====== CLI Arguments & Options ======
EXTRA_IPS=()
EXTRA_DOMAINS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --extra-ip)
            EXTRA_IPS+=("$2")
            shift 2
            ;;
        --domain)
            EXTRA_DOMAINS+=("$2")
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

echo "================================================================="
echo "🔒  LSMP SECURITY: GENERATING TLS CERTS FOR LOKI GATEWAY"
echo "================================================================="

mkdir -p "${CLIENT_CERTS_DIR}" "${OUTPUT_CERTS_DIR}"

# ====== Step 1: Locate or Generate Root CA ======
CA_KEY=""
CA_CRT=""

if [ -f "${DB_SERVER_CERTS}/ca.crt" ] && [ -f "${DB_SERVER_CERTS}/ca.key" ]; then
    echo "📜 Found existing LSMP Root CA at ${DB_SERVER_CERTS}"
    CA_KEY="${DB_SERVER_CERTS}/ca.key"
    CA_CRT="${DB_SERVER_CERTS}/ca.crt"
elif [ -f "${CLIENT_CERTS_DIR}/ca.key" ] && [ -f "${CLIENT_CERTS_DIR}/ca.crt" ]; then
    echo "📜 Found existing Client Root CA at ${CLIENT_CERTS_DIR}"
    CA_KEY="${CLIENT_CERTS_DIR}/ca.key"
    CA_CRT="${CLIENT_CERTS_DIR}/ca.crt"
else
    echo "🔑 Generating new LSMP Root CA..."
    openssl genrsa -out "${CLIENT_CERTS_DIR}/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "${CLIENT_CERTS_DIR}/ca.key" -sha256 -days 3650 \
        -out "${CLIENT_CERTS_DIR}/ca.crt" \
        -subj "/C=VN/ST=Hanoi/L=Hanoi/O=LSMP Security/OU=LSMP Platform/CN=LSMP-Root-CA" 2>/dev/null
    CA_KEY="${CLIENT_CERTS_DIR}/ca.key"
    CA_CRT="${CLIENT_CERTS_DIR}/ca.crt"
fi

# Ensure client has this ca.crt
cp -f "${CA_CRT}" "${CLIENT_CERTS_DIR}/ca.crt"
cp -f "${CA_CRT}" "${OUTPUT_CERTS_DIR}/ca.crt"

# ====== Step 2: Auto-detect Host IP Addresses ======
DETECTED_IPS=$(hostname -I 2>/dev/null || ip addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
for ip in ${DETECTED_IPS}; do
    if [[ ! " ${EXTRA_IPS[*]} " =~ " ${ip} " ]] && [[ "${ip}" != "127.0.0.1" ]]; then
        EXTRA_IPS+=("${ip}")
    fi
done

# ====== Step 3: Generate Loki Gateway Server Key & CSR ======
echo "🔐 Generating Loki Gateway Private Key (loki_gateway.key)..."
openssl genrsa -out "${OUTPUT_CERTS_DIR}/loki_gateway.key" 2048 2>/dev/null

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

SAN_CONF_FILE="${OUTPUT_CERTS_DIR}/san.cnf"
echo "${SAN_CONFIG}" > "${SAN_CONF_FILE}"

echo "🛡️  Signing Loki Gateway Certificate (loki_gateway.crt)..."
openssl req -new -key "${OUTPUT_CERTS_DIR}/loki_gateway.key" \
    -out "${OUTPUT_CERTS_DIR}/loki_gateway.csr" \
    -config "${SAN_CONF_FILE}" 2>/dev/null

openssl x509 -req -in "${OUTPUT_CERTS_DIR}/loki_gateway.csr" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${OUTPUT_CERTS_DIR}/loki_gateway.crt" \
    -days 3650 -sha256 \
    -extfile "${SAN_CONF_FILE}" -extensions req_ext 2>/dev/null

rm -f "${OUTPUT_CERTS_DIR}/loki_gateway.csr" "${OUTPUT_CERTS_DIR}/san.cnf"
chmod 644 "${OUTPUT_CERTS_DIR}"/*.crt 2>/dev/null || true
chmod 600 "${OUTPUT_CERTS_DIR}"/*.key 2>/dev/null || true

# ====== Step 4: Verification ======
echo "🔍 Verifying generated certificate against Root CA..."
if openssl verify -CAfile "${CA_CRT}" "${OUTPUT_CERTS_DIR}/loki_gateway.crt" >/dev/null 2>&1; then
    echo "✅ Certificate chain is 100% VALID!"
else
    echo "❌ Error: Certificate verification failed!"
    exit 1
fi

# ====== Step 5: Output Summary ======

echo "================================================================="
echo "✅ LOKI GATEWAY TLS CERTIFICATES READY!"
echo "-----------------------------------------------------------------"
echo "📍 Certs Directory : ${OUTPUT_CERTS_DIR}"
echo "📄 Server Cert     : ${OUTPUT_CERTS_DIR}/loki_gateway.crt"
echo "🔑 Server Key      : ${OUTPUT_CERTS_DIR}/loki_gateway.key"
echo "📜 Root CA Cert    : ${CLIENT_CERTS_DIR}/ca.crt"
echo "🌐 SANs included   :"
openssl x509 -in "${OUTPUT_CERTS_DIR}/loki_gateway.crt" -noout -ext subjectAltName 2>/dev/null | grep -A5 "Subject Alternative Name" || true
echo "================================================================="
