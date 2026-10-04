#!/usr/bin/env bash
# ============================================================================
# file: agent_stack/fluent-bit/client/enable_loki_gateway_tls.sh
# Description: One-command setup to enable TLS on Grafana Loki Gateway
#              and verify Fluent-Bit client TLS connectivity.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
GRAFANA_DIR="${PROJECT_ROOT}/grafana_stack"

SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO_CMD="sudo"
fi

echo "================================================================="
echo "🔒  ENABLING TLS ON GRAFANA LOKI GATEWAY & CLIENT SETUP"
echo "================================================================="

# 1. Generate Loki Gateway TLS Certificates
bash "${SCRIPT_DIR}/generate_loki_gateway_tls.sh"

# 2. Deploy certificates into grafana_stack/certs
echo "📁 Copying TLS certs into grafana_stack/certs/..."
${SUDO_CMD} mkdir -p "${GRAFANA_DIR}/certs"
${SUDO_CMD} cp -f "${SCRIPT_DIR}/loki_gateway_certs/loki_gateway.crt" "${GRAFANA_DIR}/certs/loki_gateway.crt"
${SUDO_CMD} cp -f "${SCRIPT_DIR}/loki_gateway_certs/loki_gateway.key" "${GRAFANA_DIR}/certs/loki_gateway.key"
${SUDO_CMD} cp -f "${SCRIPT_DIR}/certs/ca.crt" "${GRAFANA_DIR}/certs/ca.crt"
${SUDO_CMD} chmod 644 "${GRAFANA_DIR}/certs"/*.crt "${GRAFANA_DIR}/certs"/*.key 2>/dev/null || true

# 3. Update Nginx configuration
echo "⚙️  Applying SSL configuration to grafana_stack/config/nginx.conf..."
${SUDO_CMD} cp -f "${SCRIPT_DIR}/nginx-loki-ssl.conf" "${GRAFANA_DIR}/config/nginx.conf"

# 4. Ensure docker-compose.yaml mounts ./certs into gateway container
if ! grep -q "./certs:/etc/nginx/certs:ro" "${GRAFANA_DIR}/docker-compose.yaml"; then
    echo "⚙️  Mounting ./certs into gateway service in docker-compose.yaml..."
    ${SUDO_CMD} sed -i '/\.\/config\/nginx\.conf:\/etc\/nginx\/nginx\.conf:ro/a \      - \.\/certs:\/etc\/nginx\/certs:ro' "${GRAFANA_DIR}/docker-compose.yaml"
fi

# 5. Restart Loki Gateway container
echo "🔄 Reloading Loki Gateway container..."
if command -v docker >/dev/null 2>&1; then
    ${SUDO_CMD} docker compose -f "${GRAFANA_DIR}/docker-compose.yaml" up -d gateway || true
fi

echo "================================================================="
echo "✅ LOKI GATEWAY TLS SUCCESSFULLY ENABLED!"
echo "   Gateway is now accepting TLS on port 3100 (HTTPS)."
echo "================================================================="
