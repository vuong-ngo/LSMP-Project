#!/usr/bin/env bash
# ============================================================================
# file: stop.sh
# description: Stop the LSMP PostgreSQL/TimescaleDB database service.
#
# Usage:
#   ./stop.sh          Stop containers (keep data)
#   ./stop.sh remove   Stop containers and remove volumes
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(dirname "$SCRIPT_DIR")"
cd "$STACK_DIR"

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CONTAINER_NAME="lsmp-postgres"

# ── Functions ───────────────────────────────────────────────────────────────

log_info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# ── Main ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  LSMP Database - Stop Script${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

MODE="${1:-normal}"

# Show current status before stopping
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
    log_info "Container $CONTAINER_NAME is currently running."
else
    log_warn "Container $CONTAINER_NAME is not running."
fi

if [[ "$MODE" == "remove" ]]; then
    log_warn "Stopping containers and removing Docker volumes..."
    docker compose down -v
    log_success "Containers stopped and volumes removed."
else
    log_info "Stopping containers (data preserved)..."
    docker compose down
    log_success "Containers stopped. Data is preserved in ./data_postgresql/."
fi

echo ""
