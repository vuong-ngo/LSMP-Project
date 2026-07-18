#!/usr/bin/env bash
# ============================================================================
# file: test.sh
# description: Run test_schema.sql against the LSMP database to verify schema.
#
# Usage:
#   ./test.sh
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
TEST_FILE="./test_schema.sql"

# Load environment variables
if [[ -f .env ]]; then
    set -a; source .env; set +a
fi

POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-lsmp_db}"

# ── Functions ───────────────────────────────────────────────────────────────

log_info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Pre-flight checks ──────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  LSMP Database - Test Script${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

# Check test file exists
if [[ ! -f "$TEST_FILE" ]]; then
    log_error "Test file not found: $TEST_FILE"
    exit 1
fi

# Check container is running
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
    log_error "Container $CONTAINER_NAME is not running."
    log_info  "Start the database first with: ./run.sh"
    exit 1
fi

# Check container is healthy
HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
if [[ "$HEALTH_STATUS" != "healthy" ]]; then
    log_error "Container $CONTAINER_NAME is not healthy (status: $HEALTH_STATUS)."
    log_info  "Wait for it to become healthy or restart with: ./run.sh"
    exit 1
fi

# ── Run tests ───────────────────────────────────────────────────────────────

log_info "Running schema tests against $POSTGRES_DB..."
echo ""

# Run test_schema.sql and capture exit code
# ON_ERROR_STOP=0: continue on expected constraint errors (savepoint handles them)
docker exec -i "$CONTAINER_NAME" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=0 \
    -f - < "$TEST_FILE"

EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    log_success "All tests completed successfully."
else
    log_error "Tests finished with errors (exit code: $EXIT_CODE)."
fi

exit $EXIT_CODE
