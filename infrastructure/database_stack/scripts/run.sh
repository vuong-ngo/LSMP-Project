#!/usr/bin/env bash
# ============================================================================
# file: run.sh
# description: Start the LSMP PostgreSQL/TimescaleDB database service.
#
# Usage:
#   ./run.sh          Start normally (keep existing data)
#   ./run.sh clear    Backup existing data, remove old volume, and reinitialize
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
NC='\033[0m' # No Color

# ── Configuration ───────────────────────────────────────────────────────────
CONTAINER_NAME="lsmp-postgres"
DATA_DIR="./data_postgresql"
BACKUP_DIR="./backups"
SCHEMA_FILE="./schema.sql"

# Load environment variables
if [[ -f .env ]]; then
    set -a; source .env; set +a
fi

POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-lsmp_db}"

# ── Functions ───────────────────────────────────────────────────────────────

log_info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

wait_for_healthy() {
    local max_attempts=30
    local attempt=0
    log_info "Waiting for $CONTAINER_NAME to become healthy..."
    while [[ $attempt -lt $max_attempts ]]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not_found")
        if [[ "$status" == "healthy" ]]; then
            log_success "$CONTAINER_NAME is healthy."
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    log_error "$CONTAINER_NAME did not become healthy within $((max_attempts * 2))s."
    return 1
}

init_schema() {
    if [[ ! -f "$SCHEMA_FILE" ]]; then
        log_warn "Schema file not found at $SCHEMA_FILE. Skipping initialization."
        return 0
    fi
    log_info "Initializing database schema from $SCHEMA_FILE..."
    docker exec -i "$CONTAINER_NAME" \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f - < "$SCHEMA_FILE"
    log_success "Schema initialized successfully."
}

backup_data() {
    if [[ ! -d "$DATA_DIR" ]] || [[ -z "$(ls -A "$DATA_DIR" 2>/dev/null)" ]]; then
        log_warn "No existing data found in $DATA_DIR. Skipping backup."
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="backup_${timestamp}"

    # If the container is running, do a pg_dump first (logical backup)
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Container is running. Creating logical backup (pg_dump)..."
        local dump_file="${BACKUP_DIR}/${backup_name}.sql.gz"
        docker exec "$CONTAINER_NAME" \
            pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
            | gzip > "$dump_file"
        log_success "Logical backup saved to $dump_file"
    fi

    # Physical backup of the data directory
    local archive_file="${BACKUP_DIR}/${backup_name}_data.tar.gz"
    log_info "Creating physical backup of $DATA_DIR..."
    tar -czf "$archive_file" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
    log_success "Physical backup saved to $archive_file"
}

clear_data() {
    # Stop containers first
    log_info "Stopping containers..."
    docker compose down -v 2>/dev/null || true

    # Remove data directory
    if [[ -d "$DATA_DIR" ]]; then
        log_info "Removing data directory $DATA_DIR..."
        rm -rf "$DATA_DIR"
        log_success "Data directory removed."
    fi
}

# ── Main ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  LSMP Database - Run Script${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

MODE="${1:-normal}"

if [[ "$MODE" == "clear" ]]; then
    log_warn "Clear mode requested. This will DESTROY existing data."
    echo ""
    read -rp "$(echo -e "${YELLOW}Are you sure? (y/N): ${NC}")" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Aborted."
        exit 0
    fi

    echo ""
    # Step 1: Backup
    log_info "── Step 1/4: Backup ──"
    backup_data

    # Step 2: Clear
    echo ""
    log_info "── Step 2/4: Clear ──"
    clear_data

    # Step 3: Start fresh
    echo ""
    log_info "── Step 3/4: Start ──"
    docker compose up -d
    wait_for_healthy

    # Step 4: Initialize schema
    echo ""
    log_info "── Step 4/4: Initialize Schema ──"
    init_schema

else
    # Normal start
    log_info "Starting database (normal mode)..."
    docker compose up -d

    if wait_for_healthy; then
        # Check if schema is already initialized
        local_table_count=$(docker exec "$CONTAINER_NAME" \
            psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('log_event','anomaly_result','risk_score','attack_scenarios','evaluation_metrics');" \
            2>/dev/null || echo "0")

        if [[ "$local_table_count" -lt 5 ]]; then
            log_warn "Schema not fully initialized ($local_table_count/5 tables found). Running schema init..."
            init_schema
        else
            log_success "Schema already initialized ($local_table_count/5 tables found)."
        fi
    fi
fi

echo ""
log_success "Database is up and running."
echo -e "  Container : ${GREEN}$CONTAINER_NAME${NC}"
echo -e "  Host      : ${GREEN}localhost:5432${NC}"
echo -e "  Database  : ${GREEN}$POSTGRES_DB${NC}"
echo -e "  User      : ${GREEN}$POSTGRES_USER${NC}"
echo ""
