#!/usr/bin/env bash
# ============================================================================
# file: scripts/start_service.sh
# Description: Automated service startup script. Automatically loads .env configuration
#              and starts the real-time AI serving daemon in the background.
# ============================================================================

set -e

# Resolve script & project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"

PID_FILE="$LOG_DIR/service.pid"
SERVICE_LOG="$LOG_DIR/service.log"

# Load .env variables automatically if file exists
if [ -f "$PROJECT_ROOT/.env" ]; then
    echo "📄 Loading environment configuration from $PROJECT_ROOT/.env..."
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Determine python executable
if [ -d "$PROJECT_ROOT/.venv" ]; then
    PYTHON_EXEC="$PROJECT_ROOT/.venv/bin/python"
else
    PYTHON_EXEC="python3"
fi

# Check if service is already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "⚠️  LSMP AI Real-time Service is ALREADY RUNNING with PID: $PID"
        echo "   Logs: $SERVICE_LOG"
        exit 0
    else
        echo "🧹 Removing stale PID file..."
        rm -f "$PID_FILE"
    fi
fi

echo "================================================================="
echo " 🚀 STARTING LSMP AI REAL-TIME SERVING DAEMON"
echo "================================================================="
echo "  • Database URL: ${POSTGRES_URL:-${DATABASE_URL:-Not set}}"
echo "  • Model Version: ${MODEL_VERSION:-cascade-v1.0}"
echo "  • Polling Interval: ${POLLING_INTERVAL:-10} seconds"
echo "  • Service Log: $SERVICE_LOG"
echo "================================================================="

# Automatically export registered models and metrics to DB on service startup
echo "🗄️ Automatically syncing model catalog & metrics to Database..."
env PYTHONPATH="$PROJECT_ROOT/src" "$PYTHON_EXEC" -m lsmp_ai.scripts.export_db || true

# Launch pure python serving daemon (verifies DB before starting)
env PYTHONPATH="$PROJECT_ROOT/src" "$PYTHON_EXEC" -m lsmp_ai.scripts.serve start --interval "${POLLING_INTERVAL:-10}"
