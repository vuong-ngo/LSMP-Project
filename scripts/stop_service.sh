#!/usr/bin/env bash
# ============================================================================
# file: scripts/stop_service.sh
# Description: Automated service shutdown script. Gracefully stops the real-time AI daemon.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PID_FILE="$PROJECT_ROOT/logs/service.pid"

echo "================================================================="
echo " 🛑 STOPPING LSMP AI REAL-TIME SERVING DAEMON"
echo "================================================================="

# Determine python executable
if [ -d "$PROJECT_ROOT/.venv" ]; then
    PYTHON_EXEC="$PROJECT_ROOT/.venv/bin/python"
else
    PYTHON_EXEC="python3"
fi

env PYTHONPATH="$PROJECT_ROOT/src" "$PYTHON_EXEC" -m lsmp_ai.scripts.serve stop
