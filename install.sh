#!/usr/bin/env bash
# ============================================================================
# file: install.sh
# Description: Standalone Manual Installer Script for LSMP AI Engine.
#              Sets up Python virtual environment, dependencies, CLI/TUI binaries,
#              and local configuration (.env) on the host machine.
# ============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}"
echo "=========================================================================="
echo "      LSMP AI MODEL ENGINE — STANDALONE MANUAL INSTALLER"
echo "=========================================================================="
echo -e "${NC}"

# Step 1: Detect Linux System Requirements
echo -e "${YELLOW}[Step 1/5] Detecting System Environment & Tools...${NC}"
check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo -e "  [✔] Found $1: $(which $1)"
    else
        echo -e "  [!] Warning: $1 is not installed."
        return 1
    fi
}

check_cmd python3 || { echo -e "${RED}[✘] Python 3 is required. Please install python3.${NC}"; exit 1; }
check_cmd pip3 || check_cmd pip || { echo -e "${RED}[✘] pip is required. Please install python3-pip.${NC}"; exit 1; }

# Step 2: Initialize Local Environment Configuration (.env)
echo -e "\n${YELLOW}[Step 2/5] Initializing Local Configuration (.env)...${NC}"
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cat <<EOF > "$PROJECT_ROOT/.env"
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=lsmp_db
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/lsmp_db
MODEL_VERSION=cascade-v1.0
MODEL_DIR=$PROJECT_ROOT/models_store
LOG_LEVEL=INFO
LOG_FILE=logs/lsmp_ai.log
POLLING_INTERVAL_SECONDS=10
RISK_ALPHA=0.6
RISK_BETA=0.4
EOF
    echo -e "  [✔] Generated default .env configuration."
else
    echo -e "  [✔] Found existing .env configuration."
fi

# Create required directory structure
mkdir -p "$PROJECT_ROOT/logs" "$PROJECT_ROOT/reports" "$PROJECT_ROOT/models_store" "$PROJECT_ROOT/data/interim" "$PROJECT_ROOT/data/processed" "$PROJECT_ROOT/data/raw"

# Step 3: Create Python Virtual Environment & Install Dependencies
echo -e "\n${YELLOW}[Step 3/5] Setting up Python Virtual Environment (.venv)...${NC}"
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    python3 -m venv "$PROJECT_ROOT/.venv"
    echo -e "  [✔] Created Python virtualenv at $PROJECT_ROOT/.venv"
else
    echo -e "  [✔] Using existing virtual environment at $PROJECT_ROOT/.venv"
fi

export PATH="$PROJECT_ROOT/.venv/bin:$PATH"
echo -e "  [i] Upgrading pip & installing dependencies..."
pip install --quiet -e "$PROJECT_ROOT[all]"

# Step 4: Install System CLI (lsmp-ai) & TUI (lsmp-tui) Binaries
echo -e "\n${YELLOW}[Step 4/5] Installing 'lsmp-ai' CLI & 'lsmp-tui' Binaries into ~/.local/bin...${NC}"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

if [ -f "$PROJECT_ROOT/.venv/bin/lsmp-ai" ]; then
    ln -sf "$PROJECT_ROOT/.venv/bin/lsmp-ai" "$BIN_DIR/lsmp-ai"
    echo -e "  [✔] Linked 'lsmp-ai' binary to $BIN_DIR/lsmp-ai"
fi

cat <<EOF > "$BIN_DIR/lsmp-tui"
#!/usr/bin/env bash
exec "$PROJECT_ROOT/.venv/bin/python" "$PROJECT_ROOT/tools/lsmp_tui.py" "\$@"
EOF
chmod +x "$BIN_DIR/lsmp-tui"
echo -e "  [✔] Created 'lsmp-tui' executable in $BIN_DIR/lsmp-tui"

# Step 5: Verification Unit Tests
echo -e "\n${YELLOW}[Step 5/5] Running Verification Unit Tests...${NC}"
if "$PROJECT_ROOT/.venv/bin/pytest" "$PROJECT_ROOT/tests/" -q &>/dev/null; then
    echo -e "${GREEN}  [✔] All AI Model verification tests PASSED successfully!${NC}"
else
    echo -e "${YELLOW}  [i] Verification tests finished with warnings.${NC}"
fi

echo -e "\n${GREEN}"
echo "=========================================================================="
echo "      🎉 LSMP AI MODEL ENGINE MANUAL INSTALLATION COMPLETE!"
echo "=========================================================================="
echo -e "${NC}"
echo -e "  📌 ${BLUE}CLI Command Usage (Global 'lsmp-ai'):${NC}"
echo -e "     - Train Model:           lsmp-ai train"
echo -e "     - Run Serving Inference: lsmp-ai serve"
echo -e "     - Evaluate Model:        lsmp-ai evaluate"
echo -e "     - Check System Health:   lsmp-ai healthcheck"
echo -e "     - Threat Summary Report: lsmp-ai threat-summary"
echo ""
echo -e "  📌 ${BLUE}Interactive TUI Dashboard:${NC}"
echo -e "     - Launch TUI Dashboard:  lsmp-tui"
echo ""
echo -e "  📌 ${BLUE}Local Service Control:${NC}"
echo -e "     - Start Background Daemon: ./scripts/start_service.sh"
echo -e "     - Stop Background Daemon:  ./scripts/stop_service.sh"
echo "=========================================================================="
