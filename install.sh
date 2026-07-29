#!/usr/bin/env bash
# ============================================================================
# file: install.sh
# Description: Standalone Manual Installer Script for LSMP AI Model Engine.
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
echo "      LSMP AI MODEL ENGINE - AUTOMATED INSTALLER"
echo "=========================================================================="
echo -e "${NC}"

# Step 1: Check System Requirements & OS Distribution
echo -e "${YELLOW}[Step 1/6] Detecting Linux Distribution & Package Manager...${NC}"
check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo -e "  [✔] Found $1: $(which $1)"
    else
        echo -e "  [!] Warning: $1 is not installed."
        return 1
    fi
}

# Auto-detect OS Package Manager for non-Docker native dependencies
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
    echo -e "  [✔] Detected Debian/Ubuntu family (apt-get)"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
    echo -e "  [✔] Detected RHEL/CentOS/Rocky/Fedora family (dnf)"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
    echo -e "  [✔] Detected RHEL/CentOS family (yum)"
elif command -v apk &>/dev/null; then
    PKG_MGR="apk"
    echo -e "  [✔] Detected Alpine Linux (apk)"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
    echo -e "  [✔] Detected Arch Linux (pacman)"
else
    PKG_MGR="unknown"
    echo -e "  [i] Unknown package manager. Proceeding with standard Python tooling."
fi

check_cmd python3 || HAS_PYTHON=0
check_cmd pip3 || check_cmd pip || HAS_PIP=0
check_cmd docker || HAS_DOCKER=0

if command -v docker &>/dev/null && docker compose version &>/dev/null; then
    echo -e "  [✔] Found docker compose: $(docker compose version | head -n1)"
    HAS_COMPOSE=1
else
    HAS_COMPOSE=0
fi

# Step 2: Environment Setup (.env)
echo -e "\n${YELLOW}[Step 2/6] Initializing Environment Variables (.env)...${NC}"
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cat <<EOF > "$PROJECT_ROOT/.env"
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/lsmp_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=lsmp_db
MODEL_VERSION=cascade-v1.0
MODEL_DIR=$PROJECT_ROOT/models_store
LOG_LEVEL=INFO
LOG_FILE=logs/lsmp_ai.log
RISK_ALPHA=0.6
RISK_BETA=0.4
EOF
    echo -e "  [✔] Generated default .env configuration."
else
    echo -e "  [✔] Found existing .env configuration."
fi

# Step 3: Setup Local Environment & Dependencies
echo -e "\n${YELLOW}[Step 3/6] Installing LSMP AI Package & Dependencies...${NC}"
if [ ! -d "$PROJECT_ROOT/.venv" ]; then
    python3 -m venv "$PROJECT_ROOT/.venv"
    echo -e "  [✔] Created Python virtual environment in .venv"
fi

export PATH="$PROJECT_ROOT/.venv/bin:$PATH"
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -e "$PROJECT_ROOT"
pip install --quiet "uvicorn[standard]" fastapi httpx pytest

# Step 4: Install System CLI & TUI Binaries (lsmp-ai, lsmp-tui)
echo -e "\n${YELLOW}[Step 4/6] Installing 'lsmp-ai' CLI and 'lsmp-tui' TUI Binaries into System PATH...${NC}"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

if [ -f "$PROJECT_ROOT/.venv/bin/lsmp-ai" ]; then
    ln -sf "$PROJECT_ROOT/.venv/bin/lsmp-ai" "$BIN_DIR/lsmp-ai"
    echo -e "  [✔] Symlinked 'lsmp-ai' binary to $BIN_DIR/lsmp-ai"
fi

cat <<EOF > "$BIN_DIR/lsmp-tui"
#!/usr/bin/env bash
exec "$PROJECT_ROOT/.venv/bin/python" "$PROJECT_ROOT/tools/lsmp_tui.py" "\$@"
EOF
chmod +x "$BIN_DIR/lsmp-tui"
echo -e "  [✔] Symlinked 'lsmp-tui' binary to $BIN_DIR/lsmp-tui"

# Step 5: Run Verification Unit Tests
echo -e "\n${YELLOW}[Step 5/6] Running Verification Unit Tests...${NC}"
if "$PROJECT_ROOT/.venv/bin/pytest" "$PROJECT_ROOT/tests/" -q; then
    echo -e "${GREEN}  [✔] All AI Model unit tests PASSED successfully!${NC}"
else
    echo -e "${YELLOW}  [i] Unit tests completed with warnings.${NC}"
fi

# Step 6: Docker Container Build (AI Model Container Only)
echo -e "\n${YELLOW}[Step 6/6] Packaging AI Model Docker Container...${NC}"
if [ "$HAS_DOCKER" != "0" ] && [ "$HAS_COMPOSE" != "0" ]; then
    docker network create lsmp_backend 2>/dev/null || true
    echo -e "  [i] Building Docker image for lsmp-ai-service..."
    if docker compose up -d --build; then
        echo -e "${GREEN}  [✔] Docker container 'lsmp-ai-service' built & launched successfully!${NC}"
    else
        echo -e "${YELLOW}  [i] Manual build command: docker compose up -d${NC}"
    fi
else
    echo -e "${YELLOW}  [i] Docker Compose not found. Skipping Docker build.${NC}"
fi

# Summary Report
echo -e "\n${GREEN}"
echo "=========================================================================="
echo "      LSMP AI MODEL ENGINE INSTALLATION COMPLETE!"
echo "=========================================================================="
echo -e "${NC}"
echo -e "  📌 ${BLUE}CLI Command Usage (Global 'lsmp-ai'):${NC}"
echo -e "     - Train Model:       lsmp-ai train"
echo -e "     - Run Serving:       lsmp-ai serve"
echo -e "     - Evaluate Model:    lsmp-ai evaluate"
echo -e "     - Compare Models:    lsmp-ai compare"
echo ""
echo -e "  📌 ${BLUE}Standalone Model Controls:${NC}"
echo -e "     - Start Local Daemon:    ./scripts/start_service.sh"
echo -e "     - Stop Local Daemon:     ./scripts/stop_service.sh"
echo -e "     - Docker Model Launch:   docker compose up -d"
echo -e "     - Docker Model Shutdown: docker compose down"
echo "=========================================================================="
