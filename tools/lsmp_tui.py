#!/usr/bin/env python3
# ============================================================================
# file: tools/lsmp_tui.py
# Description: Dedicated Interactive TUI Dashboard Entrypoint for LSMP AI Engine.
#              Supports multi-tab views: Dashboard [1], Model Catalog [2],
#              Pipeline Controls [3], Threat Summary [4], and Help Menu [H].
# ============================================================================

import sys
from pathlib import Path

# Add src/ to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from lsmp_ai.ui.tui_dashboard import launch_tui_dashboard


if __name__ == "__main__":
    launch_tui_dashboard()
