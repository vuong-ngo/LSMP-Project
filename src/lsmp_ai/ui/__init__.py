# ============================================================================
# file: src/lsmp_ai/ui/__init__.py
# Description: LSMP AI User Interface package.
# ============================================================================

from lsmp_ai.ui.tui_dashboard import launch_tui_dashboard, LSMPLazydockerTuiApp

# Class alias for backward compatibility
LSMPModelTuiApp = LSMPLazydockerTuiApp

__all__ = ["launch_tui_dashboard", "LSMPLazydockerTuiApp", "LSMPModelTuiApp"]
