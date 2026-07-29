# ============================================================================
# file: serving/__init__.py
# Description: Serving module providing inference service, scheduler, and FastAPI app.
# ============================================================================

from lsmp_ai.serving.inference_service import InferenceService
from lsmp_ai.serving.scheduler import InferenceScheduler

try:
    from lsmp_ai.serving.lsmp_writer_service import app
except ImportError:
    app = None

__all__ = [
    "InferenceService",
    "InferenceScheduler",
    "app",
]
