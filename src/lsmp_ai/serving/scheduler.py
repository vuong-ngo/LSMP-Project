# ============================================================================
# file: serving/scheduler.py
# Description: Polling scheduler for running real-time AI inference periodically.
# ============================================================================

# ===== IMPORT MODULES =====
import time
from datetime import datetime, timedelta

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.io.db_client import DatabaseClient
from lsmp_ai.serving.inference_service import InferenceService

logger = setup_logger(__name__)


# ===== INFERENCE SCHEDULER CLASS =====
class InferenceScheduler:
    def __init__(
        self,
        inference_service: InferenceService,
        poll_interval_seconds: int = 60,
        batch_size: int = 100,
    ):
        self._service = inference_service
        self._poll_interval = poll_interval_seconds
        self._batch_size = batch_size
        self._running = False

    def start(self) -> None:
        self._running = True
        logger.info(
            f"Scheduler started: poll every {self._poll_interval}s, "
            f"batch size {self._batch_size}"
        )

        while self._running:
            try:
                count = self._service.run_inference(limit=self._batch_size)
                if count > 0:
                    logger.info(f"Inferred {count} records")
            except Exception as e:
                logger.error(f"Inference error: {e}", exc_info=True)

            time.sleep(self._poll_interval)

    def stop(self) -> None:
        self._running = False
        logger.info("Scheduler stopped")
