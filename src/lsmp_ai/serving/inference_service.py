# ============================================================================
# file: serving/inference_service.py
# Description: Real-time inference service for feature scoring and risk calculation.
# ============================================================================

# ===== IMPORT MODULES =====
import pandas as pd
import numpy as np

from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.io.db_client import DatabaseClient
from lsmp_ai.io.result_writer import ResultWriter
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.risk_scoring.risk_classifier import classify_risk_for_df
from lsmp_ai.risk_scoring.risk_score import compute_risk_scores_for_df

logger = setup_logger(__name__)


# ===== INFERENCE SERVICE CLASS =====
class InferenceService:
    def __init__(
        self,
        db_client: DatabaseClient,
        result_writer: ResultWriter,
        model_registry: ModelRegistry,
        alpha: float = 0.6,
        beta: float = 0.4,
    ):
        self._db = db_client
        self._writer = result_writer
        self._registry = model_registry
        self._model: CascadeModel | None = None
        self.alpha = alpha
        self.beta = beta

    def load_model(self, version: str | None = None) -> None:
        if version:
            self._model = self._registry.load_version(version)
        else:
            self._model = self._registry.load_latest()
        logger.info("Inference model successfully loaded.")

    def infer_on_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        if self._model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        if features_df.empty:
            return pd.DataFrame()

        # Check required feature columns
        feat_cols = config.features if (config and hasattr(config, "features") and config.features) else FEATURE_COLUMNS
        missing = [c for c in feat_cols if c not in features_df.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing}")

        # Extract features matrix & handle NaNs
        X_df = features_df[feat_cols].copy().fillna(0.0)
        X = X_df.values

        # Safely extract src_ips and window_starts
        if "src_ip" in features_df.columns:
            src_ips = features_df["src_ip"].tolist()
        else:
            src_ips = ["0.0.0.0"] * len(features_df)

        if "window_start" in features_df.columns:
            window_starts = features_df["window_start"].tolist()
        else:
            window_starts = [None] * len(features_df)

        details = self._model.predict_with_details(
            X,
            src_ips=src_ips,
            window_starts=window_starts,
        )

        # Preserve feature_vector_id if present in input
        if "id" in features_df.columns:
            details["feature_vector_id"] = features_df["id"].values
        elif "feature_vector_id" in features_df.columns:
            details["feature_vector_id"] = features_df["feature_vector_id"].values

        # Preserve severity_weight if present in input
        if "severity_weight" in features_df.columns:
            details["severity_weight"] = features_df["severity_weight"].values

        details = compute_risk_scores_for_df(details, alpha=self.alpha, beta=self.beta)
        details = classify_risk_for_df(details)

        return details

    def run_inference(self, limit: int = 100) -> int:
        features = self._db.fetch_feature_vectors(limit=limit)
        if features.empty:
            logger.info("No features found in database for inference.")
            return 0

        results = self.infer_on_features(features)
        return self._writer.write_predictions(results)
