# ============================================================================
# file: serving/inference_service.py
# Description: Real-time inference service for feature scoring and risk calculation.
# ============================================================================

# ===== IMPORT MODULES =====
import pandas as pd
import numpy as np

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_UNCERTAIN
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
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
        self._feat_pipeline: FeaturePipeline | None = None
        self.alpha = alpha
        self.beta = beta

    def load_model(self, version: str | None = None) -> None:
        import os
        if version:
            self._model = self._registry.load_version(version)
        else:
            self._model = self._registry.load_latest()

        # Load corresponding FeaturePipeline for standardization
        ver = getattr(self._model, "model_version", None)
        if ver and hasattr(self._registry, "registry_dir"):
            pipeline_path = os.path.join(self._registry.registry_dir, ver, "feature_pipeline.joblib")
            if os.path.exists(pipeline_path):
                try:
                    self._feat_pipeline = FeaturePipeline.load(pipeline_path)
                    logger.info(f"Loaded FeaturePipeline from {pipeline_path}.")
                except Exception as e:
                    logger.warning(f"Could not load FeaturePipeline from {pipeline_path}: {e}")
                    self._feat_pipeline = None

        logger.info("Inference model successfully loaded.")

    def infer_on_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        if self._model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        if features_df.empty:
            return pd.DataFrame()

        # Check required feature columns
        feat_cols = config.features if (config and hasattr(config, "features") and config.features) else list(FEATURE_COLUMNS)
        missing = [c for c in feat_cols if c not in features_df.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing}")

        # Extract features matrix & apply FeaturePipeline scaling if available
        # Preserve missing values so the fitted train-only imputer applies the
        # same transformation used during benchmark and model training.
        X_df = features_df[feat_cols].copy()
        if self._feat_pipeline is not None:
            X = self._feat_pipeline.transform(X_df)
        else:
            raise RuntimeError(
                "FeaturePipeline is missing in InferenceService. Anomaly models require StandardScaler "
                "transformation prior to inference. Ensure feature_pipeline.joblib exists in the model directory."
            )

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

        # Gate Risk Scoring (Three-Way Decision Policy):
        # If predicted_label == 'Uncertain', skip risk scoring & classification.
        # Defer to human-in-the-loop review.
        details["review_required"] = details["predicted_label"] == LABEL_UNCERTAIN
        details["uncertainty_reason"] = np.where(
            details["predicted_label"] == LABEL_UNCERTAIN,
            "Anomaly score in decision boundary uncertainty band; deferred to SOC review.",
            None
        )

        confident_mask = details["predicted_label"] != LABEL_UNCERTAIN
        if confident_mask.all():
            details = compute_risk_scores_for_df(details, alpha=self.alpha, beta=self.beta)
            details = classify_risk_for_df(details)
        elif confident_mask.any():
            # Compute risk only for confident rows
            df_conf = details[confident_mask].copy()
            df_conf = compute_risk_scores_for_df(df_conf, alpha=self.alpha, beta=self.beta)
            df_conf = classify_risk_for_df(df_conf)

            for col in ["risk_score", "score", "risk_class", "ai_component", "rule_component"]:
                if col in df_conf.columns:
                    if col == "risk_class":
                        details[col] = pd.Series(index=details.index, dtype=object)
                    else:
                        details[col] = np.nan
                    details.loc[confident_mask, col] = df_conf[col].values
        else:
            # All samples are uncertain
            details["risk_score"] = np.nan
            details["score"] = np.nan
            details["risk_class"] = pd.Series(index=details.index, dtype=object)
            details["ai_component"] = np.nan
            details["rule_component"] = np.nan


        return details

    def run_inference(self, limit: int = 100) -> int:
        features = self._db.fetch_feature_vectors(limit=limit)
        if features.empty:
            logger.info("No features found in database for inference.")
            return 0

        results = self.infer_on_features(features)
        return self._writer.write_predictions(results)
