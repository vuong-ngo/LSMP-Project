# ============================================================================
# file: models/cascade_model.py
# Description: Implementation of Cascade model for anomaly detection in LSMP.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import json
import numpy as np
import pandas as pd
from typing import Union, Dict, Any, Optional

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.models.isolation_forest_model import IsolationForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.constants import LABEL_NORMAL, LABEL_ANOMALY

# ===== Cascade Model =====
class CascadeModel(BaseModel):
    """Two-stage Cascade Model combining Isolation Forest (Stage 1) and One-Class SVM (Stage 2).

    Stage 1 rapidly filters out clear normal and clear anomalous samples using fast tree-based
    partitioning. Stage 2 evaluates ambiguous samples using a precise kernel-based decision boundary.

    Attributes:
        iforest_model (IsolationForestModel): The Stage 1 Isolation Forest estimator.
        ocsvm_model (OCSVMModel): The Stage 2 One-Class SVM estimator.
        anomaly_threshold (float): Stage 1 score threshold below which samples are flagged as Anomaly.
        normal_threshold (float): Stage 1 score threshold above which samples are flagged as Normal.
        threshold_percentile (Optional[float]): Optional percentile used to compute thresholds dynamically.
        model_version (str): Version identifier for the trained cascade pipeline.
    """

    def __init__(
        self,
        iforest: Any = None,
        ocsvm: Any = None,
        threshold_percentile: Optional[float] = None,
        iforest_params: Optional[Dict[str, Any]] = None,
        ocsvm_params: Optional[Dict[str, Any]] = None,
        cascade_params: Optional[Dict[str, Any]] = None
    ):
        """Initializes the CascadeModel with submodel instances or hyperparameter configurations.

        Args:
            iforest (Any, optional): Pre-constructed IsolationForestModel instance or dict of parameters.
            ocsvm (Any, optional): Pre-constructed OCSVMModel instance or dict of parameters.
            threshold_percentile (float, optional): Percentile for dynamic thresholding. Defaults to None.
            iforest_params (Dict[str, Any], optional): Hyperparameters for Isolation Forest if instance not provided.
            ocsvm_params (Dict[str, Any], optional): Hyperparameters for One-Class SVM if instance not provided.
            cascade_params (Dict[str, Any], optional): General cascade routing configurations.
        """
        if isinstance(iforest, BaseModel):
            self.iforest_model = iforest
        else:
            params = iforest if isinstance(iforest, dict) else iforest_params
            self.iforest_model = IsolationForestModel(params)

        if isinstance(ocsvm, BaseModel):
            self.ocsvm_model = ocsvm
        else:
            params = ocsvm if isinstance(ocsvm, dict) else ocsvm_params
            self.ocsvm_model = OCSVMModel(params)

        if isinstance(threshold_percentile, (list, tuple, np.ndarray)) and len(threshold_percentile) > 0:
            self.threshold_percentile = threshold_percentile[0]
        else:
            self.threshold_percentile = threshold_percentile

        c_params = cascade_params or (config.cascade_params if config else {})
        self.anomaly_threshold = c_params.get("iforest_anomaly_threshold", -0.6)
        self.normal_threshold = c_params.get("iforest_normal_threshold", -0.45)
        self.model_version = c_params.get("model_version", "cascade-v1.0")

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'CascadeModel':
        """Fits both Stage 1 (Isolation Forest) and Stage 2 (One-Class SVM) models.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            y (Any, optional): Optional labels. If provided, OCSVM is trained exclusively on normal samples.

        Returns:
            CascadeModel: The fitted cascade model instance (self).
        """
        logger.info("Starting CascadeModel training...")

        # Step 1: Fit Isolation Forest on all data
        self.iforest_model.fit(X, y)

        # Determine thresholds if percentile is given
        if self.threshold_percentile is not None:
            scores = self.iforest_model.score(X)
            # Ensure p_val is lower tail (e.g. 5-10%)
            p_val = min(float(self.threshold_percentile), 100.0 - float(self.threshold_percentile))
            p_val = max(1.0, p_val)
            self.anomaly_threshold = float(np.percentile(scores, p_val))
            self.normal_threshold = float(np.percentile(scores, 100.0 - p_val))
            logger.info(f"Set percentile thresholds: anomaly={self.anomaly_threshold:.4f}, normal={self.normal_threshold:.4f}")

        # Step 2: Fit One-Class SVM on normal baseline traffic
        if y is not None:
            labels = np.array(y)
            normal_mask = (labels == LABEL_NORMAL) | (labels == 0) | (labels == '0') | (labels == 'BENIGN') | (labels == 'benign')
            X_normal = X[normal_mask] if isinstance(X, pd.DataFrame) else X[normal_mask]
            if len(X_normal) > 0:
                logger.info(f"Fitting OCSVM on {len(X_normal)} Normal samples.")
                self.ocsvm_model.fit(X_normal)
            else:
                logger.warning("No Normal samples found in training data. Fitting OCSVM on all data.")
                self.ocsvm_model.fit(X, y)
        else:
            logger.info("No labels provided. Fitting OCSVM on all training data.")
            self.ocsvm_model.fit(X, y)

        logger.info("CascadeModel training completed successfully.")
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predicts string anomaly labels ('Normal' or 'Anomaly') for input dataset.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of predicted class strings.
        """
        predictions_df = self.predict_detailed(X)
        return predictions_df['predicted_label'].values

    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes unified continuous anomaly scores in range [0, 1].

        A score of 1.0 indicates high anomaly confidence, while 0.0 indicates normal behavior.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of float anomaly scores.
        """
        predictions_df = self.predict_detailed(X)
        return predictions_df['anomaly_score'].values

    def predict_detailed(self, X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        """Evaluates the two-stage cascade routing for each sample in X.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            pd.DataFrame: DataFrame containing stage1_score, stage2_score, anomaly_score, and predicted_label.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.array(X)
        n_samples = len(X_arr)

        if n_samples == 0:
            return pd.DataFrame({
                "stage1_score": [],
                "stage2_score": [],
                "anomaly_score": [],
                "predicted_label": []
            })

        # 1. Stage 1: Isolation Forest
        iforest_scores = self.iforest_model.score(X_arr)

        stage1_scores = iforest_scores
        stage2_scores = np.full(n_samples, np.nan)
        anomaly_scores = np.zeros(n_samples)
        labels = np.full(n_samples, LABEL_NORMAL, dtype=object)

        # 2. Categorize routing using Boolean masks
        clear_anomaly_mask = iforest_scores < self.anomaly_threshold
        clear_normal_mask = iforest_scores > self.normal_threshold
        uncertain_mask = ~(clear_anomaly_mask | clear_normal_mask)

        # Direct Stage 1 Decisions
        labels[clear_anomaly_mask] = LABEL_ANOMALY
        anomaly_scores[clear_anomaly_mask] = 1.0

        labels[clear_normal_mask] = LABEL_NORMAL
        anomaly_scores[clear_normal_mask] = 0.0

        # Stage 2 Batch Evaluation for Uncertain Zone
        if np.any(uncertain_mask):
            X_uncertain = X_arr[uncertain_mask]
            score2_batch = self.ocsvm_model.score(X_uncertain)
            pred2_batch = self.ocsvm_model.predict(X_uncertain)

            stage2_scores[uncertain_mask] = score2_batch
            score2_clipped = np.clip(score2_batch, -50.0, 50.0)
            anomaly_prob_batch = 1.0 / (1.0 + np.exp(score2_clipped))
            anomaly_scores[uncertain_mask] = anomaly_prob_batch

            labels[uncertain_mask] = np.where(pred2_batch == -1, LABEL_ANOMALY, LABEL_NORMAL)

        return pd.DataFrame({
            "stage1_score": stage1_scores,
            "stage2_score": stage2_scores,
            "anomaly_score": anomaly_scores,
            "predicted_label": labels
        })

    def save(self, model_dir: str) -> None:
        """Serializes both IForest and OCSVM submodels and saves cascade metadata.

        Args:
            model_dir (str): Target directory to save model assets.
        """
        os.makedirs(model_dir, exist_ok=True)
        self.iforest_model.save(os.path.join(model_dir, "iforest.joblib"))
        self.ocsvm_model.save(os.path.join(model_dir, "ocsvm.joblib"))

        meta = {
            "model_version": self.model_version,
            "iforest_anomaly_threshold": self.anomaly_threshold,
            "iforest_normal_threshold": self.normal_threshold
        }
        with open(os.path.join(model_dir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=4)
        logger.info(f"Saved CascadeModel metadata to {model_dir}")

    def load(self, model_dir: str) -> 'CascadeModel':
        """Deserializes submodels and restores cascade state from directory.

        Args:
            model_dir (str): Path to directory containing saved assets.

        Returns:
            CascadeModel: Restored model instance (self).
        """
        self.iforest_model.load(os.path.join(model_dir, "iforest.joblib"))
        self.ocsvm_model.load(os.path.join(model_dir, "ocsvm.joblib"))

        meta_path = os.path.join(model_dir, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
            self.model_version = meta.get("model_version", self.model_version)
            self.anomaly_threshold = meta.get("iforest_anomaly_threshold", self.anomaly_threshold)
            self.normal_threshold = meta.get("iforest_normal_threshold", self.normal_threshold)
        logger.info(f"Successfully loaded CascadeModel from {model_dir}")
        return self

    def predict_with_details(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        src_ips: Optional[list] = None,
        window_starts: Optional[list] = None
    ) -> pd.DataFrame:
        """Runs detailed inference and appends IP and window timestamp identifiers if provided.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            src_ips (list, optional): List of source IP addresses corresponding to rows in X.
            window_starts (list, optional): List of window timestamps corresponding to rows in X.

        Returns:
            pd.DataFrame: Detailed prediction DataFrame with attached identifiers.
        """
        df = self.predict_detailed(X)
        if src_ips is not None:
            df["src_ip"] = src_ips
        if window_starts is not None:
            df["window_start"] = window_starts
        return df
