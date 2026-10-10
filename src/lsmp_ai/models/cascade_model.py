# ============================================================================
# file: models/cascade_model.py
# Description: Production two-stage Cascade Model combining Isolation Forest and One-Class SVM.
# Based on the SME security monitoring architecture:
# - Stage 1 (Isolation Forest, near-linear time) screens all traffic and passes only the top gate_rate
#   fraction of most suspicious windows/samples to Stage 2.
# - Stage 2 (One-Class SVM, kernel-based boundary) evaluates only the gated samples.
# - Unified score fusion: s_casc = w * norm(s_if) + (1 - w) * norm(s_oc).
# - Optimal operational threshold selection via validation (f1, f2, or fpr_budget).
# ============================================================================
from __future__ import annotations

import os
import json
import time
import numpy as np
import pandas as pd
from typing import Union, Dict, Any, Optional, Sequence

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.models.isolation_forest_model import IsolationForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.constants import LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.risk_scoring.risk_score import calculate_risk_score

EPS = 1e-12


class CascadeModel(BaseModel):
    """Production Two-Stage Cascade Detector for High-Efficiency Security Monitoring.

    Combines the computational efficiency of Isolation Forest (Stage 1 screening)
    with the decision boundary precision of One-Class SVM (Stage 2 verification).

    Attributes:
        iforest_model (IsolationForestModel): Fast tree-based screening detector.
        ocsvm_model (OCSVMModel): Precision kernel-based boundary detector.
        gate_rate (float): Ratio of traffic routed to Stage 2 (default 0.20 = 20%).
        gate_threshold (float): Stage 1 anomaly score cutoff for Stage 2 admission.
        threshold (float): Final decision threshold for anomaly classification.
        w_stage1 (float): Weight of Stage 1 score in fused anomaly score.
        model_version (str): Model version identifier.
    """

    def __init__(
        self,
        iforest: Any = None,
        ocsvm: Any = None,
        threshold_percentile: Optional[Union[float, Sequence[float]]] = None,
        gate_rate: Optional[float] = None,
        w_stage1: Optional[float] = None,
        iforest_params: Optional[Dict[str, Any]] = None,
        ocsvm_params: Optional[Dict[str, Any]] = None,
        cascade_params: Optional[Dict[str, Any]] = None,
    ):
        """Initializes the CascadeModel.

        Args:
            iforest (Any, optional): Pre-instantiated IsolationForestModel or dict of parameters.
            ocsvm (Any, optional): Pre-instantiated OCSVMModel or dict of parameters.
            threshold_percentile (float, optional): Percentile cutoff for legacy compatibility.
            gate_rate (float, optional): Fraction of traffic routed to Stage 2 (e.g. 0.20).
            w_stage1 (float, optional): Weight of Stage 1 in score fusion (default 0.4).
            iforest_params (Dict[str, Any], optional): Hyperparameters for Isolation Forest.
            ocsvm_params (Dict[str, Any], optional): Hyperparameters for One-Class SVM.
            cascade_params (Dict[str, Any], optional): General cascade routing configuration.
        """
        c_params = cascade_params or (config.cascade_params if config and hasattr(config, "cascade_params") else {})

        # 1. Initialize Submodels
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

        # 2. Extract threshold_percentile (legacy support)
        if isinstance(threshold_percentile, (list, tuple, np.ndarray)) and len(threshold_percentile) > 0:
            self.threshold_percentile = float(threshold_percentile[0])
        elif threshold_percentile is not None:
            self.threshold_percentile = float(threshold_percentile)
        else:
            self.threshold_percentile = None

        # 3. Determine gate_rate
        if gate_rate is not None:
            self.gate_rate = float(gate_rate)
        elif "gate_rate" in c_params:
            self.gate_rate = float(c_params["gate_rate"])
        elif self.threshold_percentile is not None:
            if self.threshold_percentile >= 50.0:
                self.gate_rate = max(0.01, min(0.99, (100.0 - self.threshold_percentile) / 100.0))
            else:
                self.gate_rate = max(0.01, min(0.99, self.threshold_percentile / 100.0))
        else:
            self.gate_rate = 0.20

        self.w_stage1 = float(w_stage1 if w_stage1 is not None else c_params.get("w_stage1", 0.4))
        self.model_version = str(c_params.get("model_version", "cascade-v1.0"))

        # 4. Routing and decision thresholds
        self.gate_threshold: float = 0.0
        self.threshold: float = 0.5
        self.is_fitted: bool = False

        # Min-max normalization anchors
        self.if_min: float = 0.0
        self.if_max: float = 1.0
        self.oc_min: float = 0.0
        self.oc_max: float = 1.0

        # Legacy backward-compatibility attributes
        self.anomaly_threshold: float = float(c_params.get("iforest_anomaly_threshold", -0.6))
        self.normal_threshold: float = float(c_params.get("iforest_normal_threshold", -0.45))

    def _if_score(self, X: np.ndarray) -> np.ndarray:
        """Computes Stage 1 anomaly score (-decision_function)."""
        if hasattr(self.iforest_model, "decision_function"):
            return -self.iforest_model.decision_function(X)
        return -self.iforest_model.model.decision_function(X)

    def _oc_score(self, X: np.ndarray) -> np.ndarray:
        """Computes Stage 2 anomaly score (-decision_function)."""
        if hasattr(self.ocsvm_model, "decision_function"):
            return -self.ocsvm_model.decision_function(X)
        return -self.ocsvm_model.model.decision_function(X)

    def fit(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        y: Any = None,
        X_val: Optional[Union[pd.DataFrame, np.ndarray]] = None,
        y_val: Any = None,
        criterion: str = "f2",
        max_fpr: float = 0.02,
    ) -> 'CascadeModel':
        """Fits both Stage 1 and Stage 2 models using novelty detection principles.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Training feature matrix.
            y (Any, optional): Ground-truth labels for filtering benign baseline data.
            X_val (Union[pd.DataFrame, np.ndarray], optional): Validation feature matrix for threshold tuning.
            y_val (Any, optional): Validation labels for threshold calibration.
            criterion (str, optional): Threshold selection criterion ('f1', 'f2', 'fpr_budget').
            max_fpr (float, optional): Maximum false positive rate for 'fpr_budget'.

        Returns:
            CascadeModel: The fitted model instance (self).
        """
        logger.info(f"Fitting CascadeModel (gate_rate={self.gate_rate:.2f}, w_stage1={self.w_stage1:.2f})...")
        from lsmp_ai.evaluation.metrics import pick_threshold, to_binary_labels
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)

        # Novelty detection: isolate clean normal data for training
        X_train_clean = X_arr
        if y is not None:
            bin_labels = to_binary_labels(y)
            normal_mask = (bin_labels == 0)
            if np.any(normal_mask):
                X_train_clean = X_arr[normal_mask]
                logger.info(f"Training on {len(X_train_clean)} benign samples (out of {len(X_arr)} total).")
            else:
                logger.warning("No benign samples identified; fitting on all available samples.")

        # 1. Fit Stage 1: Isolation Forest
        self.iforest_model.fit(X_train_clean)
        s_if_tr = self._if_score(X_train_clean)
        self.if_min = float(np.min(s_if_tr))
        self.if_max = float(np.max(s_if_tr))

        # 2. Compute Gating Threshold
        q_level = max(0.01, min(0.9999, 1.0 - self.gate_rate))
        self.gate_threshold = float(np.quantile(s_if_tr, q_level))
        self.anomaly_threshold = self.gate_threshold
        self.normal_threshold = float(np.quantile(s_if_tr, max(0.01, q_level - 0.2)))
        logger.info(f"Gating threshold set to {self.gate_threshold:.4f} (gate_rate={self.gate_rate*100:.1f}%)")

        # 3. Fit Stage 2: One-Class SVM on normal data
        self.ocsvm_model.fit(X_train_clean)
        s_oc_tr = self._oc_score(X_train_clean)
        self.oc_min = float(np.min(s_oc_tr))
        self.oc_max = float(np.max(s_oc_tr))

        # 4. Calibrate Final Threshold
        if X_val is not None and y_val is not None:
            X_v = X_val.values if isinstance(X_val, pd.DataFrame) else np.asarray(X_val)
            s_val = self.score(X_v)
            self.threshold = pick_threshold(y_val, s_val, criterion=criterion, max_fpr=max_fpr)
            logger.info(f"Optimal threshold chosen on validation ({criterion}): {self.threshold:.4f}")
        else:
            s_train = self.score(X_arr)
            self.threshold = float(np.quantile(s_train, max(0.5, 1.0 - self.gate_rate)))

        self.is_fitted = True
        logger.info(f"CascadeModel training completed. Decision threshold: {self.threshold:.4f}")
        return self

    def _normalize_score(self, s: np.ndarray, lo: float, hi: float) -> np.ndarray:
        """Min-max normalizes scores into [0, 1] without overflow or NaNs."""
        diff = hi - lo
        if abs(diff) < EPS:
            diff = 1.0
        finite_s = np.where(np.isfinite(s), s, lo)
        norm_s = (finite_s - lo) / (diff + EPS)
        return np.clip(norm_s, 0.0, 1.0)

    def predict_detailed(self, X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        """Runs the two-stage cascade routing for each sample in X.

        Stage 1: Evaluates iForest anomaly scores for all samples.
        Gating: Filters samples with stage1_score >= gate_threshold to Stage 2.
        Stage 2: Evaluates OCSVM anomaly scores only for gated samples.
        Fusion: Blends scores via w_stage1 * norm(s_if) + (1 - w_stage1) * norm(s_oc).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            pd.DataFrame: Contains stage1_score, stage2_score, anomaly_score, and predicted_label.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        n_samples = len(X_arr)

        if n_samples == 0:
            return pd.DataFrame({
                "stage1_score": np.array([], dtype=float),
                "stage2_score": np.array([], dtype=float),
                "anomaly_score": np.array([], dtype=float),
                "predicted_label": np.array([], dtype=object),
            })

        # Stage 1: Isolation Forest
        s_if = self._if_score(X_arr)

        # Stage 1 Gating
        gated_mask = s_if >= self.gate_threshold

        # Stage 2: One-Class SVM on gated samples only
        stage2_scores = np.full(n_samples, np.nan, dtype=float)
        s_oc_gated = np.full(n_samples, self.oc_min if np.isfinite(self.oc_min) else 0.0, dtype=float)

        if np.any(gated_mask):
            X_gated = X_arr[gated_mask]
            s_oc = self._oc_score(X_gated)
            stage2_scores[gated_mask] = s_oc
            s_oc_gated[gated_mask] = s_oc

        # Normalized Fusion
        norm_if = self._normalize_score(s_if, self.if_min, self.if_max)
        norm_oc = self._normalize_score(s_oc_gated, self.oc_min, self.oc_max)
        norm_oc[~gated_mask] = 0.0

        fused_score = self.w_stage1 * norm_if + (1.0 - self.w_stage1) * norm_oc
        fused_score = np.nan_to_num(fused_score, nan=0.0, posinf=1.0, neginf=0.0)
        fused_score = np.clip(fused_score, 0.0, 1.0)

        # Classification decision
        labels = np.where(fused_score >= self.threshold, LABEL_ANOMALY, LABEL_NORMAL)

        return pd.DataFrame({
            "stage1_score": s_if,
            "stage2_score": stage2_scores,
            "anomaly_score": fused_score,
            "predicted_label": labels,
        })

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predicts anomaly labels (LABEL_NORMAL / LABEL_ANOMALY).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of class label strings.
        """
        df = self.predict_detailed(X)
        return df["predicted_label"].values

    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes continuous unified anomaly score in range [0.0, 1.0].

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of float anomaly scores.
        """
        df = self.predict_detailed(X)
        return df["anomaly_score"].values

    def anomaly_score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes continuous unified anomaly score in range [0.0, 1.0] (alias for score)."""
        return self.score(X)

    def predict_risk(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        severity_weight: Union[float, np.ndarray, pd.Series] = 0.0,
        alpha: float = 0.6,
        beta: float = 0.4,
    ) -> np.ndarray:
        """Predicts composite risk score (0.0 to 100.0) combining AI anomaly confidence and rule severity.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            severity_weight (Union[float, np.ndarray, pd.Series], optional): External rule severity (e.g. Wazuh level).
            alpha (float, optional): Weight of AI anomaly score. Defaults to 0.6.
            beta (float, optional): Weight of rule severity. Defaults to 0.4.

        Returns:
            np.ndarray: 1D array of composite risk scores [0.0, 100.0].
        """
        scores = self.score(X)
        return calculate_risk_score(scores, severity_weight, alpha=alpha, beta=beta)

    def predict_with_details(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        src_ips: Optional[list] = None,
        window_starts: Optional[list] = None,
    ) -> pd.DataFrame:
        """Runs detailed inference and attaches IP and window timestamp identifiers if provided.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            src_ips (Optional[list], optional): Source IPs for each sample.
            window_starts (Optional[list], optional): Window timestamps.

        Returns:
            pd.DataFrame: Detailed inference results DataFrame.
        """
        df = self.predict_detailed(X)
        if src_ips is not None:
            df["src_ip"] = src_ips
        if window_starts is not None:
            df["window_start"] = window_starts
        return df

    def benchmark_timing(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        repeats: int = 5,
    ) -> Dict[str, Any]:
        """Benchmarks computational latency, throughput, and compute savings vs full OCSVM.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Feature matrix for benchmarking.
            repeats (int, optional): Number of warm-up repetitions. Defaults to 5.

        Returns:
            Dict[str, Any]: Benchmark results dictionary.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        n = len(X_arr)
        if n == 0:
            return {}

        def timed(fn, *args):
            fn(*args)  # warm-up
            ts = []
            for _ in range(repeats):
                t0 = time.perf_counter()
                out = fn(*args)
                ts.append(time.perf_counter() - t0)
            return out, float(np.median(ts))

        _, t_if = timed(self._if_score, X_arr)
        _, t_oc_full = timed(self._oc_score, X_arr)

        s_if = self._if_score(X_arr)
        gated = s_if >= self.gate_threshold

        def oc_gated_fn(X_sub, g):
            if np.any(g):
                return self._oc_score(X_sub[g])
            return np.array([])

        _, t_oc_gated = timed(oc_gated_fn, X_arr, gated)
        t_cascade = t_if + t_oc_gated
        saving = 1.0 - (t_cascade / (t_oc_full + EPS))

        return {
            "n_samples": n,
            "inference_seconds": {
                "iforest_all": t_if,
                "ocsvm_all": t_oc_full,
                "ocsvm_gated": t_oc_gated,
                "cascade_total": t_cascade,
            },
            "gate_rate_actual": float(np.mean(gated)),
            "compute_saving_vs_ocsvm_only": float(saving),
            "throughput_rows_sec": float(n / max(t_cascade, EPS)),
            "avg_latency_ms": float((t_cascade / max(n, 1)) * 1000.0),
        }

    def save(self, model_dir: str) -> None:
        """Serializes submodels and stores complete cascade metadata.

        Args:
            model_dir (str): Target directory path.
        """
        os.makedirs(model_dir, exist_ok=True)
        self.iforest_model.save(os.path.join(model_dir, "iforest.joblib"))
        self.ocsvm_model.save(os.path.join(model_dir, "ocsvm.joblib"))

        meta = {
            "model_version": self.model_version,
            "gate_rate": self.gate_rate,
            "gate_threshold": self.gate_threshold,
            "threshold": self.threshold,
            "w_stage1": self.w_stage1,
            "threshold_percentile": self.threshold_percentile,
            "iforest_anomaly_threshold": self.gate_threshold,
            "iforest_normal_threshold": self.normal_threshold,
            "normalization": {
                "if_min": self.if_min,
                "if_max": self.if_max,
                "oc_min": self.oc_min,
                "oc_max": self.oc_max,
            }
        }
        with open(os.path.join(model_dir, "metadata.json"), "w") as f:
            json.dump(meta, f, indent=4)
        logger.info(f"Saved CascadeModel and metadata to {model_dir}")

    def load(self, model_dir: str) -> 'CascadeModel':
        """Deserializes submodels and restores cascade state from directory.

        Args:
            model_dir (str): Path to model directory.

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
            self.gate_rate = float(meta.get("gate_rate", self.gate_rate))
            self.gate_threshold = float(meta.get("gate_threshold", meta.get("iforest_anomaly_threshold", self.gate_threshold)))
            self.threshold = float(meta.get("threshold", self.threshold))
            self.w_stage1 = float(meta.get("w_stage1", self.w_stage1))
            self.threshold_percentile = meta.get("threshold_percentile", self.threshold_percentile)
            self.anomaly_threshold = self.gate_threshold
            self.normal_threshold = float(meta.get("iforest_normal_threshold", self.normal_threshold))

            norm = meta.get("normalization", {})
            self.if_min = float(norm.get("if_min", 0.0))
            self.if_max = float(norm.get("if_max", 1.0))
            self.oc_min = float(norm.get("oc_min", 0.0))
            self.oc_max = float(norm.get("oc_max", 1.0))

        self.is_fitted = True
        logger.info(f"Successfully loaded CascadeModel from {model_dir}")
        return self
