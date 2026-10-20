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
from lsmp_ai.common.constants import (
    LABEL_NORMAL,
    LABEL_ANOMALY,
    LABEL_UNCERTAIN,
    STATUS_CONFIDENT,
    STATUS_UNCERTAIN,
)
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
        uncertainty_margin: Optional[float] = None,
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

        self.w_stage1 = float(w_stage1 if w_stage1 is not None else c_params.get("w_stage1", 0.45))
        self.model_version = str(c_params.get("model_version", "cascade-v1.0"))

        # 4. Routing and decision thresholds
        self.gate_threshold: float = 0.0
        self.threshold: float = float(c_params.get("threshold", 0.45))
        self.uncertainty_margin: float = float(uncertainty_margin if uncertainty_margin is not None else c_params.get("uncertainty_margin", 0.06))
        self.tau_low: float = max(0.0, self.threshold - self.uncertainty_margin)
        self.tau_high: float = self.threshold
        self.is_fitted: bool = False

        # Min-max and ECDF quantile normalization anchors
        self.if_min: float = 0.0
        self.if_max: float = 1.0
        self.oc_min: float = 0.0
        self.oc_max: float = 1.0
        self.if_quantiles: Optional[np.ndarray] = None
        self.oc_quantiles: Optional[np.ndarray] = None

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
        criterion: str = "fpr_budget",
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
                raise ValueError(
                    "No benign samples identified; refusing to fit novelty detector "
                    "on an unverified training partition."
                )
        if len(X_train_clean) == 0:
            raise ValueError("Cannot fit CascadeModel with an empty benign training partition.")

        # 1. Fit Stage 1: Isolation Forest
        self.iforest_model.fit(X_train_clean)
        s_if_tr = self._if_score(X_train_clean)
        self.if_min = float(np.min(s_if_tr))
        self.if_max = float(np.max(s_if_tr))
        self.if_quantiles = np.quantile(s_if_tr, np.linspace(0.0, 1.0, 501))

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
        self.oc_quantiles = np.quantile(s_oc_tr, np.linspace(0.0, 1.0, 501))

        # 4. Calibrate Final Threshold
        if X_val is not None and y_val is not None:
            X_v = X_val.values if isinstance(X_val, pd.DataFrame) else np.asarray(X_val)
            s_val = self.score(X_v)
            yt_v = to_binary_labels(y_val)
            if np.any(yt_v == 1) and np.any(yt_v == 0):
                self.threshold = pick_threshold(y_val, s_val, criterion=criterion, max_fpr=max_fpr)
                logger.info(f"Optimal threshold chosen on validation ({criterion}): {self.threshold:.4f}")
            else:
                logger.warning("Validation set has only 1 class. Using robust score quantile threshold.")
                self.threshold = float(np.quantile(s_val, max(0.5, 1.0 - self.gate_rate)))
        else:
            s_train = self.score(X_train_clean)
            self.threshold = float(np.quantile(s_train, max(0.5, 1.0 - self.gate_rate)))

        self.tau_low = max(0.0, float(self.threshold - self.uncertainty_margin))
        self.tau_high = float(self.threshold)
        self.is_fitted = True
        logger.info(
            f"CascadeModel training completed. Decision threshold: {self.threshold:.4f} "
            f"(Uncertainty Band: [{self.tau_low:.4f}, {self.tau_high:.4f}])"
        )
        return self

    def _normalize_score(
        self,
        s: np.ndarray,
        lo: float,
        hi: float,
        quantiles: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        """Normalizes anomaly scores into [0, 1] using empirical CDF percentiles,
        providing resilience against extreme benign training outliers,
        with robust min-max fallback."""
        finite_s = np.where(np.isfinite(s), s, lo)
        if quantiles is not None and len(quantiles) > 1:
            norm_s = np.interp(
                finite_s,
                quantiles,
                np.linspace(0.0, 1.0, len(quantiles)),
                left=0.0,
                right=1.0,
            )
            return np.clip(norm_s, 0.0, 1.0)
        diff = hi - lo
        if abs(diff) < EPS:
            diff = 1.0
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
                "confidence_margin": np.array([], dtype=float),
                "prediction_status": np.array([], dtype=object),
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

        # Normalized Fusion using ECDF percentiles
        norm_if = self._normalize_score(s_if, self.if_min, self.if_max, getattr(self, "if_quantiles", None))
        norm_oc = self._normalize_score(s_oc_gated, self.oc_min, self.oc_max, getattr(self, "oc_quantiles", None))

        # Soft Cascade Fusion:
        # Gated samples combine Stage 1 and Stage 2 according to w_stage1.
        # Non-gated samples keep their Stage 1 score directly (norm_if),
        # eliminating the hard w_stage1 ceiling where non-gated samples could never exceed 0.40.
        fused_score = np.where(
            gated_mask,
            self.w_stage1 * norm_if + (1.0 - self.w_stage1) * norm_oc,
            norm_if,
        )
        fused_score = np.nan_to_num(fused_score, nan=0.0, posinf=1.0, neginf=0.0)
        fused_score = np.clip(fused_score, 0.0, 1.0)

        # Three-Way Classification Decision via Dual-Threshold Band
        tau_l = getattr(self, "tau_low", self.threshold)
        tau_h = getattr(self, "tau_high", self.threshold)

        labels = np.full(n_samples, LABEL_UNCERTAIN, dtype=object)
        labels[fused_score < tau_l] = LABEL_NORMAL
        labels[fused_score >= tau_h] = LABEL_ANOMALY
        if tau_l >= tau_h:
            labels[fused_score < tau_h] = LABEL_NORMAL

        status = np.where(labels == LABEL_UNCERTAIN, STATUS_UNCERTAIN, STATUS_CONFIDENT)
        confidence_margin = np.abs(fused_score - self.threshold)

        return pd.DataFrame({
            "stage1_score": s_if,
            "stage2_score": stage2_scores,
            "anomaly_score": fused_score,
            "confidence_margin": confidence_margin,
            "prediction_status": status,
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
        alpha: Optional[float] = None,
        beta: Optional[float] = None,
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
            "uncertainty_margin": self.uncertainty_margin,
            "tau_low": self.tau_low,
            "tau_high": self.tau_high,
            "w_stage1": self.w_stage1,
            "threshold_percentile": self.threshold_percentile,
            "iforest_anomaly_threshold": self.gate_threshold,
            "iforest_normal_threshold": self.normal_threshold,
            "normalization": {
                "if_min": self.if_min,
                "if_max": self.if_max,
                "oc_min": self.oc_min,
                "oc_max": self.oc_max,
                "if_quantiles": self.if_quantiles.tolist() if getattr(self, "if_quantiles", None) is not None else None,
                "oc_quantiles": self.oc_quantiles.tolist() if getattr(self, "oc_quantiles", None) is not None else None,
            }
        }

        # Compute cryptographic artifact hashes & harden permissions (S2 defense)
        from lsmp_ai.common.security import compute_file_sha256, secure_file_permissions, secure_directory_permissions
        if_path = os.path.join(model_dir, "iforest.joblib")
        oc_path = os.path.join(model_dir, "ocsvm.joblib")
        secure_directory_permissions(model_dir, 0o750)
        if os.path.exists(if_path):
            secure_file_permissions(if_path, 0o640)
        if os.path.exists(oc_path):
            secure_file_permissions(oc_path, 0o640)

        meta["artifact_hashes"] = {
            "iforest.joblib": compute_file_sha256(if_path) if os.path.exists(if_path) else None,
            "ocsvm.joblib": compute_file_sha256(oc_path) if os.path.exists(if_path) else None,
        }

        meta_file = os.path.join(model_dir, "metadata.json")
        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=4)
        secure_file_permissions(meta_file, 0o640)
        logger.info(f"Saved CascadeModel and metadata to {model_dir}")

    def load(self, model_dir: str) -> 'CascadeModel':
        """Deserializes submodels and restores cascade state from directory.
        Performs cryptographic SHA-256 verification before deserialization to prevent RCE.

        Args:
            model_dir (str): Path to model directory.

        Returns:
            CascadeModel: Restored model instance (self).
        """
        # Cryptographic artifact integrity verification before joblib.load()
        manifest_path = os.path.join(model_dir, "manifest.json")
        meta_path = os.path.join(model_dir, "metadata.json")
        artifact_hashes = None
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    artifact_hashes = json.load(f).get("artifact_hashes")
            except Exception:
                pass
        if not artifact_hashes and os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    artifact_hashes = json.load(f).get("artifact_hashes")
            except Exception:
                pass

        sub_hashes = {}
        if artifact_hashes:
            from lsmp_ai.common.security import verify_artifacts_in_dir
            sub_hashes = {k: v for k, v in artifact_hashes.items() if k in ("iforest.joblib", "ocsvm.joblib") and v}
            verify_artifacts_in_dir(model_dir, sub_hashes)

        self.iforest_model.load(os.path.join(model_dir, "iforest.joblib"), expected_hash=sub_hashes.get("iforest.joblib"))
        self.ocsvm_model.load(os.path.join(model_dir, "ocsvm.joblib"), expected_hash=sub_hashes.get("ocsvm.joblib"))

        meta_path = os.path.join(model_dir, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
            self.model_version = meta.get("model_version", self.model_version)
            self.gate_rate = float(meta.get("gate_rate", self.gate_rate))
            self.gate_threshold = float(meta.get("gate_threshold", meta.get("iforest_anomaly_threshold", self.gate_threshold)))
            self.threshold = float(meta.get("threshold", self.threshold))
            self.uncertainty_margin = float(meta.get("uncertainty_margin", getattr(self, "uncertainty_margin", 0.05)))
            self.tau_low = float(meta.get("tau_low", max(0.0, self.threshold - self.uncertainty_margin)))
            self.tau_high = float(meta.get("tau_high", self.threshold))
            self.w_stage1 = float(meta.get("w_stage1", self.w_stage1))
            self.threshold_percentile = meta.get("threshold_percentile", self.threshold_percentile)
            self.anomaly_threshold = self.gate_threshold
            self.normal_threshold = float(meta.get("iforest_normal_threshold", self.normal_threshold))

            norm = meta.get("normalization", {})
            self.if_min = float(norm.get("if_min", 0.0))
            self.if_max = float(norm.get("if_max", 1.0))
            self.oc_min = float(norm.get("oc_min", 0.0))
            self.oc_max = float(norm.get("oc_max", 1.0))
            if norm.get("if_quantiles") is not None:
                self.if_quantiles = np.asarray(norm["if_quantiles"], dtype=float)
            if norm.get("oc_quantiles") is not None:
                self.oc_quantiles = np.asarray(norm["oc_quantiles"], dtype=float)

        self.is_fitted = True
        logger.info(f"Successfully loaded CascadeModel from {model_dir}")
        return self
