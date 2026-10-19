# ============================================================================
# file: feature_engineering/feature_pipeline.py
# Description: Feature extraction and preprocessing pipeline for LSMP AI module.
#              Orchestrates 14 standardized Auth & Nginx features.
# ============================================================================

import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from typing import Union, Optional, List, Dict, Any
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.feature_engineering.auth_features import (
    calculate_auth_fail_count,
    calculate_auth_success_count,
    calculate_auth_fail_ratio,
    calculate_distinct_username,
    calculate_fail_interarrival_stats,
)
from lsmp_ai.feature_engineering.web_features import (
    calculate_http_req_rate,
    calculate_http_status_ratios,
    calculate_http_post_ratio,
    calculate_distinct_user_agent,
    calculate_bytes_sent_mean,
)
from lsmp_ai.feature_engineering.behavior_features import (
    calculate_global_active_ips,
    calculate_burst_rate,
)


# ============================================================================
# FEATURE PREPROCESSING PIPELINE
# ============================================================================

class FeaturePipeline:
    """Standard feature transformation pipeline combining SimpleImputer and StandardScaler.

    Attributes:
        feature_cols (List[str]): List of expected 14 feature column names.
        pipeline (Pipeline): The scikit-learn preprocessing pipeline.
    """

    def __init__(self, feature_cols: Optional[List[str]] = None):
        """Initializes the FeaturePipeline with default feature columns and preprocessors."""
        self.feature_cols = feature_cols or list(FEATURE_COLUMNS)

        self.pipeline = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

    def _prepare_input(self, X: Union[pd.DataFrame, np.ndarray]) -> Union[pd.DataFrame, np.ndarray]:
        """Extracts required feature columns if DataFrame is provided, else returns array.

        Always enforces the correct column order matching self.feature_cols.
        Missing columns are filled with 0.0 to prevent silent schema mismatches.
        """
        if isinstance(X, pd.DataFrame):
            df_copy = X.copy()
            # Map legacy column names if present
            legacy_mapping = {
                "login_fail_count": "auth_fail_count",
                "fail_success_ratio": "auth_fail_ratio",
                "unique_failed_ip_count": "distinct_username",
                "request_rate": "http_req_rate",
                "status_4xx_rate": "http_4xx_ratio",
                "user_agent_entropy": "distinct_user_agent",
                "ip_entropy": "global_active_ips",
                # SME-kit research aliases
                "http_req_count": "http_req_rate",
                "distinct_src_ip": "global_active_ips",
                "max_fail_per_ip": "burst_rate",
                # xu-ly-du-lieu web & SSH aliases
                "req_count": "http_req_rate",
                "unique_ua_count": "distinct_user_agent",
                "post_ratio": "http_post_ratio",
                "status_4xx_ratio": "http_4xx_ratio",
                "status_5xx_ratio": "http_5xx_ratio",
                "bytes_per_request": "bytes_sent_mean",
                "failed_auth_count": "auth_fail_count",
                "accepted_count": "auth_success_count",
                "failed_auth_ratio": "auth_fail_ratio",
                "unique_user_count": "distinct_username",
            }
            for old_col, new_col in legacy_mapping.items():
                if new_col not in df_copy.columns and old_col in df_copy.columns:
                    df_copy[new_col] = df_copy[old_col]

            missing = [c for c in self.feature_cols if c not in df_copy.columns]
            if missing:
                logger.warning(f"Missing {len(missing)} feature columns, filling with 0.0: {missing}")
                for col in missing:
                    df_copy[col] = 0.0

            res = df_copy[self.feature_cols]
            return res.replace([np.inf, -np.inf], np.nan)

        if isinstance(X, np.ndarray):
            arr = np.copy(X)
            arr[np.isinf(arr)] = np.nan
            return arr
        return X

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> 'FeaturePipeline':
        """Fits the imputer and scaler on feature data."""
        X_clean = self._prepare_input(X)
        self.pipeline.fit(X_clean)
        logger.info("Successfully fitted FeaturePipeline.")
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Transforms feature data using fitted pipeline."""
        X_clean = self._prepare_input(X)
        return self.pipeline.transform(X_clean)

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Fits and transforms feature data."""
        X_clean = self._prepare_input(X)
        return self.pipeline.fit_transform(X_clean)

    def save(self, filepath: str) -> None:
        """Serializes and saves the fitted feature pipeline to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        logger.info(f"Saved FeaturePipeline to {filepath}.")

    @classmethod
    def load(cls, filepath: str, expected_hash: Optional[str] = None) -> 'FeaturePipeline':
        """Loads a serialized FeaturePipeline instance from disk after verifying cryptographic integrity.

        Args:
            filepath: Target file path.
            expected_hash: Optional expected SHA-256 digest. If omitted, checks sibling manifest.json.

        Raises:
            FileNotFoundError: If pipeline file does not exist.
            SecurityError: If artifact integrity verification fails (RCE defense).
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Pipeline file not found: {filepath}")

        if expected_hash is None:
            parent_dir = os.path.dirname(os.path.abspath(filepath))
            manifest_file = os.path.join(parent_dir, "manifest.json")
            if os.path.exists(manifest_file):
                try:
                    with open(manifest_file, "r") as f:
                        m_data = json.load(f)
                    base_name = os.path.basename(filepath)
                    expected_hash = m_data.get("artifact_hashes", {}).get(base_name)
                except Exception:
                    pass

        if expected_hash:
            from lsmp_ai.common.security import verify_file_integrity
            from lsmp_ai.common.exceptions import SecurityError
            if not verify_file_integrity(filepath, expected_hash):
                raise SecurityError(
                    f"Security integrity check FAILED for '{filepath}'! "
                    "Deserialization aborted to prevent arbitrary code execution (RCE)."
                )

        pipeline = joblib.load(filepath)
        logger.info(f"Loaded FeaturePipeline from {filepath}.")
        return pipeline


# ============================================================================
# RAW LOG FEATURE EXTRACTION ORCHESTRATOR
# ============================================================================

def extract_features_from_logs(
    df_raw: pd.DataFrame,
    df_historical: Optional[pd.DataFrame] = None,
    window_start: Optional[datetime] = None,
    window_seconds: float = 60.0
) -> pd.DataFrame:
    """Transforms raw log events in a time window into aggregate 14 AI feature vectors per src_ip.

    Args:
        df_raw (pd.DataFrame): Raw log events within current sliding time window.
        df_historical (Optional[pd.DataFrame], optional): Historical log events for burst rate comparison.
        window_start (Optional[datetime], optional): Window start timestamp. Defaults to now.
        window_seconds (float, optional): Duration of the window in seconds. Defaults to 60.0.

    Returns:
        pd.DataFrame: Aggregated feature vectors DataFrame with columns matching FEATURE_COLUMNS.
    """
    empty_cols = ["window_start", "src_ip"] + list(FEATURE_COLUMNS) + ["computed_at"]
    if df_raw.empty:
        logger.warning("Empty raw logs DataFrame. Returning empty features.")
        return pd.DataFrame(columns=empty_cols)

    df_work = df_raw.copy()

    # Fast vectorized src_ip extraction fallback if missing
    if 'src_ip' not in df_work.columns:
        if 'source_ip' in df_work.columns:
            df_work['src_ip'] = df_work['source_ip']
        else:
            raw_col = 'raw_log' if 'raw_log' in df_work.columns else 'raw_message'
            if raw_col in df_work.columns:
                extracted_ips = df_work[raw_col].astype(str).str.extract(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)', expand=False)
                df_work['src_ip'] = extracted_ips.fillna('0.0.0.0')
            else:
                df_work['src_ip'] = '0.0.0.0'

    df_work = df_work.dropna(subset=['src_ip'])
    if df_work.empty:
        logger.warning("No logs with valid src_ip. Returning empty features.")
        return pd.DataFrame(columns=empty_cols)

    unique_ips = df_work['src_ip'].unique()

    # 1. AUTH FEATURES (per src_ip)
    auth_fails = calculate_auth_fail_count(df_work)
    auth_successes = calculate_auth_success_count(df_work)
    auth_ratios = calculate_auth_fail_ratio(df_work)
    distinct_users = calculate_distinct_username(df_work)
    ia_mean, ia_std = calculate_fail_interarrival_stats(df_work)

    # 2. WEB / NGINX FEATURES (per src_ip)
    http_req_rates = calculate_http_req_rate(df_work, window_seconds=window_seconds)
    r4xx, r5xx = calculate_http_status_ratios(df_work)
    r_post = calculate_http_post_ratio(df_work)
    distinct_uas = calculate_distinct_user_agent(df_work)
    bytes_mean = calculate_bytes_sent_mean(df_work)

    # 3. CONTEXT & TEMPORAL FEATURES
    global_active = calculate_global_active_ips(df_work)
    burst = calculate_burst_rate(df_work, df_historical=df_historical)

    # 4. ASSEMBLE 14 STANDARDIZED FEATURE ROWS
    w_start = window_start or datetime.now(timezone.utc)
    rows = []
    for ip in unique_ips:
        row = {
            "window_start": w_start,
            "src_ip": ip,
            # Authentication features
            "auth_fail_count": float(auth_fails.get(ip, 0.0)),
            "auth_success_count": float(auth_successes.get(ip, 0.0)),
            "auth_fail_ratio": float(auth_ratios.get(ip, 0.0)),
            "distinct_username": float(distinct_users.get(ip, 0.0)),
            "fail_interarrival_mean": float(ia_mean.get(ip, 0.0)),
            "fail_interarrival_std": float(ia_std.get(ip, 0.0)),
            # Web features
            "http_req_rate": float(http_req_rates.get(ip, 0.0)),
            "http_4xx_ratio": float(r4xx.get(ip, 0.0)),
            "http_5xx_ratio": float(r5xx.get(ip, 0.0)),
            "http_post_ratio": float(r_post.get(ip, 0.0)),
            "distinct_user_agent": float(distinct_uas.get(ip, 0.0)),
            "bytes_sent_mean": float(bytes_mean.get(ip, 0.0)),
            # Context features
            "global_active_ips": float(global_active),
            "burst_rate": float(burst.get(ip, 1.0)),
            "feature_version": getattr(config, "feature_version", "v2") if config else "v2",
            "computed_at": datetime.now(timezone.utc)
        }
        rows.append(row)

    return pd.DataFrame(rows)
