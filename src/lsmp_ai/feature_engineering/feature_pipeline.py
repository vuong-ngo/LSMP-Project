# ============================================================================
# file: feature_engineering/feature_pipeline.py
# Description: Feature extraction and preprocessing pipeline for LSMP AI module.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Union, Optional, List, Dict, Any
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.feature_engineering.auth_features import (
    calculate_login_fail_count, calculate_unique_failed_ip_count,
    calculate_fail_success_ratio, calculate_ip_entropy
)
from lsmp_ai.feature_engineering.web_features import (
    calculate_request_rate, calculate_status_4xx_rate,
    calculate_url_frequency, calculate_user_agent_entropy,
    calculate_method_distribution
)
from lsmp_ai.feature_engineering.behavior_features import (
    calculate_time_window_count, calculate_burst_rate,
    calculate_ip_switch_frequency
)


# ===== Feature Preprocessing Pipeline =====
class FeaturePipeline:
    """Standard feature transformation pipeline combining SimpleImputer and StandardScaler.

    Attributes:
        feature_cols (List[str]): List of expected feature column names.
        pipeline (Pipeline): The scikit-learn preprocessing pipeline.
    """

    def __init__(self):
        """Initializes the FeaturePipeline with default feature columns and preprocessors."""
        self.feature_cols = FEATURE_COLUMNS

        self.pipeline = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

    def _prepare_input(self, X: Union[pd.DataFrame, np.ndarray]) -> Union[pd.DataFrame, np.ndarray]:
        """Extracts required feature columns if DataFrame is provided, else returns array."""
        if isinstance(X, pd.DataFrame):
            missing = [c for c in self.feature_cols if c not in X.columns]
            if not missing:
                return X[self.feature_cols]
        return X

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> 'FeaturePipeline':
        """Fits the imputer and scaler on feature data.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            FeaturePipeline: The fitted pipeline instance (self).
        """
        X_clean = self._prepare_input(X)
        self.pipeline.fit(X_clean)
        logger.info("Successfully fitted FeaturePipeline.")
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Transforms feature data using fitted pipeline.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: Scaled and imputed feature numpy array.
        """
        X_clean = self._prepare_input(X)
        return self.pipeline.transform(X_clean)

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Fits and transforms feature data.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: Scaled and imputed feature numpy array.
        """
        X_clean = self._prepare_input(X)
        return self.pipeline.fit_transform(X_clean)

    def save(self, filepath: str) -> None:
        """Serializes and saves the fitted feature pipeline to disk.

        Args:
            filepath (str): Target destination file path.
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        logger.info(f"Saved FeaturePipeline to {filepath}.")

    @classmethod
    def load(cls, filepath: str) -> 'FeaturePipeline':
        """Loads a serialized FeaturePipeline instance from disk.

        Args:
            filepath (str): Source file path.

        Returns:
            FeaturePipeline: Deserialized FeaturePipeline instance.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Pipeline file not found: {filepath}")
        pipeline = joblib.load(filepath)
        logger.info(f"Loaded FeaturePipeline from {filepath}.")
        return pipeline


# ===== Raw Log Feature Extraction Helper =====
def extract_features_from_logs(
    df_raw: pd.DataFrame, 
    df_historical: Optional[pd.DataFrame] = None, 
    window_start: Optional[datetime] = None
) -> pd.DataFrame:
    """Transforms raw log events in a time window into aggregate 14 AI feature vectors per src_ip.

    Args:
        df_raw (pd.DataFrame): Raw log events within current sliding time window.
        df_historical (Optional[pd.DataFrame], optional): Historical log events for burst rate comparison.
        window_start (Optional[datetime], optional): Window start timestamp. Defaults to now.

    Returns:
        pd.DataFrame: Aggregated feature vectors DataFrame with columns matching FEATURE_COLUMNS.
    """
    if df_raw.empty:
        logger.warning("Empty raw logs DataFrame. Returning empty features.")
        return pd.DataFrame()

    if 'src_ip' not in df_raw.columns:
        raw_col = 'raw_log' if 'raw_log' in df_raw.columns else 'raw_message'
        if raw_col in df_raw.columns:
            import re
            def parse_ip(msg):
                match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(msg))
                return match.group(0) if match else None
            df_raw['src_ip'] = df_raw[raw_col].apply(parse_ip)
        else:
            df_raw['src_ip'] = '0.0.0.0'

    df_raw = df_raw.dropna(subset=['src_ip'])
    if df_raw.empty:
        logger.warning("No logs with valid src_ip. Returning empty features.")
        return pd.DataFrame()

    unique_ips = df_raw['src_ip'].unique()

    # Calculate feature series per IP
    login_fails = calculate_login_fail_count(df_raw)
    failed_target_ips = calculate_unique_failed_ip_count(df_raw)
    fail_succ_ratio = calculate_fail_success_ratio(df_raw)

    # Shared batch metrics (applied to all)
    entropy_ip = calculate_ip_entropy(df_raw)
    hr_of_day = window_start.hour if window_start else datetime.now().hour

    # Web metrics
    req_rate = calculate_request_rate(df_raw, config.time_window_minutes if config else 1)
    status_4xx = calculate_status_4xx_rate(df_raw)
    url_freq = calculate_url_frequency(df_raw)
    ua_entropy = calculate_user_agent_entropy(df_raw)
    method_dist = calculate_method_distribution(df_raw)

    # Behavior metrics
    time_window_cnt = calculate_time_window_count(df_raw)
    burst = calculate_burst_rate(df_raw, df_historical if df_historical is not None else pd.DataFrame())
    ip_switch = calculate_ip_switch_frequency(df_raw)

    # Assemble feature rows
    rows = []
    w_start = window_start or datetime.now()
    for ip in unique_ips:
        row = {
            "window_start": w_start,
            "src_ip": ip,
            "login_fail_count": float(login_fails.get(ip, 0.0)),
            "unique_failed_ip_count": float(failed_target_ips.get(ip, 0.0)),
            "fail_success_ratio": float(fail_succ_ratio.get(ip, 0.0)),
            "ip_entropy": float(entropy_ip),
            "hour_of_day": int(hr_of_day),
            "request_rate": float(req_rate.get(ip, 0.0)),
            "status_4xx_rate": float(status_4xx.get(ip, 0.0)),
            "url_frequency": float(url_freq.get(ip, 0.0)),
            "user_agent_entropy": float(ua_entropy.get(ip, 0.0)),
            "method_distribution": float(method_dist.get(ip, 0.0)),
            "time_window_count": float(time_window_cnt.get(ip, 0.0)),
            "burst_rate": float(burst.get(ip, 1.0)),
            "sliding_window_count": float(time_window_cnt.get(ip, 0.0)),
            "ip_switch_frequency": float(ip_switch.get(ip, 0.0)),
            "computed_at": datetime.now()
        }
        rows.append(row)

    return pd.DataFrame(rows)
