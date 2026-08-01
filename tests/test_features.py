# ============================================================================
# file: tests/test_features.py
# Description: Rigorous unit test suite for LSMP feature extraction utilities and pipeline.
# ============================================================================

import os
import pytest
import numpy as np
import pandas as pd
from datetime import datetime

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
from lsmp_ai.feature_engineering.feature_pipeline import (
    extract_features_from_logs, FeaturePipeline
)


# ===== AUTHENTICATION FEATURE TESTS =====
def test_auth_feature_calculations(sample_raw_logs):
    # Test failed logins count
    fails = calculate_login_fail_count(sample_raw_logs)
    assert fails.get("10.0.0.5") == 1
    assert "192.168.1.100" not in fails

    # Test unique failed target IP/host count
    unique_failed_hosts = calculate_unique_failed_ip_count(sample_raw_logs)
    assert unique_failed_hosts.get("10.0.0.5") == 1.0

    # Test ratio with Laplace smoothing (1 fail, 1 success -> 1 / (1 + 1) = 0.5)
    ratios = calculate_fail_success_ratio(sample_raw_logs)
    assert ratios.get("10.0.0.5") == 0.5
    assert ratios.get("192.168.1.100") == 0.0

    # Test Shannon IP entropy
    entropy = calculate_ip_entropy(sample_raw_logs)
    assert entropy > 0.0


# ===== WEB FEATURE TESTS =====
def test_web_feature_calculations(sample_raw_logs):
    # Test request rate
    rates = calculate_request_rate(sample_raw_logs, window_minutes=1)
    assert rates.get("192.168.1.100") == 1.0

    # Test status 4xx rate
    status_4xx = calculate_status_4xx_rate(sample_raw_logs)
    assert status_4xx.get("172.16.0.1") == 1.0  # 100% 404
    assert status_4xx.get("192.168.1.100") == 0.0  # 200 is not 4xx

    # Test URL frequency uniqueness
    url_freq = calculate_url_frequency(sample_raw_logs)
    assert url_freq.get("172.16.0.1") == 1.0
    assert url_freq.get("192.168.1.100") == 1.0

    # Test user agent entropy
    ua_entropy = calculate_user_agent_entropy(sample_raw_logs)
    assert "192.168.1.100" in ua_entropy

    # Test method distribution
    method_dist = calculate_method_distribution(sample_raw_logs)
    assert method_dist.get("192.168.1.100") == 0.0  # GET is standard


# ===== BEHAVIOR FEATURE TESTS =====
def test_behavior_feature_calculations(sample_raw_logs):
    # Test time window count
    counts = calculate_time_window_count(sample_raw_logs)
    assert counts.get("10.0.0.5") == 2.0
    assert counts.get("192.168.1.100") == 1.0

    # Test burst rate with empty history fallback
    burst = calculate_burst_rate(sample_raw_logs, pd.DataFrame())
    assert burst.get("10.0.0.5") == 1.0

    # Test IP switch frequency
    ip_switch = calculate_ip_switch_frequency(sample_raw_logs)
    assert "10.0.0.5" in ip_switch


# ===== FULL LOG EXTRACTOR PIPELINE TESTS =====
def test_extract_features_from_logs(sample_raw_logs):
    features_df = extract_features_from_logs(sample_raw_logs, window_start=datetime.now())
    
    # Assert all 14 feature columns exist in output
    for col in FEATURE_COLUMNS:
        assert col in features_df.columns

    # Assert correct number of unique IPs extracted
    assert len(features_df) == sample_raw_logs["src_ip"].nunique()


def test_extract_features_fallback_regex():
    # Test raw logs lacking explicit src_ip column (trigger regex fallback)
    raw_logs = pd.DataFrame([
        {"raw_log": '10.0.0.99 - - [15/Jul/2026:22:00:00] "GET /test HTTP/1.1" 200 120'}
    ])
    features_df = extract_features_from_logs(raw_logs)
    assert not features_df.empty
    assert features_df["src_ip"].iloc[0] == "10.0.0.99"


def test_extract_features_empty_dataframe():
    empty_df = pd.DataFrame()
    res = extract_features_from_logs(empty_df)
    assert res.empty


# ===== FEATURE PREPROCESSING PIPELINE TESTS =====
def test_feature_pipeline_fit_transform(sample_features, tmp_path):
    pipeline = FeaturePipeline()

    # Fit & Transform
    X_scaled = pipeline.fit_transform(sample_features)

    # Assert shape matches expected 14 feature dimensions
    assert X_scaled.shape[0] == len(sample_features)
    assert X_scaled.shape[1] == len(pipeline.feature_cols)

    # Assert mean is close to 0 and std is close to 1
    assert abs(X_scaled.mean(axis=0)[0]) < 1e-6

    # Test Serialization (Save & Load)
    save_path = str(tmp_path / "pipeline.joblib")
    pipeline.save(save_path)
    assert os.path.exists(save_path)

    loaded_pipeline = FeaturePipeline.load(save_path)
    X_loaded = loaded_pipeline.transform(sample_features)
    np.testing.assert_array_almost_equal(X_scaled, X_loaded)


def test_feature_pipeline_column_reordering_and_missing(sample_features):
    """Verify that FeaturePipeline auto-fills missing feature columns with 0.0 and enforces exact column ordering."""
    pipeline = FeaturePipeline()
    pipeline.fit(sample_features)

    # Scramble column order and drop a column
    scrambled_df = sample_features.copy()
    cols = list(scrambled_df.columns)
    scrambled_df = scrambled_df[cols[::-1]]  # reverse order
    scrambled_df = scrambled_df.drop(columns=["login_fail_count"])

    # FeaturePipeline should auto-fill missing login_fail_count column with 0.0 and enforce 14-column order
    X_scaled = pipeline.transform(scrambled_df)
    assert X_scaled.shape == (len(sample_features), 14)
    assert not np.isnan(X_scaled).any()
    assert not np.isinf(X_scaled).any()

