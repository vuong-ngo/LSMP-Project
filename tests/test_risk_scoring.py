# ============================================================================
# file: tests/test_risk_scoring.py
# Description: Rigorous unit test suite for risk score computation and classification modules.
# ============================================================================

import pytest
import numpy as np
import pandas as pd

from lsmp_ai.risk_scoring import (
    calculate_risk_score,
    compute_risk_scores_for_df,
    classify_risk_score,
    classify_risk_for_df,
    RiskClassifier,
)


# ===== RISK SCORE CALCULATION TESTS =====
def test_calculate_risk_score_scalars():
    # Maximum risk score calculation (anomaly=1.0, severity=15.0 -> 100.0)
    val_max = calculate_risk_score(1.0, 15.0)
    assert abs(val_max - 100.0) < 1e-5

    # Minimum risk score calculation (anomaly=0.0, severity=0.0 -> 0.0)
    val_min = calculate_risk_score(0.0, 0.0)
    assert abs(val_min - 0.0) < 1e-5

    # Check upper clipping: severity level > 15.0 should be clipped at 15.0
    val_clipped_upper = calculate_risk_score(0.5, 20.0)
    val_expected_upper = calculate_risk_score(0.5, 15.0)
    assert abs(val_clipped_upper - val_expected_upper) < 1e-5

    # Check lower clipping: severity level < 0.0 should be clipped at 0.0
    val_clipped_lower = calculate_risk_score(0.5, -5.0)
    val_expected_lower = calculate_risk_score(0.5, 0.0)
    assert abs(val_clipped_lower - val_expected_lower) < 1e-5


def test_calculate_risk_score_vectorized_and_lists():
    anomaly_scores = np.array([0.0, 0.5, 1.0])
    severity_weights = np.array([0.0, 7.5, 15.0])

    scores = calculate_risk_score(anomaly_scores, severity_weights)
    assert len(scores) == 3
    assert abs(scores[0] - 0.0) < 1e-5
    assert abs(scores[2] - 100.0) < 1e-5

    # Test python lists and NaN handling
    scores_list = calculate_risk_score([0.0, None, 1.0], [0.0, 7.5, np.nan])
    assert len(scores_list) == 3
    assert abs(scores_list[0] - 0.0) < 1e-5


def test_compute_risk_scores_for_df():
    df = pd.DataFrame({
        "src_ip": ["192.168.1.1", "192.168.1.2"],
        "anomaly_score": [0.2, 0.8],
        "severity_weight": [3.0, 12.0]
    })
    df_out = compute_risk_scores_for_df(df)

    assert "risk_score" in df_out.columns
    assert len(df_out["risk_score"]) == 2
    assert df_out["risk_score"].iloc[1] > df_out["risk_score"].iloc[0]

    # Test empty DataFrame handling
    empty_df = pd.DataFrame()
    assert compute_risk_scores_for_df(empty_df).empty


# ===== RISK CLASSIFICATION TESTS =====
def test_classify_risk_score_boundaries():
    # Boundary thresholds (low <= 25.0, medium <= 50.0, high <= 80.0, critical > 80.0)
    assert classify_risk_score(0.0) == "Low"
    assert classify_risk_score(25.0) == "Low"
    assert classify_risk_score(25.1) == "Medium"
    assert classify_risk_score(50.0) == "Medium"
    assert classify_risk_score(50.1) == "High"
    assert classify_risk_score(80.0) == "High"
    assert classify_risk_score(80.1) == "Critical"
    assert classify_risk_score(100.0) == "Critical"

    # Vectorized array check
    scores = np.array([10.0, 35.0, 70.0, 95.0])
    classes = classify_risk_score(scores)
    assert list(classes) == ["Low", "Medium", "High", "Critical"]


def test_classify_risk_for_df():
    df = pd.DataFrame({
        "risk_score": [15.0, 45.0, 75.0, 90.0]
    })
    df_out = classify_risk_for_df(df)

    assert "risk_class" in df_out.columns
    assert list(df_out["risk_class"]) == ["Low", "Medium", "High", "Critical"]

    # Test missing risk_score column exception when anomaly_score is also missing
    df_invalid = pd.DataFrame({"other_col": [1, 2]})
    with pytest.raises(ValueError, match="risk_score or anomaly_score column must be present"):
        classify_risk_for_df(df_invalid)


# ===== RISK CLASSIFIER CLASS TESTS =====
def test_risk_classifier_class():
    classifier = RiskClassifier(alpha=0.7, beta=0.3, low_threshold=20.0, medium_threshold=60.0, high_threshold=85.0)

    score = classifier.calculate_score(1.0, 15.0)
    assert abs(score - 100.0) < 1e-5

    label = classifier.classify(55.0)
    assert label == "Medium"

    df = pd.DataFrame({"anomaly_score": [0.1, 0.9], "severity_weight": [0.0, 15.0]})
    df_classified = classifier.classify_dataframe(df)

    assert "risk_score" in df_classified.columns
    assert "risk_class" in df_classified.columns
    assert df_classified["risk_class"].iloc[0] == "Low"
    assert df_classified["risk_class"].iloc[1] == "Critical"
