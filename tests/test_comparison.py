import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from lsmp_ai.evaluation.comparison import ModelComparator, run_iforest_ocsvm_comparison
from lsmp_ai.common.constants import FEATURE_COLUMNS


def test_model_comparator_with_sample_df(sample_feature_df):
    df = sample_feature_df
    X = df[FEATURE_COLUMNS].values
    y = np.where(df["label"] == "Anomaly", 1, 0)

    split = int(len(df) * 0.7)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    comparator = ModelComparator(benchmark_runs=5, random_state=42)
    df_results, full_details = comparator.compare(X_train, X_test, y_test, y_train=y_train)

    assert "Isolation Forest" in df_results.index
    assert "One-Class SVM" in df_results.index
    assert "Cascade (iForest->OCSVM)" in df_results.index

    assert "f1_score" in df_results.columns
    assert "accuracy" in df_results.columns
    assert "latency_mean_ms" in df_results.columns
    assert "throughput_rows_sec" in df_results.columns

    assert "models" in full_details
    assert "significance_tests" in full_details


def test_run_iforest_ocsvm_comparison_helper(sample_feature_df):
    df = sample_feature_df
    X = df[FEATURE_COLUMNS].values
    y = np.where(df["label"] == "Anomaly", 1, 0)

    split = int(len(df) * 0.7)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    df_results, full_details = run_iforest_ocsvm_comparison(
        X_train=X_train,
        X_test=X_test,
        y_test=y_test,
        y_train=y_train,
        benchmark_runs=3,
    )

    assert isinstance(df_results, pd.DataFrame)
    assert len(df_results) == 3
