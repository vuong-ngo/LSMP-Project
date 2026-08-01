import numpy as np

from lsmp_ai.evaluation.ablation import run_ablation_study
from lsmp_ai.evaluation.metrics import compute_classification_metrics


def test_classification_metrics():
    y_true = np.array([1, 1, -1, -1, 1, -1])
    y_pred = np.array([1, -1, -1, 1, 1, -1])
    y_score = np.array([0.1, 0.6, 0.8, 0.3, 0.2, 0.9])

    metrics = compute_classification_metrics(y_true, y_pred, y_score)
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "roc_auc" in metrics
    assert 0 <= metrics["accuracy"] <= 1


def test_ablation_study(sample_feature_df):
    from lsmp_ai.common.constants import FEATURE_COLUMNS

    df = sample_feature_df
    X = df[FEATURE_COLUMNS].values
    y = np.where(df["label"] == "Anomaly", -1, 1)

    n = len(df)
    split = int(n * 0.7)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    results = run_ablation_study(X_train, X_test, y_test)
    assert "iForest Only" in results.index
    assert "OCSVM Only" in results.index
    assert "Cascade iForest→OCSVM" in results.index
    assert "f1_score" in results.columns
