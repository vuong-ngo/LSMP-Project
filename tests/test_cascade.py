import numpy as np

from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel


def test_cascade_threshold_effect():
    X_normal = np.random.randn(80, 14) * 0.5 + 0.5
    X_anomaly = np.random.randn(20, 14) * 2.0 + 3.0
    X = np.vstack([X_normal, X_anomaly])

    iforest = IForestModel(contamination=0.1)
    ocsvm = OCSVMModel(nu=0.1)
    cascade = CascadeModel(iforest, ocsvm, threshold_percentile=90)
    cascade.fit(X)

    preds = cascade.predict(X)
    scores = cascade.score(X)

    assert preds.shape == (100,)
    assert scores.shape == (100,)
    assert scores.min() >= 0
    assert scores.max() <= 1


def test_cascade_stages():
    X = np.random.randn(100, 14)
    iforest = IForestModel(contamination=0.1)
    ocsvm = OCSVMModel(nu=0.1)
    cascade = CascadeModel(iforest, ocsvm, threshold_percentile=80)
    cascade.fit(X)

    details = cascade.predict_with_details(
        X,
        src_ips=["192.168.1.1"] * 100,
        window_starts=["2026-07-01"] * 100,
    )

    assert "stage1_score" in details.columns
    assert "stage2_score" in details.columns
    assert "anomaly_score" in details.columns
    assert "predicted_label" in details.columns


def test_cascade_fit_with_labels():
    """Verify that fitting CascadeModel with binary string/integer labels trains OCSVM on pure Normal samples."""
    X_normal = np.random.randn(80, 14) * 0.5
    X_anomaly = np.random.randn(20, 14) * 5.0 + 10.0
    X = np.vstack([X_normal, X_anomaly])
    y = np.array(["Normal"] * 80 + ["Anomaly"] * 20)

    cascade = CascadeModel(threshold_percentile=80)
    cascade.fit(X, y)

    # Verify predictions are produced without error
    preds = cascade.predict(X)
    assert len(preds) == 100
    assert set(preds).issubset({"Normal", "Anomaly"})


def test_cascade_sigmoid_clip():
    """Verify that extreme OCSVM decision_function outputs do not cause float overflow or NaNs."""
    X = np.random.randn(50, 14)
    cascade = CascadeModel(threshold_percentile=80)
    cascade.fit(X)

    # Artificially test predict_detailed with extreme values
    details = cascade.predict_detailed(X)
    assert not details["anomaly_score"].isna().any()
    assert not np.isinf(details["anomaly_score"]).any()
    assert (details["anomaly_score"] >= 0.0).all()
    assert (details["anomaly_score"] <= 1.0).all()

