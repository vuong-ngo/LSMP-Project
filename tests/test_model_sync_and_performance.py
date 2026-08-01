import os
import time
import inspect
import pytest
import numpy as np
import pandas as pd
from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.models.isolation_forest_model import IsolationForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel


# =====================================================================
# 1. STYLE & INTERFACE SYNCHRONIZATION TESTS
# =====================================================================

MODEL_CLASSES = [IsolationForestModel, OCSVMModel, CascadeModel]

def test_models_inherit_from_base_model():
    """Verify that all concrete model classes inherit from BaseModel interface."""
    for model_cls in MODEL_CLASSES:
        assert issubclass(model_cls, BaseModel), f"{model_cls.__name__} must inherit from BaseModel"


def test_models_implement_required_interface_methods():
    """Verify that all model classes implement fit, predict, score, save, load."""
    required_methods = ["fit", "predict", "score", "save", "load"]
    for model_cls in MODEL_CLASSES:
        for method_name in required_methods:
            assert hasattr(model_cls, method_name), f"{model_cls.__name__} missing method {method_name}"
            method = getattr(model_cls, method_name)
            assert callable(method), f"{model_cls.__name__}.{method_name} must be callable"


def test_models_docstrings_completeness():
    """Verify code style consistency: all model classes and key methods must have valid docstrings."""
    required_methods = ["fit", "predict", "score", "save", "load"]
    for model_cls in MODEL_CLASSES:
        assert model_cls.__doc__ is not None and len(model_cls.__doc__.strip()) > 0, \
            f"Class {model_cls.__name__} is missing class-level docstring."
        for method_name in required_methods:
            method = getattr(model_cls, method_name)
            assert method.__doc__ is not None and len(method.__doc__.strip()) > 0, \
                f"{model_cls.__name__}.{method_name} is missing a docstring."


# =====================================================================
# 2. FUNCTIONAL CORRECTNESS & INTERFACE COMPATIBILITY TESTS
# =====================================================================

def test_models_accept_both_dataframe_and_numpy():
    """Verify input polymorphism: models accept pd.DataFrame and np.ndarray seamlessly."""
    np.random.seed(42)
    X_np = np.random.randn(100, 5)
    X_df = pd.DataFrame(X_np, columns=[f"feat_{i}" for i in range(5)])

    for model_cls in [IsolationForestModel, OCSVMModel]:
        model_df = model_cls().fit(X_df)
        preds_df = model_df.predict(X_df)
        preds_np = model_df.predict(X_np)
        scores_df = model_df.score(X_df)
        scores_np = model_df.score(X_np)

        np.testing.assert_array_equal(preds_df, preds_np)
        np.testing.assert_array_almost_equal(scores_df, scores_np)


def test_models_score_dimensions_and_types():
    """Verify that score returns a 1D ndarray of floats matching sample length."""
    np.random.seed(42)
    X = np.random.randn(50, 4)

    for model_cls in MODEL_CLASSES:
        model = model_cls().fit(X)
        scores = model.score(X)
        assert isinstance(scores, np.ndarray), f"{model_cls.__name__}.score must return np.ndarray"
        assert scores.ndim == 1, f"{model_cls.__name__}.score must return 1D array, got {scores.ndim}D"
        assert len(scores) == 50, f"{model_cls.__name__}.score returned length {len(scores)}, expected 50"


def test_models_save_and_load_integrity(tmp_path):
    """Verify model state serialization and deserialization reproducibility."""
    np.random.seed(42)
    X = np.random.randn(100, 4)

    # Isolation Forest
    iforest = IsolationForestModel(n_estimators=20, random_state=42).fit(X)
    iforest_path = str(tmp_path / "iforest.joblib")
    iforest.save(iforest_path)
    loaded_iforest = IsolationForestModel().load(iforest_path)
    np.testing.assert_array_equal(iforest.predict(X), loaded_iforest.predict(X))

    # OCSVM
    ocsvm = OCSVMModel(nu=0.05).fit(X)
    ocsvm_path = str(tmp_path / "ocsvm.joblib")
    ocsvm.save(ocsvm_path)
    loaded_ocsvm = OCSVMModel().load(ocsvm_path)
    np.testing.assert_array_equal(ocsvm.predict(X), loaded_ocsvm.predict(X))

    # Cascade Model
    cascade = CascadeModel().fit(X)
    cascade_dir = str(tmp_path / "cascade_saved")
    cascade.save(cascade_dir)
    loaded_cascade = CascadeModel().load(cascade_dir)
    np.testing.assert_array_equal(cascade.predict(X), loaded_cascade.predict(X))


# =====================================================================
# 3. PERFORMANCE & OPTIMIZATION BENCHMARK TESTS
# =====================================================================

def test_cascade_stage1_bypass_optimization():
    """
    Verify optimization: CascadeModel uses Stage 1 (IForest) to bypass Stage 2 (OCSVM)
    for clear normal/anomalous samples, avoiding unnecessary OCSVM calculations.
    """
    np.random.seed(42)
    # Generate 1000 synthetic samples
    X_normal = np.random.randn(900, 5)
    X_outlier = np.random.randn(100, 5) * 5 + 10
    X = np.vstack([X_normal, X_outlier])

    cascade = CascadeModel().fit(X)
    detailed_df = cascade.predict_detailed(X)

    # Check stage 2 evaluations count
    evaluated_stage2_count = detailed_df["stage2_score"].notna().sum()
    total_count = len(X)

    # In a cascade model, only ambiguous samples enter Stage 2 (typically < 30% of total)
    bypass_rate = (total_count - evaluated_stage2_count) / total_count
    print(f"\n[Cascade Optimization] Evaluated Stage 2: {evaluated_stage2_count}/{total_count} ({evaluated_stage2_count/total_count:.1%})")
    print(f"[Cascade Optimization] Stage 1 Bypass Rate: {bypass_rate:.1%}")

    # Stage 1 must bypass at least 50% of total traffic
    assert bypass_rate > 0.50, f"Expected Stage 1 bypass rate > 50%, got {bypass_rate:.1%}"


def test_models_performance_throughput_and_latency():
    """
    Benchmark execution time (throughput in samples/sec and latency per sample)
    across IsolationForestModel, OCSVMModel, and CascadeModel.
    """
    np.random.seed(42)
    n_train = 2000
    n_test = 1000
    n_features = 10

    X_train = np.random.randn(n_train, n_features)
    X_test = np.random.randn(n_test, n_features)

    print("\n" + "=" * 60)
    print(" MODEL PERFORMANCE BENCHMARK REPORT ")
    print("=" * 60)

    for model_cls in [IsolationForestModel, OCSVMModel, CascadeModel]:
        model = model_cls()

        # Measure Fit Time
        start_fit = time.perf_counter()
        model.fit(X_train)
        fit_duration = time.perf_counter() - start_fit
        fit_throughput = n_train / fit_duration

        # Measure Predict Time
        start_pred = time.perf_counter()
        preds = model.predict(X_test)
        pred_duration = time.perf_counter() - start_pred
        pred_throughput = n_test / pred_duration
        latency_per_sample_ms = (pred_duration / n_test) * 1000.0

        print(f"[{model_cls.__name__}]")
        print(f"  - Fit Time         : {fit_duration:.4f}s ({fit_throughput:.0f} samples/sec)")
        print(f"  - Inference Time   : {pred_duration:.4f}s ({pred_throughput:.0f} samples/sec)")
        print(f"  - Avg Latency      : {latency_per_sample_ms:.4f} ms/sample")
        print("-" * 60)

        # Basic performance thresholds
        assert pred_duration < 5.0, f"Inference for {model_cls.__name__} took > 5s ({pred_duration:.2f}s)"
        assert len(preds) == n_test
