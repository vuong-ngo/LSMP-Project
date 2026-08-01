import os
import pytest
import numpy as np
import pandas as pd
from lsmp_ai.models.isolation_forest_model import IsolationForestModel, IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline


def test_isolation_forest_model_lifecycle(sample_features, tmp_path):
    pipeline = FeaturePipeline()
    X_scaled = pipeline.fit_transform(sample_features)

    # 1. Test init with custom params & kwargs
    iforest = IsolationForestModel(n_estimators=50, contamination=0.1, random_state=42)
    assert iforest.params["n_estimators"] == 50
    assert iforest.params["contamination"] == 0.1

    # 2. Test fit & predict
    iforest.fit(X_scaled)
    preds = iforest.predict(X_scaled)
    assert len(preds) == len(sample_features)
    assert set(preds).issubset({1, -1})

    # 3. Test score
    scores = iforest.score(X_scaled)
    assert len(scores) == len(sample_features)
    assert isinstance(scores, np.ndarray)

    # 4. Test save and load
    save_path = str(tmp_path / "iforest.joblib")
    iforest.save(save_path)
    assert os.path.exists(save_path)

    loaded_iforest = IsolationForestModel()
    loaded_iforest.load(save_path)
    loaded_preds = loaded_iforest.predict(X_scaled)
    np.testing.assert_array_equal(preds, loaded_preds)

    # 5. Verify alias
    assert IForestModel is IsolationForestModel


def test_ocsvm_model_lifecycle(sample_features, tmp_path):
    pipeline = FeaturePipeline()
    X_scaled = pipeline.fit_transform(sample_features)

    # 1. Test init with custom params
    ocsvm = OCSVMModel(kernel="rbf", nu=0.1, gamma="scale")
    assert ocsvm.params["kernel"] == "rbf"
    assert ocsvm.params["nu"] == 0.1

    # 2. Test fit & predict
    ocsvm.fit(X_scaled)
    preds = ocsvm.predict(X_scaled)
    assert len(preds) == len(sample_features)
    assert set(preds).issubset({1, -1})

    # 3. Test score (decision_function)
    scores = ocsvm.score(X_scaled)
    assert len(scores) == len(sample_features)
    assert isinstance(scores, np.ndarray)

    # 4. Test save and load
    save_path = str(tmp_path / "ocsvm.joblib")
    ocsvm.save(save_path)
    assert os.path.exists(save_path)

    loaded_ocsvm = OCSVMModel()
    loaded_ocsvm.load(save_path)
    loaded_preds = loaded_ocsvm.predict(X_scaled)
    np.testing.assert_array_equal(preds, loaded_preds)


def test_models_fit_predict_with_dataframe_and_numpy(sample_features):
    pipeline = FeaturePipeline()
    X_scaled_np = pipeline.fit_transform(sample_features) # Numpy array
    X_scaled_df = pd.DataFrame(X_scaled_np) # DataFrame

    iforest = IsolationForestModel(random_state=42).fit(X_scaled_df)
    preds_df = iforest.predict(X_scaled_df)
    preds_np = iforest.predict(X_scaled_np)
    np.testing.assert_array_equal(preds_df, preds_np)

    ocsvm = OCSVMModel().fit(X_scaled_df)
    preds_df_ocsvm = ocsvm.predict(X_scaled_df)
    preds_np_ocsvm = ocsvm.predict(X_scaled_np)
    np.testing.assert_array_equal(preds_df_ocsvm, preds_np_ocsvm)



def test_cascade_uses_both_models(sample_features, tmp_path):
    pipeline = FeaturePipeline()
    X_scaled = pipeline.fit_transform(sample_features)

    iforest_custom = IsolationForestModel(n_estimators=30, random_state=42)
    ocsvm_custom = OCSVMModel(nu=0.05)

    cascade = CascadeModel(
        iforest=iforest_custom,
        ocsvm=ocsvm_custom,
        threshold_percentile=80
    )

    # Verify both submodels are correctly assigned
    assert cascade.iforest_model is iforest_custom
    assert cascade.ocsvm_model is ocsvm_custom

    cascade.fit(X_scaled, sample_features['label'].values)

    detailed_df = cascade.predict_detailed(X_scaled)
    assert len(detailed_df) == len(sample_features)
    assert "stage1_score" in detailed_df.columns
    assert "stage2_score" in detailed_df.columns
    assert "anomaly_score" in detailed_df.columns
    assert "predicted_label" in detailed_df.columns

    # Test CascadeModel save/load persists both submodels
    model_dir = str(tmp_path / "cascade_saved")
    cascade.save(model_dir)
    assert os.path.exists(os.path.join(model_dir, "iforest.joblib"))
    assert os.path.exists(os.path.join(model_dir, "ocsvm.joblib"))
    assert os.path.exists(os.path.join(model_dir, "metadata.json"))

    loaded_cascade = CascadeModel()
    loaded_cascade.load(model_dir)
    loaded_preds = loaded_cascade.predict(X_scaled)
    np.testing.assert_array_equal(cascade.predict(X_scaled), loaded_preds)

