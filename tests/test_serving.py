import os
import pytest
import pandas as pd
import numpy as np
from unittest.mock import MagicMock, patch

from lsmp_ai.serving.inference_service import InferenceService
from lsmp_ai.serving.scheduler import InferenceScheduler
from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.models.cascade_model import CascadeModel


@pytest.fixture
def mock_db_client():
    client = MagicMock()
    return client


@pytest.fixture
def mock_result_writer():
    writer = MagicMock()
    writer.write_predictions.return_value = 5
    return writer


@pytest.fixture
def mock_model_registry():
    registry = MagicMock()
    cascade = CascadeModel()
    X = np.random.randn(10, len(FEATURE_COLUMNS))
    cascade.fit(X)
    registry.load_latest.return_value = cascade
    registry.load_version.return_value = cascade
    return registry


@pytest.fixture
def sample_feature_df():
    data = {col: np.random.randn(5) for col in FEATURE_COLUMNS}
    data["src_ip"] = [f"192.168.1.{i+1}" for i in range(5)]
    data["window_start"] = pd.date_range("2026-07-23 10:00:00", periods=5, freq="1min")
    return pd.DataFrame(data)


def test_inference_service_load_and_infer(mock_db_client, mock_result_writer, mock_model_registry, sample_feature_df):
    service = InferenceService(
        db_client=mock_db_client,
        result_writer=mock_result_writer,
        model_registry=mock_model_registry,
    )
    
    # 1. Test infer before model loaded raises RuntimeError
    with pytest.raises(RuntimeError):
        service.infer_on_features(sample_feature_df)
        
    # 2. Test model loading
    service.load_model()
    assert service._model is not None
    mock_model_registry.load_latest.assert_called_once()
    
    # 3. Test infer_on_features
    results_df = service.infer_on_features(sample_feature_df)
    assert len(results_df) == 5
    assert "anomaly_score" in results_df.columns
    assert "risk_score" in results_df.columns
    assert "risk_class" in results_df.columns


def test_inference_service_run_inference(mock_db_client, mock_result_writer, mock_model_registry, sample_feature_df):
    mock_db_client.fetch_feature_vectors.return_value = sample_feature_df
    
    service = InferenceService(
        db_client=mock_db_client,
        result_writer=mock_result_writer,
        model_registry=mock_model_registry,
    )
    service.load_model()
    
    written_count = service.run_inference(limit=50)
    mock_db_client.fetch_feature_vectors.assert_called_with(limit=50)
    mock_result_writer.write_predictions.assert_called_once()
    assert written_count == 5


def test_inference_service_missing_features_raises_error(mock_db_client, mock_result_writer, mock_model_registry):
    service = InferenceService(
        db_client=mock_db_client,
        result_writer=mock_result_writer,
        model_registry=mock_model_registry,
    )
    service.load_model()
    
    bad_df = pd.DataFrame({"src_ip": ["1.1.1.1"]})
    with pytest.raises(ValueError, match="Missing feature columns"):
        service.infer_on_features(bad_df)


def test_inference_scheduler_start_stop():
    mock_service = MagicMock()
    mock_service.run_inference.return_value = 3
    
    scheduler = InferenceScheduler(
        inference_service=mock_service,
        poll_interval_seconds=0.1,
        batch_size=10
    )
    
    with patch("time.sleep", side_effect=InterruptedError("Stop loop")):
        with pytest.raises(InterruptedError):
            scheduler.start()
            
    mock_service.run_inference.assert_called_with(limit=10)


def test_fastapi_writer_service_endpoints():
    try:
        from fastapi.testclient import TestClient
        from lsmp_ai.serving.lsmp_writer_service import app
    except ImportError:
        pytest.skip("fastapi or httpx is not installed in the environment.")
    
    client = TestClient(app)
    
    # 1. Health check
    response = client.get("/health")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "healthy"
    
    # 2. Process manual trigger endpoint
    payload = {
        "start_time": "2026-07-23T10:00:00",
        "end_time": "2026-07-23T10:05:00"
    }
    with patch("lsmp_ai.serving.lsmp_writer_service.run_serve_pipeline"):
        process_resp = client.post("/process", json=payload)
        assert process_resp.status_code == 200
        assert process_resp.json()["status"] == "queued"
