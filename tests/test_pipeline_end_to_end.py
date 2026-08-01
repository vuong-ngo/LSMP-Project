import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from lsmp_ai.common.config_loader import DataConfig, ModelConfig
from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_ANOMALY, LABEL_NORMAL
from lsmp_ai.pipeline.evaluate_pipeline import EvaluatePipeline
from lsmp_ai.pipeline.train_pipeline import TrainPipeline


def _create_mini_dataset(tmp_path: Path) -> str:
    np.random.seed(42)
    n = 100
    rows = []
    for i in range(n):
        row = {
            "window_start": f"2026-07-01 {i:02d}:00:00",
            "src_ip": f"192.168.1.{i % 10 + 1}",
            "feature_version": "v1",
            "label": LABEL_ANOMALY if i < 20 else LABEL_NORMAL,
        }
        for col in FEATURE_COLUMNS:
            if col == "hour_of_day":
                row[col] = i % 24
            else:
                row[col] = float(np.random.rand())
        rows.append(row)

    df = pd.DataFrame(rows)
    path = tmp_path / "mini_dataset.csv"
    df.to_csv(path, index=False)
    return str(path)


def test_train_pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_path = _create_mini_dataset(tmp_path)

        data_config = DataConfig(train_ratio=0.7, test_ratio=0.3)
        model_config = ModelConfig(
            model_store_path=str(tmp_path / "models"),
        )

        pipeline = TrainPipeline(data_config, model_config)
        version = pipeline.run(dataset_path=dataset_path, do_grid_search=False)
        assert version is not None
        assert (tmp_path / "models" / version).exists()
        assert (tmp_path / "models" / version / "feature_pipeline.joblib").exists()

        # Verify One-Class split rule: Train = 100% Pure Normal (55 samples), Test = 25 Normal + 20 Anomaly (45 samples)
        summary = pipeline.last_run_summary
        assert summary["train_samples"] == 55
        assert summary["test_samples"] == 45
        assert summary["normal_count"] == 80
        assert summary["anomaly_count"] == 20
        assert "metrics" in summary
        assert summary["metrics"]["accuracy"] >= 0.0




def test_evaluate_pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dataset_path = _create_mini_dataset(tmp_path)

        data_config = DataConfig(train_ratio=0.7, test_ratio=0.3)
        model_config = ModelConfig()

        pipeline = EvaluatePipeline(data_config, model_config)
        output_path = tmp_path / "results.csv"
        results = pipeline.run(dataset_path=dataset_path, output_path=str(output_path))

        assert len(results) == 3
        assert output_path.exists()
