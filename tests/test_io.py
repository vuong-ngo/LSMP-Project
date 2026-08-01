from datetime import datetime

import pandas as pd
import pytest

from lsmp_ai.io.data_loader import DataLoader
from lsmp_ai.io.db_client import DatabaseClient


def test_data_loader_csv(tmp_path):
    df = pd.DataFrame({
        "window_start": ["2026-07-01"],
        "src_ip": ["192.168.1.1"],
        "feature_version": ["v1"],
        "login_fail_count": [5.0],
        "unique_failed_ip_count": [2.0],
        "fail_success_ratio": [10.0],
        "ip_entropy": [1.0],
        "hour_of_day": [14],
        "request_rate": [100.0],
        "status_4xx_rate": [0.5],
        "url_frequency": [0.8],
        "user_agent_entropy": [1.5],
        "method_distribution": [1.0],
        "time_window_count": [50.0],
        "burst_rate": [5.0],
        "sliding_window_count": [30.0],
        "ip_switch_frequency": [0.5],
        "label": ["Normal"],
    })
    path = tmp_path / "test.csv"
    df.to_csv(path, index=False)

    loader = DataLoader()
    loaded = loader.load_from_csv(str(path))
    assert len(loaded) == 1

    X, y = loader.split_features_target(loaded)
    assert X.shape[1] == 14
    assert y is not None
    assert y.iloc[0] == "Normal"
