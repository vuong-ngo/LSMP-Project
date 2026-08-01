import pytest
from pathlib import Path
import pandas as pd
import numpy as np

prepare_cicids2017 = pytest.importorskip("scripts.prepare_cicids2017")
find_raw_data_dir = prepare_cicids2017.find_raw_data_dir
map_cicids_to_lsmp_features = prepare_cicids2017.map_cicids_to_lsmp_features
from lsmp_ai.common.constants import FEATURE_COLUMNS


def test_find_raw_data_dir():
    raw_dir = find_raw_data_dir()
    assert raw_dir.exists()
    assert any(raw_dir.glob("*.csv"))


def test_map_cicids_to_lsmp_features():
    raw_dir = find_raw_data_dir()
    csv_file = next(raw_dir.glob("*.csv"))

    df_mapped = map_cicids_to_lsmp_features(csv_file)
    assert len(df_mapped) > 0
    for col in FEATURE_COLUMNS:
        assert col in df_mapped.columns
    assert "label" in df_mapped.columns
    # Verify no infinity values remain
    X = df_mapped[FEATURE_COLUMNS].values
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()
