# ============================================================================
# file: scripts/prepare_data.py
# Description: Modular dataset preparation orchestrator for LSMP AI Module.
#              Provides unified interface for CICIDS2017 and Loghub datasets.
# ============================================================================

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import pandas as pd
import numpy as np

# Resolve BASE_DIR (project root)
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.data_preparation.cicids2017 import CICIDS2017Preparer
from lsmp_ai.data_preparation.loghub import LoghubPreparer
from lsmp_ai.data_preparation.unified import UnifiedDatasetPreparer

logger = setup_logger(__name__)


# ===== BACKWARD COMPATIBLE API FUNCTIONS =====

def find_raw_data_dir() -> Path:
    """Locates the primary raw dataset directory. Backward compatible helper."""
    preparer = CICIDS2017Preparer()
    files = preparer.discover_raw_files()
    if files:
        return files[0].parent

    raw_dir = BASE_DIR / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    return raw_dir


def clean_and_map_cicids_file(file_path: Path) -> Tuple[pd.DataFrame, Dict]:
    """Cleans and standardizes a CICIDS2017 CSV file. Backward compatible helper."""
    preparer = CICIDS2017Preparer()
    df_clean, stats = preparer.clean_and_transform(file_path)
    return preparer.sanitize_dataframe(df_clean), stats


def map_cicids_to_lsmp_features(file_path: Path) -> pd.DataFrame:
    """Extracts mapped features DataFrame from a CICIDS CSV file. Backward compatible helper."""
    preparer = CICIDS2017Preparer()
    df_clean, _ = preparer.clean_and_transform(file_path)
    return preparer.sanitize_dataframe(df_clean)


def prepare_loghub_syslog_file(file_path: Path) -> Tuple[pd.DataFrame, Dict]:
    """Parses a Loghub OpenSSH syslog file into features. Backward compatible helper."""
    preparer = LoghubPreparer()
    df_clean, stats = preparer.clean_and_transform(file_path)
    return preparer.sanitize_dataframe(df_clean), stats


def temporal_split(
    df: pd.DataFrame,
    frac: Tuple[float, float, float] = (0.6, 0.2, 0.2),
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Splits dataset temporally into Train, Val, and Test. Backward compatible helper."""
    preparer = CICIDS2017Preparer()
    return preparer.temporal_split(df, frac=frac)


def prepare_dataset(
    max_samples: Optional[int] = None,
    split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
    source: str = "all",
    split_strategy: str = "day",
) -> Path:
    """Prepares datasets with SME-kit 60/20/20 temporal split or day-based split.

    Args:
        max_samples: Optional row limit for fast debugging/testing.
        split_ratio: Train / Validation / Test temporal split ratio.
        source: 'all', 'cicids2017', or 'loghub'.
        split_strategy: 'day' (Monday=Train, Tuesday=Val, Thursday=Test) or 'ratio'.
    """
    source_lower = source.lower().strip()
    if source_lower in ("cicids", "cicids2017"):
        preparer = CICIDS2017Preparer()
        return preparer.prepare(max_samples=max_samples, split_ratio=split_ratio, split_strategy=split_strategy)
    elif source_lower in ("loghub", "syslog"):
        preparer = LoghubPreparer()
        return preparer.prepare(max_samples=max_samples, split_ratio=split_ratio)
    else:
        orchestrator = UnifiedDatasetPreparer()
        return orchestrator.prepare_all(max_samples=max_samples, split_ratio=split_ratio)


def prepare_full_cicids2017_dataset(max_samples: Optional[int] = None) -> Path:
    """Alias for backward compatibility."""
    return prepare_dataset(max_samples=max_samples, source="cicids2017")


def main():
    parser = argparse.ArgumentParser(description="LSMP Dataset Preparation & Feature Extraction")
    parser.add_argument(
        "--source", "-s", type=str, default="all",
        choices=["all", "cicids2017", "loghub"],
        help="Dataset source: CICIDS2017, Loghub, or both.",
    )
    parser.add_argument(
        "--max-samples", "-m", type=int, default=None,
        help="Maximum sample count limit (default: None - full dataset)"
    )
    parser.add_argument(
        "--split-strategy", type=str, default="day", choices=["day", "ratio"],
        help="Splitting strategy for CICIDS2017: 'day' (default) or 'ratio' (60/20/20)"
    )

    args = parser.parse_args()

    prepare_dataset(max_samples=args.max_samples, source=args.source, split_strategy=args.split_strategy)


if __name__ == "__main__":
    main()
