# ============================================================================
# file: src/lsmp_ai/scripts/prepare_cicids2017.py
# Description: Data cleaning, feature extraction, and dataset preparation for CICIDS2017.
# ============================================================================

import os
import sys
import glob
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime

# Resolve BASE_DIR (project root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger

logger = setup_logger(__name__)


def find_raw_data_dir() -> Path:
    raw_dir = BASE_DIR / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    dummy_csv = raw_dir / "sample_raw.csv"
    if not dummy_csv.exists() and not list(raw_dir.glob("*.csv")):
        df_dummy = pd.DataFrame(np.random.randn(50, len(FEATURE_COLUMNS)), columns=FEATURE_COLUMNS)
        df_dummy["Label"] = "BENIGN"
        df_dummy.to_csv(dummy_csv, index=False)
    return raw_dir


def map_cicids_to_lsmp_features(csv_file: Path) -> pd.DataFrame:
    df_clean, _ = clean_and_map_cicids_file(csv_file)
    return df_clean


def find_raw_cicids_files() -> list[Path]:
    raw_dir = find_raw_data_dir()
    csv_files = sorted(list(raw_dir.glob("*.csv")))
    logger.info(f"Found {len(csv_files)} raw CSV files in {raw_dir}:")
    for f in csv_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        logger.info(f"  - {f.name} ({size_mb:.2f} MB)")
    return csv_files


def clean_and_map_cicids_file(file_path: Path) -> tuple[pd.DataFrame, dict]:
    logger.info(f"Processing: {file_path.name}...")
    try:
        df_raw = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df_raw = pd.read_csv(file_path, encoding='cp1252', low_memory=False)

    initial_rows = len(df_raw)
    df_raw.columns = df_raw.columns.str.strip()

    label_col = None
    for col in ["Label", "label", "LABEL"]:
        if col in df_raw.columns:
            label_col = col
            break
            
    if label_col is None:
        raise ValueError(f"No 'Label' column found in {file_path.name}")

    raw_labels = df_raw[label_col].astype(str).str.strip()
    df_raw["attack_category"] = raw_labels
    
    binary_label = raw_labels.apply(
        lambda x: LABEL_NORMAL if x.upper() in ["BENIGN", "NORMAL"] else LABEL_ANOMALY
    )
    df_raw["label"] = binary_label

    feature_cols_raw = [c for c in df_raw.columns if c not in [label_col, "label", "attack_category"]]
    
    for c in feature_cols_raw:
        df_raw[c] = pd.to_numeric(df_raw[c], errors='coerce')

    nan_count = df_raw[feature_cols_raw].isna().sum().sum()
    inf_count = np.isinf(df_raw[feature_cols_raw].values).sum()

    df_raw[feature_cols_raw] = df_raw[feature_cols_raw].replace([np.inf, -np.inf], np.nan)
    for c in feature_cols_raw:
        median_val = df_raw[c].median()
        fill_val = median_val if pd.notna(median_val) else 0.0
        df_raw[c] = df_raw[c].fillna(fill_val)

    df_raw = df_raw.drop_duplicates(subset=feature_cols_raw)
    cleaned_rows = len(df_raw)
    duplicates_removed = initial_rows - cleaned_rows

    def get_val(col_name: str, default: float = 0.0) -> np.ndarray:
        if col_name in df_raw.columns:
            return df_raw[col_name].values
        return np.full(len(df_raw), default)

    flow_dur_sec = get_val("Flow Duration", 1.0) / 1e6
    flow_dur_sec = np.where(flow_dur_sec <= 0, 1e-3, flow_dur_sec)

    flow_pkts_sec = get_val("Flow Packets/s", 0.0)
    flow_bytes_sec = get_val("Flow Bytes/s", 0.0)
    fwd_pkts = get_val("Total Fwd Packets", 0.0)
    bwd_pkts = get_val("Total Backward Packets", 0.0)
    pkt_len_std = get_val("Packet Length Std", 0.0)
    pkt_len_var = get_val("Packet Length Variance", 0.0)
    syn_flags = get_val("SYN Flag Count", 0.0)
    rst_flags = get_val("RST Flag Count", 0.0)
    down_up_ratio = get_val("Down/Up Ratio", 0.0)
    fwd_seg_size_avg = get_val("Avg Fwd Segment Size", 0.0)
    psh_flags = get_val("PSH Flag Count", 0.0) + get_val("Fwd PSH Flags", 0.0)
    active_mean = get_val("Active Mean", 0.0)
    subflow_fwd_pkts = get_val("Subflow Fwd Packets", 0.0)

    features_mapped = {
        "login_fail_count": np.clip(syn_flags, 0, 1000),
        "unique_failed_ip_count": np.clip(syn_flags * 0.5, 0, 100),
        "fail_success_ratio": np.clip(down_up_ratio, 0, 10),
        "ip_entropy": np.log1p(np.abs(pkt_len_std)),
        "hour_of_day": np.full(len(df_raw), 12.0),
        "request_rate": np.clip(flow_pkts_sec, 0, 50000),
        "status_4xx_rate": np.clip(rst_flags, 0, 1.0),
        "url_frequency": np.log1p(np.abs(fwd_seg_size_avg)),
        "user_agent_entropy": np.log1p(np.abs(pkt_len_var)),
        "method_distribution": np.clip(psh_flags, 0, 1.0),
        "time_window_count": flow_dur_sec,
        "burst_rate": np.clip(flow_bytes_sec / (active_mean + 1.0), 0, 100000),
        "sliding_window_count": np.clip(fwd_pkts + bwd_pkts, 0, 100000),
        "ip_switch_frequency": np.clip(subflow_fwd_pkts, 0, 1000),
        "label": df_raw["label"].values,
        "attack_category": df_raw["attack_category"].values
    }

    df_cleaned = pd.DataFrame(features_mapped)

    stats = {
        "file_name": file_path.name,
        "initial_rows": initial_rows,
        "cleaned_rows": cleaned_rows,
        "duplicates_removed": duplicates_removed,
        "nan_replaced": int(nan_count),
        "inf_replaced": int(inf_count),
        "normal_count": int((df_cleaned["label"] == LABEL_NORMAL).sum()),
        "anomaly_count": int((df_cleaned["label"] == LABEL_ANOMALY).sum()),
        "attack_breakdown": df_cleaned["attack_category"].value_counts().to_dict()
    }
    
    return df_cleaned, stats


def prepare_full_cicids2017_dataset(max_samples_per_class: int = 100000) -> Path:
    csv_files = find_raw_cicids_files()
    if not csv_files:
        raise FileNotFoundError("No CSV files found in data/raw directory.")

    all_dfs = []
    all_stats = []

    logger.info("=== STARTING CICIDS2017 DATASET CLEANING PIPELINE ===")
    
    for f in csv_files:
        df_clean, stats = clean_and_map_cicids_file(f)
        all_dfs.append(df_clean)
        all_stats.append(stats)

    df_combined = pd.concat(all_dfs, ignore_index=True)
    total_initial = sum(s["initial_rows"] for s in all_stats)
    total_cleaned = len(df_combined)

    logger.info(f"Successfully combined all files: {total_cleaned} clean records (from {total_initial} raw rows).")

    df_normal = df_combined[df_combined["label"] == LABEL_NORMAL]
    df_anomaly = df_combined[df_combined["label"] == LABEL_ANOMALY]

    if len(df_normal) > max_samples_per_class:
        df_normal = df_normal.sample(n=max_samples_per_class, random_state=42)
    if len(df_anomaly) > max_samples_per_class:
        df_anomaly = df_anomaly.sample(n=max_samples_per_class, random_state=42)

    df_final = pd.concat([df_normal, df_anomaly], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)

    proc_dir = BASE_DIR / "data" / "processed"
    proc_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = proc_dir / "dataset.csv"
    df_final.to_csv(dataset_path, index=False)
    logger.info(f"Saved primary training dataset to {dataset_path} ({len(df_final):,} records)")

    cicids_dir = proc_dir / "cicids2017"
    cicids_dir.mkdir(parents=True, exist_ok=True)
    full_dataset_path = cicids_dir / "cleaned_dataset_full.csv"
    df_combined.to_csv(full_dataset_path, index=False)

    split_dir = BASE_DIR / "data" / "train_test_split"
    split_dir.mkdir(parents=True, exist_ok=True)

    from sklearn.model_selection import train_test_split
    df_normal_train, df_normal_test = train_test_split(
        df_normal, test_size=0.3, random_state=42
    )

    train_df = df_normal_train.reset_index(drop=True)
    test_df = pd.concat([df_normal_test, df_anomaly], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)

    train_df.to_csv(split_dir / "train.csv", index=False)
    test_df.to_csv(split_dir / "test.csv", index=False)
    logger.info(f"Saved PURE BENIGN train split ({len(train_df):,} rows) and test split ({len(test_df):,} rows) to {split_dir}")

    return dataset_path


if __name__ == "__main__":
    prepare_full_cicids2017_dataset()
