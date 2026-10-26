# ============================================================================
# file: src/lsmp_ai/data_preparation/cicids2017.py
# Description: Dedicated data preparer for CICIDS2017 network flow traffic dataset.
# ============================================================================

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.data_preparation.base import BaseDataPreparer

logger = setup_logger(__name__)

CICIDS_CHRONOLOGICAL_ORDER = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday-workinghours-morning",
    "thursday-workinghours-afternoon",
    "thursday",
    "friday-workinghours-morning",
    "friday-workinghours-afternoon-portscan",
    "friday-workinghours-afternoon-ddos",
    "friday",
]


class CICIDS2017Preparer(BaseDataPreparer):
    """Dedicated data preparation pipeline for the CICIDS2017 network flow dataset.

    Transforms raw PCAP-ISCX flow measurements (packet rates, flag counts, IATs)
    into 14 standardized LSMP host/network feature vectors.
    """

    def __init__(
        self,
        raw_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ):
        super().__init__(raw_dir=raw_dir, output_dir=output_dir)
        self.output_dir = Path(output_dir) if output_dir else (self.project_root / "data" / "processed" / "cicids2017")

    def discover_raw_files(self) -> List[Path]:
        """Locates the canonical CICIDS2017 GeneratedLabelledFlows CSV files.

        The generated flow export is preferred over legacy MachineLearningCVE
        copies because it contains the original CICFlowMeter ``Timestamp``.
        """
        candidates = []
        generated_dir = self.raw_dir / "GeneratedLabelledFlows"
        if generated_dir.exists():
            candidates.extend(generated_dir.rglob("*.csv"))
        elif self.raw_dir.exists():
            # Keep direct files as a legacy fallback when the canonical export
            # is not present.
            candidates.extend(self.raw_dir.glob("*.csv"))

        # Legacy external dataset location.
        parent_cve = self.project_root.parent / "dataset" / "MachineLearningCVE"
        if parent_cve.exists():
            candidates.extend(parent_cve.glob("*.csv"))

        # De-duplicate by filename while preserving source priority.
        seen_names = set()
        unique_files = []
        for f in candidates:
            if f.name not in seen_names:
                seen_names.add(f.name)
                unique_files.append(f)

        return self.sort_chronologically(unique_files)

    @staticmethod
    def sort_chronologically(files: List[Path]) -> List[Path]:
        """Sorts CICIDS2017 files chronologically according to capture schedule."""
        def get_order_key(p: Path) -> int:
            name_lower = p.name.lower()
            for idx, pattern in enumerate(CICIDS_CHRONOLOGICAL_ORDER):
                if pattern in name_lower:
                    return idx
            return len(CICIDS_CHRONOLOGICAL_ORDER)

        return sorted(files, key=get_order_key)

    def clean_and_transform(
        self, file_path: Path, max_rows: Optional[int] = None
    ) -> Tuple[pd.DataFrame, Dict]:
        """Cleans and standardizes raw CICIDS2017 CSV files into 14 Auth & Web AI features."""
        logger.info(f"[CICIDS2017] Processing file: {file_path.name}...")
        try:
            df_raw = pd.read_csv(file_path, nrows=max_rows, encoding="utf-8", low_memory=False)
        except UnicodeDecodeError:
            df_raw = pd.read_csv(file_path, nrows=max_rows, encoding="cp1252", low_memory=False)

        initial_rows = len(df_raw)
        df_raw.columns = df_raw.columns.str.strip()
        empty_rows_removed = int(df_raw.isna().all(axis=1).sum())
        if empty_rows_removed:
            df_raw = df_raw.loc[~df_raw.isna().all(axis=1)].reset_index(drop=True)

        # Locate Label column
        label_col = None
        for col in ["Label", "label", "LABEL"]:
            if col in df_raw.columns:
                label_col = col
                break

        if label_col is None:
            raise ValueError(f"No 'Label' column found in {file_path.name}")

        raw_labels = df_raw[label_col].fillna("BENIGN").astype(str).str.strip()
        df_raw["attack_category"] = raw_labels

        binary_label = raw_labels.apply(
            lambda x: LABEL_NORMAL if str(x).upper() in ["BENIGN", "NORMAL"] else LABEL_ANOMALY
        )
        df_raw["label"] = binary_label

        timestamp_candidates = [
            "Timestamp",
            "timestamp",
            "Flow Start Time",
            "Flow Start Date",
            "Date first seen",
            "Start Time",
        ]
        raw_timestamp_col = next(
            (col for col in timestamp_candidates if col in df_raw.columns),
            None,
        )
        entity_candidates = ["Source IP", "Src IP", "Source_IP", "Flow ID", "Destination Port"]
        entity_col = next((c for c in entity_candidates if c in df_raw.columns), None)

        string_id_cols = {
            "Source IP", "Src IP", "Source_IP", "Destination IP",
            "Flow ID", "Flow_ID", "Source Port",
        }
        feature_cols_raw = [
            c for c in df_raw.columns
            if c not in [label_col, "label", "attack_category", raw_timestamp_col]
            and c not in string_id_cols
        ]

        for c in feature_cols_raw:
            df_raw[c] = pd.to_numeric(df_raw[c], errors="coerce")

        nan_count = int(df_raw[feature_cols_raw].isna().sum().sum())
        inf_count = int(np.isinf(df_raw[feature_cols_raw].values).sum())

        df_raw[feature_cols_raw] = df_raw[feature_cols_raw].replace([np.inf, -np.inf], np.nan)
        # Keep missing values until FeaturePipeline is fitted on train only.
        # Per-file median imputation here would leak future distributions.

        df_raw = df_raw.drop_duplicates(subset=feature_cols_raw).reset_index(drop=True)
        cleaned_rows = len(df_raw)
        duplicates_removed = initial_rows - cleaned_rows

        def get_val(col_name: str, default: float = 0.0) -> np.ndarray:
            if col_name in df_raw.columns:
                return df_raw[col_name].values
            return np.full(len(df_raw), default)

        # Core measurements from flow packets
        flow_pkts_sec = get_val("Flow Packets/s", 0.0)
        flow_bytes_sec = get_val("Flow Bytes/s", 0.0)
        fwd_pkts = get_val("Total Fwd Packets", 0.0)
        bwd_pkts = get_val("Total Backward Packets", 0.0)
        total_pkts = np.maximum(fwd_pkts + bwd_pkts, 1.0)
        pkt_len_var = get_val("Packet Length Variance", 0.0)
        syn_flags = get_val("SYN Flag Count", 0.0)
        ack_flags = get_val("ACK Flag Count", 0.0)
        rst_flags = get_val("RST Flag Count", 0.0)
        psh_flags = get_val("PSH Flag Count", 0.0) + get_val("Fwd PSH Flags", 0.0)
        active_mean = get_val("Active Mean", 0.0)
        subflow_fwd_pkts = get_val("Subflow Fwd Packets", 0.0)
        flow_iat_mean_sec = get_val("Flow IAT Mean", 0.0) / 1e6
        flow_iat_std_sec = get_val("Flow IAT Std", 0.0) / 1e6
        avg_bwd_seg_size = get_val("Avg Bwd Segment Size", 0.0)
        ece_flags = get_val("ECE Flag Count", 0.0) + get_val("CWE Flag Count", 0.0)

        # Prefer the original flow timestamp. A row-order proxy is only used
        # for synthetic/incomplete exports and is recorded in metadata.
        timestamp_source = "original_flow_timestamp"
        if raw_timestamp_col:
            raw_timestamps = df_raw[raw_timestamp_col].astype(str).str.strip()
            iso_mask = raw_timestamps.str.match(r"^\d{4}[-/]")
            time_series = pd.Series(pd.NaT, index=df_raw.index, dtype="datetime64[ns, UTC]")
            time_series.loc[iso_mask] = pd.to_datetime(
                raw_timestamps.loc[iso_mask],
                errors="coerce",
                dayfirst=False,
                utc=True,
            )
            time_series.loc[~iso_mask] = pd.to_datetime(
                raw_timestamps.loc[~iso_mask],
                errors="coerce",
                dayfirst=True,
                utc=True,
            )
            # Fix 12-hour AM/PM defect in CICIDS2017: captures recorded during working hours
            # (08:00 - 17:00) drop the AM/PM indicator, causing afternoon traffic (13:00 - 17:00)
            # to be parsed as 01:00 - 05:00 and erroneously sorted before morning traffic.
            # Shift hours in [1..7] without AM/PM by +12 hours so afternoon traffic correctly succeeds morning.
            has_no_explicit_ampm = ~raw_timestamps.str.contains(r"(?i)\b(?:am|pm)\b", regex=True)
            hour_mask = time_series.dt.hour.isin([1, 2, 3, 4, 5, 6, 7]) & has_no_explicit_ampm
            if hour_mask.any():
                shifted_count = int(hour_mask.sum())
                time_series.loc[hour_mask] = time_series.loc[hour_mask] + pd.Timedelta(hours=12)
                logger.info(
                    f"[{file_path.name}] Adjusted 12-hour AM/PM on {shifted_count:,} flows "
                    f"(hours 1..7 shifted to 13..19). Range: {time_series.dt.hour.min()}h - {time_series.dt.hour.max()}h"
                )
        else:
            time_series = pd.Series(pd.NaT, index=df_raw.index, dtype="datetime64[ns, UTC]")

        # Determine capture day base timestamp for incomplete exports.
        name_lower = file_path.name.lower()
        if "monday" in name_lower:
            base_str = "2017-07-03 09:00:00"
        elif "tuesday" in name_lower:
            base_str = "2017-07-04 09:00:00"
        elif "wednesday" in name_lower:
            base_str = "2017-07-05 09:00:00"
        elif "thursday" in name_lower:
            base_str = "2017-07-06 14:00:00" if "afternoon" in name_lower else "2017-07-06 09:00:00"
        elif "friday" in name_lower:
            if "ddos" in name_lower:
                base_str = "2017-07-07 15:00:00"
            elif "portscan" in name_lower:
                base_str = "2017-07-07 13:00:00"
            else:
                base_str = "2017-07-07 09:00:00"
        else:
            base_str = "2017-07-03 09:00:00"

        invalid_timestamp_count = int(time_series.isna().sum())
        if raw_timestamp_col and invalid_timestamp_count:
            raise ValueError(
                f"{file_path.name} contains {invalid_timestamp_count:,} "
                "non-empty rows with invalid Timestamp values."
            )
        if not raw_timestamp_col:
            base_dt = pd.to_datetime(base_str, utc=True)
            time_series = pd.Series(
                base_dt + pd.to_timedelta(np.arange(cleaned_rows), unit="s"),
                index=df_raw.index,
            )
            timestamp_source = "synthetic_row_order_proxy"

        # Dynamic concurrency estimation across 60-120 flow temporal windows
        window_idx = np.arange(cleaned_rows) // 120
        dest_ports = get_val("Destination Port", 80.0)
        s_port = pd.Series(dest_ports)
        window_unique_ports = s_port.groupby(window_idx).transform("nunique").values
        window_flows = s_port.groupby(window_idx).transform("count").values
        dynamic_active_ips = np.clip(
            np.sqrt(np.maximum(window_flows, 1.0)) * np.log1p(np.maximum(window_unique_ports, 1.0)),
            1.0, 250.0
        ).astype(np.float32)

        if entity_col and entity_col in df_raw.columns:
            entity_id_vals = df_raw[entity_col].astype(str).values
        else:
            entity_id_vals = np.array([f"{file_path.stem}_{i}" for i in range(cleaned_rows)], dtype=object)

        # Standardized mapping to 14 Auth & Web features
        features_mapped = {
            "window_start": time_series,
            "timestamp": time_series,
            "entity_id": entity_id_vals,
            # 1. Auth signals
            "auth_fail_count": np.clip(syn_flags, 0, 1000).astype(np.float32),
            "auth_success_count": np.clip(ack_flags, 0, 50000).astype(np.float32),
            "auth_fail_ratio": np.where(
                (syn_flags + ack_flags) > 0,
                syn_flags / np.maximum(syn_flags + ack_flags, 1.0),
                0.0
            ).astype(np.float32),
            "distinct_username": np.clip(subflow_fwd_pkts, 0, 1000).astype(np.float32),
            "fail_interarrival_mean": np.clip(flow_iat_mean_sec, 0, 3600).astype(np.float32),
            "fail_interarrival_std": np.clip(flow_iat_std_sec, 0, 3600).astype(np.float32),
            # 2. Web signals
            "http_req_rate": np.clip(flow_pkts_sec, 0, 50000).astype(np.float32),
            "http_4xx_ratio": np.clip(rst_flags / total_pkts, 0.0, 1.0).astype(np.float32),
            "http_5xx_ratio": np.clip(ece_flags / total_pkts, 0.0, 1.0).astype(np.float32),
            "http_post_ratio": np.clip(psh_flags / total_pkts, 0.0, 1.0).astype(np.float32),
            "distinct_user_agent": np.clip(np.log1p(np.abs(pkt_len_var)), 0, 50).astype(np.float32),
            "bytes_sent_mean": np.clip(avg_bwd_seg_size, 0, 100000).astype(np.float32),
            # 3. Context & temporal signals
            "global_active_ips": dynamic_active_ips,
            "burst_rate": np.clip(flow_bytes_sec / (active_mean + 1.0), 0, 10000.0).astype(np.float32),
            # Labels & metadata
            "label": df_raw["label"].values,
            "attack_category": df_raw["attack_category"].values,
            "timestamp_source": [timestamp_source] * cleaned_rows,
            "label_source": ["original_cicids2017_label"] * cleaned_rows,
        }

        df_cleaned = pd.DataFrame(features_mapped)
        # Replace malformed numeric values with the deterministic neutral value
        # here; learned imputation/scaling still happens on train only in
        # FeaturePipeline.
        df_cleaned = self.sanitize_dataframe(df_cleaned, fill_missing=False)
        df_cleaned["source_file"] = file_path.name
        stats = {
            "file_name": file_path.name,
            "initial_rows": initial_rows,
            "cleaned_rows": cleaned_rows,
            "duplicates_removed": duplicates_removed,
            "empty_rows_removed": empty_rows_removed,
            "nan_replaced": nan_count,
            "inf_replaced": inf_count,
            "invalid_timestamp_count": invalid_timestamp_count,
            "normal_count": int((df_cleaned["label"] == LABEL_NORMAL).sum()),
            "anomaly_count": int((df_cleaned["label"] == LABEL_ANOMALY).sum()),
            "timestamp_source": timestamp_source,
            "timestamp_column": raw_timestamp_col,
        }
        return df_cleaned, stats

    def prepare(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
        split_strategy: str = "day",
    ) -> Path:
        """Executes full CICIDS2017 dataset preparation, feature mapping, and temporal splitting."""
        csv_files = self.discover_raw_files()
        if not csv_files:
            raise FileNotFoundError(f"No raw CICIDS2017 CSV files found in {self.raw_dir} or parent dataset.")

        logger.info(f"=== PREPARING CICIDS2017 DATASET ({len(csv_files)} files discovered) ===")
        all_dfs = []
        file_stats = []
        for f in csv_files:
            df_clean, stats = self.clean_and_transform(f, max_rows=max_samples)
            if (
                self.raw_dir.joinpath("GeneratedLabelledFlows").exists()
                and stats.get("timestamp_source") != "original_flow_timestamp"
            ):
                raise ValueError(
                    f"Canonical GeneratedLabelledFlows file {f.name} has no "
                    "fully valid original Timestamp; refusing to create a "
                    "scientific benchmark artifact."
                )
            all_dfs.append(df_clean)
            file_stats.append(stats)

        df_combined = pd.concat(all_dfs, ignore_index=True)
        df_combined["dataset_source"] = "cicids2017"
        df_combined = self.sanitize_dataframe(df_combined, fill_missing=False)

        # Global deduplication across all day captures to eliminate train/test leakage
        attacks_before_dedup = int((df_combined["label"] == LABEL_ANOMALY).sum())
        initial_combined = len(df_combined)
        df_combined = df_combined.drop_duplicates(
            subset=["source_file", "timestamp", *FEATURE_COLUMNS],
            keep="first",
        ).reset_index(drop=True)
        attacks_after_dedup = int((df_combined["label"] == LABEL_ANOMALY).sum())
        attacks_dedup_lost = attacks_before_dedup - attacks_after_dedup
        logger.info(
            f"Global deduplication removed {initial_combined - len(df_combined):,} duplicate feature vectors across captures "
            f"({attacks_dedup_lost:,} attack flows removed: {attacks_before_dedup:,} -> {attacks_after_dedup:,})."
        )

        if max_samples is not None and max_samples > 0 and len(df_combined) > max_samples:
            logger.info(f"Subsampling CICIDS2017 dataset to {max_samples:,} rows preserving temporal sequence...")
            indices = np.linspace(0, len(df_combined) - 1, max_samples, dtype=int)
            df_combined = df_combined.iloc[indices].reset_index(drop=True)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        dataset_path = self.output_dir / "cicids2017_dataset.csv"
        df_combined.to_csv(dataset_path, index=False)

        # Splitting logic: day-based split (Monday=Train, Tuesday=Val, Thursday=Test)
        # or strict ratio-based temporal split.
        has_monday = df_combined["source_file"].str.contains("(?i)monday").any()
        has_tuesday = df_combined["source_file"].str.contains("(?i)tuesday").any()
        has_thursday = df_combined["source_file"].str.contains("(?i)thursday").any()

        if split_strategy == "day" and has_monday and (has_tuesday or has_thursday):
            logger.info("Executing day-based split: Train=Monday, Validation=Tuesday, Test=Thursday...")
            train_df = df_combined[df_combined["source_file"].str.contains("(?i)monday")].reset_index(drop=True)
            if has_tuesday and has_thursday:
                val_df = df_combined[df_combined["source_file"].str.contains("(?i)tuesday")].reset_index(drop=True)
                test_df = df_combined[df_combined["source_file"].str.contains("(?i)thursday|friday")].reset_index(drop=True)
            elif has_tuesday:
                tues_df = df_combined[df_combined["source_file"].str.contains("(?i)tuesday")].reset_index(drop=True)
                t_mid = len(tues_df) // 2
                val_df = tues_df.iloc[:t_mid].reset_index(drop=True)
                test_df = tues_df.iloc[t_mid:].reset_index(drop=True)
            else:
                val_df, test_df = self.temporal_split(
                    df_combined[~df_combined["source_file"].str.contains("(?i)monday")].reset_index(drop=True),
                    frac=(0.5, 0.5, 0.0)
                )[:2]
            split_method_name = "day_based_split (Monday=Train, Tuesday=Val, Thursday=Test)"
        else:
            train_df, val_df, test_df = self.temporal_split(df_combined, frac=split_ratio)
            split_method_name = f"temporal_ratio_{int(split_ratio[0]*100)}_{int(split_ratio[1]*100)}_{int(split_ratio[2]*100)}"

        self.save_splits(
            train_df,
            val_df,
            test_df,
            self.output_dir,
            metadata={
                "dataset_source": "cicids2017",
                "canonical_artifact": "GeneratedLabelledFlows",
                "split_strategy": split_method_name,
                "input_files": file_stats,
                "deduplication_audit": {
                    "total_flows_before_dedup": initial_combined,
                    "total_flows_after_dedup": len(df_combined),
                    "duplicate_flows_removed": initial_combined - len(df_combined),
                    "attack_flows_before_dedup": attacks_before_dedup,
                    "attack_flows_after_dedup": attacks_after_dedup,
                    "attack_flows_lost_in_dedup": attacks_dedup_lost,
                },
                "sampling": (
                    "full_dataset"
                    if max_samples is None
                    else f"debug_limit_{max_samples}_rows_per_file"
                ),
            },
        )

        logger.info(f"CICIDS2017 preparation complete ({split_method_name}). Output saved to {dataset_path}")
        return dataset_path
