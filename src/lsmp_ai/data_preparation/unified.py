# ============================================================================
# file: src/lsmp_ai/data_preparation/unified.py
# Description: Unified multi-source dataset orchestrator coordinating CICIDS2017 & Loghub.
# ============================================================================

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.data_preparation.base import BaseDataPreparer
from lsmp_ai.data_preparation.cicids2017 import CICIDS2017Preparer
from lsmp_ai.data_preparation.loghub import LoghubPreparer

logger = setup_logger(__name__)


class UnifiedDatasetPreparer:
    """Master orchestrator for preparing multi-source datasets for LSMP AI Engine.

    Coordinates individual source preparers:
        - CICIDS2017Preparer (Network Flow PCAP)
        - LoghubPreparer (Syslog & Host OpenSSH)
    Merges their extracted features into unified, standardized datasets.
    """

    def __init__(
        self,
        raw_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ):
        self.project_root = Path(__file__).resolve().parent.parent.parent.parent
        self.raw_dir = Path(raw_dir) if raw_dir else (self.project_root / "data" / "raw")
        self.output_dir = Path(output_dir) if output_dir else (self.project_root / "data" / "processed")

        self.cicids_preparer = CICIDS2017Preparer(raw_dir=self.raw_dir, output_dir=self.output_dir / "cicids2017")
        self.loghub_preparer = LoghubPreparer(raw_dir=self.raw_dir, output_dir=self.output_dir / "loghub")

    def prepare_cicids_only(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
    ) -> Path:
        """Prepares strictly the CICIDS2017 dataset into data/processed/cicids2017/."""
        return self.cicids_preparer.prepare(max_samples=max_samples, split_ratio=split_ratio)

    def prepare_loghub_only(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
    ) -> Path:
        """Prepares strictly the Loghub dataset into data/processed/loghub/."""
        return self.loghub_preparer.prepare(max_samples=max_samples, split_ratio=split_ratio)

    def prepare_all(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
        split_dir: Optional[Union[str, Path]] = None,
    ) -> Path:
        """Prepares and combines both CICIDS2017 and Loghub into the unified primary dataset."""
        logger.info("=== STARTING UNIFIED MULTI-SOURCE DATASET PREPARATION ===")
        all_dfs: List[pd.DataFrame] = []

        cicids_ds = self.output_dir / "cicids2017" / "cicids2017_dataset.csv"
        loghub_ds = self.output_dir / "loghub" / "loghub_dataset.csv"

        if max_samples is None and cicids_ds.exists() and loghub_ds.exists():
            logger.info("Loading preprocessed CICIDS2017 and Loghub datasets for master fusion...")
            df_c = pd.read_csv(cicids_ds)
            df_l = pd.read_csv(loghub_ds)
            df_c["dataset_source"] = "cicids2017"
            df_l["dataset_source"] = "loghub"
            all_dfs = [df_c, df_l]
        else:
            # 1. Process CICIDS2017
            try:
                cicids_files = self.cicids_preparer.discover_raw_files()
                if cicids_files:
                    logger.info(f"Discovered {len(cicids_files)} CICIDS2017 flow file(s).")
                    for f in cicids_files:
                        df_c, _ = self.cicids_preparer.clean_and_transform(f, max_rows=max_samples)
                        df_c["dataset_source"] = "cicids2017"
                        all_dfs.append(df_c)
            except Exception as e:
                logger.warning(f"Could not ingest CICIDS2017 files: {e}")

            # 2. Process Loghub
            try:
                loghub_files = self.loghub_preparer.discover_raw_files()
                if loghub_files:
                    logger.info(f"Discovered {len(loghub_files)} Loghub syslog file(s).")
                    max_log_lines = (max_samples * 100) if max_samples is not None else None
                    for f in loghub_files:
                        df_l, _ = self.loghub_preparer.clean_and_transform(f, max_rows=max_log_lines)
                        if not df_l.empty:
                            df_l["dataset_source"] = "loghub"
                            all_dfs.append(df_l)
            except Exception as e:
                logger.warning(f"Could not ingest Loghub files: {e}")

        if not all_dfs:
            raise RuntimeError(f"No valid raw files could be ingested from {self.raw_dir}.")

        # 3. Standardize and align columns
        target_cols = [
            "timestamp",
            "window_start",
            "entity_id",
            "timestamp_source",
            "source_file",
            "label_source",
            "dataset_source",
        ] + list(FEATURE_COLUMNS) + ["label", "attack_category"]
        aligned_dfs = []
        for df in all_dfs:
            df_sanitized = self.cicids_preparer.sanitize_dataframe(
                df,
                fill_missing=False,
            )
            aligned_dfs.append(df_sanitized[[c for c in target_cols if c in df_sanitized.columns]])

        df_unified = pd.concat(aligned_dfs, ignore_index=True)

        # Keep source identity. A mixed-domain global split is not a valid
        # scientific evaluation, even when feature names are aligned.
        initial_count = len(df_unified)
        df_unified = df_unified.drop_duplicates(
            subset=["dataset_source", "source_file", "timestamp", *FEATURE_COLUMNS],
            keep="first",
        ).reset_index(drop=True)
        if len(df_unified) < initial_count:
            logger.info(f"Unified dataset deduplication removed {initial_count - len(df_unified):,} duplicate feature vectors.")

        # 4. Optional subsampling (preserves strict chronological sequence)
        if max_samples is not None and max_samples > 0 and len(df_unified) > max_samples:
            logger.info(f"Subsampling combined dataset to {max_samples:,} rows preserving temporal sequence...")
            indices = np.linspace(0, len(df_unified) - 1, max_samples, dtype=int)
            df_unified = df_unified.iloc[indices].reset_index(drop=True)

        # 5. Save master processed dataset
        self.output_dir.mkdir(parents=True, exist_ok=True)
        master_path = self.output_dir / "dataset.csv"
        df_unified.to_csv(master_path, index=False)

        # 6. Source-specific splits are the scientific evaluation artifacts.
        source_split_root = self.output_dir / "source_splits"
        for source_name, source_df in df_unified.groupby("dataset_source", sort=False):
            source_train, source_val, source_test = self.cicids_preparer.temporal_split(
                source_df, frac=split_ratio
            )
            self.cicids_preparer.save_splits(
                source_train,
                source_val,
                source_test,
                source_split_root / str(source_name),
            )

        # 7. Legacy combined split retained for production compatibility only.
        if split_dir is not None:
            resolved_split_dir = Path(split_dir)
        elif self.output_dir.resolve() == (self.project_root / "data" / "processed").resolve():
            resolved_split_dir = self.project_root / "data" / "train_test_split"
        else:
            resolved_split_dir = self.output_dir / "train_test_split"

        train_df, val_df, test_df = self.cicids_preparer.temporal_split(df_unified, frac=split_ratio)
        self.cicids_preparer.save_splits(train_df, val_df, test_df, resolved_split_dir)

        val_anom = int((val_df["label"] == LABEL_ANOMALY).sum())
        test_anom = int((test_df["label"] == LABEL_ANOMALY).sum())

        print("\n" + "=" * 80)
        print("✅ UNIFIED DATASET PREPARATION COMPLETE")
        print(f"  • Master Dataset Path:          {master_path}")
        print(f"  • Total Processed Samples:      {len(df_unified):,} rows")
        print(f"  • Master Split Directory:       {resolved_split_dir}")
        print(f"  • Scientific Source Splits:     {source_split_root}")
        print(f"  • Pure Benign Train Set:        {(train_df['label'] == LABEL_NORMAL).sum():,} rows")
        print(f"  • Mixed Validation Set:         {len(val_df):,} rows ({val_anom:,} Anomaly)")
        print(f"  • Mixed Test Set:               {len(test_df):,} rows ({test_anom:,} Anomaly)")
        print("=" * 80 + "\n")

        return master_path
