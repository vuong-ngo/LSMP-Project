# ============================================================================
# file: src/lsmp_ai/data_preparation/base.py
# Description: Abstract base class and common utilities for dataset preparation.
# ============================================================================

from abc import ABC, abstractmethod
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import json
import numpy as np
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger

logger = setup_logger(__name__)


class BaseDataPreparer(ABC):
    """Abstract Base Class defining the lifecycle protocol for dataset preparation.

    Lifecycle:
        1. discover_raw_files() -> List[Path]
        2. clean_and_transform(file_path: Path) -> Tuple[pd.DataFrame, Dict]
        3. prepare(max_samples, split_ratio) -> Path
        4. temporal_split(df, frac) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]
        5. save_splits(train, val, test, output_dir)
    """

    def __init__(
        self,
        raw_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
    ):
        self.project_root = Path(__file__).resolve().parent.parent.parent.parent
        self.raw_dir = Path(raw_dir) if raw_dir else (self.project_root / "data" / "raw")
        self.output_dir = Path(output_dir) if output_dir else (self.project_root / "data" / "processed")

    @abstractmethod
    def discover_raw_files(self) -> List[Path]:
        """Locates all raw files to be ingested by this preparer."""
        raise NotImplementedError

    @abstractmethod
    def clean_and_transform(
        self, file_path: Path, max_rows: Optional[int] = None
    ) -> Tuple[pd.DataFrame, Dict]:
        """Cleans a single raw input file and maps its contents into standardized 14 features."""
        raise NotImplementedError

    def sanitize_dataframe(
        self,
        df: pd.DataFrame,
        *,
        fill_missing: bool = True,
    ) -> pd.DataFrame:
        """Sanitizes feature matrix without learning statistics from the dataset.

        ``fill_missing=True`` is retained for backward-compatible helper calls.
        Scientific preparation passes ``False`` so the fitted FeaturePipeline can
        impute from the benign training partition only.
        """
        df_out = df.copy()

        # Check required columns
        for col in FEATURE_COLUMNS:
            if col not in df_out.columns:
                df_out[col] = 0.0

        # Replace infinities and NaNs
        features = list(FEATURE_COLUMNS)
        df_out[features] = df_out[features].replace([np.inf, -np.inf], np.nan)
        for col in features:
            df_out[col] = pd.to_numeric(df_out[col], errors="coerce")
            if fill_missing:
                df_out[col] = df_out[col].fillna(0.0)
            df_out[col] = df_out[col].astype(np.float32)

        # Ensure label column exists
        if "label" not in df_out.columns:
            df_out["label"] = LABEL_NORMAL

        if "attack_category" not in df_out.columns:
            df_out["attack_category"] = np.where(
                df_out["label"] == LABEL_NORMAL, "BENIGN", "Anomaly"
            )

        return df_out

    def temporal_split(
        self,
        df: pd.DataFrame,
        frac: Tuple[float, float, float] = (0.6, 0.2, 0.2),
        entity_disjoint: bool = False,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Splits dataset temporally into Train (60%), Validation (20%), and Test (20%).

        Preserves chronological sequence to prevent temporal data leakage.
        When entity_disjoint=True, purges overlapping entities from later partitions.
        """
        if len(frac) != 3 or any(float(x) < 0 for x in frac) or not np.isclose(sum(frac), 1.0):
            raise ValueError(f"Split fractions must be non-negative and sum to 1.0: {frac}")

        if "window_end" in df.columns:
            df_sorted = df.sort_values("window_end").reset_index(drop=True)
        elif "timestamp" in df.columns:
            df_sorted = df.sort_values("timestamp").reset_index(drop=True)
        elif "window_start" in df.columns:
            df_sorted = df.sort_values("window_start").reset_index(drop=True)
        else:
            df_sorted = df.reset_index(drop=True)

        n = len(df_sorted)
        target_i1 = int(n * frac[0])
        target_i2 = int(n * (frac[0] + frac[1]))

        time_col = next(
            (c for c in ("window_end", "timestamp", "window_start") if c in df_sorted.columns),
            None,
        )
        if time_col and n:
            # Keep identical timestamps in one partition. This prevents
            # same-window flows/events from crossing a scientific split.
            time_values = pd.to_datetime(df_sorted[time_col], errors="coerce", utc=True)
            group_end_positions = (
                pd.Series(np.arange(n), index=df_sorted.index)
                .groupby(time_values, sort=False)
                .max()
                .sort_index()
                .to_numpy()
                + 1
            )

            def nearest_boundary(target: int, lower_bound: int = 0) -> int:
                candidates = group_end_positions[group_end_positions > lower_bound]
                if not len(candidates):
                    return n
                return int(candidates[np.argmin(np.abs(candidates - target))])

            i1 = nearest_boundary(target_i1)
            i2 = nearest_boundary(target_i2, lower_bound=i1)
        else:
            i1 = target_i1
            i2 = target_i2

        train_df = df_sorted.iloc[:i1].reset_index(drop=True)
        val_df = df_sorted.iloc[i1:i2].reset_index(drop=True)
        test_df = df_sorted.iloc[i2:].reset_index(drop=True)

        if entity_disjoint:
            ent_col = "entity_id" if "entity_id" in df_sorted.columns else (
                "src_ip" if "src_ip" in df_sorted.columns else None
            )
            if ent_col:
                train_entities = set(train_df[ent_col].dropna().astype(str))
                val_df = val_df[~val_df[ent_col].astype(str).isin(train_entities)].reset_index(drop=True)
                val_entities = set(val_df[ent_col].dropna().astype(str))
                test_df = test_df[
                    ~test_df[ent_col].astype(str).isin(train_entities | val_entities)
                ].reset_index(drop=True)

        return train_df, val_df, test_df

    def save_splits(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
        target_dir: Path,
        metadata: Optional[Dict] = None,
    ) -> Dict[str, Path]:
        """Saves train, validation, and test splits into CSV files.

        Preserves 100% of samples and exact temporal 60/20/20 split proportions without dropping anomalies.
        Also outputs train_benign.csv containing pure normal samples for novelty detection.
        """
        target_dir.mkdir(parents=True, exist_ok=True)

        train_path = target_dir / "train.csv"
        val_path = target_dir / "val.csv"
        test_path = target_dir / "test.csv"
        train_benign_path = target_dir / "train_benign.csv"

        # 1. Full temporal splits (all rows preserved, exactly 60/20/20)
        train_df.to_csv(train_path, index=False)
        val_df.to_csv(val_path, index=False)
        test_df.to_csv(test_path, index=False)

        # 2. Pure benign training partition for unsupervised novelty detection
        tr_clean = train_df[train_df["label"] == LABEL_NORMAL].reset_index(drop=True)
        if tr_clean.empty:
            logger.warning(
                "Train split contains no benign samples; train_benign.csv will be "
                "empty and training must be rejected by the model pipeline."
            )
        tr_clean.to_csv(train_benign_path, index=False)

        def summary(df: pd.DataFrame) -> Dict:
            time_col = next(
                (c for c in ("window_end", "timestamp", "window_start") if c in df.columns),
                None,
            )
            times = pd.to_datetime(df[time_col], errors="coerce") if time_col else pd.Series(dtype="datetime64[ns]")
            counts = df["label"].astype(str).value_counts().to_dict() if "label" in df.columns else {}
            timestamp_sources = (
                sorted(df["timestamp_source"].dropna().astype(str).unique().tolist())
                if "timestamp_source" in df.columns
                else []
            )
            label_sources = (
                sorted(df["label_source"].dropna().astype(str).unique().tolist())
                if "label_source" in df.columns
                else []
            )
            return {
                "rows": int(len(df)),
                "label_counts": {str(k): int(v) for k, v in counts.items()},
                "time_column": time_col,
                "time_min": str(times.min()) if not times.empty and times.notna().any() else None,
                "time_max": str(times.max()) if not times.empty and times.notna().any() else None,
                "timestamp_sources": timestamp_sources,
                "label_sources": label_sources,
            }

        ent_col = "entity_id" if "entity_id" in train_df.columns else (
            "src_ip" if "src_ip" in train_df.columns else None
        )
        overlap_info = {}
        if ent_col:
            s_tr = set(train_df[ent_col].dropna().astype(str))
            s_val = set(val_df[ent_col].dropna().astype(str))
            s_te = set(test_df[ent_col].dropna().astype(str))
            overlap_info = {
                "train_validation": len(s_tr & s_val),
                "train_test": len(s_tr & s_te),
                "validation_test": len(s_val & s_te),
            }

        manifest = {
            "protocol": "temporal_train_validation_test",
            "saved_counts": {
                "train": int(len(train_df)),
                "validation": int(len(val_df)),
                "test": int(len(test_df)),
                "train_benign": int(len(tr_clean)),
            },
            "entity_disjoint": bool(not any(overlap_info.values())) if overlap_info else False,
            "entity_overlap": overlap_info,
            "splits": {
                "train": summary(train_df),
                "validation": summary(val_df),
                "test": summary(test_df),
                "train_benign": summary(tr_clean),
            },
            "training_allowed": bool(not tr_clean.empty),
            "preprocessing": {
                "imputation": "FeaturePipeline median fitted on train_benign only",
                "missing_values_retained": True,
                "infinite_values": "converted to missing before train-only preprocessing",
            },
        }
        if metadata:
            manifest["provenance"] = metadata
        manifest_path = target_dir / "split_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return {
            "train": train_path,
            "train_benign": train_benign_path,
            "val": val_path,
            "test": test_path,
            "manifest": manifest_path,
        }

    @abstractmethod
    def prepare(
        self,
        max_samples: Optional[int] = None,
        split_ratio: Tuple[float, float, float] = (0.6, 0.2, 0.2),
    ) -> Path:
        """Executes complete data preparation pipeline and returns path to primary dataset."""
        raise NotImplementedError
