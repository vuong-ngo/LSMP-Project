# ============================================================================
# file: io/data_loader.py
# Description: Module for loading data from CSV files or database.
# ============================================================================

# ===== IMPORT MODULES =====
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import numpy as np
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_ANOMALY, LABEL_NORMAL
from lsmp_ai.common.exceptions import DataValidationError
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.io.db_client import DatabaseClient, validate_table_name

logger = setup_logger(__name__)

# Standardized storage paths for unlabelled / audit data
DEFAULT_UNLABELED_DIR = Path("data/unlabeled")
DEFAULT_UNLABELED_CSV = DEFAULT_UNLABELED_DIR / "unlabeled_samples.csv"
DEFAULT_METADATA_JSON = DEFAULT_UNLABELED_DIR / "audit_metadata.json"
DEFAULT_LEGACY_AUDIT_CSV = Path("data/unlabeled_audit.csv")

# ===== DATA LOADER =====
class DataLoader:
    def __init__(self, db_client: DatabaseClient | None = None):
        self._db = db_client

    def load_from_csv(self, path: str | Path) -> pd.DataFrame:
        path = Path(path)
        if not path.exists():
            raise DataValidationError(f"File not found: {path}")
        df = pd.read_csv(path)
        logger.info(f"Loaded {len(df)} rows from {path}")
        return df

    def load_from_db(
        self,
        table: str = "anomaly_result",
        limit: int = 50000,
    ) -> pd.DataFrame:
        if self._db is None:
            raise DataValidationError("DatabaseClient not configured")

        safe_table = validate_table_name(table)
        if safe_table in ["anomaly_result", "feature_vectors"]:
            # Leverage the automated JSONB flattener inside db_client
            df = self._db.fetch_features_with_labels()
            if not df.empty:
                df = df.head(limit)
        else:
            query = f"SELECT * FROM {safe_table} LIMIT :limit"
            df = self._db.fetch_df(query, limit=limit)

        logger.info(f"Loaded {len(df)} rows from {table}")
        return df

    def load_train_test(
        self,
        train_path: str | Path = "data/processed/train_test_split/train.csv",
        test_path: str | Path = "data/processed/train_test_split/test.csv",
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        train = self.load_from_csv(train_path)
        test = self.load_from_csv(test_path)
        return train, test

    @staticmethod
    def optimize_dtypes(df: pd.DataFrame, feature_cols: list[str] | None = None) -> pd.DataFrame:
        """Optimizes DataFrame memory footprint by downcasting 64-bit types to 32-bit types."""
        cols = feature_cols or [c for c in df.columns if c in FEATURE_COLUMNS]
        for col in cols:
            if col in df.columns:
                if df[col].dtype == 'float64':
                    df[col] = df[col].astype('float32')
                elif df[col].dtype == 'int64':
                    df[col] = df[col].astype('int32')
        return df

    @staticmethod
    def split_features_target(
        df: pd.DataFrame,
        feature_cols: list[str] | None = None,
        label_col: str = "label",
    ) -> tuple[pd.DataFrame, pd.Series | None]:
        cols = feature_cols or FEATURE_COLUMNS
        df_copy = df.copy()
        alias_map = {
            "login_fail_count": "auth_fail_count",
            "fail_success_ratio": "auth_fail_ratio",
            "unique_failed_ip_count": "distinct_username",
            "request_rate": "http_req_rate",
            "status_4xx_rate": "http_4xx_ratio",
            "user_agent_entropy": "distinct_user_agent",
            "ip_entropy": "global_active_ips",
            # SME-kit research aliases
            "http_req_count": "http_req_rate",
            "distinct_src_ip": "global_active_ips",
            "max_fail_per_ip": "burst_rate",
            # xu-ly-du-lieu web & SSH aliases
            "req_count": "http_req_rate",
            "unique_ua_count": "distinct_user_agent",
            "post_ratio": "http_post_ratio",
            "bytes_per_request": "bytes_sent_mean",
            "failed_auth_count": "auth_fail_count",
            "accepted_count": "auth_success_count",
            "failed_auth_ratio": "auth_fail_ratio",
            "unique_user_count": "distinct_username",
        }
        for old_c, new_c in alias_map.items():
            if new_c not in df_copy.columns and old_c in df_copy.columns:
                df_copy[new_c] = df_copy[old_c]

        missing = [c for c in cols if c not in df_copy.columns]
        if missing:
            raise DataValidationError(f"Missing feature columns: {missing}")

        X = DataLoader.optimize_dtypes(df_copy[cols].copy())
        y = df_copy[label_col].copy() if label_col in df_copy.columns else None
        return X, y

    @staticmethod
    def audit_and_separate_unknowns(
        df: pd.DataFrame,
        label_col: str = "label",
        audit_csv_path: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        save_metadata: bool = True,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Separates Unknown/unlabeled samples from the four-state dataset.

        Persists unknown samples into a standardized scientific storage structure:
        - data/unlabeled/unlabeled_samples.csv (Primary structured storage)
        - data/unlabeled/audit_metadata.json (Audit manifest: counts, ratios, column schemas, timestamps)
        - data/unlabeled_audit.csv (Maintained for full backward compatibility)

        Args:
            df (pd.DataFrame): Input dataset.
            label_col (str, optional): Target label column name. Defaults to "label".
            audit_csv_path (str | Path, optional): Custom path for audit CSV. If None, uses default.
            output_dir (str | Path, optional): Directory to store unlabeled data and metadata.
            save_metadata (bool): Whether to generate audit_metadata.json. Defaults to True.

        Returns:
            tuple[pd.DataFrame, pd.DataFrame]: (df_labeled, df_unknown)
        """
        if df.empty or label_col not in df.columns:
            return df, pd.DataFrame()

        from lsmp_ai.common.constants import LABEL_UNKNOWN_ALIASES
        s = df[label_col].astype(str).str.strip().str.lower()
        is_na = df[label_col].isna()
        is_alias = s.isin(LABEL_UNKNOWN_ALIASES)
        unknown_mask = is_alias | is_na

        df_unknown = df[unknown_mask].copy()
        df_labeled = df[~unknown_mask].copy()

        if not df_unknown.empty:
            # Determine directory and file paths
            if output_dir:
                target_dir = Path(output_dir)
                primary_csv = target_dir / "unlabeled_samples.csv"
            elif audit_csv_path:
                primary_csv = Path(audit_csv_path)
                target_dir = primary_csv.parent
            else:
                target_dir = DEFAULT_UNLABELED_DIR
                primary_csv = DEFAULT_UNLABELED_CSV

            target_dir.mkdir(parents=True, exist_ok=True)
            df_unknown.to_csv(primary_csv, index=False)

            # Also maintain legacy path for backward compatibility
            try:
                DEFAULT_LEGACY_AUDIT_CSV.parent.mkdir(parents=True, exist_ok=True)
                df_unknown.to_csv(DEFAULT_LEGACY_AUDIT_CSV, index=False)
            except Exception as e:
                logger.debug(f"Could not write legacy audit CSV: {e}")

            # Ensure README.md exists in data/unlabeled
            readme_p = target_dir / "README.md"
            if not readme_p.exists():
                try:
                    with open(readme_p, "w", encoding="utf-8") as rf:
                        rf.write(
                            "# 📁 LSMP Audited Unlabeled Data Repository\n\n"
                            "This directory contains feature vectors and log records that lack verified ground-truth labels "
                            "(e.g., missing labels, NaN, or marked as 'unknown').\n\n"
                            "### Purpose & Policy (User Policy A2)\n"
                            "1. **Zero-Contamination Principle**: Unknown/unlabeled samples are isolated here and NEVER used in unsupervised training "
                            "or supervised benchmarking to preserve statistical rigor.\n"
                            "2. **SOC Active Learning**: Security analysts review `unlabeled_samples.csv` to confirm ground-truth labels, "
                            "which can then be promoted to verified training datasets.\n"
                        )
                except Exception:
                    pass

            # Generate scientific metadata manifest
            if save_metadata:
                metadata_path = target_dir / "audit_metadata.json"
                total_samples = len(df)
                unknown_count = len(df_unknown)
                metadata = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "total_input_samples": int(total_samples),
                    "labeled_samples_count": int(len(df_labeled)),
                    "unknown_samples_count": int(unknown_count),
                    "unknown_ratio_percent": round((unknown_count / max(total_samples, 1)) * 100.0, 4),
                    "breakdown": {
                        "missing_or_nan_count": int(is_na.sum()),
                        "explicit_unknown_alias_count": int(is_alias.sum()),
                    },
                    "features_available": [c for c in FEATURE_COLUMNS if c in df.columns],
                    "storage_paths": {
                        "primary_csv": str(primary_csv),
                        "legacy_csv": str(DEFAULT_LEGACY_AUDIT_CSV),
                        "metadata_json": str(metadata_path),
                    },
                    "policy": "Policy A2: Strict Separation of Unlabeled Data for SOC Inspection & Active Labeling",
                }
                try:
                    with open(metadata_path, "w", encoding="utf-8") as mf:
                        json.dump(metadata, mf, indent=4)
                except Exception as e:
                    logger.warning(f"Could not persist audit metadata manifest: {e}")

            logger.info(
                f"Separated {len(df_unknown)} unknown samples ({round(len(df_unknown)/max(len(df),1)*100, 2)}%) "
                f"to {primary_csv} with metadata manifest."
            )

        return df_labeled, df_unknown

    @staticmethod
    def load_unlabeled_samples(path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Loads audited unlabeled samples from structured repository."""
        target_path = Path(path) if path else DEFAULT_UNLABELED_CSV
        if not target_path.exists():
            if DEFAULT_LEGACY_AUDIT_CSV.exists():
                target_path = DEFAULT_LEGACY_AUDIT_CSV
            else:
                return pd.DataFrame()
        return pd.read_csv(target_path)

    @staticmethod
    def load_audit_metadata(path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """Loads audit metadata manifest for unlabeled samples."""
        target_path = Path(path) if path else DEFAULT_METADATA_JSON
        if not target_path.exists():
            return {}
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def prepare_labels(y: pd.Series) -> pd.Series:
        from lsmp_ai.evaluation.metrics import to_binary_labels
        bin_labels = to_binary_labels(y)
        # In scikit-learn anomaly detection convention: 1.0 = Normal (inlier), -1.0 = Anomaly (outlier)
        # Unknown (-1 in bin_labels) is mapped to np.nan to avoid collision with anomaly sentinel (-1)
        res = np.full(len(bin_labels), np.nan, dtype=float)
        res[bin_labels == 0] = 1.0
        res[bin_labels == 1] = -1.0
        return pd.Series(res, index=y.index)
