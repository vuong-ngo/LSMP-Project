# ============================================================================
# file: io/data_loader.py
# Description: Module for loading data from CSV files or database.
# ============================================================================

# ===== IMPORT MODULES =====
from pathlib import Path

import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_ANOMALY, LABEL_NORMAL
from lsmp_ai.common.exceptions import DataValidationError
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.io.db_client import DatabaseClient

logger = setup_logger(__name__)

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

        if table in ["anomaly_result", "feature_vectors"]:
            # Leverage the automated JSONB flattener inside db_client
            df = self._db.fetch_features_with_labels()
            if not df.empty:
                df = df.head(limit)
        else:
            query = f"SELECT * FROM {table} LIMIT :limit"
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
        missing = [c for c in cols if c not in df.columns]
        if missing:
            raise DataValidationError(f"Missing feature columns: {missing}")

        X = DataLoader.optimize_dtypes(df[cols].copy())
        y = df[label_col].copy() if label_col in df.columns else None
        return X, y

    @staticmethod
    def prepare_labels(y: pd.Series) -> pd.Series:
        return y.map({LABEL_NORMAL: 1, LABEL_ANOMALY: -1}).fillna(-1)
