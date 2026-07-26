# ============================================================================
# file: feature_engineering/build_features.py
# Description: Feature extraction execution entrypoints for CSV and Database sources.
# ============================================================================

# ===== IMPORT MODULES =====
from pathlib import Path
from datetime import datetime
from typing import Union, Any
import pandas as pd

from lsmp_ai.common.constants import FEATURE_COLUMNS
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import extract_features_from_logs

logger = setup_logger(__name__)


# ===== FEATURE BUILDERS =====
def build_features_from_csv(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    window_minutes: int = 60,
    feature_version: str = "v1",
) -> pd.DataFrame:
    """Reads raw logs CSV file and builds aggregated feature vectors CSV.

    Args:
        input_path (Union[str, Path]): Path to source raw logs CSV.
        output_path (Union[str, Path]): Destination path for generated feature vectors CSV.
        window_minutes (int, optional): Duration of time window in minutes. Defaults to 60.
        feature_version (str, optional): Version identifier for features. Defaults to "v1".

    Returns:
        pd.DataFrame: DataFrame containing generated feature vectors.
    """
    logger.info(f"Building features from {input_path}")

    df = pd.read_csv(input_path)
    features = extract_features_from_logs(df, window_start=datetime.now())
    features["feature_version"] = feature_version

    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(out_p, index=False)
    logger.info(f"Saved {len(features)} feature vectors to {out_p}")

    return features


def build_features_from_db(
    db_client: Any,
    output_path: Union[str, Path],
    window_minutes: int = 60,
    feature_version: str = "v1",
    limit: int = 50000,
) -> pd.DataFrame:
    """Queries raw logs from database and builds aggregated feature vectors CSV.

    Args:
        db_client (Any): Database client instance with fetch_df method.
        output_path (Union[str, Path]): Destination path for generated feature vectors CSV.
        window_minutes (int, optional): Duration of time window. Defaults to 60.
        feature_version (str, optional): Version identifier. Defaults to "v1".
        limit (int, optional): Max logs to fetch. Defaults to 50000.

    Returns:
        pd.DataFrame: DataFrame containing generated feature vectors.
    """
    logger.info("Building features from database")
    from lsmp_ai.common.config_loader import config

    query = f"""
        SELECT * FROM {config.db_tables['wazuh_alerts']}
        ORDER BY timestamp DESC
        LIMIT :limit
    """
    logs_df = db_client.fetch_df(query, limit=limit)

    if not logs_df.empty and 'source_ip' in logs_df.columns:
        logs_df['src_ip'] = logs_df['source_ip']

    features = extract_features_from_logs(logs_df, window_start=datetime.now())
    features["feature_version"] = feature_version

    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(out_p, index=False)
    logger.info(f"Saved {len(features)} feature vectors to {out_p}")

    return features
