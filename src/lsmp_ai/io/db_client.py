# ============================================================================
# file: io/db_client.py
# Description: Database client for PostgreSQL. Used to query/insert data into the database.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import json
import pandas as pd
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from lsmp_ai.common.exceptions import DatabaseConnectionError
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config

# ===== DB CLIENT =====
class DBClient:
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL")
        self._engine: Optional[Engine] = None
        
        if not self.db_url:
            logger.warning("DATABASE_URL environment variable is not set. Database interactions will use offline file fallbacks.")
            
    @property
    def engine(self) -> Engine:
        if self._engine is None:
            if not self.db_url:
                raise DatabaseConnectionError("Cannot connect: DATABASE_URL is not set.")
            try:
                self._engine = create_engine(self.db_url)
                # Test connection
                with self._engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                logger.info("Successfully connected to the database.")
            except Exception as e:
                self._engine = None
                raise DatabaseConnectionError(f"Failed to connect to the database: {e}")
        return self._engine

    def fetch_features(self, start_time: datetime, end_time: datetime, version: str = "v1") -> pd.DataFrame:
        """Fetches feature vectors in a given time window from the feature_vectors table."""
        table_name = config.db_tables['feature_vectors'] if config else "feature_vectors"
        query = text(f"""
            SELECT * FROM {table_name}
            WHERE window_start >= :start_time AND window_start <= :end_time
              AND feature_version = :version
            ORDER BY window_start ASC, src_ip ASC
        """)
        try:
            with self.engine.connect() as conn:
                df = pd.read_sql(query, conn, params={"start_time": start_time, "end_time": end_time, "version": version})
            logger.info(f"Fetched {len(df)} feature vectors between {start_time} and {end_time}.")
            return df
        except Exception as e:
            logger.error(f"Error fetching features from database: {e}")
            raise DatabaseConnectionError(f"Error fetching features: {e}")

    def fetch_features_with_labels(self, version: str = "cascade-v1.0") -> pd.DataFrame:
        """Loads training dataset from anomaly_result table and flattens feature_snapshot JSON."""
        query = text(f"""
            SELECT id, window_start, src_ip, feature_snapshot, anomaly_score, 
                   predicted_label, ground_truth_label, label_source
            FROM anomaly_result
            WHERE model_version = :version
        """)
        try:
            with self.engine.connect() as conn:
                df = pd.read_sql(query, conn, params={"version": version})
            logger.info(f"Fetched {len(df)} records from anomaly_result.")
            
            if not df.empty and "feature_snapshot" in df.columns:
                # Flatten the feature_snapshot JSON column into separate columns
                feature_dicts = df['feature_snapshot'].apply(
                    lambda x: json.loads(x) if isinstance(x, str) else (x if isinstance(x, dict) else {})
                ).tolist()
                df_flat = pd.DataFrame(feature_dicts)
                
                # Combine metadata with flattened features
                df = pd.concat([df.drop(columns=['feature_snapshot']), df_flat], axis=1)
                # Map ground_truth_label to 'label' for backward compatibility
                if 'ground_truth_label' in df.columns:
                    df['label'] = df['ground_truth_label']
                return df
        except Exception as e:
            logger.warning(f"Database query for anomaly_result failed or empty: {e}. Trying offline fallbacks.")

        # Offline fallbacks if DB query fails or returns empty
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        fallback_paths = [
            os.path.join(base_dir, "data", "processed", "dataset.csv"),
            os.path.join(base_dir, "data", "processed", "cicids2017", "test_attacks.csv"),
            os.path.join(base_dir, "data", "processed", "cicids2017", "train_monday.csv")
        ]
        for path in fallback_paths:
            if os.path.exists(path):
                logger.info(f"Falling back to local dataset file: {path}")
                return pd.read_csv(path)

        raise DatabaseConnectionError("Error fetching labeled features: Database unavailable and no local offline CSV dataset found.")

    def fetch_latest_wazuh_severity(self, src_ip: str, start_time: datetime, end_time: datetime) -> float:
        """
        Gets the maximum severity for an IP within a time window from the log_event (wazuh_alerts) table.
        This severity acts as the SeverityWeight in risk scoring.
        """
        table_name = config.db_tables['wazuh_alerts'] if config else "log_event"
        query = text(f"""
            SELECT COALESCE(MAX(severity), 0) as max_level
            FROM {table_name}
            WHERE source_ip = :src_ip 
              AND timestamp >= :start_time AND timestamp <= :end_time
        """)
        try:
            with self.engine.connect() as conn:
                result = conn.execute(query, {"src_ip": src_ip, "start_time": start_time, "end_time": end_time}).fetchone()
                return float(result[0]) if result else 0.0
        except Exception as e:
            logger.warning(f"Error fetching Wazuh severity from DB for IP {src_ip}: {e}. Returning default 0.0.")
            return 0.0

    def write_predictions(self, df_anomaly: pd.DataFrame, df_risk: pd.DataFrame) -> None:
        """Writes anomaly results and risk scores to PostgreSQL tables (anomaly_result and risk_score)."""
        # Define strict table column schemas matching schema.sql
        anomaly_columns = [
            "id", "window_start", "src_ip", "event_id", "feature_vector_id",
            "feature_snapshot", "anomaly_score", "model_version",
            "predicted_label", "ground_truth_label", "label_source"
        ]
        risk_columns = [
            "id", "src_ip", "asset_id", "anomaly_result_id",
            "ai_component", "rule_component", "score", "risk_class", "timestamp"
        ]

        try:
            with self.engine.begin() as conn:
                if not df_anomaly.empty:
                    df_anomaly_clean = df_anomaly[[c for c in anomaly_columns if c in df_anomaly.columns]]
                    df_anomaly_clean.to_sql(
                        name="anomaly_result",
                        con=conn,
                        if_exists="append",
                        index=False
                    )
                    logger.info(f"Successfully wrote {len(df_anomaly_clean)} anomaly results to database.")

                if not df_risk.empty:
                    df_risk_clean = df_risk[[c for c in risk_columns if c in df_risk.columns]]
                    df_risk_clean.to_sql(
                        name="risk_score",
                        con=conn,
                        if_exists="append",
                        index=False
                    )
                    logger.info(f"Successfully wrote {len(df_risk_clean)} risk scores to database.")
        except Exception as e:
            logger.error(f"Error writing predictions to database: {e}")
            # Offline fallback save
            fallback_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                "data", "interim"
            )
            os.makedirs(fallback_dir, exist_ok=True)
            fallback_path = os.path.join(fallback_dir, "predictions_fallback.csv")
            if not df_risk.empty:
                df_risk.to_csv(fallback_path, mode='a', header=not os.path.exists(fallback_path), index=False)
                logger.warning(f"Saved predictions to offline backup at {fallback_path}.")
            raise DatabaseConnectionError(f"Error writing predictions: {e}")

    def write_feature_vectors(self, df_features: pd.DataFrame) -> pd.DataFrame:
        """Writes computed feature vectors to the feature_vectors table and returns DataFrame with UUID ids."""
        if df_features.empty:
            logger.info("No feature vectors to write.")
            return df_features
        try:
            import uuid
            df_features = df_features.copy()
            if "id" not in df_features.columns or df_features["id"].isnull().any():
                df_features["id"] = [str(uuid.uuid4()) for _ in range(len(df_features))]

            fv_columns = [
                "id", "window_start", "src_ip",
                "login_fail_count", "unique_failed_ip_count", "fail_success_ratio",
                "ip_entropy", "hour_of_day", "request_rate", "status_4xx_rate",
                "url_frequency", "user_agent_entropy", "method_distribution",
                "time_window_count", "burst_rate", "sliding_window_count",
                "ip_switch_frequency", "feature_version", "computed_at"
            ]
            if "feature_version" not in df_features.columns:
                df_features["feature_version"] = "v1"
            if "computed_at" not in df_features.columns:
                df_features["computed_at"] = datetime.now(timezone.utc)

            cols_to_write = [c for c in fv_columns if c in df_features.columns]
            df_write = df_features[cols_to_write]

            with self.engine.begin() as conn:
                df_write.to_sql(
                    name="feature_vectors",
                    con=conn,
                    if_exists="append",
                    index=False
                )
            logger.info(f"Successfully wrote {len(df_write)} feature vectors to database.")
            return df_features
        except Exception as e:
            logger.error(f"Error writing feature vectors to database: {e}")
            return df_features

    def fetch_df(self, query: str, limit: int = 50000) -> pd.DataFrame:
        """Executes a SQL query and returns a pandas DataFrame."""
        try:
            with self.engine.connect() as conn:
                df = pd.read_sql(text(query), conn, params={"limit": limit})
            return df
        except Exception as e:
            logger.error(f"Error executing fetch_df: {e}")
            return pd.DataFrame()

    def insert_df(self, df: pd.DataFrame, table_name: str, if_exists: str = "append") -> None:
        """Inserts a pandas DataFrame into a specified table."""
        if df.empty:
            return
        try:
            with self.engine.begin() as conn:
                df.to_sql(name=table_name, con=conn, if_exists=if_exists, index=False)
            logger.info(f"Successfully inserted {len(df)} rows into {table_name}")
        except Exception as e:
            logger.error(f"Error executing insert_df for {table_name}: {e}")

    def fetch_feature_vectors(self, limit: int = 100) -> pd.DataFrame:
        """Fetches the latest feature vectors for real-time inference."""
        table = config.db_tables['feature_vectors'] if config else "feature_vectors"
        query = f"SELECT * FROM {table} ORDER BY window_start DESC LIMIT :limit"
        try:
            with self.engine.connect() as conn:
                df = pd.read_sql(text(query), conn, params={"limit": limit})
            return df
        except Exception as e:
            logger.warning(f"Error fetching feature vectors from database: {e}. Returning empty DataFrame.")
            return pd.DataFrame()

# Class alias for backward compatibility
DatabaseClient = DBClient
