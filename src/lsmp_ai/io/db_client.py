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
        url = db_url or os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
        if not url:
            user = os.getenv("POSTGRES_USER")
            password = os.getenv("POSTGRES_PASSWORD")
            host = os.getenv("POSTGRES_HOST", "localhost")
            port = os.getenv("POSTGRES_PORT", "5432")
            dbname = os.getenv("POSTGRES_DB", "wazuh_db")
            if user and password:
                url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

        self.db_url = url
        self._engine: Optional[Engine] = None

        if not self.db_url:
            logger.warning("DATABASE_URL / POSTGRES_URL environment variable is not set. Database interactions will use offline file fallbacks.")


    @property
    def engine(self) -> Engine:
        if self._engine is None:
            if not self.db_url:
                raise DatabaseConnectionError("Cannot connect: DATABASE_URL is not set.")
            try:
                sslmode = os.getenv("POSTGRES_SSLMODE")
                connect_args = {}
                if sslmode:
                    connect_args["sslmode"] = sslmode

                self._engine = create_engine(self.db_url, connect_args=connect_args)
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
        """Writes anomaly results and risk scores to PostgreSQL tables using idempotent SQL ON CONFLICT upsert."""
        if (df_anomaly is None or df_anomaly.empty) and (df_risk is None or df_risk.empty):
            return

        sql_anomaly = text("""
            INSERT INTO anomaly_result (
                id, window_start, src_ip, event_id, feature_vector_id,
                feature_snapshot, anomaly_score, model_version,
                predicted_label, ground_truth_label, label_source
            ) VALUES (
                :id, :window_start, :src_ip, :event_id, :feature_vector_id,
                :feature_snapshot, :anomaly_score, :model_version,
                :predicted_label, :ground_truth_label, :label_source
            )
            ON CONFLICT (window_start, src_ip, model_version) DO UPDATE SET
                anomaly_score = EXCLUDED.anomaly_score,
                predicted_label = EXCLUDED.predicted_label,
                feature_snapshot = EXCLUDED.feature_snapshot,
                feature_vector_id = EXCLUDED.feature_vector_id;
        """)

        sql_risk = text("""
            INSERT INTO risk_score (
                id, src_ip, asset_id, anomaly_result_id,
                ai_component, rule_component, score, risk_class, timestamp
            ) VALUES (
                :id, :src_ip, :asset_id, :anomaly_result_id,
                :ai_component, :rule_component, :score, :risk_class, :timestamp
            )
            ON CONFLICT (anomaly_result_id) DO UPDATE SET
                score = EXCLUDED.score,
                risk_class = EXCLUDED.risk_class,
                ai_component = EXCLUDED.ai_component,
                rule_component = EXCLUDED.rule_component,
                "timestamp" = EXCLUDED.timestamp;
        """)

        try:
            with self.engine.begin() as conn:
                if df_anomaly is not None and not df_anomaly.empty:
                    records_anom = df_anomaly.to_dict(orient="records")
                    conn.execute(sql_anomaly, records_anom)
                    logger.info(f"Successfully upserted {len(records_anom)} anomaly results to database.")

                if df_risk is not None and not df_risk.empty:
                    records_risk = df_risk.to_dict(orient="records")
                    conn.execute(sql_risk, records_risk)
                    logger.info(f"Successfully upserted {len(records_risk)} risk scores to database.")
        except Exception as e:
            logger.error(f"Error writing predictions to database: {e}")
            fallback_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                "data", "interim"
            )
            os.makedirs(fallback_dir, exist_ok=True)
            fallback_path = os.path.join(fallback_dir, "predictions_fallback.csv")
            if df_risk is not None and not df_risk.empty:
                df_risk.to_csv(fallback_path, mode='a', header=not os.path.exists(fallback_path), index=False)
                logger.warning(f"Saved predictions to offline backup at {fallback_path}.")
            raise DatabaseConnectionError(f"Error writing predictions: {e}")

    def write_feature_vectors(self, df_features: pd.DataFrame) -> pd.DataFrame:
        """Writes computed feature vectors to the feature_vectors table using idempotent SQL ON CONFLICT upsert."""
        if df_features.empty:
            logger.info("No feature vectors to write.")
            return df_features
        try:
            import uuid
            df_features = df_features.copy()
            if "id" not in df_features.columns or df_features["id"].isnull().any():
                df_features["id"] = [str(uuid.uuid4()) for _ in range(len(df_features))]

            if "feature_version" not in df_features.columns:
                df_features["feature_version"] = "v1"
            if "computed_at" not in df_features.columns:
                df_features["computed_at"] = datetime.now(timezone.utc)

            sql_fv = text("""
                INSERT INTO feature_vectors (
                    id, window_start, src_ip,
                    login_fail_count, unique_failed_ip_count, fail_success_ratio,
                    ip_entropy, hour_of_day, request_rate, status_4xx_rate,
                    url_frequency, user_agent_entropy, method_distribution,
                    time_window_count, burst_rate, sliding_window_count,
                    ip_switch_frequency, feature_version, computed_at
                ) VALUES (
                    :id, :window_start, :src_ip,
                    :login_fail_count, :unique_failed_ip_count, :fail_success_ratio,
                    :ip_entropy, :hour_of_day, :request_rate, :status_4xx_rate,
                    :url_frequency, :user_agent_entropy, :method_distribution,
                    :time_window_count, :burst_rate, :sliding_window_count,
                    :ip_switch_frequency, :feature_version, :computed_at
                )
                ON CONFLICT (window_start, src_ip, feature_version) DO UPDATE SET
                    login_fail_count = EXCLUDED.login_fail_count,
                    request_rate = EXCLUDED.request_rate,
                    status_4xx_rate = EXCLUDED.status_4xx_rate,
                    computed_at = EXCLUDED.computed_at;
            """)

            records_fv = df_features.to_dict(orient="records")
            with self.engine.begin() as conn:
                conn.execute(sql_fv, records_fv)
            logger.info(f"Successfully upserted {len(records_fv)} feature vectors to database.")
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

    def write_attack_scenario(
        self,
        scenario_name: str,
        attack_type: str,
        start_time: datetime,
        end_time: datetime,
        attacker_ip: str
    ) -> None:
        """Writes a detected or simulated attack scenario record to attack_scenarios table."""
        valid_types = {'ssh_bruteforce', 'web_bruteforce', 'ddos', 'dos', 'portscan', 'other'}
        atk_type = attack_type.lower() if attack_type else 'other'
        if atk_type not in valid_types:
            if 'brute' in atk_type or 'ssh' in atk_type:
                atk_type = 'ssh_bruteforce'
            elif 'web' in atk_type:
                atk_type = 'web_bruteforce'
            elif 'ddos' in atk_type:
                atk_type = 'ddos'
            elif 'dos' in atk_type:
                atk_type = 'dos'
            elif 'scan' in atk_type:
                atk_type = 'portscan'
            else:
                atk_type = 'other'

        query = text("""
            INSERT INTO attack_scenarios (scenario_name, attack_type, start_time, end_time, attacker_ip)
            VALUES (:scenario_name, :attack_type, :start_time, :end_time, :attacker_ip)
        """)
        try:
            with self.engine.begin() as conn:
                conn.execute(query, {
                    "scenario_name": str(scenario_name)[:100],
                    "attack_type": atk_type,
                    "start_time": start_time,
                    "end_time": end_time,
                    "attacker_ip": str(attacker_ip)[:45]
                })
            logger.info(f"Successfully recorded attack scenario '{scenario_name}' for IP {attacker_ip} in database.")
        except Exception as e:
            logger.error(f"Error writing attack scenario to database: {e}")

    def write_evaluation_metrics(
        self,
        run_id: str,
        model_config_name: str,
        dataset_split: str,
        precision: float,
        recall: float,
        f1: float,
        fpr: float = 0.0,
        roc_auc: float = 0.5,
        latency_ms_avg: float = None,
        latency_ms_p95: float = None,
        throughput_events_per_sec: float = None,
        cpu_usage_percent: float = None,
        ram_usage_mb: float = None,
        hyperparameters: dict = None,
        model_version: str = "cascade-v1.0"
    ) -> None:
        """Writes model evaluation metrics into evaluation_metrics table matching schema.sql."""
        valid_configs = {'wazuh_rule_only', 'iforest_only', 'ocsvm_only', 'cascade_iforest_ocsvm', 'cascade-v1.0'}
        cfg_name = model_config_name if model_config_name in valid_configs else 'cascade_iforest_ocsvm'

        query = text("""
            INSERT INTO evaluation_metrics (
                run_id, model_config, model_version, dataset_split,
                precision_score, recall_score, f1_score, false_positive_rate, roc_auc,
                latency_ms_avg, latency_ms_p95, throughput_events_per_sec,
                cpu_usage_percent, ram_usage_mb,
                hyperparameters, evaluated_at
            )
            VALUES (
                :run_id, :model_config, :model_version, :dataset_split,
                :precision_score, :recall_score, :f1_score, :false_positive_rate, :roc_auc,
                :latency_ms_avg, :latency_ms_p95, :throughput_events_per_sec,
                :cpu_usage_percent, :ram_usage_mb,
                :hyperparameters, :evaluated_at
            )
            ON CONFLICT (run_id, model_config, dataset_split) DO UPDATE SET
                precision_score = EXCLUDED.precision_score,
                recall_score = EXCLUDED.recall_score,
                f1_score = EXCLUDED.f1_score,
                false_positive_rate = EXCLUDED.false_positive_rate,
                roc_auc = EXCLUDED.roc_auc,
                latency_ms_avg = EXCLUDED.latency_ms_avg,
                latency_ms_p95 = EXCLUDED.latency_ms_p95,
                throughput_events_per_sec = EXCLUDED.throughput_events_per_sec,
                cpu_usage_percent = EXCLUDED.cpu_usage_percent,
                ram_usage_mb = EXCLUDED.ram_usage_mb,
                hyperparameters = EXCLUDED.hyperparameters,
                evaluated_at = EXCLUDED.evaluated_at
        """)

        if not self.db_url:
            logger.warning("DATABASE_URL is not set. Skipping database metric write.")
            return

        try:
            with self.engine.begin() as conn:
                conn.execute(query, {
                    "run_id": str(run_id)[:100],
                    "model_config": cfg_name,
                    "model_version": str(model_version)[:50],
                    "dataset_split": str(dataset_split)[:50],
                    "precision_score": min(max(float(precision), 0.0), 1.0) if precision is not None else None,
                    "recall_score": min(max(float(recall), 0.0), 1.0) if recall is not None else None,
                    "f1_score": min(max(float(f1), 0.0), 1.0) if f1 is not None else None,
                    "false_positive_rate": min(max(float(fpr), 0.0), 1.0) if fpr is not None else None,
                    "roc_auc": min(max(float(roc_auc), 0.0), 1.0) if roc_auc is not None else None,
                    "latency_ms_avg": float(latency_ms_avg) if latency_ms_avg is not None else None,
                    "latency_ms_p95": float(latency_ms_p95) if latency_ms_p95 is not None else None,
                    "throughput_events_per_sec": float(throughput_events_per_sec) if throughput_events_per_sec is not None else None,
                    "cpu_usage_percent": float(cpu_usage_percent) if cpu_usage_percent is not None else None,
                    "ram_usage_mb": float(ram_usage_mb) if ram_usage_mb is not None else None,
                    "hyperparameters": json.dumps(hyperparameters or {}),
                    "evaluated_at": datetime.now(timezone.utc)
                })
            logger.info(f"Successfully recorded evaluation metrics (Run ID: {run_id}) to database.")
        except Exception as e:
            logger.warning(f"Could not record evaluation metrics to database (DB offline/unreachable): {e}")

    def write_model_comparison_benchmark(
        self,
        benchmark_run_id: str,
        model_name: str,
        dataset_name: str = "CICIDS2017",
        accuracy: float = None,
        precision: float = None,
        recall: float = None,
        f1: float = None,
        roc_auc: float = None,
        pr_auc: float = None,
        fpr: float = None,
        fnr: float = None,
        training_time_sec: float = None,
        latency_mean_ms: float = None,
        latency_p99_ms: float = None,
        throughput_rows_sec: float = None,
    ) -> None:
        """Writes model comparison benchmark to standard evaluation_metrics table in schema.sql."""
        cfg_name = 'cascade_iforest_ocsvm'
        if 'iforest' in model_name.lower() and 'ocsvm' not in model_name.lower():
            cfg_name = 'iforest_only'
        elif 'ocsvm' in model_name.lower() and 'iforest' not in model_name.lower():
            cfg_name = 'ocsvm_only'
        elif 'rule' in model_name.lower() or 'wazuh' in model_name.lower():
            cfg_name = 'wazuh_rule_only'

        self.write_evaluation_metrics(
            run_id=benchmark_run_id,
            model_config_name=cfg_name,
            model_version=model_name[:50],
            dataset_split=dataset_name[:50],
            precision=precision,
            recall=recall,
            f1=f1,
            fpr=fpr,
            roc_auc=roc_auc,
            latency_ms_avg=latency_mean_ms,
            latency_ms_p95=latency_p99_ms,
            throughput_events_per_sec=throughput_rows_sec,
            hyperparameters={"accuracy": accuracy, "pr_auc": pr_auc, "fnr": fnr, "training_time_sec": training_time_sec}
        )

    def write_per_attack_category_metrics(
        self,
        evaluation_run_id: str,
        model_version: str,
        attack_category: str,
        total_samples: int,
        detected_count: int,
        missed_count: int,
        detection_rate: float,
        false_alarm_count: int = 0,
    ) -> None:
        """Writes per-attack category detection metrics to standard evaluation_metrics table in schema.sql."""
        self.write_evaluation_metrics(
            run_id=f"{evaluation_run_id}_{attack_category[:20]}",
            model_config_name='cascade_iforest_ocsvm',
            model_version=model_version[:50],
            dataset_split=attack_category[:50],
            precision=0.0,
            recall=detection_rate,
            f1=0.0,
            hyperparameters={
                "attack_category": attack_category,
                "total_samples": total_samples,
                "detected_count": detected_count,
                "missed_count": missed_count,
                "false_alarm_count": false_alarm_count
            }
        )


# Class alias for backward compatibility
DatabaseClient = DBClient
