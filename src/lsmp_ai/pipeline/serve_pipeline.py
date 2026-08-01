# ============================================================================
# file: pipeline/serve_pipeline.py
# Description: Real-time batch serving pipeline for pulling new logs, computing features,
#              inferring anomalies, and writing risk scores to PostgreSQL cleanly
#              without duplicate recalculation on stale data.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import uuid
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional
from pathlib import Path
from sqlalchemy import text

from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.exceptions import ModelNotFoundError
from lsmp_ai.io.db_client import DBClient
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline, extract_features_from_logs
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.risk_scoring.risk_score import calculate_risk_score
from lsmp_ai.risk_scoring.risk_classifier import classify_risk_score


STATE_FILE = Path(__file__).resolve().parent.parent.parent.parent / "data" / "interim" / "serving_watermark.json"


def get_last_watermark() -> Optional[datetime]:
    """Reads last processed timestamp watermark to prevent reprocessing stale logs."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                ts_str = data.get("last_processed_timestamp")
                if ts_str:
                    return datetime.fromisoformat(ts_str)
        except Exception:
            pass
    return None


def save_last_watermark(ts: datetime) -> None:
    """Persists last processed timestamp watermark atomically."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = STATE_FILE.with_suffix(".tmp")
    try:
        with open(temp_file, "w") as f:
            json.dump({"last_processed_timestamp": ts.isoformat()}, f, indent=4)
        temp_file.replace(STATE_FILE)
    except Exception as e:
        logger.warning(f"Could not save watermark state: {e}")



# ===== SERVE PIPELINE FUNCTION =====
def run_serve_pipeline(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    model_version: Optional[str] = None,
    db_url: Optional[str] = None,
    allow_simulation_fallback: bool = False
) -> pd.DataFrame:
    """
    Executes a single batch inference loop:
    1. Loads the active model and feature pipeline.
    2. Pulls ONLY new raw events (log_event) from database since last watermark.
    3. If no new logs exist, exits cleanly without recalculating stale risk scores.
    4. Runs Feature Engineering and CascadeModel Inference.
    5. Computes combined risk scores and writes predictions to PostgreSQL.
    """
    now_utc = datetime.now(timezone.utc)

    if end_time is None:
        end_time = now_utc

    if start_time is None:
        last_wm = get_last_watermark()
        if last_wm is not None:
            start_time = last_wm
        else:
            start_time = end_time - timedelta(minutes=10)

    logger.info(f"Executing serving pipeline for window: {start_time.isoformat()} -> {end_time.isoformat()}...")

    # 1. Load Registry and Model
    registry = ModelRegistry()
    try:
        cascade_model = registry.load_model(model_version)
        version = cascade_model.model_version
    except Exception as e:
        logger.error(f"Failed to load cascade model: {e}")
        raise ModelNotFoundError(f"Serving model could not be loaded: {e}")

    # Load corresponding feature pipeline
    pipeline_path = os.path.join(registry.registry_dir, version, "feature_pipeline.joblib")
    if not os.path.exists(pipeline_path):
        raise ModelNotFoundError(f"Feature pipeline for version {version} not found at {pipeline_path}")
    feat_pipeline = FeaturePipeline.load(pipeline_path)

    # 2. Fetch Raw Alerts from DB
    db_client = DBClient(db_url)
    df_raw = pd.DataFrame()

    try:
        table_name = config.db_tables.get('wazuh_alerts', 'log_event') if (config and hasattr(config, "db_tables") and config.db_tables) else 'log_event'
        query = f"""
            SELECT * FROM {table_name}
            WHERE timestamp > :start_time AND timestamp <= :end_time
            ORDER BY timestamp ASC
        """

        with db_client.engine.connect() as conn:
            df_raw = pd.read_sql(text(query), conn, params={"start_time": start_time, "end_time": end_time})

        logger.info(f"Fetched {len(df_raw)} new raw log events from DB table '{table_name}'.")
    except Exception as e:
        logger.warning(f"Database query for new logs encountered an issue: {e}")
        if allow_simulation_fallback:
            logger.info("Simulation mode enabled: loading sample fallback dataset.")
            fallback_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "processed" / "dataset.csv"
            if fallback_path.exists():
                df_features = pd.read_csv(fallback_path).head(5)
                if 'window_start' not in df_features.columns:
                    df_features['window_start'] = start_time
                else:
                    df_features['window_start'] = pd.to_datetime(df_features['window_start'], utc=True)
                if 'src_ip' not in df_features.columns:
                    df_features['src_ip'] = '192.168.1.100'
                # Skip watermark update for offline simulation
                return _process_and_save_predictions(df_features, pd.DataFrame(), cascade_model, feat_pipeline, version, start_time, end_time, db_client)

        # If DB query failed or no simulation allowed, exit safely without duplicate recalculation
        return pd.DataFrame()

    # IF NO NEW LOGS EXIST: Apply decay to baseline normal risk level (Low Risk < 25.0)
    if df_raw.empty:
        logger.info("🟢 No new raw logs found for current window. Service idle: Applying score decay to baseline normal risk level.")
        df_decay = apply_decay_to_baseline_risk(db_client, end_time)
        save_last_watermark(end_time)
        return df_decay

    # Map source_ip to src_ip for Feature Engineering
    if 'source_ip' in df_raw.columns:
        df_raw['src_ip'] = df_raw['source_ip']

    # Extract 16 security features from raw alerts
    df_features = extract_features_from_logs(df_raw, window_start=start_time)

    if df_features.empty:
        logger.info("No feature vectors generated from raw logs. Applying baseline decay.")
        df_decay = apply_decay_to_baseline_risk(db_client, end_time)
        save_last_watermark(end_time)
        return df_decay

    # Persist feature vectors to feature_vectors table
    try:
        db_client.write_feature_vectors(df_features)
    except Exception as fv_err:
        logger.warning(f"Could not persist feature vectors: {fv_err}")

    # Process predictions, save, and update watermark
    df_risk = _process_and_save_predictions(df_features, df_raw, cascade_model, feat_pipeline, version, start_time, end_time, db_client)

    # Save watermark timestamp of the latest log processed
    max_log_ts = df_raw['timestamp'].max() if 'timestamp' in df_raw.columns and not df_raw['timestamp'].empty else end_time
    if isinstance(max_log_ts, str):
        max_log_ts = datetime.fromisoformat(max_log_ts)
    save_last_watermark(max_log_ts)

    return df_risk


FALLBACK_PREDS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "interim" / "predictions_fallback.csv"


def apply_decay_to_baseline_risk(db_client: DBClient, end_time: datetime) -> pd.DataFrame:
    """
    Applies time decay & baseline normal fallback (Low Risk < 25.0) when no new anomaly logs arrive.
    Prevents stale high risk scores (e.g. 70.0) from persisting indefinitely after an attack finishes.
    """
    df_prev = pd.DataFrame()
    if FALLBACK_PREDS_PATH.exists():
        try:
            df_prev = pd.read_csv(FALLBACK_PREDS_PATH)
        except Exception:
            pass

    if df_prev.empty and db_client.is_connected:
        try:
            df_prev = db_client.fetch_latest_risk_scores(limit=20)
        except Exception:
            pass

    decay_rows = []
    baseline_normal_score = 15.0  # Baseline Low Risk (< 25.0)

    if not df_prev.empty and "score" in df_prev.columns and "src_ip" in df_prev.columns:
        seen_ips = set()
        for idx, row in df_prev.iterrows():
            ip = str(row.get("src_ip", "192.168.1.100"))
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            prev_score = float(row.get("score", baseline_normal_score))
            # Exponential decay towards 15.0 baseline
            decayed_score = max(baseline_normal_score, prev_score * 0.5)
            risk_class = classify_risk_score(decayed_score)

            alpha = 0.6
            beta = 0.4
            if config and hasattr(config, "risk_params") and config.risk_params:
                alpha = float(config.risk_params.get("alpha", alpha))
                beta = float(config.risk_params.get("beta", beta))

            asset_id = str(row.get("asset_id", "agent-001"))
            decay_rows.append({
                "id": str(uuid.uuid4()),
                "src_ip": ip,
                "asset_id": asset_id,
                "anomaly_result_id": None,
                "ai_component": alpha * decayed_score,
                "rule_component": beta * (decayed_score / 100.0 * 15.0),
                "score": round(decayed_score, 1),
                "risk_class": risk_class,
                "timestamp": end_time
            })
    else:
        decay_rows.append({
            "id": str(uuid.uuid4()),
            "src_ip": "192.168.1.100",
            "asset_id": "agent-001",
            "anomaly_result_id": None,
            "ai_component": 9.0,
            "rule_component": 6.0,
            "score": 15.0,
            "risk_class": "Low",
            "timestamp": end_time
        })

    df_decay = pd.DataFrame(decay_rows)

    # Save to local fallback file for instant dashboard rendering
    FALLBACK_PREDS_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        df_decay.to_csv(FALLBACK_PREDS_PATH, index=False)
    except Exception:
        pass

    # Save to database if connected
    if db_client.is_connected:
        try:
            db_client.write_predictions(pd.DataFrame(), df_decay)
        except Exception:
            pass

    logger.info(f"🟢 Idle system: Decayed {len(df_decay)} host risk scores to baseline normal level (Low Risk < 25.0).")
    return df_decay


def _process_and_save_predictions(
    df_features: pd.DataFrame,
    df_raw: pd.DataFrame,
    cascade_model,
    feat_pipeline,
    version: str,
    start_time: datetime,
    end_time: datetime,
    db_client: DBClient
) -> pd.DataFrame:
    """Helper method to transform features, compute risk scores, and persist predictions."""
    X_scaled = feat_pipeline.transform(df_features)
    df_detailed = cascade_model.predict_detailed(X_scaled)

    anomaly_rows = []
    risk_rows = []

    for idx, row in df_features.iterrows():
        ip = row['src_ip']

        feature_dict = {}
        for col in feat_pipeline.feature_cols:
            if col in row:
                feature_dict[col] = float(row[col])

        anomaly_id = str(uuid.uuid4())
        risk_id = str(uuid.uuid4())

        ip_alerts = df_raw[df_raw['source_ip'] == ip] if (not df_raw.empty and 'source_ip' in df_raw.columns) else pd.DataFrame()
        if not ip_alerts.empty and 'severity' in ip_alerts.columns:
            sev_val = ip_alerts['severity'].max()
            max_severity = float(sev_val) if pd.notna(sev_val) else 0.0
        else:
            max_severity = 0.0

        event_id = str(ip_alerts.iloc[0]['event_id']) if (not ip_alerts.empty and 'event_id' in ip_alerts.columns and pd.notna(ip_alerts.iloc[0]['event_id'])) else None
        agent_id = str(ip_alerts.iloc[0]['agent_id']) if (not ip_alerts.empty and 'agent_id' in ip_alerts.columns and pd.notna(ip_alerts.iloc[0]['agent_id'])) else None
        fv_id = str(row['id']) if ('id' in row and pd.notna(row['id'])) else None

        ip_detailed = df_detailed.iloc[idx]
        anomaly_score = float(ip_detailed['anomaly_score'])
        predicted_label = str(ip_detailed['predicted_label'])

        risk = calculate_risk_score(anomaly_score, max_severity)
        risk_class = classify_risk_score(risk)

        alpha = 0.6
        beta = 0.4
        if config and hasattr(config, "risk_params") and config.risk_params:
            alpha = float(config.risk_params.get("alpha", alpha))
            beta = float(config.risk_params.get("beta", beta))

        anomaly_rows.append({
            "id": anomaly_id,
            "window_start": start_time,
            "src_ip": ip,
            "event_id": event_id,
            "feature_vector_id": fv_id,
            "feature_snapshot": json.dumps(feature_dict),
            "anomaly_score": anomaly_score,
            "model_version": version,
            "predicted_label": predicted_label,
            "ground_truth_label": None,
            "label_source": None
        })

        risk_rows.append({
            "id": risk_id,
            "src_ip": ip,
            "asset_id": agent_id,
            "anomaly_result_id": anomaly_id,
            "ai_component": alpha * anomaly_score,
            "rule_component": beta * (min(max(max_severity, 0.0), 15.0) / 15.0),
            "score": risk,
            "risk_class": risk_class,
            "timestamp": datetime.now(timezone.utc)
        })

    df_anomaly = pd.DataFrame(anomaly_rows)
    df_risk = pd.DataFrame(risk_rows)

    # Save to local fallback file for instant TUI / CLI rendering
    FALLBACK_PREDS_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        df_risk.to_csv(FALLBACK_PREDS_PATH, index=False)
    except Exception:
        pass

    try:
        db_client.write_predictions(df_anomaly, df_risk)
        logger.info(f"Successfully processed and wrote {len(df_risk)} new risk score records.")
    except Exception as e:
        logger.warning(f"Could not write predictions to database: {e}")

    return df_risk
