# ============================================================================
# file: pipeline/serve_pipeline.py
# Description: Real-time batch serving pipeline for pulling logs, computing features,
#              inferring anomalies, and writing risk scores to PostgreSQL.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import uuid
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy import text

from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.exceptions import ModelNotFoundError
from lsmp_ai.io.db_client import DBClient
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline, extract_features_from_logs
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.risk_scoring.risk_score import calculate_risk_score
from lsmp_ai.risk_scoring.risk_classifier import classify_risk_score


# ===== SERVE PIPELINE FUNCTION =====
def run_serve_pipeline(
    start_time: datetime,
    end_time: datetime,
    model_version: Optional[str] = None,
    db_url: Optional[str] = None
) -> pd.DataFrame:
    """
    Executes a single batch inference loop:
    1. Loads the active model and feature pipeline.
    2. Pulls new raw events (log_event) from database for the given time window.
    3. Runs Feature Engineering to extract 14 security features.
    4. Infers anomaly scores using the CascadeModel.
    5. Computes combined risk scores and creates separate anomaly_result and risk_score records.
    6. Writes predictions to PostgreSQL.
    """
    logger.info(f"Executing serving pipeline from {start_time} to {end_time}...")
    
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
    
    # 2. Fetch Raw Alerts from DB and Run Feature Engineering
    db_client = DBClient(db_url)
    try:
        table_name = config.db_tables.get('wazuh_alerts', 'log_event') if (config and hasattr(config, "db_tables") and config.db_tables) else 'log_event'
        query = f"""
            SELECT * FROM {table_name}
            WHERE timestamp >= :start_time AND timestamp <= :end_time
        """
        logger.info(f"Fetching raw events from DB table: {table_name}")
        
        with db_client.engine.connect() as conn:
            df_raw = pd.read_sql(text(query), conn, params={"start_time": start_time, "end_time": end_time})
            
        logger.info(f"Fetched {len(df_raw)} raw alerts between {start_time} and {end_time}.")
        
        if df_raw.empty:
            logger.info("No raw alerts found in the specified window. Nothing to process.")
            return pd.DataFrame()
            
        # Map source_ip to src_ip for Feature Engineering compatibility
        if 'source_ip' in df_raw.columns:
            df_raw['src_ip'] = df_raw['source_ip']
            
        # Extract 14 security features from raw alerts
        df_features = extract_features_from_logs(df_raw, window_start=start_time)
        
        if df_features.empty:
            logger.info("No feature vectors generated. Empty alerts or missing src_ip.")
            return pd.DataFrame()
        
        # Persist feature vectors to feature_vectors table for easy querying
        try:
            db_client.write_feature_vectors(df_features)
        except Exception as fv_err:
            logger.warning(f"Could not persist feature vectors: {fv_err}")
        
    except Exception as e:
        logger.warning(f"Failed database interaction: {e}. Falling back to offline dataset.csv for simulation.")
        fallback_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
            "data", "processed", "dataset.csv"
        )
        if os.path.exists(fallback_path):
            df_features = pd.read_csv(fallback_path).head(5)
            df_features['window_start'] = pd.to_datetime(df_features['window_start'], utc=True)
        else:
            raise e

    # 3. Preprocess and Run Cascade Model Inference
    X_scaled = feat_pipeline.transform(df_features)
    df_detailed = cascade_model.predict_detailed(X_scaled)
    
    # 4. Process predictions, compute Risk Score and split into two tables
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
        
        ip_alerts = df_raw[df_raw['source_ip'] == ip] if ('df_raw' in locals() and 'source_ip' in df_raw.columns) else pd.DataFrame()
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
        stage1_score = float(ip_detailed['stage1_score'])
        stage2_score = float(ip_detailed['stage2_score']) if pd.notna(ip_detailed['stage2_score']) else None
        
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
    
    # 5. Save Results to PostgreSQL
    try:
        db_client.write_predictions(df_anomaly, df_risk)
    except Exception as e:
        logger.warning(f"Could not write predictions to database: {e}.")
    
    logger.info("Serving pipeline execution complete.")
    return df_risk
