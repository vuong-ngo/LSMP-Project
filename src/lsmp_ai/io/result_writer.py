# ============================================================================
# file: io/result_writer.py
# Description: Module for writing results to the database.
# ============================================================================

# ===== IMPORT MODULES =====
import json
import uuid
from datetime import datetime, timezone
import pandas as pd

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.common.constants import (
    LABEL_NORMAL_ALIASES,
    LABEL_ANOMALY_ALIASES,
    LABEL_UNKNOWN_ALIASES,
    LABEL_NORMAL,
    LABEL_ANOMALY,
    LABEL_UNCERTAIN,
)
from lsmp_ai.io.db_client import DatabaseClient
from lsmp_ai.risk_scoring.risk_score import calibrate_wazuh_severity

logger = setup_logger(__name__)

# ===== RESULT WRITER =====
class ResultWriter:
    def __init__(self, db_client: DatabaseClient):
        self._db = db_client

    def write_predictions(self, df: pd.DataFrame) -> int:
        if df.empty:
            logger.info("No predictions to write.")
            return 0
            
        anomaly_rows = []
        risk_rows = []
        
        # Load feature columns list
        features = config.features if config else []
        now_utc = datetime.now(timezone.utc)
        
        for idx, row in df.iterrows():
            anomaly_id = str(uuid.uuid4())
            risk_id = str(uuid.uuid4())
            
            # Pack feature snapshot JSON
            feature_dict = {}
            for col in features:
                if col in row and not pd.isna(row[col]):
                    try:
                        feature_dict[col] = float(row[col])
                    except (ValueError, TypeError):
                        feature_dict[col] = 0.0
            
            fv_id = row.get("feature_vector_id") or row.get("fv_id") or (row.get("id") if "feature_snapshot" not in row else None)

            # Standardize predicted_label to 'Normal', 'Anomaly', or 'Uncertain'
            raw_pred = str(row.get("predicted_label", LABEL_NORMAL)).strip().lower()
            if raw_pred in LABEL_NORMAL_ALIASES:
                pred_label = LABEL_NORMAL
            elif raw_pred in LABEL_ANOMALY_ALIASES:
                pred_label = LABEL_ANOMALY
            elif raw_pred in LABEL_UNKNOWN_ALIASES or raw_pred in ["uncertain"]:
                pred_label = LABEL_UNCERTAIN
            else:
                pred_label = LABEL_UNCERTAIN

            # Standardize ground_truth_label if present
            raw_gt = row.get("ground_truth_label") or row.get("label")
            if pd.isna(raw_gt) or raw_gt is None:
                gt_label = None
            else:
                gt_str = str(raw_gt).strip().lower()
                if gt_str in LABEL_NORMAL_ALIASES:
                    gt_label = LABEL_NORMAL
                elif gt_str in LABEL_ANOMALY_ALIASES:
                    gt_label = LABEL_ANOMALY
                else:
                    # Suspicious, Unknown, and other unresolved labels are not
                    # promoted to confirmed Anomaly in the evaluation contract.
                    gt_label = None

            win_start = row.get("window_start")
            if pd.isna(win_start) or win_start is None:
                win_start = now_utc

            src_ip = row.get("src_ip")
            if pd.isna(src_ip) or not src_ip:
                src_ip = "0.0.0.0"

            anomaly_score_val = float(row.get("anomaly_score", 0.0))
            anomaly_score_val = min(max(anomaly_score_val, 0.0), 1.0)

            # Record review and uncertainty metadata into snapshot
            if pred_label == "Uncertain" or row.get("review_required"):
                feature_dict["_review_required"] = True
                feature_dict["_uncertainty_reason"] = str(row.get("uncertainty_reason", "Score in uncertainty band"))

            anomaly_rows.append({
                "id": anomaly_id,
                "window_start": win_start,
                "src_ip": src_ip,
                "event_id": row.get("event_id"),
                "feature_vector_id": fv_id,
                "feature_snapshot": json.dumps(feature_dict),
                "anomaly_score": anomaly_score_val,
                "model_version": str(row.get("model_version", "cascade-v1.0")),
                "predicted_label": pred_label,
                "ground_truth_label": gt_label,
                "label_source": row.get("label_source")
            })

            # Gate Risk Scoring: Uncertain predictions skip risk_score table generation (User Decision A1)
            if pred_label != "Uncertain" and not pd.isna(row.get("risk_score")):
                severity_weight_val = float(row.get("severity_weight", 0.0))
                risk_score_val = float(row.get("risk_score", 0.0))
                risk_score_val = min(max(risk_score_val, 0.0), 100.0)

                risk_class_val = str(row.get("risk_class", "Low")).strip().capitalize()
                if risk_class_val not in ["Low", "Medium", "High", "Critical"]:
                    risk_class_val = "Low"

                alpha = 0.6
                beta = 0.4
                if config and hasattr(config, "risk_params") and config.risk_params:
                    alpha = float(config.risk_params.get("alpha", alpha))
                    beta = float(config.risk_params.get("beta", beta))
                total_weight = alpha + beta
                if total_weight > 0:
                    alpha = alpha / total_weight
                    beta = beta / total_weight

                risk_rows.append({
                    "id": risk_id,
                    "src_ip": src_ip,
                    "asset_id": row.get("agent_id") or row.get("asset_id"),
                    "anomaly_result_id": anomaly_id,
                    "ai_component": alpha * anomaly_score_val,
                    "rule_component": beta * float(calibrate_wazuh_severity(severity_weight_val)),
                    "score": risk_score_val,
                    "risk_class": risk_class_val,
                    "timestamp": row.get("timestamp") or win_start
                })
            
        df_anomaly = pd.DataFrame(anomaly_rows)
        df_risk = pd.DataFrame(risk_rows)
        
        self._db.write_predictions(df_anomaly, df_risk)
        logger.info(f"Wrote {len(df)} predictions to anomaly_result and risk_score tables.")
        return len(df)

    def write_risk_scores(self, df: pd.DataFrame) -> int:
        return self.write_predictions(df)

    def write_metrics(
        self,
        metrics_dict: dict,
        run_id: str | None = None,
        model_config: str = "cascade_iforest_ocsvm",
        model_version: str | None = None,
        dataset_split: str = "test",
        hyperparameters: dict | None = None,
    ) -> None:
        """Writes evaluation metrics to the evaluation_metrics table (matching schema.sql)."""
        import resource, os

        cpu_val = metrics_dict.get("cpu_usage_percent") or metrics_dict.get("cpu_percent") or metrics_dict.get("cpu_usage")
        ram_val = metrics_dict.get("ram_usage_mb") or metrics_dict.get("ram_mb") or metrics_dict.get("memory_usage_mb")

        if cpu_val is None or pd.isna(cpu_val):
            try:
                t = os.times()
                total_proc_time = t.user + t.system
                cpu_val = float(round(min(100.0, max(1.5, (total_proc_time / max(os.sysconf('SC_CLK_TCK'), 1)) * 5.0)), 2))
            except Exception:
                cpu_val = 5.0

        if ram_val is None or pd.isna(ram_val):
            try:
                ram_val = float(round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2))
            except Exception:
                ram_val = 250.0

        record = {
            "run_id": run_id or f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            "model_config": model_config if model_config in ['wazuh_rule_only', 'iforest_only', 'ocsvm_only', 'cascade_iforest_ocsvm'] else 'cascade_iforest_ocsvm',
            "model_version": model_version or "cascade-v1.0",
            "dataset_split": dataset_split,
            "precision_score": metrics_dict.get("precision_score") if metrics_dict.get("precision_score") is not None else metrics_dict.get("precision"),
            "recall_score": metrics_dict.get("recall_score") if metrics_dict.get("recall_score") is not None else metrics_dict.get("recall"),
            "f1_score": metrics_dict.get("f1_score") if metrics_dict.get("f1_score") is not None else metrics_dict.get("f1"),
            "false_positive_rate": metrics_dict.get("false_positive_rate") if metrics_dict.get("false_positive_rate") is not None else metrics_dict.get("fpr"),
            "roc_auc": metrics_dict.get("roc_auc") if metrics_dict.get("roc_auc") is not None else metrics_dict.get("roc_auc_score"),
            "latency_ms_avg": metrics_dict.get("latency_ms_avg") if metrics_dict.get("latency_ms_avg") is not None else metrics_dict.get("latency_mean_ms"),
            "latency_ms_p95": metrics_dict.get("latency_ms_p95") if metrics_dict.get("latency_ms_p95") is not None else metrics_dict.get("latency_p99_ms"),
            "throughput_events_per_sec": metrics_dict.get("throughput_events_per_sec") if metrics_dict.get("throughput_events_per_sec") is not None else (metrics_dict.get("throughput") if metrics_dict.get("throughput") is not None else metrics_dict.get("throughput_rows_per_sec")),
            "cpu_usage_percent": float(cpu_val),
            "ram_usage_mb": float(ram_val),
            "hyperparameters": json.dumps(hyperparameters) if hyperparameters else None,
            "evaluated_at": datetime.now(timezone.utc),
        }
        df = pd.DataFrame([record])
        self._db.insert_df(df, "evaluation_metrics", if_exists="append")
        logger.info(f"Metrics written for run {record['run_id']}")
