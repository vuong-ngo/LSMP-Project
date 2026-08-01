# ============================================================================
# file: src/lsmp_ai/scripts/status.py
# Description: Operational Program Status & Model Parameter Inspector.
#              Displays active model hyper-parameters, thresholds, database connectivity,
#              serving daemon status, and risk classification rules.
# ============================================================================

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.config_loader import config
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.pipeline.serve_pipeline import get_last_watermark
from lsmp_ai.common.constants import FEATURE_COLUMNS

logger = setup_logger(__name__)


def show_program_status() -> dict:
    """Inspects and displays operational parameters of the active LSMP AI Engine."""
    print("=" * 80)
    print("📋 LSMP AI ENGINE — OPERATIONAL PROGRAM & MODEL PARAMETER STATUS")
    print("=" * 80)

    status_data = {}

    # 1. Active Model Catalog Inspection
    models_dir = BASE_DIR / "models_store"
    catalog_path = models_dir / "catalog.json"

    if catalog_path.exists():
        try:
            with open(catalog_path, "r") as f:
                catalog = json.load(f)
            latest_ver = catalog.get("latest_version", "cascade-v1.0")
            model_info = catalog.get(latest_ver, {})
            metrics = model_info.get("metrics", {})
            hparams = model_info.get("hyperparameters", {})

            print("\n🤖 [ACTIVE MODEL CONFIGURATION]")
            print(f"  • Active Model Version:        {latest_ver}")
            print(f"  • Registration Date:           {model_info.get('registered_at', 'N/A')}")
            print(f"  • iForest Anomaly Threshold:   {hparams.get('iforest_anomaly_threshold', -0.6):.4f}")
            print(f"  • iForest Normal Threshold:    {hparams.get('iforest_normal_threshold', -0.45):.4f}")

            iforest_p = hparams.get("iforest_params", {})
            print(f"  • Isolation Forest Hyperparams: n_estimators={iforest_p.get('n_estimators', 100)}, contamination={iforest_p.get('contamination', 0.05)}")

            ocsvm_p = hparams.get("ocsvm_params", {})
            print(f"  • One-Class SVM Hyperparams:   kernel='{ocsvm_p.get('kernel', 'rbf')}', nu={ocsvm_p.get('nu', 0.05)}, gamma='{ocsvm_p.get('gamma', 'scale')}'")

            print("\n📊 [MODEL EVALUATION METRICS]")
            print(f"  • Accuracy:                    {metrics.get('accuracy', 0.0)*100:.2f}%")
            print(f"  • Precision:                   {metrics.get('precision', 0.0)*100:.2f}%")
            print(f"  • Recall (Sensitivity):        {metrics.get('recall', 0.0)*100:.2f}%")
            print(f"  • F1-Score:                    {metrics.get('f1_score', 0.0)*100:.2f}%")
            print(f"  • ROC-AUC Score:               {metrics.get('roc_auc', 0.5):.4f}")
            print(f"  • False Positive Rate (FPR):   {metrics.get('false_positive_rate', 0.0)*100:.2f}%")

            status_data["active_version"] = latest_ver
            status_data["metrics"] = metrics
            status_data["hyperparameters"] = hparams
        except Exception as err:
            print(f"  [!] Warning: Error reading catalog.json: {err}")
    else:
        print("\n⚠️ [ACTIVE MODEL CONFIGURATION]")
        print("  • No active model registered yet in models_store/catalog.json")

    # 2. Feature Dimension Info
    print("\n📐 [FEATURE VECTOR PIPELINE]")
    print(f"  • Total AI Feature Dimension:  {len(FEATURE_COLUMNS)} Features")
    print(f"  • Feature Names:               {', '.join(FEATURE_COLUMNS[:5])} ... ({len(FEATURE_COLUMNS)-5} more)")

    # 3. Database Connection & Schema Status
    print("\n🗄️ [DATABASE CONNECTION & TABLES]")
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        print(f"  • Database Connection String:  Configured ({db_url.split('@')[-1] if '@' in db_url else 'Set'})")
        try:
            from lsmp_ai.io.db_client import DBClient
            db_client = DBClient()
            tables = ["log_event", "feature_vectors", "anomaly_result", "risk_score", "evaluation_metrics"]
            existing = []
            with db_client.engine.connect() as conn:
                from sqlalchemy import inspect
                inspector = inspect(db_client.engine)
                existing = inspector.get_table_names()

            found_tables = [t for t in tables if t in existing]
            print(f"  • Database Status:             ONLINE (Connected successfully)")
            print(f"  • Tables Validated ({len(found_tables)}/{len(tables)}):  {', '.join(found_tables)}")
            status_data["db_status"] = "ONLINE"
        except Exception as db_err:
            print(f"  • Database Status:             OFFLINE ({db_err})")
            status_data["db_status"] = f"OFFLINE ({db_err})"
    else:
        print("  • Database Connection String:  NOT CONFIGURED (Check .env file)")
        status_data["db_status"] = "NOT_CONFIGURED"

    # 4. Serving Daemon Process Status & Watermark
    print("\n⚙️ [REAL-TIME SERVING DAEMON STATUS]")
    pid_file = BASE_DIR / "logs" / "service.pid"
    daemon_running = False
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            import psutil
            if psutil.pid_exists(pid):
                daemon_running = True
                print(f"  • Daemon Process State:        RUNNING (PID: {pid})")
            else:
                print(f"  • Daemon Process State:        STOPPED (Stale PID: {pid})")
        except Exception:
            print("  • Daemon Process State:        STOPPED")
    else:
        print("  • Daemon Process State:        STOPPED")

    last_wm = get_last_watermark()
    print(f"  • Last Log Watermark Timestamp: {last_wm.isoformat() if last_wm else 'None (No logs processed yet)'}")
    status_data["daemon_running"] = daemon_running

    # 5. Risk Scoring Formula Parameters
    print("\n🧮 [RISK SCORING WEIGHTS & THRESHOLDS]")
    r_p = config.risk_params
    c_p = config.risk_classification_params
    alpha = float(r_p.get("alpha", 0.6))
    beta = float(r_p.get("beta", 0.4))
    low_t = float(c_p.get("low_threshold", 25.0))
    med_t = float(c_p.get("medium_threshold", 50.0))
    high_t = float(c_p.get("high_threshold", 80.0))
    print(f"  • Risk Formula: RiskScore = 100 * [ {alpha:.2f} * AI_Score + {beta:.2f} * Wazuh_Severity/15.0 ]")
    print(f"  • Risk Classes: Low (< {low_t}), Medium (< {med_t}), High (< {high_t}), Critical (>= {high_t})")
    print("=" * 80)

    return status_data


def main():
    show_program_status()


if __name__ == "__main__":
    main()
