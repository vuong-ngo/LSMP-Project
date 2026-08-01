# ============================================================================
# file: src/lsmp_ai/scripts/export_db.py
# Description: Export and sync all registered AI model catalog versions and metrics to Database.
# ============================================================================

import os
import sys
import json
import argparse
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.io.db_client import DBClient

logger = setup_logger(__name__)


def export_models_to_db(db_url: str = None) -> bool:
    """Syncs all registered model catalog versions and evaluation metrics into PostgreSQL/TimescaleDB."""
    print("=" * 80)
    print("🚀 EXPORTING ALL REGISTERED MODEL VERSIONS & METRICS TO DATABASE")
    print("=" * 80)

    client = DBClient(db_url=db_url)

    if not client.db_url:
        print("❌ [DATABASE ERROR] DATABASE_URL is not set. Please export DATABASE_URL variable or set in .env")
        return False

    models_dir = BASE_DIR / "models_store"
    catalog_path = models_dir / "catalog.json"

    if not catalog_path.exists():
        print(f"⚠️ [CATALOG WARNING] No catalog.json found at {catalog_path}. Train a model first using `lsmp-ai train`.")
        return False

    with open(catalog_path, "r") as f:
        catalog = json.load(f)

    exported_count = 0
    for version, info in catalog.items():
        if version == "latest_version":
            continue

        metrics = info.get("metrics", {})
        hparams = info.get("hyperparameters", {})
        run_id = f"export_{version}"

        try:
            client.write_evaluation_metrics(
                run_id=run_id,
                model_config_name="cascade_iforest_ocsvm",
                dataset_split=metrics.get("dataset_source", "cicids2017"),
                precision=metrics.get("precision", 0.0),
                recall=metrics.get("recall", 0.0),
                f1=metrics.get("f1_score", 0.0),
                fpr=metrics.get("false_positive_rate", 0.0),
                roc_auc=metrics.get("roc_auc", 0.5),
                latency_ms_avg=metrics.get("latency_ms_avg", 0.0),
                throughput_events_per_sec=metrics.get("throughput_events_per_sec", 0.0),
                ram_usage_mb=metrics.get("ram_usage_mb", 0.0),
                hyperparameters=hparams,
                model_version=version,
            )
            exported_count += 1
            print(f"  • Model Version '{version}': F1-Score={metrics.get('f1_score', 0.0)*100:.2f}%, Precision={metrics.get('precision', 0.0)*100:.2f}%, Recall={metrics.get('recall', 0.0)*100:.2f}% -> SYNCD TO DB")
        except Exception as err:
            logger.error(f"Failed to export metrics for version '{version}': {err}")
            print(f"  [!] Failed to sync version '{version}': {err}")

    # Also export fallback prediction results if interim predictions exist
    predictions_file = BASE_DIR / "data" / "interim" / "predictions_fallback.csv"
    if predictions_file.exists():
        try:
            df_preds = pd.read_csv(predictions_file)
            if not df_preds.empty and "score" in df_preds.columns:
                from lsmp_ai.io.result_writer import ResultWriter
                writer = ResultWriter(db_client=client)
                count = writer.write_predictions(df_preds)
                print(f"  • Prediction Risk Scores: {count} records synced to 'risk_score' table.")
        except Exception as pred_err:
            logger.warning(f"Could not export prediction results: {pred_err}")

    print("=" * 80)
    print(f"✅ EXPORT COMPLETE: Successfully synced {exported_count} model catalog versions into Database.")
    print("=" * 80)

    return exported_count > 0


def main():
    parser = argparse.ArgumentParser(description="Export & Sync LSMP Model Catalog & Metrics to Database")
    parser.add_argument("--db-url", "-d", type=str, default=None, help="Database connection URL string")
    args = parser.parse_args()

    export_models_to_db(db_url=args.db_url)


if __name__ == "__main__":
    main()
