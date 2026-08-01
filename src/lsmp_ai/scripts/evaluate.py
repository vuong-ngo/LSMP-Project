# ============================================================================
# file: src/lsmp_ai/scripts/evaluate.py
# Description: Model Comparative Ablation Study & Research Evaluation Script.
#              Evaluates iForest-Only vs OCSVM-Only vs 2-Stage Cascade (iForest + OCSVM)
#              vs Wazuh Rule-Only. Exports detailed comparison report to CSV and Database
#              to provide empirical evidence for scientific research papers & thesis.
# ============================================================================

import os
import sys
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_ANOMALY, LABEL_NORMAL
from lsmp_ai.evaluation.comparison import ModelComparator
from lsmp_ai.io.db_client import DBClient
from lsmp_ai.io.data_loader import DataLoader

logger = setup_logger(__name__)


def run_evaluation(
    db_url: str | None = None,
    dataset_path: str | Path | None = None,
    output_csv_path: str | Path | None = None,
    benchmark_runs: int = 5,
) -> bool | pd.DataFrame:
    """Executes model comparison ablation study, exports CSV report and DB metrics."""
    print("=" * 80)
    print("📊 LSMP ABLATION STUDY & MODEL COMPARISON BENCHMARK FOR RESEARCH PAPER")
    print("=" * 80)

    db_client = DBClient(db_url=db_url)
    if not db_client.db_url:
        logger.warning("DATABASE_URL is not set. Please export DATABASE_URL variable.")
        return False

    ds_path = Path(dataset_path) if dataset_path else (BASE_DIR / "data" / "processed" / "dataset.csv")
    if not ds_path.exists():
        ds_path = BASE_DIR / "data" / "train_test_split" / "test.csv"

    if not ds_path.exists():
        logger.error(f"[DATA ERROR] Dataset file not found at {ds_path}. Run `lsmp-ai prepare-data` first.")
        return False

    logger.info(f"Loading dataset from [DATA]: {ds_path}...")
    df = pd.read_csv(ds_path)
    df = DataLoader.optimize_dtypes(df)

    X = df[[c for c in FEATURE_COLUMNS if c in df.columns]]
    y = np.where(df["label"].isin([LABEL_ANOMALY, "Anomaly", 1, "1"]), 1, 0)

    split_idx = int(len(df) * 0.7)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    logger.info("Executing Comparative Benchmark across Architectures (iForest vs OCSVM vs Cascade)...")
    comparator = ModelComparator(benchmark_runs=benchmark_runs)
    df_comp, full_details = comparator.compare(X_train, X_test, y_test, y_train=y_train)

    # Output CSV Report Path
    out_csv = Path(output_csv_path) if output_csv_path else (BASE_DIR / "reports" / "results" / "ablation_study_comparison.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df_comp.to_csv(out_csv, index=True)
    logger.info(f"Successfully saved scientific evaluation CSV report to [DATA]: {out_csv}")

    # Export detailed metrics for each architecture to Database
    run_id = f"eval_ablation_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    db_client = DBClient()
    if db_client.db_url:
        for model_name, row in df_comp.iterrows():
            bench_info = full_details.get("models", {}).get(model_name, {}).get("benchmark", {})
            train_time = full_details.get("models", {}).get(model_name, {}).get("training_time_sec", 0.0)

            db_client.write_model_comparison_benchmark(
                benchmark_run_id=run_id,
                model_name=str(model_name),
                dataset_name=ds_path.name,
                accuracy=float(row.get("accuracy", 0.0)),
                precision=float(row.get("precision", 0.0)),
                recall=float(row.get("recall", 0.0)),
                f1=float(row.get("f1_score", 0.0)),
                roc_auc=float(row.get("roc_auc", 0.5)),
                pr_auc=float(row.get("pr_auc", 0.0)),
                fpr=float(row.get("false_positive_rate", 0.0)),
                fnr=float(row.get("false_negative_rate", 0.0)),
                training_time_sec=float(train_time),
                latency_mean_ms=float(bench_info.get("latency_mean_ms", 0.0)),
                latency_p99_ms=float(bench_info.get("latency_p99_ms", 0.0)),
                throughput_rows_sec=float(bench_info.get("throughput_rows_per_sec", 0.0)),
            )
        logger.info(f"Successfully recorded research comparison metrics for run '{run_id}' into Database.")

    print("\n" + "=" * 80)
    print("🎯 SCIENTIFIC MODEL ABLATION STUDY COMPARISON TABLE")
    print("=" * 80)
    print(f"{'Model Architecture':<30} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'ROC-AUC':<10} | {'FPR':<10}")
    print("-" * 88)
    for idx, row in df_comp.iterrows():
        print(
            f"{str(idx):<30} | "
            f"{row.get('precision', 0.0)*100:>9.2f}% | "
            f"{row.get('recall', 0.0)*100:>9.2f}% | "
            f"{row.get('f1_score', 0.0)*100:>9.2f}% | "
            f"{row.get('roc_auc', 0.0):>10.4f} | "
            f"{row.get('false_positive_rate', 0.0)*100:>9.2f}%"
        )
    print("-" * 88)
    print(f"✅ CSV Report Export Location: {out_csv}")
    print("=" * 80)

    return df_comp


def main():
    parser = argparse.ArgumentParser(description="LSMP Model Ablation Study & Research Evaluation Script")
    parser.add_argument("--dataset", "-f", type=str, default=None, help="[DATA] Path to input evaluation dataset CSV")
    parser.add_argument("--output", "-o", type=str, default=None, help="[DATA] Path for output comparison CSV report")
    parser.add_argument("--runs", "-r", type=int, default=5, help="Number of benchmark runs for latency measurement (default: 5)")
    args = parser.parse_args()

    run_evaluation(dataset_path=args.dataset, output_csv_path=args.output, benchmark_runs=args.runs)


if __name__ == "__main__":
    main()
