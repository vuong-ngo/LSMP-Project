# ============================================================================
# file: src/lsmp_ai/scripts/train.py
# Description: Production Training Script for LSMP 2-Stage Cascade AI Engine.
#              Fits Isolation Forest & One-Class SVM on pure benign baseline data,
#              evaluates comprehensive metrics, registers model catalog,
#              and exports detailed scientific benchmark metrics to Database.
# ============================================================================

import os
import sys
import time
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.evaluation.metrics import compute_classification_metrics, compute_confusion_matrix_df
from lsmp_ai.io.data_loader import DataLoader

logger = setup_logger(__name__)


def run_training(
    dataset_path: str | Path | None = None,
    model_version: str = "cascade-v1.0",
    test_size: float = 0.3,
    do_grid_search: bool = False,
) -> dict:
    """Executes the production Cascade Model training, evaluation, and DB registration pipeline."""
    print("=" * 80)
    print(f"🚀 LSMP AI ENGINE — PRODUCTION MODEL TRAINING PIPELINE ({model_version})")
    print("=" * 80)

    # 1. Load Dataset
    if dataset_path:
        input_path = Path(dataset_path).resolve()
        if not input_path.exists():
            raise FileNotFoundError(f"[DATA ERROR] Specified dataset file does not exist: {input_path}")
        logger.info(f"Loading custom dataset from [DATA]: {input_path}...")
        df_full = pd.read_csv(input_path)
        dataset_source = str(input_path)
    else:
        full_dataset_path = BASE_DIR / "data" / "processed" / "dataset.csv"
        train_path = BASE_DIR / "data" / "train_test_split" / "train.csv"
        test_path = BASE_DIR / "data" / "train_test_split" / "test.csv"

        if full_dataset_path.exists():
            logger.info(f"Loading primary dataset from [DATA]: {full_dataset_path}...")
            df_full = pd.read_csv(full_dataset_path)
            dataset_source = "data/processed/dataset.csv"
        elif train_path.exists() and test_path.exists():
            logger.info(f"Loading pre-split dataset files from [DATA]: {train_path} and {test_path}...")
            df_train = pd.read_csv(train_path)
            df_test = pd.read_csv(test_path)
            df_full = pd.concat([df_train, df_test], ignore_index=True)
            dataset_source = "data/train_test_split/ (Combined)"
        else:
            raise FileNotFoundError(f"[DATA ERROR] Dataset files not found in {BASE_DIR / 'data'}. Run `lsmp-ai prepare-data` first.")

    # 2. Optimize Dtypes & Extract Labels
    df_full = DataLoader.optimize_dtypes(df_full)

    if 'label' not in df_full.columns:
        df_full['label'] = LABEL_NORMAL

    df_normal = df_full[(df_full['label'] == LABEL_NORMAL) | (df_full['label'] == 'Normal') | (df_full['label'] == 0)]
    df_anomaly = df_full[(df_full['label'] == LABEL_ANOMALY) | (df_full['label'] == 'Anomaly') | (df_full['label'] == 1)]

    # Rule for Unsupervised One-Class Training:
    # - Train set MUST contain ONLY pure BENIGN/NORMAL traffic.
    # - Test set contains remaining BENIGN traffic + ALL ATTACK/ANOMALY traffic.
    if not df_normal.empty and not df_anomaly.empty:
        df_normal_train, df_normal_test = train_test_split(
            df_normal, 
            test_size=test_size, 
            random_state=42
        )
        train_df = df_normal_train.reset_index(drop=True)
        test_df = pd.concat([df_normal_test, df_anomaly], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    else:
        train_df, test_df = train_test_split(df_full, test_size=test_size, random_state=42)

    total_samples = len(train_df) + len(test_df)
    logger.info(f"Training set size (Pure Benign): {len(train_df):,} rows | Test set size (Mixed): {len(test_df):,} rows")

    # 3. Fit Feature Pipeline Scaler
    feat_pipeline = FeaturePipeline()
    X_train_scaled = feat_pipeline.fit_transform(train_df)
    X_test_scaled = feat_pipeline.transform(test_df)

    # 4. Initialize & Train 2-Stage Cascade Model
    if do_grid_search:
        logger.info("Executing Grid Search hyperparameter tuning before model fitting...")
        from lsmp_ai.models.hyperparameter_search import HyperparameterSearch
        search = HyperparameterSearch()
        search_res = search.search(X_train_scaled, train_df["label"].values)
        cascade_model = CascadeModel(
            iforest_params=search_res.get("iforest_params", {}),
            ocsvm_params=search_res.get("ocsvm_params", {}),
            threshold_percentile=15.0,
            cascade_params={"model_version": model_version}
        )
    else:
        cascade_model = CascadeModel(
            threshold_percentile=15.0,
            cascade_params={"model_version": model_version}
        )

    t0 = time.time()
    cascade_model.fit(X_train_scaled, train_df["label"].values)
    fit_time = time.time() - t0

    # 5. Predict & Benchmark Inference Performance
    t_inf_start = time.time()
    preds = cascade_model.predict(X_test_scaled)
    scores = cascade_model.score(X_test_scaled)
    inf_time = time.time() - t_inf_start

    eps = len(test_df) / max(inf_time, 1e-5)
    latency_ms_avg = (inf_time / len(test_df)) * 1000.0

    ram_mb = 0.0
    try:
        import psutil
        process = psutil.Process(os.getpid())
        ram_mb = process.memory_info().rss / (1024 * 1024)
    except Exception:
        pass

    # 6. Compute Comprehensive Research Metrics
    y_true = test_df["label"].values
    metrics = compute_classification_metrics(y_true, preds, y_score=scores)
    metrics["dataset_source"] = dataset_source
    metrics["total_samples"] = total_samples
    metrics["train_samples"] = len(train_df)
    metrics["test_samples"] = len(test_df)
    metrics["training_time_sec"] = round(fit_time, 4)
    metrics["throughput_events_per_sec"] = round(eps, 2)
    metrics["latency_ms_avg"] = round(latency_ms_avg, 4)

    # 7. Register Artifacts & Catalog Version (Overwrites if version tag exists)
    registry_dir = BASE_DIR / "models_store"
    registry = ModelRegistry(registry_dir=str(registry_dir))
    registered_version = registry.register_model(cascade_model, metrics=metrics)
    pipeline_path = registry_dir / registered_version / "feature_pipeline.joblib"
    feat_pipeline.save(str(pipeline_path))

    # 8. Export Detailed Research Metrics to Database Table
    try:
        from lsmp_ai.io.db_client import DBClient
        db_client = DBClient()
        if db_client.db_url:
            db_client.write_evaluation_metrics(
                run_id=f"train_{registered_version}",
                model_config_name="cascade_iforest_ocsvm",
                dataset_split="cicids2017",
                precision=metrics.get("precision", 0.0),
                recall=metrics.get("recall", 0.0),
                f1=metrics.get("f1_score", 0.0),
                fpr=metrics.get("false_positive_rate", 0.0),
                roc_auc=metrics.get("roc_auc", 0.5),
                latency_ms_avg=latency_ms_avg,
                throughput_events_per_sec=eps,
                ram_usage_mb=ram_mb,
                hyperparameters=getattr(cascade_model, "cascade_params", {}),
                model_version=registered_version,
            )
            logger.info(f"Successfully exported research evaluation metrics for '{registered_version}' to Database.")
    except Exception as db_err:
        logger.warning(f"Could not record model metrics to DB: {db_err}")

    print("\n" + "=" * 80)
    print(f"🎯 PRODUCTION TRAINING COMPLETED SUCCESSFULLY (Version: {registered_version})")
    print("=" * 80)
    print(f"  • Accuracy:              {metrics['accuracy'] * 100:.2f}%")
    print(f"  • Precision:             {metrics['precision'] * 100:.2f}%")
    print(f"  • Recall (Sensitivity):  {metrics['recall'] * 100:.2f}%")
    print(f"  • F1-Score:              {metrics['f1_score'] * 100:.2f}%")
    print(f"  • ROC-AUC Score:         {metrics.get('roc_auc', 0.5):.4f}")
    print(f"  • False Positive Rate:   {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"  • Training Time:         {fit_time:.2f} seconds")
    print(f"  • Throughput:            {eps:,.1f} events/sec")
    print(f"  • Model Location:        models_store/{registered_version}/")
    print("=" * 80)

    return metrics


def main():
    parser = argparse.ArgumentParser(description="LSMP Production AI Cascade Model Training Script")
    parser.add_argument("--dataset", "-f", type=str, default=None, help="[DATA] Path to input training dataset CSV")
    parser.add_argument("--model-version", "-v", type=str, default="cascade-v1.0", help="Model version identifier to register")
    parser.add_argument("--test-size", "-s", type=float, default=0.3, help="Test dataset split ratio (default: 0.3)")
    parser.add_argument("--grid-search", "-g", action="store_true", help="Execute hyperparameter GridSearch tuning before fitting")
    args = parser.parse_args()

    run_training(
        dataset_path=args.dataset,
        model_version=args.model_version,
        test_size=args.test_size,
        do_grid_search=args.grid_search,
    )


if __name__ == "__main__":
    main()
