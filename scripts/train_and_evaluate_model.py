# ============================================================================
# file: scripts/train_and_evaluate_model.py
# Description: Script to train CascadeModel (IForest + OCSVM) on custom or default
#              datasets with dynamic argparse support and accurate dataset metrics reporting.
# ============================================================================

import os
import sys
import time
import argparse
import psutil
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Ensure src/ is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.evaluation.metrics import compute_classification_metrics, compute_confusion_matrix_df

logger = setup_logger(__name__)


def main():
    parser = argparse.ArgumentParser(description="LSMP Cascade Model Training & Evaluation Script")
    parser.add_argument("--dataset", "-f", type=str, default=None, help="Path to input dataset CSV")
    parser.add_argument("--model-version", "-v", type=str, default="cascade-v2.0-clean", help="Model version identifier")
    parser.add_argument("--test-size", "-s", type=float, default=0.3, help="Test dataset split ratio")
    args = parser.parse_args()

    print("=" * 80)
    print(f"🚀 LSMP CASCADE MODEL (IForest + OCSVM) TRAINING & EVALUATION PIPELINE ({args.model_version})")
    print("=" * 80)

    if args.dataset:
        input_path = Path(args.dataset).resolve()
        if not input_path.exists():
            print(f"❌ Error: Specified dataset file does not exist: {input_path}")
            sys.exit(1)
        logger.info(f"Loading custom dataset from {input_path}...")
        df_full = pd.read_csv(input_path)
        dataset_source = str(input_path)
    else:
        full_dataset_path = BASE_DIR / "data" / "processed" / "dataset.csv"
        train_path = BASE_DIR / "data" / "train_test_split" / "train.csv"
        test_path = BASE_DIR / "data" / "train_test_split" / "test.csv"

        if full_dataset_path.exists():
            logger.info(f"Loading full dataset from {full_dataset_path}...")
            df_full = pd.read_csv(full_dataset_path)
            dataset_source = "data/processed/dataset.csv"
        elif train_path.exists() and test_path.exists():
            logger.info(f"Combining pre-split dataset files from {train_path} and {test_path}...")
            df_train = pd.read_csv(train_path)
            df_test = pd.read_csv(test_path)
            df_full = pd.concat([df_train, df_test], ignore_index=True)
            dataset_source = "data/train_test_split/ (Combined)"
        else:
            print(f"❌ Error: Dataset files not found in {BASE_DIR / 'data'}")
            print("Please run scripts/prepare_cicids2017.py or pass --dataset <file.csv>.")
            sys.exit(1)

    if 'label' not in df_full.columns:
        df_full['label'] = LABEL_NORMAL

    # Perform Unsupervised One-Class train/test split:
    # Train set = 100% PURE BENIGN/NORMAL traffic
    # Test set = Remaining BENIGN + ALL ATTACK/ANOMALY samples
    df_normal = df_full[(df_full['label'] == LABEL_NORMAL) | (df_full['label'] == 'Normal') | (df_full['label'] == 0)]
    df_anomaly = df_full[(df_full['label'] == LABEL_ANOMALY) | (df_full['label'] == 'Anomaly') | (df_full['label'] == 1)]

    if not df_normal.empty and not df_anomaly.empty:
        df_normal_train, df_normal_test = train_test_split(
            df_normal, 
            test_size=args.test_size, 
            random_state=42
        )
        train_df = df_normal_train.reset_index(drop=True)
        test_df = pd.concat([df_normal_test, df_anomaly], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    else:
        # Fallback to standard split if labels missing
        train_df, test_df = train_test_split(df_full, test_size=args.test_size, random_state=42)

    total_samples = len(train_df) + len(test_df)
    train_normal = (train_df['label'] == LABEL_NORMAL).sum()
    train_anomaly = (train_df['label'] == LABEL_ANOMALY).sum()
    test_normal = (test_df['label'] == LABEL_NORMAL).sum()
    test_anomaly = (test_df['label'] == LABEL_ANOMALY).sum()

    print(f"\n📊 ACCURATE DATASET SUMMARY:")
    print(f"  • Source Location:   {dataset_source}")
    print(f"  • Total Dataset Size:{total_samples:,} rows")
    print(f"  • Training Samples:  {len(train_df):,} (Normal: {train_normal:,}, Anomaly: {train_anomaly:,})")
    print(f"  • Testing Samples:   {len(test_df):,} (Normal: {test_normal:,}, Anomaly: {test_anomaly:,})")
    print(f"  • Feature Columns:   {len(FEATURE_COLUMNS)} vectors")

    # 2. Fit Feature Pipeline
    logger.info("Fitting FeaturePipeline (StandardScaler + SimpleImputer)...")
    feat_pipeline = FeaturePipeline()
    X_train_scaled = feat_pipeline.fit_transform(train_df)
    X_test_scaled = feat_pipeline.transform(test_df)

    # 3. Fit Cascade Model
    logger.info(f"Initializing CascadeModel (Stage 1: IsolationForest, Stage 2: One-Class SVM) version {args.model_version}...")
    cascade_model = CascadeModel(
        threshold_percentile=15.0,
        cascade_params={"model_version": args.model_version}
    )

    t0 = time.time()
    logger.info("Fitting CascadeModel on training data...")
    cascade_model.fit(X_train_scaled, train_df["label"].values)
    fit_time = time.time() - t0
    logger.info(f"Training completed in {fit_time:.2f} seconds.")

    # 4. Evaluation & Inference Benchmarking
    logger.info(f"Evaluating CascadeModel on {len(test_df):,} test samples...")
    t_inf_start = time.time()
    preds = cascade_model.predict(X_test_scaled)
    scores = cascade_model.score(X_test_scaled)
    inf_time = time.time() - t_inf_start

    eps = len(test_df) / max(inf_time, 1e-5)
    latency_ms_avg = (inf_time / len(test_df)) * 1000.0
    process = psutil.Process(os.getpid())
    ram_mb = process.memory_info().rss / (1024 * 1024)

    y_true = test_df["label"].values
    metrics = compute_classification_metrics(y_true, preds, y_score=scores)
    metrics["dataset_source"] = dataset_source
    metrics["total_samples"] = total_samples
    metrics["train_samples"] = len(train_df)
    metrics["test_samples"] = len(test_df)

    cm_df = compute_confusion_matrix_df(y_true, preds)

    # 5. Register Model Assets
    registry_dir = BASE_DIR / "models_store"
    registry = ModelRegistry(registry_dir=str(registry_dir))
    model_version = registry.register_model(cascade_model, metrics=metrics)
    pipeline_path = registry_dir / model_version / "feature_pipeline.joblib"
    feat_pipeline.save(str(pipeline_path))

    # Automatically persist trained model metrics & resource performance to Database
    try:
        from lsmp_ai.io.db_client import DBClient
        db_client = DBClient()
        if db_client.db_url:
            db_client.write_evaluation_metrics(
                run_id=f"train_{model_version}",
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
                model_version=model_version,
            )
            logger.info(f"Successfully recorded trained model '{model_version}' metrics to Database.")
    except Exception as db_err:
        logger.warning(f"Could not record model metrics to DB (using file storage): {db_err}")


    # 6. Display Detailed Results
    print("\n" + "=" * 80)
    print(f"🎯 EVALUATION & BENCHMARK RESULTS (Model Version: {model_version})")
    print("=" * 80)
    print(f"  • Accuracy:              {metrics['accuracy'] * 100:.2f}%")
    print(f"  • Precision:             {metrics['precision'] * 100:.2f}%")
    print(f"  • Recall:                {metrics['recall'] * 100:.2f}%")
    print(f"  • F1-Score:              {metrics['f1_score'] * 100:.2f}%")
    print(f"  • ROC-AUC Score:         {metrics.get('roc_auc', 0.5):.4f}")
    print(f"  • False Positive Rate:   {metrics['false_positive_rate'] * 100:.2f}%")
    print("-" * 80)
    print("🧩 CONFUSION MATRIX:")
    print(cm_df)
    print("-" * 80)
    print("⚡ THROUGHPUT & RESOURCE BENCHMARK:")
    print(f"  • Throughput (EPS):      {eps:,.1f} Events/sec")
    print(f"  • Latency per log:       {latency_ms_avg:.3f} ms")
    print(f"  • RAM Footprint:         {ram_mb:.1f} MB")
    print("=" * 80)
    print(f"✅ Trained model successfully saved and registered at: {registry_dir / model_version}")
    print("=" * 80)


if __name__ == "__main__":
    main()
