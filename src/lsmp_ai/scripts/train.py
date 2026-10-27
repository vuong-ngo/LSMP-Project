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
import json
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from lsmp_ai.common.constants import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_ANOMALY
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.evaluation.metrics import compute_classification_metrics, compute_confusion_matrix_df
from lsmp_ai.io.data_loader import DataLoader

logger = setup_logger(__name__)


def _validate_canonical_splits(
    canonical_dir: Path,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> dict:
    """Validate the manifest-backed split contract before production training."""
    with (canonical_dir / "split_manifest.json").open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    expected = manifest.get("saved_counts", {})
    actual = {
        "train_benign": len(train_df),
        "validation": len(val_df),
        "test": len(test_df),
    }
    for name, count in actual.items():
        if expected.get(name) is not None and int(expected[name]) != count:
            raise ValueError(
                f"Canonical split count mismatch for {name}: "
                f"manifest={expected[name]}, file={count}"
            )
    if not train_df.get("label", pd.Series(dtype=object)).astype(str).str.strip().str.lower().isin(
        {"normal", "benign", "clean", "0", "0.0", "inlier"}
    ).all():
        raise ValueError("train_benign.csv contains non-benign labels")
    if all("entity_id" in frame.columns for frame in (train_df, val_df, test_df)):
        sets = [
            set(frame["entity_id"].dropna().astype(str))
            for frame in (train_df, val_df, test_df)
        ]
        overlaps = {
            "train_validation": len(sets[0] & sets[1]),
            "train_test": len(sets[0] & sets[2]),
            "validation_test": len(sets[1] & sets[2]),
        }
        if any(overlaps.values()):
            raise ValueError(f"Canonical entity overlap detected: {overlaps}")
    return {
        "manifest": str(canonical_dir / "split_manifest.json"),
        "saved_counts": expected,
        "actual_counts": actual,
        "entity_disjoint": bool(manifest.get("entity_disjoint", False)),
    }


def run_training(
    dataset_path: str | Path | None = None,
    source: str = "cicids2017",
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
        if input_path.is_dir():
            canonical_dir = input_path
        else:
            canonical_dir = input_path.parent
        canonical_files = {
            name: canonical_dir / name
            for name in ("train_benign.csv", "val.csv", "test.csv")
        }
        if all(path.exists() for path in canonical_files.values()):
            manifest_path = canonical_dir / "split_manifest.json"
            if not manifest_path.exists():
                raise ValueError(
                    f"Found split CSVs in {canonical_dir}, but split_manifest.json "
                    "is missing. Refusing to call this data canonical. "
                    f"Resolved dataset path: {input_path}. "
                    "From the LSMP-Project directory, use "
                    "../LSMP-REFACTOR/Data-HCMUE/data/processed/hcmue/dataset.csv "
                    "or run the command from the LSMP-REFACTOR root with "
                    "Data-HCMUE/data/processed/hcmue/dataset.csv."
                )
            logger.info(
                "Loading canonical train_benign/val/test files from [DATA]: "
                f"{canonical_dir}"
            )
            train_df = pd.read_csv(canonical_files["train_benign.csv"])
            val_df = pd.read_csv(canonical_files["val.csv"])
            test_df = pd.read_csv(canonical_files["test.csv"])
            canonical_validation = _validate_canonical_splits(
                canonical_dir, train_df, val_df, test_df
            )
            dataset_source = f"{canonical_dir} (canonical split files)"
        else:
            if input_path.is_dir():
                raise FileNotFoundError(
                    f"Canonical directory {input_path} must contain "
                    "train_benign.csv, val.csv, and test.csv."
                )
            logger.info(f"Loading non-canonical custom dataset from [DATA]: {input_path}...")
            df_full = pd.read_csv(input_path)
            dataset_source = str(input_path)
            from scripts.prepare_data import temporal_split
            tr, va, te = temporal_split(df_full, frac=(0.6, 0.2, 0.2))
            train_df = tr[(tr['label'] == LABEL_NORMAL) | (tr['label'] == 'Normal') | (tr['label'] == 0)].reset_index(drop=True)
            val_df = va.reset_index(drop=True)
            test_df = te.reset_index(drop=True)
    else:
        if source not in {"cicids2017", "loghub"}:
            raise ValueError("source must be one of: cicids2017, loghub")
        source_dir = BASE_DIR / "data" / "processed" / source
        full_dataset_path = source_dir / f"{source}_dataset.csv"
        train_path = source_dir / "train.csv"
        benign_train_path = source_dir / "train_benign.csv"
        val_path = source_dir / "val.csv"
        test_path = source_dir / "test.csv"

        if train_path.exists() and test_path.exists():
            logger.info(f"Loading pre-split dataset files from [DATA]: {train_path} and {test_path}...")
            train_df = pd.read_csv(benign_train_path if benign_train_path.exists() else train_path)
            val_df = pd.read_csv(val_path) if val_path.exists() else pd.DataFrame()
            test_df = pd.read_csv(test_path)
            # Scientific novelty-detection training must use benign rows only.
            # The prepared directory also contains train_benign.csv, but
            # filtering here protects callers that provide only train.csv.
            if "label" in train_df.columns:
                train_df = train_df[
                    train_df["label"].astype(str).str.strip().str.lower().isin(
                        {"normal", "benign", "0", "inlier"}
                    )
                ].reset_index(drop=True)
            dataset_source = f"data/processed/{source}/ (source-specific 60/20/20 temporal split)"
        elif full_dataset_path.exists():
            logger.info(f"Loading primary dataset from [DATA]: {full_dataset_path}...")
            df_full = pd.read_csv(full_dataset_path)
            dataset_source = f"data/processed/{source}_dataset.csv"
            from scripts.prepare_data import temporal_split
            tr, va, te = temporal_split(df_full, frac=(0.6, 0.2, 0.2))
            train_df = tr[(tr['label'] == LABEL_NORMAL) | (tr['label'] == 'Normal') | (tr['label'] == 0)].reset_index(drop=True)
            val_df = va.reset_index(drop=True)
            test_df = te.reset_index(drop=True)
        else:
            raise FileNotFoundError(f"[DATA ERROR] Dataset files not found in {BASE_DIR / 'data'}. Run `python scripts/prepare_data.py` first.")

    # Standardize label aliases and apply Policy A2 (isolate unknowns)
    from lsmp_ai.common.constants import LABEL_NORMAL_ALIASES, LABEL_ANOMALY_ALIASES
    for df_split in [train_df, val_df, test_df]:
        if not df_split.empty and "label" in df_split.columns:
            s_lbl = df_split["label"].astype(str).str.strip().str.lower()
            df_split.loc[s_lbl.isin(LABEL_NORMAL_ALIASES), "label"] = LABEL_NORMAL
            df_split.loc[s_lbl.isin(LABEL_ANOMALY_ALIASES), "label"] = LABEL_ANOMALY

    train_df = DataLoader.optimize_dtypes(train_df)
    test_df = DataLoader.optimize_dtypes(test_df)
    if not val_df.empty:
        val_df = DataLoader.optimize_dtypes(val_df)

    if train_df.empty:
        raise ValueError(
            "No benign samples are available in the training partition. "
            "Refusing to fit novelty detectors on attack data."
        )

    total_samples = len(train_df) + len(test_df) + (len(val_df) if not val_df.empty else 0)
    logger.info(f"Dataset summary: Total={total_samples:,} | Train (Pure Benign 60%)={len(train_df):,} | Val (20%)={len(val_df):,} | Test (20%)={len(test_df):,}")

    # 3. Fit Feature Pipeline Scaler
    feat_pipeline = FeaturePipeline()
    X_train_scaled = feat_pipeline.fit_transform(train_df)
    X_test_scaled = feat_pipeline.transform(test_df)
    X_val_scaled = feat_pipeline.transform(val_df) if not val_df.empty else None
    y_val = val_df["label"].values if not val_df.empty else None

    # 4. Initialize & Train 2-Stage Cascade Model
    from lsmp_ai.common.config_loader import config
    cfg_cascade = dict(config.cascade_params) if (config and hasattr(config, "cascade_params")) else {}
    thresh_pct = float(cfg_cascade.get("threshold_percentile", 80.0))
    cfg_cascade["model_version"] = model_version
    threshold_cfg = getattr(config, "_raw_model_config", {}).get("threshold", {}) if config else {}
    threshold_criterion = str(threshold_cfg.get("criterion", "fpr_budget"))
    max_fpr = float(threshold_cfg.get("max_fpr", 0.02))

    if do_grid_search:
        logger.info("Executing Grid Search hyperparameter tuning with validation set...")
        from lsmp_ai.models.hyperparameter_search import HyperparameterSearch
        search = HyperparameterSearch()
        search_res = search.search(
            X_train_scaled,
            train_df["label"].values,
            X_val=X_val_scaled,
            y_val=y_val,
        )
        cascade_model = CascadeModel(
            iforest_params=search_res.get("iforest_params", {}),
            ocsvm_params=search_res.get("ocsvm_params", {}),
            gate_rate=search_res.get("gate_rate", cfg_cascade.get("gate_rate", 0.20)),
            w_stage1=search_res.get("w_stage1", cfg_cascade.get("w_stage1", 0.40)),
            cascade_params=cfg_cascade
        )
    else:
        cascade_model = CascadeModel(
            gate_rate=cfg_cascade.get("gate_rate", 0.20),
            w_stage1=cfg_cascade.get("w_stage1", 0.40),
            cascade_params=cfg_cascade
        )

    t0 = time.time()
    cascade_model.fit(
        X_train_scaled,
        train_df["label"].values,
        X_val=X_val_scaled,
        y_val=y_val,
        criterion=threshold_criterion,
        max_fpr=max_fpr,
    )
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
    metrics["val_samples"] = len(val_df) if not val_df.empty else 0
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
    registry.refresh_artifact_manifest(registered_version)

    # 8. Export Detailed Research Metrics to Database Table
    try:
        from lsmp_ai.io.db_client import DBClient
        db_client = DBClient()
        if db_client.db_url:
            db_written = db_client.write_evaluation_metrics(
                run_id=f"train_{registered_version}",
                model_config_name="cascade_iforest_ocsvm",
                dataset_split=source if not dataset_path else "custom_dataset",
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
            if db_written:
                logger.info(
                    f"Successfully exported research evaluation metrics for "
                    f"'{registered_version}' to Database."
                )
            else:
                logger.warning(
                    f"Model '{registered_version}' was saved, but research "
                    "evaluation metrics were not written to the database."
                )
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
    parser.add_argument("--source", choices=("cicids2017", "loghub"), default="cicids2017",
                        help="Prepared source to benchmark when --dataset is not supplied")
    parser.add_argument("--model-version", "-v", type=str, default="cascade-v1.0", help="Model version identifier to register")
    parser.add_argument("--test-size", "-s", type=float, default=0.3, help="Test dataset split ratio (default: 0.3)")
    parser.add_argument("--grid-search", "-g", action="store_true", help="Execute hyperparameter GridSearch tuning before fitting")
    args = parser.parse_args()

    run_training(
        dataset_path=args.dataset,
        source=args.source,
        model_version=args.model_version,
        test_size=args.test_size,
        do_grid_search=args.grid_search,
    )


if __name__ == "__main__":
    main()
