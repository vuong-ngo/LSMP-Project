# ============================================================================
# file: src/lsmp_ai/scripts/evaluate.py
# Description: Model Comparative Ablation Study & Research Evaluation Script.
#              Evaluates iForest-Only vs OCSVM-Only vs 2-Stage Cascade (iForest + OCSVM)
#              vs Wazuh Rule-Only. Exports detailed comparison report to CSV, JSON,
#              and Database strictly following SME research paper methodology.
#
# Outputs:
#   - results/metrics.json         -> Complete serialized metrics report
#   - results/table_baselines.csv  -> Section VIII Comparative Table
#   - results/table_bdr.csv        -> Bayesian Detection Rate Table
#   - results/table_topk.csv       -> Risk Score Ranking Verification Table
# ============================================================================

from __future__ import annotations

import os
import sys
import json
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
from lsmp_ai.evaluation.metrics import to_binary_labels, rule_only_score
from lsmp_ai.io.db_client import DBClient
from lsmp_ai.io.data_loader import DataLoader

logger = setup_logger(__name__)


def run_evaluation(
    db_url: str | None = None,
    dataset_path: str | Path | None = None,
    output_csv_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    benchmark_runs: int = 5,
    require_db: bool = True,
    criterion: str = "fpr_budget",
    max_fpr: float = 0.02,
    include_rule_only: bool | None = None,
    include_full_ablation: bool = False,
) -> bool | pd.DataFrame:
    """Executes model comparison ablation study, exports CSV reports and DB metrics matching SME kit."""
    print("=" * 80)
    print("📊 LSMP RESEARCH PAPER EVALUATION & MODEL COMPARISON BENCHMARK (SME-KIT)")
    print("=" * 80)

    db_client = DBClient(db_url=db_url)
    if not db_client.db_url:
        if require_db:
            logger.warning("DATABASE_URL is not set. Please export DATABASE_URL variable.")
            return False
        logger.warning("DATABASE_URL is not set. Offline mode: DB metric export will be skipped.")

    # Resolve dataset path: default to canonical loghub benchmark if present
    if dataset_path:
        ds_path = Path(dataset_path)
    elif (BASE_DIR / "data" / "processed" / "loghub" / "test.csv").exists():
        ds_path = BASE_DIR / "data" / "processed" / "loghub"
    elif (BASE_DIR / "data" / "processed" / "source_splits" / "loghub" / "test.csv").exists():
        ds_path = BASE_DIR / "data" / "processed" / "source_splits" / "loghub"
    else:
        ds_path = BASE_DIR / "data" / "processed" / "cicids2017" / "cicids2017_dataset.csv"

    if not ds_path.exists():
        logger.error(
            f"[DATA ERROR] Dataset file or directory not found at {ds_path}. "
            "Prepare the source-specific dataset first or pass --dataset explicitly. "
            "Legacy combined/test artifacts are not valid scientific defaults."
        )
        return False

    feature_cols = list(FEATURE_COLUMNS)
    df_unknown = pd.DataFrame()
    canonical_dir = None

    # Check if ds_path is a directory or points inside a directory with canonical splits
    check_dir = ds_path if ds_path.is_dir() else ds_path.parent
    if (check_dir / "val.csv").exists() and (check_dir / "test.csv").exists() and (
        (check_dir / "train_benign.csv").exists() or (check_dir / "train.csv").exists()
    ):
        canonical_dir = check_dir

    if canonical_dir is not None:
        logger.info(f"Loading canonical pre-split dataset from directory: {canonical_dir}...")
        tr_file = canonical_dir / "train_benign.csv" if (canonical_dir / "train_benign.csv").exists() else canonical_dir / "train.csv"
        df_tr = DataLoader.optimize_dtypes(pd.read_csv(tr_file))
        df_va = DataLoader.optimize_dtypes(pd.read_csv(canonical_dir / "val.csv"))
        df_te = DataLoader.optimize_dtypes(pd.read_csv(canonical_dir / "test.csv"))

        for frame in (df_tr, df_va, df_te):
            missing_cols = [c for c in FEATURE_COLUMNS if c not in frame.columns]
            for c in missing_cols:
                frame[c] = 0.0

        label_col = "label" if "label" in df_te.columns else ("ground_truth_label" if "ground_truth_label" in df_te.columns else None)
        timestamp_col = next((c for c in ("event_ts", "window_end", "timestamp") if c in df_te.columns), None)

        X_train = df_tr[feature_cols]
        y_train = to_binary_labels(df_tr[label_col]) if label_col and label_col in df_tr.columns else np.zeros(len(df_tr), dtype=int)

        X_val = df_va[feature_cols]
        y_val = to_binary_labels(df_va[label_col]) if label_col and label_col in df_va.columns else np.zeros(len(df_va), dtype=int)

        X_test = df_te[feature_cols]
        y_test = to_binary_labels(df_te[label_col]) if label_col and label_col in df_te.columns else np.zeros(len(df_te), dtype=int)

        df = pd.concat([df_tr, df_va, df_te], ignore_index=True)

        has_rule_col = ("wazuh_severity" in df_te.columns) or ("rule_level" in df_te.columns)
        should_include_rule = include_rule_only if include_rule_only is not None else has_rule_col
        rule_val = None
        rule_test = None
        if should_include_rule:
            try:
                rule_val = rule_only_score(df_va)
                rule_test = rule_only_score(df_te)
            except Exception as e:
                logger.info(f"Rule baseline fallback: {e}")
                should_include_rule = False
    else:
        logger.info(f"Loading dataset from [DATA]: {ds_path}...")
        df = pd.read_csv(ds_path)
        df = DataLoader.optimize_dtypes(df)

        missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing_cols:
            logger.warning(f"Imputing missing feature columns with 0.0: {missing_cols}")
            for c in missing_cols:
                df[c] = 0.0
        X_all = df[feature_cols]
        label_col = "label" if "label" in df.columns else ("ground_truth_label" if "ground_truth_label" in df.columns else None)
        if label_col:
            df_labeled, df_unknown = DataLoader.audit_and_separate_unknowns(df, label_col=label_col)
            if not df_unknown.empty:
                logger.info(f"Policy A2: Separated {len(df_unknown)} unknown samples to data/unlabeled/unlabeled_samples.csv; excluded from evaluation metrics.")
            df = df_labeled
            X_all = df[feature_cols]
            y_all = to_binary_labels(df[label_col])
        else:
            X_all = df[feature_cols]
            y_all = np.zeros(len(df), dtype=int)

        # Transparent rule-only baseline scoring
        rule_scores_all = None
        has_rule_col = ("wazuh_severity" in df.columns) or ("rule_level" in df.columns)
        should_include_rule = include_rule_only if include_rule_only is not None else has_rule_col

        if should_include_rule:
            if has_rule_col:
                logger.info("Detected genuine Wazuh SIEM rule severity column. Evaluating actual SIEM rule baseline.")
            else:
                logger.info("Evaluating multi-vector static threshold heuristic rule baseline on network flow features.")
            try:
                rule_scores_all = rule_only_score(df)
            except Exception as e:
                logger.info(f"Rule baseline fallback: {e}")
                should_include_rule = False
        else:
            logger.info("Dataset has no explicit Wazuh SIEM rule levels. Evaluating pure AI architectures (iForest, OCSVM, Cascade) without fabricated rule baseline.")

        # Temporal split: sort explicitly before applying the 60/20/20 protocol.
        timestamp_col = next(
            (c for c in ("event_ts", "window_end", "timestamp") if c in df.columns), None
        )
        if timestamp_col is not None:
            parsed_ts = pd.to_datetime(df[timestamp_col], errors="coerce", utc=True)
            if parsed_ts.isna().any():
                logger.error(f"Invalid timestamps found in {timestamp_col}; refusing evaluation.")
                return False
            order = parsed_ts.sort_values(kind="mergesort").index
            df = df.loc[order].reset_index(drop=True)
            X_all = df[feature_cols]
            y_all = to_binary_labels(df[label_col]) if label_col else np.zeros(len(df), dtype=int)
            if rule_scores_all is not None:
                rule_scores_all = np.asarray(rule_scores_all)[order.to_numpy()]
        else:
            logger.warning("No timestamp column found; positional split is not a temporal benchmark.")

        # Temporal split: 60% train, 20% validation, 20% test (matching SME kit).
        n = len(df)
        if n >= 10:
            from lsmp_ai.data_preparation.cicids2017 import CICIDS2017Preparer
            split_df = df.copy()
            split_df["_evaluation_row_id"] = np.arange(n)
            if timestamp_col == "event_ts" and "timestamp" not in split_df.columns:
                split_df["timestamp"] = split_df["event_ts"]
            train_split, val_split, test_split = CICIDS2017Preparer().temporal_split(
                split_df, frac=(0.6, 0.2, 0.2)
            )
            train_ids = train_split["_evaluation_row_id"].to_numpy(dtype=int)
            val_ids = val_split["_evaluation_row_id"].to_numpy(dtype=int)
            test_ids = test_split["_evaluation_row_id"].to_numpy(dtype=int)
            X_train, y_train = X_all.iloc[train_ids], y_all[train_ids]
            X_val, y_val = X_all.iloc[val_ids], y_all[val_ids]
            X_test, y_test = X_all.iloc[test_ids], y_all[test_ids]
            rule_val = rule_scores_all[val_ids] if rule_scores_all is not None else None
            rule_test = rule_scores_all[test_ids] if rule_scores_all is not None else None
        else:
            split_idx = int(n * 0.7)
            X_train, y_train = X_all.iloc[:split_idx], y_all[:split_idx]
            X_val, y_val = X_all.iloc[split_idx:], y_all[split_idx:]
            X_test, y_test = X_all.iloc[split_idx:], y_all[split_idx:]
            rule_val = rule_scores_all[split_idx:] if rule_scores_all is not None else None
            rule_test = rule_scores_all[split_idx:] if rule_scores_all is not None else None

    # Fit preprocessing only on benign training rows. Attack rows remain in
    # validation/test for threshold selection and final evaluation.
    train_benign_mask = y_train == 0
    if not np.any(train_benign_mask):
        logger.error("Training partition contains no benign samples; refusing evaluation.")
        return False
    X_train = X_train.iloc[np.flatnonzero(train_benign_mask)].reset_index(drop=True)
    y_train = y_train[train_benign_mask]

    from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
    feat_pipeline = FeaturePipeline(feature_cols=feature_cols)
    X_train_scaled = feat_pipeline.fit_transform(X_train)
    X_val_scaled = feat_pipeline.transform(X_val) if (X_val is not None and not X_val.empty) else None
    X_test_scaled = feat_pipeline.transform(X_test)

    logger.info("Executing Comparative Benchmark across Architectures (iForest vs OCSVM vs Cascade)...")
    comparator = ModelComparator(
        benchmark_runs=benchmark_runs,
        criterion=criterion,
        max_fpr=max_fpr,
    )
    df_comp, full_details = comparator.compare(
        X_train=X_train_scaled,
        X_test=X_test_scaled,
        y_test=y_test,
        y_train=y_train,
        X_val=X_val_scaled,
        y_val=y_val,
        rule_scores_val=rule_val,
        rule_scores_test=rule_test,
        include_rule_only=should_include_rule and (rule_test is not None),
    )

    # 1. Output CSV Report Path for backward compatibility
    out_csv = Path(output_csv_path) if output_csv_path else (BASE_DIR / "reports" / "results" / "ablation_study_comparison.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df_comp.to_csv(out_csv, index=True)
    logger.info(f"Successfully saved scientific evaluation CSV report to [DATA]: {out_csv}")

    # 2. Output Exact 4 SME-Kit Research Artifacts to results/ and reports/results/
    if output_dir:
        out_dirs = [Path(output_dir)]
    else:
        out_dirs = [
            BASE_DIR / "results",
            BASE_DIR / "reports" / "results",
        ]
    for d in out_dirs:
        d.mkdir(parents=True, exist_ok=True)

        run_manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dataset_path": str(ds_path.resolve()),
            "dataset_name": ds_path.name,
            "timestamp_column": timestamp_col,
            "split": {
                "train_rows": int(len(X_train)),
                "validation_rows": int(len(X_val)) if X_val is not None else 0,
                "test_rows": int(len(X_test)),
                "protocol": "canonical_pre_split" if canonical_dir else ("temporal_60_20_20" if timestamp_col else "positional_fallback"),
            },
            "label_column": label_col,
            "unknowns_excluded": int(len(df_unknown)) if label_col else 0,
            "criterion": criterion,
            "max_fpr": max_fpr,
            "benchmark_runs": benchmark_runs,
            "rule_baseline": {
                "included": bool(should_include_rule),
                "source": "wazuh_severity_or_rule_level" if has_rule_col else "heuristic_proxy",
                "threshold_source": "validation_quantile_0.95" if rule_val is not None else "fixed_default_without_validation",
            },
        }
        (d / "run_manifest.json").write_text(
            json.dumps(run_manifest, indent=2, default=str), encoding="utf-8"
        )

        # metrics.json
        metrics_json_path = d / "metrics.json"
        with open(metrics_json_path, "w", encoding="utf-8") as f:
            json.dump(full_details.get("metrics_json", {}), f, indent=2)

        # table_baselines.csv
        if full_details.get("table_baselines") is not None:
            full_details["table_baselines"].to_csv(d / "table_baselines.csv")

        # table_bdr.csv
        if full_details.get("table_bdr") is not None:
            full_details["table_bdr"].to_csv(d / "table_bdr.csv")

        # table_topk.csv
        if full_details.get("table_topk") is not None:
            full_details["table_topk"].to_csv(d / "table_topk.csv")

    logger.info("Successfully exported SME-kit compatible tables: metrics.json, table_baselines.csv, table_bdr.csv, table_topk.csv")

    if include_full_ablation:
        logger.info("Executing Full Feature Group Ablation, Hyperparameter Sensitivity & Gate Rate Sweep...")
        from lsmp_ai.evaluation.ablation import (
            run_feature_group_ablation,
            run_hyperparameter_sensitivity,
            run_gate_rate_sweep,
        )
        for d in out_dirs:
            run_feature_group_ablation(df, feature_cols=feature_cols, output_dir=d)
            run_hyperparameter_sensitivity(df, feature_cols=feature_cols, output_dir=d)
            run_gate_rate_sweep(df, feature_cols=feature_cols, output_dir=d)
        logger.info("Successfully exported all 3 ablation study tables: table_ablation.csv, table_sensitivity.csv, table_gate.csv")

    # 3. Export detailed metrics to Database if connected
    run_id = f"eval_ablation_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    if db_client.db_url:
        any_success = False
        for model_name, row in df_comp.iterrows():
            bench_info = full_details.get("models", {}).get(model_name, {}).get("benchmark", {})
            train_time = full_details.get("models", {}).get(model_name, {}).get("training_time_sec", 0.0)

            ok = db_client.write_model_comparison_benchmark(
                benchmark_run_id=run_id,
                model_name=str(model_name),
                dataset_name=ds_path.name,
                accuracy=float(row.get("accuracy", 0.0)),
                precision=float(row.get("precision", 0.0)),
                recall=float(row.get("recall", 0.0)),
                f1=float(row.get("f1_score", 0.0)),
                roc_auc=float(row.get("roc_auc", 0.5)),
                pr_auc=float(row.get("pr_auc", 0.0)),
                fpr=float(row.get("false_positive_rate", row.get("fpr", 0.0))),
                fnr=float(row.get("false_negative_rate", 0.0)),
                training_time_sec=float(train_time),
                latency_mean_ms=float(bench_info.get("latency_mean_ms", 0.0)),
                latency_p99_ms=float(bench_info.get("latency_p99_ms", 0.0)),
                throughput_rows_sec=float(bench_info.get("throughput_rows_per_sec", 0.0)),
            )
            if ok:
                any_success = True
        if any_success:
            logger.info(f"Successfully recorded research comparison metrics for run '{run_id}' into Database.")

    # 4. Print SME-Kit Formatted Paper Summary
    print("\n" + "=" * 92)
    print("🎯 SCIENTIFIC MODEL BASELINE EVALUATION (SME-KIT FORMAT)")
    print("=" * 92)
    metrics_json = full_details.get("metrics_json", {})
    for name, rep in metrics_json.items():
        if isinstance(rep, dict) and "precision" in rep:
            p = rep.get("precision", 0.0)
            r = rep.get("recall", 0.0)
            f1 = rep.get("f1", 0.0)
            fpr = rep.get("fpr", 0.0)
            prauc = rep.get("pr_auc", 0.0)
            bdr1 = rep.get("bdr@0.01", 0.0)
            print(f"{name:16s} P={p:.3f} R={r:.3f} F1={f1:.3f} FPR={fpr:.3f} PR-AUC={prauc:.3f} BDR@1%={bdr1:.3f}")

    if "alert_reduction" in metrics_json:
        ar = metrics_json["alert_reduction"]
        print("-" * 92)
        print("🔔 ALERT REDUCTION VS RULE-ONLY BASELINE:")
        print(f"  • Rule-only alerts: {ar['alerts_rule_only']:,}  | Cascade alerts: {ar['alerts_cascade']:,}")
        print(f"  • Reduction rate:   {ar['reduction_pct']:.1f}%")
        print(f"  • Recall delta:     {ar['recall_delta']:+.3f} (Rule: {ar['recall_rule_only']:.3f} -> Cascade: {ar['recall_cascade']:.3f})")
        print(f"  ℹ️ {ar['NOTE']}")

    print("-" * 92)
    print("📝 PAPER AUDIT CHECKLIST:")
    casc_bdr_001 = metrics_json.get("cascade", {}).get("bdr@0.001", 1.0)
    if casc_bdr_001 < 0.10:
        print(f"  ⚠️ BDR@0.001 = {casc_bdr_001:.3f} < 0.10 -> Discuss in Paper Limitations (Axelsson Base-Rate Fallacy).")
    else:
        print(f"  ✅ BDR@0.001 = {casc_bdr_001:.3f} >= 0.10 -> Strong robustness under extreme class imbalance.")

    if "alert_reduction" in metrics_json and metrics_json["alert_reduction"]["recall_delta"] < 0:
        print("  ⚠️ recall_delta is negative! Do NOT claim alert reduction without highlighting recall tradeoff.")
    else:
        print("  ✅ Recall maintained or improved alongside alert reduction.")

    print(f"\n✅ Generated artifacts:")
    print(f"  • results/metrics.json")
    print(f"  • results/table_baselines.csv")
    print(f"  • results/table_bdr.csv")
    print(f"  • results/table_topk.csv")
    print("=" * 92)

    return df_comp


def main():
    parser = argparse.ArgumentParser(description="LSMP Model Ablation Study & Research Evaluation Script")
    parser.add_argument("--dataset", "-f", type=str, default=None, help="[DATA] Path to input evaluation dataset CSV")
    parser.add_argument("--output", "-o", type=str, default=None, help="[DATA] Path for output comparison CSV report")
    parser.add_argument("--runs", "-r", type=int, default=5, help="Number of benchmark runs for latency measurement (default: 5)")
    parser.add_argument("--criterion", "-c", type=str, default="fpr_budget", help="Threshold criterion ('f2' or 'fpr_budget')")
    parser.add_argument("--max-fpr", type=float, default=0.02, help="Max FPR budget when criterion='fpr_budget' (default: 0.02)")
    parser.add_argument("--full-ablation", "-a", action="store_true", help="Execute feature group ablation, sensitivity, and gate sweep")
    args = parser.parse_args()

    run_evaluation(
        dataset_path=args.dataset,
        output_csv_path=args.output,
        benchmark_runs=args.runs,
        criterion=args.criterion,
        max_fpr=args.max_fpr,
        require_db=False,
        include_full_ablation=args.full_ablation,
    )


if __name__ == "__main__":
    main()
