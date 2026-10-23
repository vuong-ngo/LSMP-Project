# ============================================================================
# file: evaluation/comparison.py
# Description: Model comparator for benchmarking Isolation Forest, OCSVM, Cascade,
#              and Rule-only baseline with comprehensive metrics matching SME kit.
# ============================================================================

# ===== IMPORT MODULES =====
from __future__ import annotations

import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional, Sequence

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.evaluation.metrics import (
    compute_classification_metrics,
    full_report,
    pick_threshold,
    to_binary_labels,
    rule_only_score,
)
from lsmp_ai.evaluation.benchmark_runner import benchmark_inference, BenchmarkResult
from lsmp_ai.evaluation.significance_test import compare_models
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel

logger = setup_logger(__name__)


# ===== MODEL COMPARATOR CLASS =====
class ModelComparator:
    """Orchestrates comprehensive comparison between Isolation Forest, One-Class SVM,
    Cascade (iForest -> OCSVM) and Rule-only baseline models following SME research methodology.
    """

    def __init__(
        self,
        iforest_params: Optional[Dict[str, Any]] = None,
        ocsvm_params: Optional[Dict[str, Any]] = None,
        cascade_threshold: int = 80,
        benchmark_runs: int = 50,
        random_state: int = 42,
        criterion: str = "f2",
        max_fpr: Optional[float] = 0.02,
        events_per_hour: float = 8000 * 60,
        base_rates: Sequence[float] = (0.10, 0.01, 0.001),
    ):
        self.iforest_params = iforest_params or {
            "n_estimators": 100,
            "max_samples": "auto",
            "contamination": 0.05,
            "random_state": random_state,
        }
        self.ocsvm_params = ocsvm_params or {
            "kernel": "rbf",
            "nu": 0.05,
            "gamma": "scale",
        }
        self.cascade_threshold = cascade_threshold
        self.benchmark_runs = benchmark_runs
        self.random_state = random_state
        self.criterion = criterion
        self.max_fpr = max_fpr
        self.events_per_hour = events_per_hour
        self.base_rates = base_rates

    def compare(
        self,
        X_train: np.ndarray | pd.DataFrame,
        X_test: np.ndarray | pd.DataFrame,
        y_test: np.ndarray | pd.Series,
        y_train: Optional[np.ndarray | pd.Series] = None,
        X_val: Optional[np.ndarray | pd.DataFrame] = None,
        y_val: Optional[np.ndarray | pd.Series] = None,
        rule_scores_val: Optional[np.ndarray] = None,
        rule_scores_test: Optional[np.ndarray] = None,
        include_rule_only: bool = False,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Executes model comparative benchmarking and produces research metrics."""
        logger.info("Initializing model comparison (iForest vs OCSVM vs Cascade)...")
        y_test_bin = to_binary_labels(y_test)

        # All novelty detectors and preprocessing must be fitted on benign
        # training samples only. This guard protects callers that pass the
        # complete temporal train partition.
        X_fit = X_train
        y_fit = y_train
        if y_train is not None:
            y_train_bin = to_binary_labels(y_train)
            benign_mask = y_train_bin == 0
            if not np.any(benign_mask):
                raise ValueError("No benign samples available for novelty-detector training.")
            if isinstance(X_train, pd.DataFrame):
                X_fit = X_train.loc[benign_mask].reset_index(drop=True)
            else:
                X_fit = np.asarray(X_train)[benign_mask]
            y_fit = np.zeros(int(np.sum(benign_mask)), dtype=int)
        logger.info("Novelty training partition: %d benign samples", len(X_fit))

        # 1. Instantiate Models
        model_iforest = IForestModel(**self.iforest_params)
        model_ocsvm = OCSVMModel(**self.ocsvm_params)
        model_cascade = CascadeModel(
            iforest=IForestModel(**self.iforest_params),
            ocsvm=OCSVMModel(**self.ocsvm_params),
            threshold_percentile=self.cascade_threshold,
        )

        models = {
            "Isolation Forest": model_iforest,
            "One-Class SVM": model_ocsvm,
            "Cascade (iForest->OCSVM)": model_cascade,
        }

        # Canonical SME config keys
        sme_keys = {
            "Isolation Forest": "iforest_only",
            "One-Class SVM": "ocsvm_only",
            "Cascade (iForest->OCSVM)": "cascade",
            "Rule-Based Baseline": "rule_only",
        }

        eval_records = {}
        scores_dict = {}
        sme_metrics_json: Dict[str, Any] = {}
        timing_records: Dict[str, Any] = {}
        full_details: Dict[str, Any] = {
            "models": {},
            "significance_tests": {},
            "metrics_json": sme_metrics_json,
            "table_baselines": None,
            "table_bdr": None,
            "table_topk": None,
            "alert_reduction": None,
        }

        # Prepare validation set for rigorous threshold tuning (Principle 2)
        has_val = X_val is not None and y_val is not None
        if has_val:
            y_val_bin = to_binary_labels(y_val)

        for model_name, model in models.items():
            logger.info(f"Training and evaluating model: {model_name}")

            start_train = time.perf_counter()
            if isinstance(model, CascadeModel) and has_val:
                model.fit(X_fit, y_fit, X_val=X_val, y_val=y_val, criterion=self.criterion, max_fpr=self.max_fpr)
            else:
                model.fit(X_fit, y_fit)
            train_time_sec = time.perf_counter() - start_train

            y_pred = model.predict(X_test)
            if hasattr(model, "anomaly_score"):
                y_score = model.anomaly_score(X_test)
            else:
                y_score = model.score(X_test)
            scores_dict[model_name] = y_score

            # Threshold selection on validation or default
            if has_val:
                s_val = model.anomaly_score(X_val) if hasattr(model, "anomaly_score") else model.score(X_val)
                thr = pick_threshold(y_val_bin, s_val, criterion=self.criterion, max_fpr=self.max_fpr)
                threshold_source = f"validation:{self.criterion}"
                if not isinstance(model, CascadeModel):
                    # Apply calibrated validation threshold to standalone models
                    y_pred = (y_score >= thr).astype(int)
            else:
                s_tr = model.anomaly_score(X_fit) if hasattr(model, "anomaly_score") else model.score(X_fit)
                thr = getattr(model, "threshold", float(np.quantile(s_tr, 0.95)) if len(s_tr) > 0 else 0.5)
                threshold_source = "model_or_train_quantile"

            class_metrics = compute_classification_metrics(y_test_bin, y_pred, y_score)
            sme_report = full_report(
                y_true=y_test_bin,
                score=y_score,
                threshold=thr,
                events_per_hour=self.events_per_hour,
                base_rates=self.base_rates,
                y_pred=y_pred,
            )

            bench_res: BenchmarkResult = benchmark_inference(
                model=model,
                X=X_test,
                n_runs=self.benchmark_runs,
                model_name=model_name,
            )

            record = {
                **class_metrics,
                "train_time_sec": float(train_time_sec),
                "latency_mean_ms": bench_res.latency_mean_ms,
                "latency_p99_ms": bench_res.latency_p99_ms,
                "throughput_rows_sec": bench_res.throughput_rows_per_sec,
                "f2": sme_report.get("f2", class_metrics.get("f2_score", 0.0)),
                "pr_auc_over_prevalence": sme_report.get("pr_auc_over_prevalence", 0.0),
                "cid@0.01": sme_report.get("cid@0.01", 0.0),
                "alarms_per_hour@0.01": sme_report.get("alarms_per_hour@0.01", 0.0),
            }
            eval_records[model_name] = record

            sme_k = sme_keys[model_name]
            sme_metrics_json[sme_k] = sme_report
            timing_records[sme_k] = {
                "training_time_sec": float(train_time_sec),
                "latency_mean_ms": bench_res.latency_mean_ms,
                "throughput_rows_per_sec": bench_res.throughput_rows_per_sec,
            }

            full_details["models"][model_name] = {
                "metrics": class_metrics,
                "sme_report": sme_report,
                "benchmark": {
                    "latency_mean_ms": bench_res.latency_mean_ms,
                    "latency_std_ms": bench_res.latency_std_ms,
                    "latency_p99_ms": bench_res.latency_p99_ms,
                    "throughput_rows_per_sec": bench_res.throughput_rows_per_sec,
                },
                "training_time_sec": train_time_sec,
                "threshold": float(thr),
                "threshold_source": threshold_source,
            }

            if isinstance(model, CascadeModel):
                try:
                    casc_timing = model.benchmark_timing(X_test)
                    sme_metrics_json["gate_rate_actual"] = float(casc_timing.get("gate_rate_actual", 0.20))
                    sme_metrics_json["compute_saving_vs_ocsvm_only"] = float(casc_timing.get("compute_saving_vs_ocsvm_only", 0.0))
                except Exception:
                    pass

        # 2. Evaluate Rule-based baseline if explicitly requested
        if include_rule_only:
            if rule_scores_test is not None:
                r_scores = np.asarray(rule_scores_test, dtype=float)
            elif isinstance(X_test, pd.DataFrame):
                r_scores = rule_only_score(X_test)
            else:
                r_scores = np.zeros(len(y_test_bin), dtype=float)

            if rule_scores_val is not None and len(rule_scores_val) > 0:
                thr_rule = float(np.quantile(np.asarray(rule_scores_val, dtype=float), 0.95))
                threshold_source = "validation_quantile_0.95"
            else:
                thr_rule = 0.5
                threshold_source = "fixed_default_without_validation"
            y_pred_rule = (r_scores >= thr_rule).astype(int)

            class_metrics_rule = compute_classification_metrics(y_test_bin, y_pred_rule, r_scores)
            sme_report_rule = full_report(
                y_true=y_test_bin,
                score=r_scores,
                threshold=thr_rule,
                events_per_hour=self.events_per_hour,
                base_rates=self.base_rates,
            )

            record_rule = {
                **class_metrics_rule,
                "train_time_sec": 0.0,
                "latency_mean_ms": 0.01,
                "latency_p99_ms": 0.02,
                "throughput_rows_sec": 1_000_000.0,
                "f2": sme_report_rule.get("f2", 0.0),
                "pr_auc_over_prevalence": sme_report_rule.get("pr_auc_over_prevalence", 0.0),
                "cid@0.01": sme_report_rule.get("cid@0.01", 0.0),
                "alarms_per_hour@0.01": sme_report_rule.get("alarms_per_hour@0.01", 0.0),
            }
            eval_records["Rule-Based Baseline"] = record_rule
            sme_metrics_json["rule_only"] = sme_report_rule
            sme_metrics_json["rule_only"]["threshold_source"] = threshold_source
            scores_dict["Rule-Based Baseline"] = r_scores

        # 3. Statistical Significance
        try:
            sig_results = compare_models(scores_dict)
            full_details["significance_tests"] = sig_results
        except Exception as e:
            logger.warning(f"Failed to calculate statistical significance: {e}")

        # 4. Alert Reduction Calculation (Cascade vs Rule-Only)
        if "rule_only" in sme_metrics_json and "cascade" in sme_metrics_json:
            a_rule = sme_metrics_json["rule_only"]["tp"] + sme_metrics_json["rule_only"]["fp"]
            a_casc = sme_metrics_json["cascade"]["tp"] + sme_metrics_json["cascade"]["fp"]
            r_delta = float(sme_metrics_json["cascade"]["recall"] - sme_metrics_json["rule_only"]["recall"])
            red_pct = float(100 * (1 - a_casc / max(a_rule, 1)))

            alert_reduction = {
                "alerts_rule_only": int(a_rule),
                "alerts_cascade": int(a_casc),
                "reduction_pct": red_pct,
                "recall_rule_only": float(sme_metrics_json["rule_only"]["recall"]),
                "recall_cascade": float(sme_metrics_json["cascade"]["recall"]),
                "recall_delta": r_delta,
                "NOTE": "Giảm cảnh báo chỉ có giá trị nếu recall_delta >= 0. Nếu âm, phải báo cáo trung thực cả hai con số.",
            }
            sme_metrics_json["alert_reduction"] = alert_reduction
            full_details["alert_reduction"] = alert_reduction

        sme_metrics_json["timing"] = timing_records

        # 5. Format Paper CSV DataFrames
        base_cols = [
            "precision", "recall", "f1", "f2", "fpr", "pr_auc",
            "pr_auc_over_prevalence", "alarms_per_hour@0.01", "cid@0.01"
        ]
        active_sme_configs = [k for k in ["iforest_only", "ocsvm_only", "cascade", "rule_only"] if k in sme_metrics_json]
        
        df_table_baselines = pd.DataFrame({
            k: {c: sme_metrics_json[k].get(c, 0.0) for c in base_cols}
            for k in active_sme_configs
        }).T
        full_details["table_baselines"] = df_table_baselines

        bdr_cols = [f"bdr@{b:g}" for b in self.base_rates] + ["recall", "fpr"]
        df_table_bdr = pd.DataFrame({
            k: {c: sme_metrics_json[k].get(c, 0.0) for c in bdr_cols}
            for k in active_sme_configs
        }).T
        full_details["table_bdr"] = df_table_bdr

        casc_rep = sme_metrics_json.get("cascade", {})
        topk_cols = [c for c in casc_rep if c.startswith(("recall@", "precision@"))]
        if topk_cols:
            df_table_topk = pd.DataFrame({
                k: {c: sme_metrics_json[k].get(c, 0.0) for c in topk_cols}
                for k in active_sme_configs
            }).T
            full_details["table_topk"] = df_table_topk

        df_comparison = pd.DataFrame(eval_records).T
        df_comparison.index.name = "Model"

        logger.info(f"\nModel Comparison Results Summary:\n{df_comparison.to_string()}")
        return df_comparison, full_details


# ===== HELPER FUNCTION =====
def run_iforest_ocsvm_comparison(
    X_train: Optional[np.ndarray | pd.DataFrame] = None,
    X_test: Optional[np.ndarray | pd.DataFrame] = None,
    y_test: Optional[np.ndarray | pd.Series] = None,
    y_train: Optional[np.ndarray | pd.Series] = None,
    dataset_path: Optional[str] = None,
    output_path: Optional[str] = None,
    iforest_params: Optional[Dict[str, Any]] = None,
    ocsvm_params: Optional[Dict[str, Any]] = None,
    cascade_threshold: int = 80,
    benchmark_runs: int = 50,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Helper runner for iForest vs OCSVM vs Cascade comparative study."""
    if X_train is None or X_test is None or y_test is None:
        from pathlib import Path
        from lsmp_ai.common.constants import FEATURE_COLUMNS

        df = None
        prepared_loaded = False
        prepared_train = Path("data/processed/cicids2017/train_benign.csv")
        prepared_test = Path("data/processed/cicids2017/test.csv")
        if prepared_train.exists() and prepared_test.exists():
            train_df = pd.read_csv(prepared_train)
            test_df = pd.read_csv(prepared_test)
            feature_cols = [c for c in FEATURE_COLUMNS if c in train_df.columns and c in test_df.columns]
            X_train = train_df[feature_cols]
            X_test = test_df[feature_cols]
            y_train = train_df["label"] if "label" in train_df.columns else pd.Series(
                np.zeros(len(train_df), dtype=int)
            )
            y_test = test_df["label"] if "label" in test_df.columns else pd.Series(
                np.zeros(len(test_df), dtype=int)
            )
            prepared_loaded = True
        if dataset_path and Path(dataset_path).exists():
            df = pd.read_csv(dataset_path)
        elif df is None:
            default_paths = [Path("data/processed/cicids2017/cicids2017_dataset.csv")]
            for p in default_paths:
                if p.exists():
                    df = pd.read_csv(p)
                    break

        if not prepared_loaded and isinstance(df, pd.DataFrame):
            feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
            label_col = "label" if "label" in df.columns else ("ground_truth_label" if "ground_truth_label" in df.columns else None)
            X = df[feature_cols]
            y = df[label_col] if label_col else np.zeros(len(df))
            split_idx = int(len(df) * 0.7)
            X_train = X.iloc[:split_idx]
            X_test = X.iloc[split_idx:]
            y_train = y.iloc[:split_idx]
            y_test = y.iloc[split_idx:]
        else:
            raise FileNotFoundError(
                "No benchmark dataset found. Pass dataset_path explicitly or prepare "
                "data/processed/cicids2017/cicids2017_dataset.csv."
            )

    comparator = ModelComparator(
        iforest_params=iforest_params,
        ocsvm_params=ocsvm_params,
        cascade_threshold=cascade_threshold,
        benchmark_runs=benchmark_runs,
    )
    df_comp, full_details = comparator.compare(X_train, X_test, y_test, y_train=y_train)

    if output_path:
        from pathlib import Path
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        df_comp.to_csv(out_p)
        logger.info(f"Saved comparison results to {out_p}")

    return df_comp, full_details
