# ============================================================================
# file: evaluation/ablation.py
# Description: Ablation study module comparing model architectures, feature groups,
#              hyperparameter sensitivity, and gate rate tradeoffs strictly
#              matching SME research paper methodology.
#
# Generates:
#   - results/table_ablation.csv     -> Feature group ablation degradation
#   - results/table_sensitivity.csv  -> Hyperparameter robustness (contamination, nu, gamma)
#   - results/table_gate.csv         -> Gate rate cost-accuracy tradeoff
# ============================================================================
from __future__ import annotations

import time
from pathlib import Path
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Sequence, Union
from sklearn.preprocessing import StandardScaler

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline
from lsmp_ai.evaluation.metrics import (
    compute_classification_metrics,
    basic_metrics,
    pick_threshold,
    to_binary_labels,
)
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.common.constants import FEATURE_COLUMNS

logger = setup_logger(__name__)

# Standard SME research feature groups (14 features)
FEATURE_GROUPS = {
    "auth_volume": ["auth_fail_count", "auth_success_count", "auth_fail_ratio"],
    "auth_spraying": ["distinct_username"],
    "auth_timing": ["fail_interarrival_mean", "fail_interarrival_std"],
    "http_volume": ["http_req_rate"],
    "http_status": ["http_4xx_ratio", "http_5xx_ratio"],
    "http_shape": ["http_post_ratio", "distinct_user_agent", "bytes_sent_mean"],
    "context": ["global_active_ips", "burst_rate"],
}


def _temporal_partitions(
    df: pd.DataFrame,
    label_col: Optional[str],
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray, np.ndarray]:
    """Create the common temporal 60/20/20 benchmark split."""
    sort_col = "window_end" if "window_end" in df.columns else ("timestamp" if "timestamp" in df.columns else None)
    ordered = df.sort_values(sort_col).reset_index(drop=True) if sort_col else df.reset_index(drop=True)
    n = len(ordered)
    train_end = max(1, int(n * train_ratio))
    val_end = min(n - 1, train_end + max(1, int(n * val_ratio)))
    train_df = ordered.iloc[:train_end].reset_index(drop=True)
    val_df = ordered.iloc[train_end:val_end].reset_index(drop=True)
    test_df = ordered.iloc[val_end:].reset_index(drop=True)

    def labels(part: pd.DataFrame) -> np.ndarray:
        return to_binary_labels(part[label_col].values) if label_col else np.zeros(len(part), dtype=int)

    return train_df, val_df, test_df, labels(train_df), labels(val_df), labels(test_df)


def _cascade_metrics(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    *,
    gate_rate: float = 0.20,
    iforest_params: Optional[dict] = None,
    ocsvm_params: Optional[dict] = None,
) -> Dict[str, Any]:
    """Fit on training normals, calibrate on validation, and score the test set."""
    cascade = CascadeModel(
        gate_rate=gate_rate,
        iforest_params=iforest_params,
        ocsvm_params=ocsvm_params,
    )
    cascade.fit(X_train, y_train, X_val=X_val, y_val=y_val, criterion="f2")
    details = cascade.predict_detailed(X_test)
    y_pred = cascade.predict(X_test)
    y_score = cascade.score(X_test)
    bm = basic_metrics(y_test, y_pred)
    from sklearn.metrics import average_precision_score
    try:
        pr_auc = float(average_precision_score(y_test, y_score))
    except Exception:
        pr_auc = 0.0
    gated = (
        float((details["stage1_score"] >= cascade.gate_threshold).mean())
        if "stage1_score" in details.columns else gate_rate
    )
    return {
        **bm,
        "pr_auc": pr_auc,
        "gate_rate_actual": gated,
        "threshold": float(cascade.threshold),
        "gate_threshold": float(cascade.gate_threshold),
    }


def run_ablation_study(
    X_train: np.ndarray | pd.DataFrame,
    X_test: np.ndarray | pd.DataFrame,
    y_test: np.ndarray | pd.Series,
    y_train: np.ndarray | pd.Series | None = None,
    iforest_params: dict | None = None,
    ocsvm_params: dict | None = None,
    cascade_threshold: int = 80,
) -> pd.DataFrame:
    """Runs model ablation study comparing iForest standalone, OCSVM standalone, and CascadeModel."""
    results = {}

    # 1. Isolation Forest standalone
    model_iforest = IForestModel(params=iforest_params)
    model_iforest.fit(X_train)
    y_pred_iforest = model_iforest.predict(X_test)
    y_score_iforest = model_iforest.score(X_test)
    results["iForest Only"] = compute_classification_metrics(y_test, y_pred_iforest, y_score_iforest)

    # 2. One-Class SVM standalone
    model_ocsvm = OCSVMModel(params=ocsvm_params)
    model_ocsvm.fit(X_train, y_train)
    y_pred_ocsvm = model_ocsvm.predict(X_test)
    y_score_ocsvm = model_ocsvm.score(X_test)
    results["OCSVM Only"] = compute_classification_metrics(y_test, y_pred_ocsvm, y_score_ocsvm)

    # 3. Cascade Model
    cascade = CascadeModel(
        iforest=model_iforest,
        ocsvm=model_ocsvm,
        threshold_percentile=cascade_threshold,
    )
    cascade.fit(X_train, y_train)
    y_pred_cascade = cascade.predict(X_test)
    y_score_cascade = cascade.score(X_test)
    results["Cascade iForest→OCSVM"] = compute_classification_metrics(
        y_test, y_pred_cascade, y_score_cascade
    )

    df_results = pd.DataFrame(results).T
    df_results.index.name = "Model"
    logger.info(f"Ablation study completed:\n{df_results.to_string()}")
    return df_results


def run_feature_group_ablation(
    df: pd.DataFrame,
    feature_cols: Sequence[str] = FEATURE_COLUMNS,
    groups: Optional[Dict[str, List[str]]] = None,
    gate_rate: float = 0.20,
    test_ratio: float = 0.30,
    output_dir: Optional[Path | str] = None,
) -> pd.DataFrame:
    """Evaluates the contribution of each feature group by measuring PR-AUC and F1 degradation when removed.
    Saves results to results/table_ablation.csv following SME-kit methodology.
    """
    groups_to_eval = groups or FEATURE_GROUPS
    lbl_col = "label" if "label" in df.columns else ("ground_truth_label" if "ground_truth_label" in df.columns else None)
    train_df, val_df, test_df, y_train, y_val, y_test = _temporal_partitions(df, lbl_col)

    def _eval_features(cols: List[str]) -> Dict[str, Any]:
        t0 = time.perf_counter()
        fp = FeaturePipeline(feature_cols=cols)
        X_tr = fp.fit_transform(train_df)
        X_va = fp.transform(val_df)
        X_te = fp.transform(test_df)
        cascade = CascadeModel(gate_rate=gate_rate)
        cascade.fit(X_tr, y_train, X_val=X_va, y_val=y_val, criterion="f2")
        details = cascade.predict_detailed(X_te)
        yp = cascade.predict(X_te)
        ys = cascade.score(X_te)
        elapsed = time.perf_counter() - t0

        bm = basic_metrics(y_test, yp)
        from sklearn.metrics import average_precision_score
        try:
            prauc = float(average_precision_score(y_test, ys))
        except Exception:
            prauc = 0.0

        gated_mean = float((details["stage1_score"] >= cascade.gate_threshold).mean()) if "stage1_score" in details.columns else gate_rate

        return {
            **bm,
            "pr_auc": prauc,
            "gate_rate_actual": gated_mean,
            "seconds": elapsed,
        }

    available_feats = [f for f in feature_cols if f in df.columns]
    base_metrics = _eval_features(available_feats)
    base_pr = base_metrics.get("pr_auc", 0.0)

    rows = [{
        "config": "full_14_features",
        "tp": base_metrics["tp"],
        "fp": base_metrics["fp"],
        "fn": base_metrics["fn"],
        "tn": base_metrics["tn"],
        "precision": base_metrics["precision"],
        "recall": base_metrics["recall"],
        "f1": base_metrics["f1"],
        "f2": base_metrics["f2"],
        "fpr": base_metrics["fpr"],
        "tnr": base_metrics["tnr"],
        "pr_auc": base_pr,
        "gate_rate_actual": base_metrics["gate_rate_actual"],
        "seconds": base_metrics["seconds"],
        "delta_pr_auc": 0.0,
        "removed": "",
    }]

    for grp_name, grp_cols in groups_to_eval.items():
        remaining = [c for c in available_feats if c not in grp_cols]
        if not remaining:
            continue
        m = _eval_features(remaining)
        rows.append({
            "config": f"minus_{grp_name}",
            "tp": m["tp"],
            "fp": m["fp"],
            "fn": m["fn"],
            "tn": m["tn"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "f2": m["f2"],
            "fpr": m["fpr"],
            "tnr": m["tnr"],
            "pr_auc": m["pr_auc"],
            "gate_rate_actual": m["gate_rate_actual"],
            "seconds": m["seconds"],
            "delta_pr_auc": m["pr_auc"] - base_pr,
            "removed": ",".join(grp_cols),
        })

    df_out = pd.DataFrame(rows)
    logger.info(f"Feature group ablation table:\n{df_out.to_string()}")

    out_dirs = [output_dir] if output_dir else [Path("results"), Path("reports/results")]
    for d in out_dirs:
        if d:
            p = Path(d)
            p.mkdir(parents=True, exist_ok=True)
            df_out.to_csv(p / "table_ablation.csv", index=False)

    return df_out


def run_hyperparameter_sensitivity(
    df: pd.DataFrame,
    feature_cols: Sequence[str] = FEATURE_COLUMNS,
    output_dir: Optional[Path | str] = None,
) -> pd.DataFrame:
    """Sweeps contamination, nu, and gamma to confirm robustness (not just random luck).
    Generates results/table_sensitivity.csv strictly matching SME-kit columns.
    """
    lbl_col = "label" if "label" in df.columns else ("ground_truth_label" if "ground_truth_label" in df.columns else None)
    train_df, val_df, test_df, y_train, y_val, y_test = _temporal_partitions(df, lbl_col)
    feats = [f for f in feature_cols if f in df.columns]

    fp = FeaturePipeline(feature_cols=feats)
    X_tr = fp.fit_transform(train_df)
    X_va = fp.transform(val_df)
    X_te = fp.transform(test_df)

    from sklearn.metrics import average_precision_score

    def _eval_casc(casc):
        t0 = time.perf_counter()
        casc.fit(X_tr, y_train, X_val=X_va, y_val=y_val, criterion="f2")
        details = casc.predict_detailed(X_te)
        yp = casc.predict(X_te)
        ys = casc.score(X_te)
        elapsed = time.perf_counter() - t0
        bm = basic_metrics(y_test, yp)
        try:
            prauc = float(average_precision_score(y_test, ys))
        except Exception:
            prauc = 0.0
        gated_mean = float((details["stage1_score"] >= casc.gate_threshold).mean()) if "stage1_score" in details.columns else 0.20
        return {
            **bm,
            "pr_auc": prauc,
            "gate_rate_actual": gated_mean,
            "seconds": elapsed,
        }

    sens_records = []

    # 1. Sweep contamination
    for cont in [0.01, 0.02, 0.05, 0.10, 0.20]:
        casc = CascadeModel(iforest_params={"contamination": cont})
        m = _eval_casc(casc)
        sens_records.append({
            "param": "contamination",
            "value": cont,
            "tp": m["tp"],
            "fp": m["fp"],
            "fn": m["fn"],
            "tn": m["tn"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "f2": m["f2"],
            "fpr": m["fpr"],
            "tnr": m["tnr"],
            "pr_auc": m["pr_auc"],
            "gate_rate_actual": m["gate_rate_actual"],
            "seconds": m["seconds"],
        })

    # 2. Sweep nu
    for nu in [0.01, 0.02, 0.05, 0.10, 0.20]:
        casc = CascadeModel(ocsvm_params={"nu": nu})
        m = _eval_casc(casc)
        sens_records.append({
            "param": "nu",
            "value": nu,
            "tp": m["tp"],
            "fp": m["fp"],
            "fn": m["fn"],
            "tn": m["tn"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "f2": m["f2"],
            "fpr": m["fpr"],
            "tnr": m["tnr"],
            "pr_auc": m["pr_auc"],
            "gate_rate_actual": m["gate_rate_actual"],
            "seconds": m["seconds"],
        })

    # 3. Sweep gamma
    for gam in ["scale", "auto", 0.01, 0.1, 1.0]:
        casc = CascadeModel(ocsvm_params={"gamma": gam})
        m = _eval_casc(casc)
        sens_records.append({
            "param": "gamma",
            "value": gam,
            "tp": m["tp"],
            "fp": m["fp"],
            "fn": m["fn"],
            "tn": m["tn"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "f2": m["f2"],
            "fpr": m["fpr"],
            "tnr": m["tnr"],
            "pr_auc": m["pr_auc"],
            "gate_rate_actual": m["gate_rate_actual"],
            "seconds": m["seconds"],
        })

    df_sens = pd.DataFrame(sens_records)
    out_dirs = [output_dir] if output_dir else [Path("results"), Path("reports/results")]
    for d in out_dirs:
        if d:
            p = Path(d)
            p.mkdir(parents=True, exist_ok=True)
            df_sens.to_csv(p / "table_sensitivity.csv", index=False)

    logger.info(f"Hyperparameter sensitivity table:\n{df_sens.to_string()}")
    return df_sens


def run_gate_rate_sweep(
    df: pd.DataFrame,
    feature_cols: Sequence[str] = FEATURE_COLUMNS,
    gate_rates: Sequence[float] = (0.05, 0.10, 0.20, 0.30, 0.50, 1.00),
    output_dir: Optional[Path | str] = None,
) -> pd.DataFrame:
    """Sweeps gate_rate to find optimal tradeoff between computational cost and recall.
    Central argument of the cascade architecture paper. Generates results/table_gate.csv matching SME-kit.
    """
    lbl_col = "label" if "label" in df.columns else ("ground_truth_label" if "ground_truth_label" in df.columns else None)
    train_df, val_df, test_df, y_train, y_val, y_test = _temporal_partitions(df, lbl_col)
    feats = [f for f in feature_cols if f in df.columns]

    fp = FeaturePipeline(feature_cols=feats)
    X_tr = fp.fit_transform(train_df)
    X_va = fp.transform(val_df)
    X_te = fp.transform(test_df)

    from sklearn.metrics import average_precision_score

    gate_records = []
    for gr in gate_rates:
        t0 = time.perf_counter()
        casc = CascadeModel(gate_rate=gr)
        casc.fit(X_tr, y_train, X_val=X_va, y_val=y_val, criterion="f2")
        details = casc.predict_detailed(X_te)
        yp = casc.predict(X_te)
        ys = casc.score(X_te)
        elapsed = time.perf_counter() - t0

        bm = basic_metrics(y_test, yp)
        try:
            prauc = float(average_precision_score(y_test, ys))
        except Exception:
            prauc = 0.0
        gated_mean = float((details["stage1_score"] >= casc.gate_threshold).mean()) if "stage1_score" in details.columns else gr

        gate_records.append({
            "gate_rate": gr,
            "tp": bm["tp"],
            "fp": bm["fp"],
            "fn": bm["fn"],
            "tn": bm["tn"],
            "precision": bm["precision"],
            "recall": bm["recall"],
            "f1": bm["f1"],
            "f2": bm["f2"],
            "fpr": bm["fpr"],
            "tnr": bm["tnr"],
            "pr_auc": prauc,
            "gate_rate_actual": gated_mean,
            "seconds": elapsed,
        })

    df_gate = pd.DataFrame(gate_records)
    out_dirs = [output_dir] if output_dir else [Path("results"), Path("reports/results")]
    for d in out_dirs:
        if d:
            p = Path(d)
            p.mkdir(parents=True, exist_ok=True)
            df_gate.to_csv(p / "table_gate.csv", index=False)

    logger.info(f"Gate rate sweep table:\n{df_gate.to_string()}")
    return df_gate
