# ============================================================================
# file: models/hyperparameter_search.py
# Description: Hyperparameter optimization and sensitivity analysis for anomaly detection models.
# ============================================================================
from __future__ import annotations

from typing import Union, Optional, Dict, Any, List, Sequence
import numpy as np
import pandas as pd
from sklearn.model_selection import ParameterGrid

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.evaluation.metrics import compute_classification_metrics

logger = setup_logger(__name__)


def _evaluate_model_score(y_true: Optional[Union[np.ndarray, pd.Series]], y_pred: np.ndarray, y_score: np.ndarray, scoring: str = "f1_score") -> float:
    """Helper to evaluate model performance given labels and scores."""
    if y_true is not None:
        metrics = compute_classification_metrics(y_true, y_pred, y_score)
        return float(metrics.get(scoring, metrics.get("f1_score", 0.0)))
    # Unsupervised heuristic: dispersion of continuous anomaly scores
    return float(np.std(y_score))


class HyperparameterSearch:
    """Comprehensive hyperparameter search optimizer for iForest, OCSVM, and Cascade detectors."""

    def __init__(
        self,
        iforest_param_grid: Optional[Dict[str, List[Any]]] = None,
        ocsvm_param_grid: Optional[Dict[str, List[Any]]] = None,
        gate_rates: Sequence[float] = (0.10, 0.20, 0.30),
    ):
        self.iforest_grid = iforest_param_grid or {
            "n_estimators": [100, 200],
            "max_samples": [128, 256],
            "contamination": [0.02, 0.05, 0.10],
        }
        self.ocsvm_grid = ocsvm_param_grid or {
            "kernel": ["rbf"],
            "nu": [0.02, 0.05, 0.10],
            "gamma": ["scale", "auto"],
        }
        self.gate_rates = gate_rates

    def search(
        self,
        X: Union[np.ndarray, pd.DataFrame],
        y: Optional[Union[np.ndarray, pd.Series]] = None,
        scoring: str = "f1_score",
    ) -> Dict[str, Any]:
        """Runs hyperparameter search across iForest, OCSVM, and gate rates.

        Args:
            X (Union[np.ndarray, pd.DataFrame]): Input feature matrix.
            y (Optional[Union[np.ndarray, pd.Series]], optional): Target labels.
            scoring (str, optional): Target optimization metric. Defaults to "f1_score".

        Returns:
            Dict[str, Any]: Dictionary containing best params and tuning history.
        """
        logger.info("Starting comprehensive HyperparameterSearch for CascadeModel...")

        # 1. Optimize Isolation Forest
        best_if = grid_search_iforest(X, self.iforest_grid, y=y, scoring=scoring)
        best_if_params = best_if["best_params"]

        # 2. Optimize One-Class SVM
        best_oc = grid_search_ocsvm(X, self.ocsvm_grid, y=y, scoring=scoring)
        best_oc_params = best_oc["best_params"]

        # 3. Optimize Gate Rate
        best_gate_rate = 0.20
        best_cascade_score = -np.inf

        for gr in self.gate_rates:
            cascade = CascadeModel(
                iforest=IForestModel(**best_if_params),
                ocsvm=OCSVMModel(**best_oc_params),
                gate_rate=gr,
            )
            cascade.fit(X, y)
            y_pred = cascade.predict(X)
            y_score = cascade.score(X)
            score_val = _evaluate_model_score(y, y_pred, y_score, scoring=scoring)

            if score_val > best_cascade_score:
                best_cascade_score = score_val
                best_gate_rate = gr

        logger.info(
            f"HyperparameterSearch completed: iforest={best_if_params}, "
            f"ocsvm={best_oc_params}, gate_rate={best_gate_rate} (score={best_cascade_score:.4f})"
        )

        return {
            "iforest_params": best_if_params,
            "ocsvm_params": best_oc_params,
            "gate_rate": best_gate_rate,
            "best_score": best_cascade_score,
            "iforest_search": best_if,
            "ocsvm_search": best_oc,
        }


def grid_search_iforest(
    X: Union[np.ndarray, pd.DataFrame],
    param_grid: Dict[str, List[Any]],
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter grid search for Isolation Forest."""
    best_score = -np.inf
    best_params = None
    results = []
    grid = list(ParameterGrid(param_grid))

    for params in grid:
        model = IForestModel(**params)
        model.fit(X)
        y_pred = model.predict(X)
        y_score = model.score(X)
        score_val = _evaluate_model_score(y, y_pred, y_score, scoring=scoring)

        results.append({**params, "score": score_val})
        if score_val > best_score or best_params is None:
            best_score = score_val
            best_params = params

    return {"best_params": best_params, "best_score": best_score, "results": results}


def grid_search_ocsvm(
    X: Union[np.ndarray, pd.DataFrame],
    param_grid: Dict[str, List[Any]],
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter grid search for One-Class SVM."""
    best_score = -np.inf
    best_params = None
    results = []
    grid = list(ParameterGrid(param_grid))

    for params in grid:
        model = OCSVMModel(**params)
        model.fit(X, y)
        y_pred = model.predict(X)
        y_score = model.score(X)
        score_val = _evaluate_model_score(y, y_pred, y_score, scoring=scoring)

        results.append({**params, "score": score_val})
        if score_val > best_score or best_params is None:
            best_score = score_val
            best_params = params

    return {"best_params": best_params, "best_score": best_score, "results": results}


def grid_search_cascade(
    X: Union[np.ndarray, pd.DataFrame],
    threshold_percentiles: List[float],
    iforest_param_grid: Optional[Dict[str, List[Any]]] = None,
    ocsvm_param_grid: Optional[Dict[str, List[Any]]] = None,
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter search for CascadeModel routing thresholds and submodels."""
    best_score = -np.inf
    best_params = None
    results = []

    iforest_grid = list(ParameterGrid(iforest_param_grid)) if iforest_param_grid else [{}]
    ocsvm_grid = list(ParameterGrid(ocsvm_param_grid)) if ocsvm_param_grid else [{}]

    for perc in threshold_percentiles:
        for if_p in iforest_grid:
            for oc_p in ocsvm_grid:
                iforest_inst = IForestModel(**if_p) if if_p else None
                ocsvm_inst = OCSVMModel(**oc_p) if oc_p else None

                cascade = CascadeModel(
                    iforest=iforest_inst,
                    ocsvm=ocsvm_inst,
                    threshold_percentile=perc,
                )
                cascade.fit(X, y)
                y_pred = cascade.predict(X)
                y_score = cascade.score(X)
                score_val = _evaluate_model_score(y, y_pred, y_score, scoring=scoring)

                params_record = {
                    "threshold_percentile": perc,
                    "iforest_params": if_p,
                    "ocsvm_params": oc_p,
                    "score": score_val,
                }
                results.append(params_record)

                if score_val > best_score or best_params is None:
                    best_score = score_val
                    best_params = params_record

    return {"best_params": best_params, "best_score": best_score, "results": results}


def grid_search_gate_rate(
    X_train: Union[np.ndarray, pd.DataFrame],
    X_test: Union[np.ndarray, pd.DataFrame],
    y_test: Union[np.ndarray, pd.Series],
    gate_rates: Sequence[float] = (0.05, 0.10, 0.20, 0.30, 0.50, 1.00),
    criterion: str = "f2",
    max_fpr: float = 0.02,
) -> pd.DataFrame:
    """Evaluates trade-off between gate_rate, detection performance, and computational savings."""
    rows = []
    for gr in gate_rates:
        cascade = CascadeModel(gate_rate=gr)
        cascade.fit(X_train, criterion=criterion, max_fpr=max_fpr)
        y_pred = cascade.predict(X_test)
        y_score = cascade.score(X_test)
        metrics = compute_classification_metrics(y_test, y_pred, y_score)
        bench = cascade.benchmark_timing(X_test)
        rows.append({
            "gate_rate": gr,
            "recall": metrics.get("recall", 0.0),
            "precision": metrics.get("precision", 0.0),
            "f1_score": metrics.get("f1_score", 0.0),
            "pr_auc": metrics.get("pr_auc", 0.0),
            "gate_rate_actual": bench.get("gate_rate_actual", gr),
            "compute_saving_vs_ocsvm_only": bench.get("compute_saving_vs_ocsvm_only", 0.0),
            "cascade_total_seconds": bench.get("inference_seconds", {}).get("cascade_total", 0.0),
        })
    df_res = pd.DataFrame(rows)
    logger.info(f"Gate rate evaluation completed:\n{df_res.to_string()}")
    return df_res
