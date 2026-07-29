# ============================================================================
# file: models/hyperparameter_search.py
# Description: Hyperparameter grid search utilities for anomaly detection models.
# ============================================================================

# ===== IMPORT MODULES =====
from itertools import product
from typing import Union, Optional, Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.model_selection import ParameterGrid

from lsmp_ai.common.exceptions import ConfigurationError
from lsmp_ai.common.logger import setup_logger
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.evaluation.metrics import compute_classification_metrics

logger = setup_logger(__name__)


# ===== HYPERPARAMETER SEARCH FUNCTIONS =====
def grid_search_iforest(
    X: Union[np.ndarray, pd.DataFrame],
    param_grid: Dict[str, List[Any]],
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter grid search for Isolation Forest.

    Args:
        X (Union[np.ndarray, pd.DataFrame]): Input feature matrix for training/evaluating grid.
        param_grid (Dict[str, List[Any]]): Dictionary specifying hyperparameter search grid.
        y (Optional[Union[np.ndarray, pd.Series]], optional): Target ground-truth labels. Defaults to None.
        scoring (str, optional): Target metric to maximize if y is provided (e.g. 'f1_score', 'roc_auc'). Defaults to "f1_score".

    Returns:
        Dict[str, Any]: Dictionary containing 'best_params', 'best_score', and 'results' history list.
    """
    best_score = -np.inf
    best_params = None
    results = []

    grid = list(ParameterGrid(param_grid))
    logger.info(f"Grid search iForest with {len(grid)} combinations")

    for params in grid:
        model = IForestModel(**params)
        model.fit(X)
        y_pred = model.predict(X)
        y_score = model.score(X)

        if y is not None:
            metrics = compute_classification_metrics(y, y_pred, y_score)
            score_val = float(metrics.get(scoring, metrics.get("f1_score", 0.0)))
        else:
            score_val = float(np.std(y_score))

        results.append({**params, "score": score_val})
        if score_val > best_score or best_params is None:
            best_score = score_val
            best_params = params

    logger.info(f"Best iForest params: {best_params} (score={best_score:.4f})")
    return {"best_params": best_params, "best_score": best_score, "results": results}


def grid_search_ocsvm(
    X: Union[np.ndarray, pd.DataFrame],
    param_grid: Dict[str, List[Any]],
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter grid search for One-Class SVM.

    Args:
        X (Union[np.ndarray, pd.DataFrame]): Input feature matrix.
        param_grid (Dict[str, List[Any]]): Dictionary specifying hyperparameter search grid.
        y (Optional[Union[np.ndarray, pd.Series]], optional): Target ground-truth labels. Defaults to None.
        scoring (str, optional): Target metric to maximize if y is provided. Defaults to "f1_score".

    Returns:
        Dict[str, Any]: Dictionary containing 'best_params', 'best_score', and 'results' history list.
    """
    best_score = -np.inf
    best_params = None
    results = []

    grid = list(ParameterGrid(param_grid))
    logger.info(f"Grid search OCSVM with {len(grid)} combinations")

    for params in grid:
        model = OCSVMModel(**params)
        model.fit(X, y)
        y_pred = model.predict(X)
        y_score = model.score(X)

        if y is not None:
            metrics = compute_classification_metrics(y, y_pred, y_score)
            score_val = float(metrics.get(scoring, metrics.get("f1_score", 0.0)))
        else:
            score_val = float(np.std(y_score))

        results.append({**params, "score": score_val})
        if score_val > best_score or best_params is None:
            best_score = score_val
            best_params = params

    logger.info(f"Best OCSVM params: {best_params} (score={best_score:.4f})")
    return {"best_params": best_params, "best_score": best_score, "results": results}


def grid_search_cascade(
    X: Union[np.ndarray, pd.DataFrame],
    threshold_percentiles: List[float],
    iforest_param_grid: Optional[Dict[str, List[Any]]] = None,
    ocsvm_param_grid: Optional[Dict[str, List[Any]]] = None,
    y: Optional[Union[np.ndarray, pd.Series]] = None,
    scoring: str = "f1_score",
) -> Dict[str, Any]:
    """Executes hyperparameter search for CascadeModel routing thresholds and submodels.

    Args:
        X (Union[np.ndarray, pd.DataFrame]): Input feature matrix.
        threshold_percentiles (List[float]): List of threshold percentiles to evaluate (e.g. [70, 80, 90]).
        iforest_param_grid (Optional[Dict[str, List[Any]]], optional): Search grid for Isolation Forest.
        ocsvm_param_grid (Optional[Dict[str, List[Any]]], optional): Search grid for One-Class SVM.
        y (Optional[Union[np.ndarray, pd.Series]], optional): Target ground-truth labels. Defaults to None.
        scoring (str, optional): Target metric to maximize. Defaults to "f1_score".

    Returns:
        Dict[str, Any]: Dictionary containing 'best_params', 'best_score', and 'results' history list.
    """
    best_score = -np.inf
    best_params = None
    results = []

    iforest_grid = list(ParameterGrid(iforest_param_grid)) if iforest_param_grid else [{}]
    ocsvm_grid = list(ParameterGrid(ocsvm_param_grid)) if ocsvm_param_grid else [{}]

    logger.info(f"Grid search CascadeModel: {len(threshold_percentiles)} percentiles x {len(iforest_grid)} iForest x {len(ocsvm_grid)} OCSVM combinations")

    for perc in threshold_percentiles:
        for if_p in iforest_grid:
            for oc_p in ocsvm_grid:
                iforest_inst = IForestModel(**if_p) if if_p else None
                ocsvm_inst = OCSVMModel(**oc_p) if oc_p else None

                cascade = CascadeModel(
                    iforest=iforest_inst,
                    ocsvm=ocsvm_inst,
                    threshold_percentile=perc
                )
                cascade.fit(X, y)
                y_pred = cascade.predict(X)
                y_score = cascade.score(X)

                if y is not None:
                    metrics = compute_classification_metrics(y, y_pred, y_score)
                    score_val = float(metrics.get(scoring, metrics.get("f1_score", 0.0)))
                else:
                    score_val = float(np.std(y_score))

                params_record = {
                    "threshold_percentile": perc,
                    "iforest_params": if_p,
                    "ocsvm_params": oc_p,
                    "score": score_val
                }
                results.append(params_record)

                if score_val > best_score or best_params is None:
                    best_score = score_val
                    best_params = params_record

    logger.info(f"Best CascadeModel params: percentile={best_params['threshold_percentile']} (score={best_score:.4f})")
    return {"best_params": best_params, "best_score": best_score, "results": results}
