# ============================================================================
# file: evaluation/ablation.py
# Description: Ablation study module comparing iForest, OCSVM, and CascadeModel.
# ============================================================================

# ===== IMPORT MODULES =====
import numpy as np
import pandas as pd

from lsmp_ai.common.logger import setup_logger
from lsmp_ai.evaluation.metrics import compute_classification_metrics
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.isolation_forest_model import IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel

logger = setup_logger(__name__)


# ===== ABLATION STUDY FUNCTION =====
def run_ablation_study(
    X_train: np.ndarray | pd.DataFrame,
    X_test: np.ndarray | pd.DataFrame,
    y_test: np.ndarray | pd.Series,
    y_train: np.ndarray | pd.Series | None = None,
    iforest_params: dict | None = None,
    ocsvm_params: dict | None = None,
    cascade_threshold: int = 80,
) -> pd.DataFrame:
    """Runs ablation study comparing iForest standalone, OCSVM standalone, and CascadeModel."""
    results = {}

    # 1. Isolation Forest standalone
    model_iforest = IForestModel(**(iforest_params or {}))
    model_iforest.fit(X_train)
    y_pred_iforest = model_iforest.predict(X_test)
    y_score_iforest = model_iforest.score(X_test)
    results["iForest Only"] = compute_classification_metrics(y_test, y_pred_iforest, y_score_iforest)

    # 2. One-Class SVM standalone
    model_ocsvm = OCSVMModel(**(ocsvm_params or {}))
    model_ocsvm.fit(X_train, y_train)
    y_pred_ocsvm = model_ocsvm.predict(X_test)
    y_score_ocsvm = model_ocsvm.score(X_test)
    results["OCSVM Only"] = compute_classification_metrics(y_test, y_pred_ocsvm, y_score_ocsvm)

    # 3. Cascade Model
    cascade = CascadeModel(model_iforest, model_ocsvm, threshold_percentile=cascade_threshold)
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
