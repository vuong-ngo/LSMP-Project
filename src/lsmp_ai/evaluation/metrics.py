# ============================================================================
# file: evaluation/metrics.py
# Description: Classification metrics computation (Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC).
# ============================================================================

# ===== IMPORT MODULES =====
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from lsmp_ai.common.constants import LABEL_ANOMALY, LABEL_NORMAL


# ===== CLASSIFICATION METRICS FUNCTION =====
def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: np.ndarray | None = None,
) -> dict:
    # Standardize both string and numeric labels to uniform binary integers (0 = Normal, 1 = Anomaly)
    def _to_binary(y):
        arr = np.asarray(y)
        # If numeric array: check if sklearn -1/1 convention or binary 0/1 convention
        if np.issubdtype(arr.dtype, np.number):
            if -1 in arr:
                return np.where(arr == -1, 1, 0)
            return (arr == 1).astype(int)

        # String or object array
        s = pd.Series(arr).astype(str).str.strip()
        mapped = s.map({
            "Anomaly": 1,
            "Normal": 0,
            "BENIGN": 0,
            "benign": 0,
            LABEL_ANOMALY: 1,
            LABEL_NORMAL: 0,
            "-1": 1,
        })
        mapped = mapped.fillna(s.apply(lambda x: 0 if x.upper() in ["0", "BENIGN", "NORMAL"] else 1))
        return pd.to_numeric(mapped).astype(int).values

    yt = _to_binary(y_true)
    yp = _to_binary(y_pred)

    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()

    metrics = {
        "accuracy": float(accuracy_score(yt, yp)),
        "precision": float(precision_score(yt, yp, zero_division=0)),
        "recall": float(recall_score(yt, yp, zero_division=0)),
        "f1_score": float(f1_score(yt, yp, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "true_positive_rate": float(tp / max(tp + fn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
    }

    if y_score is not None:
        y_eval_score = np.asarray(y_score, dtype=float)
        if np.any(yt == 1) and np.any(yt == 0):
            normal_mean = np.mean(y_eval_score[yt == 0])
            anomaly_mean = np.mean(y_eval_score[yt == 1])
            if anomaly_mean < normal_mean:
                y_eval_score = -y_eval_score

        try:
            metrics["roc_auc"] = float(roc_auc_score(yt, y_eval_score))
        except Exception:
            metrics["roc_auc"] = 0.5

        try:
            precision_pts, recall_pts, _ = precision_recall_curve(yt, y_eval_score)
            metrics["pr_auc"] = float(auc(recall_pts, precision_pts))
        except Exception:
            metrics["pr_auc"] = 0.0

    return metrics


# ===== CONFUSION MATRIX FUNCTION =====
def compute_confusion_matrix_df(y_true: np.ndarray, y_pred: np.ndarray) -> pd.DataFrame:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return pd.DataFrame(
        {
            "": ["Predicted Normal", "Predicted Anomaly"],
            "Actual Normal": [tn, fp],
            "Actual Anomaly": [fn, tp],
        }
    ).set_index("")
