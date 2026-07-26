# ============================================================================
# file: risk_scoring/risk_classifier.py
# Description: Risk classification mapping numerical risk scores to Low, Medium, High, Critical categories.
# ============================================================================

# ===== IMPORT MODULES =====
import numpy as np
import pandas as pd
from typing import Union, Optional, Dict, Any

from lsmp_ai.common.config_loader import config
from lsmp_ai.risk_scoring.risk_score import calculate_risk_score, compute_risk_scores_for_df


# ===== RISK CLASSIFICATION FUNCTIONS =====
def classify_risk_score(
    risk_score: Union[float, pd.Series, np.ndarray, list],
    low_threshold: Optional[float] = None,
    medium_threshold: Optional[float] = None,
    high_threshold: Optional[float] = None
) -> Union[str, np.ndarray]:
    """Classifies numerical risk score(s) into discrete security categories: Low, Medium, High, Critical.

    Thresholds are loaded dynamically from configs/risk_config.yaml ('classification' section):
        - low_threshold (default: 25.0): [0.0, 25.0] -> 'Low'
        - medium_threshold (default: 50.0): (25.0, 50.0] -> 'Medium'
        - high_threshold (default: 80.0): (50.0, 80.0] -> 'High', >80.0 -> 'Critical'

    Args:
        risk_score (Union[float, pd.Series, np.ndarray, list]): Risk score value(s) in range [0, 100].
        low_threshold (Optional[float], optional): Upper bound for Low level. Defaults to None.
        medium_threshold (Optional[float], optional): Upper bound for Medium level. Defaults to None.
        high_threshold (Optional[float], optional): Upper bound for High level. Defaults to None.

    Returns:
        Union[str, np.ndarray]: Risk category string or numpy array of category strings ('Low', 'Medium', 'High', 'Critical').
    """
    # Default fallbacks matching configs/risk_config.yaml
    def_low = 25.0
    def_med = 50.0
    def_high = 80.0

    if config and hasattr(config, "risk_classification_params") and config.risk_classification_params:
        def_low = float(config.risk_classification_params.get("low_threshold", def_low))
        def_med = float(config.risk_classification_params.get("medium_threshold", def_med))
        def_high = float(config.risk_classification_params.get("high_threshold", def_high))

    low_thresh = float(low_threshold) if low_threshold is not None else def_low
    med_thresh = float(medium_threshold) if medium_threshold is not None else def_med
    high_thresh = float(high_threshold) if high_threshold is not None else def_high

    if isinstance(risk_score, list):
        risk_score = np.array(risk_score, dtype=float)

    def _classify_single(val: float) -> str:
        if pd.isna(val):
            return "Low"
        if val <= low_thresh:
            return "Low"
        elif val <= med_thresh:
            return "Medium"
        elif val <= high_thresh:
            return "High"
        else:
            return "Critical"

    if isinstance(risk_score, (pd.Series, np.ndarray)):
        scores = np.array(risk_score, dtype=float)
        scores = np.nan_to_num(scores, nan=0.0)
        conditions = [
            scores <= low_thresh,
            (scores > low_thresh) & (scores <= med_thresh),
            (scores > med_thresh) & (scores <= high_thresh),
            scores > high_thresh
        ]
        choices = ["Low", "Medium", "High", "Critical"]
        return np.select(conditions, choices, default="Low")
    else:
        return _classify_single(float(risk_score) if risk_score is not None else 0.0)


def classify_risk_for_df(df: pd.DataFrame) -> pd.DataFrame:
    """Classifies risk scores for an entire DataFrame and appends the 'risk_class' column.

    If 'risk_score' is not present but 'anomaly_score' is present, computes 'risk_score' first.

    Args:
        df (pd.DataFrame): DataFrame containing 'risk_score' or 'anomaly_score' column.

    Returns:
        pd.DataFrame: DataFrame with 'risk_class' column appended.

    Raises:
        ValueError: If neither 'risk_score' nor 'anomaly_score' column is present in input DataFrame.
    """
    if df.empty:
        return df

    if "risk_score" not in df.columns:
        if "anomaly_score" in df.columns:
            df = compute_risk_scores_for_df(df)
        else:
            raise ValueError("risk_score or anomaly_score column must be present in DataFrame to classify.")

    df["risk_class"] = classify_risk_score(df["risk_score"])
    return df


# ===== RISK CLASSIFIER CLASS =====
class RiskClassifier:
    """Encapsulates risk score calculation and risk level classification into a unified class interface."""

    def __init__(
        self,
        alpha: Optional[float] = None,
        beta: Optional[float] = None,
        low_threshold: Optional[float] = None,
        medium_threshold: Optional[float] = None,
        high_threshold: Optional[float] = None,
        max_wazuh_level: Optional[float] = None
    ):
        """Initializes RiskClassifier instance with optional custom parameters."""
        self.alpha = alpha
        self.beta = beta
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.max_wazuh_level = max_wazuh_level

    def calculate_score(
        self,
        anomaly_score: Union[float, pd.Series, np.ndarray, list],
        severity_weight: Union[float, pd.Series, np.ndarray, list] = 0.0
    ) -> Union[float, np.ndarray]:
        """Calculates numerical risk score in range [0, 100]."""
        return calculate_risk_score(
            anomaly_score,
            severity_weight,
            alpha=self.alpha,
            beta=self.beta,
            max_wazuh_level=self.max_wazuh_level
        )

    def classify(
        self,
        risk_score: Union[float, pd.Series, np.ndarray, list]
    ) -> Union[str, np.ndarray]:
        """Classifies numerical risk score into Low, Medium, High, Critical string labels."""
        return classify_risk_score(
            risk_score,
            low_threshold=self.low_threshold,
            medium_threshold=self.medium_threshold,
            high_threshold=self.high_threshold
        )

    def classify_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Computes 'risk_score' and 'risk_class' for an entire DataFrame."""
        if df.empty:
            return df
        if "risk_score" not in df.columns and "anomaly_score" in df.columns:
            df["risk_score"] = self.calculate_score(
                df["anomaly_score"],
                df.get("severity_weight", 0.0)
            )
        elif "risk_score" not in df.columns:
            raise ValueError("DataFrame must contain 'anomaly_score' or 'risk_score' column.")

        df["risk_class"] = self.classify(df["risk_score"])
        return df
