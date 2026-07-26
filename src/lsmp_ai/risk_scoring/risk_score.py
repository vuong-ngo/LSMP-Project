# ============================================================================
# file: risk_scoring/risk_score.py
# Description: Risk score calculation combining AI anomaly probabilities and rule-based severity weights.
# ============================================================================

# ===== IMPORT MODULES =====
import numpy as np
import pandas as pd
from typing import Union, Optional

from lsmp_ai.common.config_loader import config
from lsmp_ai.common.logger import logger


# ===== RISK SCORE CALCULATION FUNCTIONS =====
def calculate_risk_score(
    anomaly_score: Union[float, pd.Series, np.ndarray, list],
    severity_weight: Union[float, pd.Series, np.ndarray, list] = 0.0,
    alpha: Optional[float] = None,
    beta: Optional[float] = None,
    max_wazuh_level: Optional[float] = None
) -> Union[float, np.ndarray]:
    """Computes a composite risk score in the range [0.0, 100.0] using the formula:
        RiskScore = 100 * [alpha * norm_anomaly + beta * norm_severity]

    Config defaults:
        - alpha (default: 0.6): Weight given to AI model anomaly probability.
        - beta (default: 0.4): Weight given to rule-based severity level (e.g. Wazuh 0-15).
        - max_wazuh_level (default: 15.0): Maximum benchmark severity level for normalization.

    Args:
        anomaly_score (Union[float, pd.Series, np.ndarray, list]): Anomaly probability score(s) in range [0.0, 1.0].
        severity_weight (Union[float, pd.Series, np.ndarray, list], optional): Rule-based severity level(s). Defaults to 0.0.
        alpha (Optional[float], optional): Custom weight override for AI anomaly score. Defaults to None.
        beta (Optional[float], optional): Custom weight override for severity weight. Defaults to None.
        max_wazuh_level (Optional[float], optional): Custom max severity scale. Defaults to None.

    Returns:
        Union[float, np.ndarray]: Computed risk score(s) clipped in range [0.0, 100.0].
    """
    # Load defaults from config if not explicitly provided
    def_alpha = 0.6
    def_beta = 0.4
    def_max_level = 15.0

    if config and hasattr(config, "risk_params") and config.risk_params:
        def_alpha = float(config.risk_params.get("alpha", def_alpha))
        def_beta = float(config.risk_params.get("beta", def_beta))
        def_max_level = float(config.risk_params.get("max_wazuh_level", def_max_level))

    alpha_val = float(alpha) if alpha is not None else def_alpha
    beta_val = float(beta) if beta is not None else def_beta
    max_level_val = float(max_wazuh_level) if max_wazuh_level is not None else def_max_level

    # Normalize weights so alpha + beta = 1.0
    total_weight = alpha_val + beta_val
    if total_weight > 0:
        alpha_val = alpha_val / total_weight
        beta_val = beta_val / total_weight

    # Convert inputs & handle NaNs/nulls
    if isinstance(anomaly_score, list):
        anomaly_score = np.array(anomaly_score, dtype=float)
    if isinstance(severity_weight, list):
        severity_weight = np.array(severity_weight, dtype=float)

    is_vectorized = isinstance(anomaly_score, (pd.Series, np.ndarray)) or isinstance(severity_weight, (pd.Series, np.ndarray))

    if is_vectorized:
        scores = np.array(anomaly_score, dtype=float)
        scores = np.nan_to_num(scores, nan=0.0)

        if isinstance(severity_weight, (pd.Series, np.ndarray)):
            sevs = np.array(severity_weight, dtype=float)
            sevs = np.nan_to_num(sevs, nan=0.0)
        else:
            sevs = float(severity_weight) if not pd.isna(severity_weight) else 0.0

        norm_severity = np.clip(sevs, 0.0, max_level_val) / max_level_val
        risk = 100.0 * (alpha_val * scores + beta_val * norm_severity)
        return np.clip(risk, 0.0, 100.0)
    else:
        s_val = float(anomaly_score) if anomaly_score is not None and not pd.isna(anomaly_score) else 0.0
        w_val = float(severity_weight) if severity_weight is not None and not pd.isna(severity_weight) else 0.0
        norm_severity = min(max(w_val, 0.0), max_level_val) / max_level_val
        risk = 100.0 * (alpha_val * s_val + beta_val * norm_severity)
        return float(min(max(risk, 0.0), 100.0))


def compute_risk_scores_for_df(
    df: pd.DataFrame, 
    alpha: Optional[float] = None, 
    beta: Optional[float] = None,
    max_wazuh_level: Optional[float] = None
) -> pd.DataFrame:
    """Computes risk scores in a vectorized manner for an entire DataFrame and appends 'risk_score' column.

    Args:
        df (pd.DataFrame): Input DataFrame containing 'anomaly_score' and optional 'severity_weight'.
        alpha (Optional[float], optional): Custom weight for AI anomaly score. Defaults to None.
        beta (Optional[float], optional): Custom weight for rule severity. Defaults to None.
        max_wazuh_level (Optional[float], optional): Custom max severity scale. Defaults to None.

    Returns:
        pd.DataFrame: DataFrame with 'risk_score' column appended.
    """
    if df.empty or "anomaly_score" not in df.columns:
        return df

    anomaly_scores = df["anomaly_score"].values
    severity_weights = df["severity_weight"].values if "severity_weight" in df.columns else 0.0

    df["risk_score"] = calculate_risk_score(
        anomaly_scores, 
        severity_weights, 
        alpha=alpha, 
        beta=beta, 
        max_wazuh_level=max_wazuh_level
    )
    return df
