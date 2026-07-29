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


def calibrate_wazuh_severity(severity: Union[float, np.ndarray]) -> Union[float, np.ndarray]:
    """
    Calibrates raw Wazuh rule severity levels (0-15) to prevent informational alerts
    (levels 1-3) from inflating the composite risk score.

    Wazuh Level Mapping:
      - 0-3: Informational / Normal operation -> 0.0
      - 4-6: Low / Minor warning -> 0.1 - 0.3
      - 7-9: Medium / Active attack pattern -> 0.4 - 0.65
      - 10-15: High / Critical threat -> 0.7 - 1.0
    """
    if isinstance(severity, (pd.Series, np.ndarray)):
        sevs = np.array(severity, dtype=float)
        calibrated = np.where(sevs <= 3, 0.0,
                     np.where(sevs <= 6, (sevs - 3) * (0.3 / 3.0),
                     np.where(sevs <= 9, 0.3 + (sevs - 6) * (0.35 / 3.0),
                     0.65 + np.minimum(sevs - 9, 6) * (0.35 / 6.0))))
        return np.clip(calibrated, 0.0, 1.0)
    else:
        sev = float(severity) if severity is not None and not pd.isna(severity) else 0.0
        if sev <= 3:
            return 0.0
        elif sev <= 6:
            return (sev - 3) * (0.3 / 3.0)
        elif sev <= 9:
            return 0.3 + (sev - 6) * (0.35 / 3.0)
        else:
            return min(1.0, 0.65 + (min(sev, 15) - 9) * (0.35 / 6.0))


# ===== RISK SCORE CALCULATION FUNCTIONS =====
def calculate_risk_score(
    anomaly_score: Union[float, pd.Series, np.ndarray, list],
    severity_weight: Union[float, pd.Series, np.ndarray, list] = 0.0,
    alpha: Optional[float] = None,
    beta: Optional[float] = None,
    max_wazuh_level: Optional[float] = None
) -> Union[float, np.ndarray]:
    """Computes a composite risk score in the range [0.0, 100.0] using calibrated Wazuh severity scaling.
    """
    def_alpha = 0.6
    def_beta = 0.4

    if config and hasattr(config, "risk_params") and config.risk_params:
        def_alpha = float(config.risk_params.get("alpha", def_alpha))
        def_beta = float(config.risk_params.get("beta", def_beta))

    alpha_val = float(alpha) if alpha is not None else def_alpha
    beta_val = float(beta) if beta is not None else def_beta

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

        norm_severity = calibrate_wazuh_severity(sevs)
        raw_risk = 100.0 * (alpha_val * scores + beta_val * norm_severity)

        # AI Gating: If AI score is very low (< 0.25), cap risk score < 45 to prevent false High/Critical alarms
        gated_risk = np.where(scores < 0.25, np.minimum(raw_risk, 45.0), raw_risk)
        return np.clip(gated_risk, 0.0, 100.0)
    else:
        s_val = float(anomaly_score) if anomaly_score is not None and not pd.isna(anomaly_score) else 0.0
        w_val = float(severity_weight) if severity_weight is not None and not pd.isna(severity_weight) else 0.0
        norm_severity = float(calibrate_wazuh_severity(w_val))
        raw_risk = 100.0 * (alpha_val * s_val + beta_val * norm_severity)
        if s_val < 0.25:
            raw_risk = min(raw_risk, 45.0)
        return float(min(max(raw_risk, 0.0), 100.0))


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

    risk_vals = calculate_risk_score(
        anomaly_scores,
        severity_weights,
        alpha=alpha,
        beta=beta,
        max_wazuh_level=max_wazuh_level
    )
    df["risk_score"] = risk_vals
    df["score"] = risk_vals

    alpha_val = alpha if alpha is not None else 0.6
    beta_val = beta if beta is not None else 0.4
    df["ai_component"] = alpha_val * df["anomaly_score"].values
    df["rule_component"] = beta_val * calibrate_wazuh_severity(severity_weights)
    return df
