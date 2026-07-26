# ============================================================================
# file: feature_engineering/auth_features.py
# Description: Authentication feature extraction utilities (login failures, ratio, IP entropy).
# ============================================================================

# ===== IMPORT MODULES =====
import numpy as np
import pandas as pd
from typing import Dict, Any, Union


# ===== HELPER FUNCTIONS =====
def _get_raw_text_col(df: pd.DataFrame) -> str:
    """Returns the correct raw text column name ('raw_log' or 'raw_message')."""
    if 'raw_log' in df.columns:
        return 'raw_log'
    if 'raw_message' in df.columns:
        return 'raw_message'
    return 'raw_log'


# ===== FEATURE CALCULATION FUNCTIONS =====
def calculate_login_fail_count(df: pd.DataFrame) -> pd.Series:
    """Calculates count of failed authentication attempts per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to count of failed logins.
    """
    if df.empty:
        return pd.Series(dtype=float)
    col = _get_raw_text_col(df)
    if col not in df.columns:
        idx = df['src_ip'].unique() if 'src_ip' in df.columns else []
        return pd.Series(0.0, index=idx)

    is_fail = df[col].astype(str).str.contains('Failed|invalid|auth|failure', case=False, na=False)
    return df[is_fail].groupby('src_ip').size()


def calculate_unique_failed_ip_count(df: pd.DataFrame) -> pd.Series:
    """Calculates count of unique target hosts/IPs that received failed logins per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to unique target host count.
    """
    if df.empty:
        return pd.Series(dtype=float)
    col = _get_raw_text_col(df)
    if col not in df.columns:
        idx = df['src_ip'].unique() if 'src_ip' in df.columns else []
        return pd.Series(0.0, index=idx)

    is_fail = df[col].astype(str).str.contains('Failed|invalid|auth|failure', case=False, na=False)
    failed_df = df[is_fail]
    if 'host' in failed_df.columns:
        return failed_df.groupby('src_ip')['host'].nunique()
    return pd.Series(1.0, index=failed_df['src_ip'].unique())


def calculate_fail_success_ratio(df: pd.DataFrame) -> pd.Series:
    """Calculates ratio of failed logins to successful logins per src_ip (with Laplace smoothing).

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to fail-to-success ratio.
    """
    if df.empty:
        return pd.Series(dtype=float)
    col = _get_raw_text_col(df)
    if col not in df.columns:
        return pd.Series(0.0, index=df['src_ip'].unique())

    raw_text = df[col].astype(str)
    is_fail = raw_text.str.contains('Failed|invalid|auth|failure', case=False, na=False)
    is_success = raw_text.str.contains('Accepted|success|session opened', case=False, na=False)

    fails = df[is_fail].groupby('src_ip').size()
    successes = df[is_success].groupby('src_ip').size()

    ips = df['src_ip'].dropna().unique()
    ratio = []
    for ip in ips:
        f = fails.get(ip, 0)
        s = successes.get(ip, 0)
        ratio.append(float(f) / (float(s) + 1.0))
    return pd.Series(ratio, index=ips)


def calculate_ip_entropy(df: pd.DataFrame) -> float:
    """Calculates Shannon entropy of source IP distribution across the current batch.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        float: Computed entropy value.
    """
    if df.empty or 'src_ip' not in df.columns:
        return 0.0
    counts = df['src_ip'].value_counts()
    probs = counts / counts.sum()
    entropy = -np.sum(probs * np.log2(probs + 1e-9))
    return float(entropy)
