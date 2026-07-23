# ============================================================================
# file: feature_engineering/behavior_features.py
# Description: User and network behavior feature extraction (window count, burst rate, IP switching).
# ============================================================================

# ===== IMPORT MODULES =====
import re
import json
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


def _get_parsed_json(row: Any) -> dict:
    """Safely extracts parsed_json as dict. Handles JSONB (dict) and string formats."""
    pj = row.get('parsed_json')
    if pj is None:
        return {}
    if isinstance(pj, dict):
        return pj
    if isinstance(pj, str):
        try:
            return json.loads(pj)
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


# ===== FEATURE CALCULATION FUNCTIONS =====
def calculate_time_window_count(df: pd.DataFrame) -> pd.Series:
    """Calculates absolute count of log events per src_ip in the current time window.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to log event count.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)
    return df.groupby('src_ip').size().astype(float)


def calculate_burst_rate(df_current: pd.DataFrame, df_historical: pd.DataFrame) -> pd.Series:
    """Calculates ratio of event volume in current window vs historical average per src_ip.

    Args:
        df_current (pd.DataFrame): Log events DataFrame for current window.
        df_historical (pd.DataFrame): Log events DataFrame for historical baseline.

    Returns:
        pd.Series: Series mapping src_ip to burst rate multiplier.
    """
    if df_current.empty or 'src_ip' not in df_current.columns:
        return pd.Series(dtype=float)

    current_counts = df_current.groupby('src_ip').size()
    if df_historical is None or df_historical.empty or 'src_ip' not in df_historical.columns:
        return pd.Series(1.0, index=current_counts.index)

    hist_counts_mean = df_historical.groupby('src_ip').size() / 10.0

    burst_rates = {}
    for ip, cur_val in current_counts.items():
        hist_val = hist_counts_mean.get(ip, 0.0)
        if hist_val == 0.0:
            burst_rates[ip] = float(cur_val)
        else:
            burst_rates[ip] = float(cur_val) / hist_val

    return pd.Series(burst_rates)


def calculate_ip_switch_frequency(df: pd.DataFrame) -> pd.Series:
    """Detects user accounts logging in from multiple source IPs within a short window.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to max IP switch count across associated user accounts.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    col = _get_raw_text_col(df)

    def get_user(row):
        pj = _get_parsed_json(row)
        if 'user' in pj:
            return pj['user']
        raw_text = str(row.get(col, '') or '')
        match = re.search(r'for\s+user?\s+([^\s]+)', raw_text)
        if match:
            return match.group(1)
        return 'unknown'

    users = df.apply(get_user, axis=1)
    temp_df = pd.DataFrame({'src_ip': df['src_ip'], 'user': users})

    temp_df = temp_df[temp_df['user'] != 'unknown']
    if temp_df.empty:
        return pd.Series(0.0, index=df['src_ip'].unique())

    ips_per_user = temp_df.groupby('user')['src_ip'].nunique()

    ip_switch = {}
    for ip in df['src_ip'].unique():
        user_subset = temp_df[temp_df['src_ip'] == ip]['user'].unique()
        if len(user_subset) == 0:
            ip_switch[ip] = 0.0
        else:
            ip_switch[ip] = float(max(ips_per_user.get(u, 0) for u in user_subset))

    return pd.Series(ip_switch)
