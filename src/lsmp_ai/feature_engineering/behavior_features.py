# ============================================================================
# file: feature_engineering/behavior_features.py
# Description: Production Behavioral and Contextual Feature Extraction for LSMP AI Module.
#              Aligned with SME Kit research benchmarks (Global Active IPs, Normalized Burst Rate).
# ============================================================================

import re
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Union, Optional


def _get_raw_text_series(df: pd.DataFrame) -> pd.Series:
    """Extracts raw log text series using vectorized column lookup."""
    if 'raw_message' in df.columns:
        return df['raw_message'].fillna('').astype(str)
    if 'raw_log' in df.columns:
        return df['raw_log'].fillna('').astype(str)
    return pd.Series('', index=df.index)


# ============================================================================
# CORE 14 CONTEXT & BEHAVIORAL FEATURE FUNCTIONS
# ============================================================================

def calculate_global_active_ips(df: pd.DataFrame) -> float:
    """Calculates total count of unique source IPs observed across the entire time window.

    Signal for: Distributed attacks (Botnet DDoS, Distributed Brute-force).
    Broadcasting this global context allows the model to evaluate individual IP suspicion
    relative to global network distress.
    """
    if df.empty or 'src_ip' not in df.columns:
        return 0.0
    return float(df['src_ip'].dropna().nunique())


def calculate_burst_rate(
    df_current: pd.DataFrame,
    df_historical: Optional[pd.DataFrame] = None
) -> pd.Series:
    """Calculates ratio of event volume in current window vs historical baseline per src_ip.

    Formula:
        current_count / max(mean(historical_counts), 1.0)
    Policy:
        If historical baseline is missing or empty, returns default 1.0 (normal activity).
    """
    if df_current.empty or 'src_ip' not in df_current.columns:
        return pd.Series(dtype=float)

    total_ips = df_current['src_ip'].dropna().unique()
    current_counts = df_current.groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)

    if df_historical is None or df_historical.empty or 'src_ip' not in df_historical.columns:
        # If historical baseline is absent, measure internal intra-window burstiness (peak rate vs mean rate)
        time_col = None
        for c in ['timestamp', 'time', 'window_start', 'ts', 'datetime', 'computed_at']:
            if c in df_current.columns:
                time_col = c
                break
        if time_col and len(df_current) > 1:
            try:
                ts = pd.to_datetime(df_current[time_col], utc=True, errors="coerce")
                if ts.notna().sum() > 1:
                    df_tmp = pd.DataFrame({"src_ip": df_current["src_ip"], "ts": ts}).dropna()
                    df_tmp["bucket"] = df_tmp["ts"].dt.floor("10s")
                    bucket_counts = df_tmp.groupby(["src_ip", "bucket"]).size()
                    burst_map = {}
                    for ip, sub in bucket_counts.groupby(level=0):
                        mean_val = float(sub.mean())
                        max_val = float(sub.max())
                        burst_map[ip] = float(max_val / max(mean_val, 1.0))
                    return pd.Series(burst_map).reindex(total_ips, fill_value=1.0).astype(float)
            except Exception:
                pass
        return pd.Series(1.0, index=total_ips, dtype=float)

    hist_counts = df_historical.groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)

    # Compute baseline denominator
    # If historical data represents multiple windows, divide by number of distinct windows
    window_col = None
    for c in ['window_start', 'timestamp', 'time', 'window_end', 'ts', 'datetime']:
        if c in df_historical.columns:
            window_col = c
            break

    if window_col:
        num_windows = max(float(df_historical[window_col].nunique()), 1.0)
        hist_baseline = hist_counts / num_windows
    else:
        hist_baseline = hist_counts

    denominator = np.maximum(hist_baseline, 1.0)
    burst = current_counts / denominator
    return pd.Series(burst, index=total_ips, dtype=float)


# ============================================================================
# BACKWARD COMPATIBILITY ALIASES
# ============================================================================

def calculate_time_window_count(df: pd.DataFrame) -> pd.Series:
    """Calculates total event count per src_ip in current window."""
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)
    total_ips = df['src_ip'].dropna().unique()
    return df.groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)


def calculate_ip_switch_frequency(df: pd.DataFrame) -> pd.Series:
    """Detects user accounts logging in from multiple source IPs within a short window.

    Vectorized implementation: O(N) groupby instead of nested Python loops.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    total_ips = df['src_ip'].dropna().unique()
    raw_text = _get_raw_text_series(df)
    users = raw_text.str.extract(r'for\s+(?:user\s+|invalid\s+user\s+)?([^\s]+)', expand=False).fillna('unknown')

    temp_df = pd.DataFrame({'src_ip': df['src_ip'], 'user': users})
    temp_df = temp_df[temp_df['user'] != 'unknown']

    if temp_df.empty:
        return pd.Series(0.0, index=total_ips, dtype=float)

    ips_per_user = temp_df.groupby('user')['src_ip'].nunique()
    temp_df['ips_for_this_user'] = temp_df['user'].map(ips_per_user)

    max_ips_per_src_ip = temp_df.groupby('src_ip')['ips_for_this_user'].max()
    return max_ips_per_src_ip.reindex(total_ips, fill_value=0.0).astype(float)
