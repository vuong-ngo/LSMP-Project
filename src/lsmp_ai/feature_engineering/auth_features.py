# ============================================================================
# file: feature_engineering/auth_features.py
# Description: Production Authentication Feature Extraction for LSMP AI Module.
#              Aligned with SME Kit research benchmarks and Loghub Syslog schema.
# ============================================================================

import re
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Union, Optional

# Precompiled regular expressions for high-performance authentication log parsing
AUTH_FAIL_PATTERN = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]{8})?.*?(Failed password|Invalid user|authentication failure|POSSIBLE BREAK-IN ATTEMPT)",
    re.IGNORECASE
)
AUTH_OK_PATTERN = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]{8})?.*?Accepted (?:password|publickey)",
    re.IGNORECASE
)
USER_EXTRACT_PATTERN = re.compile(
    r"for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE
)


def _get_raw_text_series(df: pd.DataFrame) -> pd.Series:
    """Extracts raw log text series using vectorized column lookup."""
    if 'raw_message' in df.columns:
        return df['raw_message'].fillna('').astype(str)
    if 'raw_log' in df.columns:
        return df['raw_log'].fillna('').astype(str)
    return pd.Series('', index=df.index)


def _extract_users_vectorized(df: pd.DataFrame, raw_text: pd.Series) -> pd.Series:
    """Extracts username per log line using vectorized regex with parsed_json fallback."""
    # 1. Fast regex extraction from raw log text
    extracted = raw_text.str.extract(r"for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\-\.]+)", expand=False)
    
    # 2. Fallback to parsed_json if available
    if 'parsed_json' in df.columns:
        def get_json_user(row):
            pj = row.get('parsed_json')
            if isinstance(pj, dict):
                return pj.get('user') or pj.get('dstuser') or pj.get('username')
            return None
        json_users = df.apply(get_json_user, axis=1)
        extracted = extracted.fillna(json_users)
        
    return extracted.fillna('unknown')


def _get_event_timestamps_sec(df: pd.DataFrame, raw_text: pd.Series) -> pd.Series:
    """Extracts event timestamps as epoch seconds for interarrival calculations."""
    for ts_col in ['timestamp', 'ts', 'time', 'window_start']:
        if ts_col in df.columns:
            ts_series = pd.to_datetime(df[ts_col], errors='coerce')
            if not ts_series.isna().all():
                if hasattr(ts_series.dt, 'tz') and ts_series.dt.tz is not None:
                    ts_series = ts_series.dt.tz_localize(None)
                return ts_series.astype('datetime64[s]').astype('int64')

    # Fallback to parsing timestamp string from raw log text
    ts_extracted = raw_text.str.extract(r"^(\w{3}\s+\d+\s[\d:]{8})", expand=False)
    if not ts_extracted.isna().all():
        curr_year = datetime.now(timezone.utc).year
        ts_dt = pd.to_datetime(f"{curr_year} " + ts_extracted, format="%Y %b %d %H:%M:%S", errors='coerce')
        if hasattr(ts_dt.dt, 'tz') and ts_dt.dt.tz is not None:
            ts_dt = ts_dt.dt.tz_localize(None)
        return ts_dt.astype('datetime64[s]').astype('int64')

    # Default fallback: sequential seconds
    return pd.Series(np.arange(len(df), dtype=float), index=df.index)


# ============================================================================
# CORE 14 AUTH FEATURE EXTRACTION FUNCTIONS
# ============================================================================

def calculate_auth_fail_count(df: pd.DataFrame) -> pd.Series:
    """Calculates count of failed authentication attempts per src_ip in current window.

    Signal for: MITRE ATT&CK T1110.001 (Password Guessing & Brute Force).
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    raw_text = _get_raw_text_series(df)
    is_http_line = raw_text.str.contains(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s', regex=True, na=False)
    is_fail = raw_text.str.contains(r'failed\s+password|invalid\s+user|authentication\s+failure|BREAK-IN', case=False, na=False)
    is_fail |= (~is_http_line) & raw_text.str.contains(r'\b(?:fail|failure)\b', case=False, na=False)
    
    # Check parsed_json status or event_type if present
    if 'event_type' in df.columns:
        is_fail |= (df['event_type'] == 'auth') & raw_text.str.contains(r'\bfail', case=False, na=False)

    total_ips = df['src_ip'].dropna().unique()
    fails = df[is_fail].groupby('src_ip').size()
    return fails.reindex(total_ips, fill_value=0).astype(float)


def calculate_auth_success_count(df: pd.DataFrame) -> pd.Series:
    """Calculates count of successful authentication attempts per src_ip in current window.

    Signal for: Distinguishing benign admin activity from successful account takeover.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    raw_text = _get_raw_text_series(df)
    is_http_line = raw_text.str.contains(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s', regex=True, na=False)
    is_success = raw_text.str.contains(r'\b(?:Accepted\s+(?:password|publickey)|session\s+opened)\b', case=False, na=False)
    is_success |= (~is_http_line) & raw_text.str.contains(r'\b(?:Accepted|success)\b', case=False, na=False)
    is_success &= ~raw_text.str.contains(r'\b(?:unsuccessful|not successful)\b', case=False, na=False)

    total_ips = df['src_ip'].dropna().unique()
    successes = df[is_success].groupby('src_ip').size()
    return successes.reindex(total_ips, fill_value=0).astype(float)


def calculate_auth_fail_ratio(df: pd.DataFrame) -> pd.Series:
    """Calculates normalized authentication failure ratio per src_ip.

    Formula: fail / (fail + success) in range [0, 1].
    Policy: If fail + success == 0, returns 0.0 (prevents division by zero).
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    fails = calculate_auth_fail_count(df)
    successes = calculate_auth_success_count(df)

    total_attempts = fails + successes
    ratio = np.where(total_attempts > 0, fails / total_attempts, 0.0)
    return pd.Series(ratio, index=fails.index, dtype=float)


def calculate_distinct_username(df: pd.DataFrame) -> pd.Series:
    """Calculates number of distinct usernames targeted per src_ip in current window.

    Signal for: MITRE ATT&CK T1110.003 (Password Spraying: trying 1 password across many usernames).
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    raw_text = _get_raw_text_series(df)
    users = _extract_users_vectorized(df, raw_text)

    temp_df = pd.DataFrame({'src_ip': df['src_ip'], 'user': users})
    temp_df = temp_df[temp_df['user'] != 'unknown']

    total_ips = df['src_ip'].dropna().unique()
    if temp_df.empty:
        return pd.Series(0.0, index=total_ips)

    distinct_users = temp_df.groupby('src_ip')['user'].nunique()
    return distinct_users.reindex(total_ips, fill_value=0).astype(float)


def calculate_fail_interarrival_stats(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series]:
    """Calculates mean and standard deviation of time intervals between consecutive failures per src_ip.

    Signal for:
        - Mean: Attack speed / pacing.
        - Std: Automated scripts (Hydra, Medusa) have low std (~0.0s), humans have high std.
    Policy:
        - If fail count < 2: mean = 0.0, std = 0.0.
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        empty = pd.Series(dtype=float)
        return empty, empty

    raw_text = _get_raw_text_series(df)
    is_http_line = raw_text.str.contains(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s', regex=True, na=False)
    is_fail = raw_text.str.contains(r'failed\s+password|invalid\s+user|authentication\s+failure|BREAK-IN', case=False, na=False)
    is_fail |= (~is_http_line) & raw_text.str.contains(r'\b(?:fail|failure)\b', case=False, na=False)

    df_fails = df[is_fail].copy()
    if df_fails.empty:
        zeros = pd.Series(0.0, index=total_ips)
        return zeros, zeros

    ts_sec = _get_event_timestamps_sec(df_fails, raw_text.loc[df_fails.index])
    df_fails['ts_sec'] = ts_sec

    mean_dict = {}
    std_dict = {}

    for ip in total_ips:
        ip_fails = df_fails[df_fails['src_ip'] == ip]
        if len(ip_fails) >= 2:
            timestamps = ip_fails['ts_sec'].sort_values().values
            gaps = np.diff(timestamps)
            # Filter negative or corrupted jumps
            gaps = gaps[gaps >= 0]
            if len(gaps) > 0:
                mean_dict[ip] = float(np.mean(gaps))
                std_dict[ip] = float(np.std(gaps))
            else:
                mean_dict[ip] = 0.0
                std_dict[ip] = 0.0
        else:
            mean_dict[ip] = 0.0
            std_dict[ip] = 0.0

    return pd.Series(mean_dict, dtype=float), pd.Series(std_dict, dtype=float)


# ============================================================================
# BACKWARD COMPATIBILITY ALIASES
# ============================================================================
calculate_login_fail_count = calculate_auth_fail_count
calculate_fail_success_ratio = calculate_auth_fail_ratio


def calculate_unique_failed_ip_count(df: pd.DataFrame) -> pd.Series:
    """Legacy alias preserved for backward compatibility."""
    return calculate_distinct_username(df)


def calculate_ip_entropy(df: pd.DataFrame) -> float:
    """Shannon entropy of source IP distribution across current batch."""
    if df.empty or 'src_ip' not in df.columns:
        return 0.0
    counts = df['src_ip'].value_counts()
    probs = counts / counts.sum()
    entropy = -np.sum(probs * np.log2(probs + 1e-9))
    return float(entropy)
