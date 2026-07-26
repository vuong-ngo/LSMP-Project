# ============================================================================
# file: feature_engineering/web_features.py
# Description: Web access log feature extraction (request rate, 4xx rate, URL uniqueness, UA entropy).
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


def _get_raw_text(row: Any, col: str = 'raw_log') -> str:
    """Gets raw text string from the specified column."""
    return str(row.get(col, '') or '')


# ===== FEATURE CALCULATION FUNCTIONS =====
def calculate_request_rate(df: pd.DataFrame, window_minutes: int = 1) -> pd.Series:
    """Calculates web request rate (requests per minute) per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.
        window_minutes (int, optional): Duration of sliding window in minutes. Defaults to 1.

    Returns:
        pd.Series: Series mapping src_ip to request rate.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)
    counts = df.groupby('src_ip').size()
    return counts / float(max(window_minutes, 1))


def calculate_status_4xx_rate(df: pd.DataFrame) -> pd.Series:
    """Calculates percentage of 4xx HTTP response status codes per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to 4xx response ratio.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    col = _get_raw_text_col(df)

    def get_status_code(row):
        pj = _get_parsed_json(row)
        if 'status' in pj:
            return str(pj['status'])
        if 'http_code' in pj:
            return str(pj['http_code'])
        match = re.search(r'\s([1-5]\d{2})\s', _get_raw_text(row, col))
        if match:
            return match.group(1)
        return None

    status_codes = df.apply(get_status_code, axis=1)
    is_4xx = status_codes.str.startswith('4', na=False)

    total = df.groupby('src_ip').size()
    fails = df[is_4xx].groupby('src_ip').size()

    return fails.reindex(total.index, fill_value=0) / total


def calculate_url_frequency(df: pd.DataFrame) -> pd.Series:
    """Calculates the ratio of unique URLs visited per src_ip (high uniqueness indicates scanning/fuzzing).

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to URL uniqueness ratio.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    col = _get_raw_text_col(df)

    def get_url(row):
        pj = _get_parsed_json(row)
        if 'url' in pj:
            return pj['url']
        match = re.search(r'"(?:GET|POST|HEAD|PUT|DELETE)\s([^\s?]+)', _get_raw_text(row, col))
        if match:
            return match.group(1)
        return '/'

    urls = df.apply(get_url, axis=1)
    temp_df = pd.DataFrame({'src_ip': df['src_ip'], 'url': urls})

    total = temp_df.groupby('src_ip').size()
    unique_urls = temp_df.groupby('src_ip')['url'].nunique()

    return unique_urls / total


def calculate_user_agent_entropy(df: pd.DataFrame) -> pd.Series:
    """Calculates User-Agent string entropy per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to user agent entropy.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    def get_ua(row):
        pj = _get_parsed_json(row)
        if 'user_agent' in pj:
            return pj['user_agent']
        return 'unknown'

    uas = df.apply(get_ua, axis=1)
    temp_df = pd.DataFrame({'src_ip': df['src_ip'], 'ua': uas})

    entropies = {}
    for ip, group in temp_df.groupby('src_ip'):
        counts = group['ua'].value_counts()
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs + 1e-9))
        entropies[ip] = float(entropy)

    return pd.Series(entropies)


def calculate_method_distribution(df: pd.DataFrame) -> pd.Series:
    """Calculates ratio of non-GET/POST HTTP methods (HEAD, OPTIONS, PUT, DELETE) per src_ip.

    Args:
        df (pd.DataFrame): Raw log events DataFrame.

    Returns:
        pd.Series: Series mapping src_ip to non-GET/POST method ratio.
    """
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    col = _get_raw_text_col(df)

    def get_method(row):
        pj = _get_parsed_json(row)
        if 'method' in pj:
            return str(pj['method']).upper()
        match = re.search(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s', _get_raw_text(row, col))
        if match:
            return match.group(1).upper()
        return 'GET'

    methods = df.apply(get_method, axis=1)
    is_other = ~methods.isin(['GET', 'POST'])

    total = df.groupby('src_ip').size()
    others = df[is_other].groupby('src_ip').size()

    return others.reindex(total.index, fill_value=0) / total
