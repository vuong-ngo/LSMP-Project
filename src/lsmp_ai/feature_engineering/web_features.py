# ============================================================================
# file: feature_engineering/web_features.py
# Description: Production Web & HTTP Access Log Feature Extraction for LSMP AI Module.
#              Aligned with SME Kit research benchmarks and Nginx Access Log format.
# ============================================================================

import re
import json
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Union, Optional

# Precompiled regular expressions for high-performance Nginx / Web log parsing
HTTP_METHOD_PATTERN = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s', re.IGNORECASE)
HTTP_STATUS_PATTERN = re.compile(r'\s([1-5]\d{2})\s')
HTTP_BYTES_PATTERN = re.compile(r'\s([1-5]\d{2})\s+(\d+|-)')
HTTP_URL_PATTERN = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s([^\s?]+)', re.IGNORECASE)
HTTP_UA_PATTERN = re.compile(r'"[^"]*"\s+"([^"]*)"')


def _get_raw_text_series(df: pd.DataFrame) -> pd.Series:
    """Extracts raw log text series using vectorized column lookup."""
    if 'raw_message' in df.columns:
        return df['raw_message'].fillna('').astype(str)
    if 'raw_log' in df.columns:
        return df['raw_log'].fillna('').astype(str)
    return pd.Series('', index=df.index)


def _extract_parsed_field(df: pd.DataFrame, key: str, fallback_series: pd.Series) -> pd.Series:
    """Extracts field from parsed_json with fallback to regex-extracted series."""
    if 'parsed_json' in df.columns:
        def get_field(row):
            pj = row.get('parsed_json')
            if isinstance(pj, dict):
                return pj.get(key)
            if isinstance(pj, str):
                try:
                    d = json.loads(pj)
                    return d.get(key)
                except Exception:
                    return None
            return None
        json_vals = df.apply(get_field, axis=1)
        return json_vals.combine_first(fallback_series)
    return fallback_series


def _extract_http_attributes(df: pd.DataFrame) -> pd.DataFrame:
    """Vectorized extraction of status, method, bytes, and user agent."""
    raw_text = _get_raw_text_series(df)

    # 1. Status Code
    status_raw = raw_text.str.extract(r'\s([1-5]\d{2})\s', expand=False)
    status = _extract_parsed_field(df, 'status', status_raw)
    status_num = pd.to_numeric(status, errors='coerce').fillna(200).astype(int)

    # 2. HTTP Method
    method_raw = raw_text.str.extract(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT)\s', expand=False)
    method = _extract_parsed_field(df, 'method', method_raw).fillna('GET').str.upper()

    # 3. Response Bytes
    bytes_raw = raw_text.str.extract(r'\s[1-5]\d{2}\s+(\d+)', expand=False)
    resp_bytes = _extract_parsed_field(df, 'bytes', bytes_raw)
    bytes_num = pd.to_numeric(resp_bytes, errors='coerce').fillna(0).astype(float)

    # 4. User Agent
    ua_raw = raw_text.str.extract(r'"[^"]*"\s+"([^"]*)"', expand=False)
    ua = _extract_parsed_field(df, 'user_agent', ua_raw).fillna('unknown')

    # 5. URL Path
    url_raw = raw_text.str.extract(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s([^\s?]+)', expand=False)
    url = _extract_parsed_field(df, 'url', url_raw).fillna('/')

    # Determine is_http
    is_http = method_raw.notna() | url_raw.notna()
    if 'parsed_json' in df.columns:
        def check_pj(val):
            if isinstance(val, dict):
                return bool('url' in val or 'method' in val or 'status' in val or 'user_agent' in val)
            return False
        is_http |= df['parsed_json'].apply(check_pj)
    if 'event_type' in df.columns:
        is_http |= df['event_type'].astype(str).str.lower().isin(['web', 'http', 'nginx', 'apache'])

    # If df has no auth indicators and no specific event_type, default to True for backward compat
    has_auth = raw_text.str.contains(r'sshd|Failed password|Invalid user|Accepted (?:password|publickey)', case=False, na=False)
    if not is_http.any() and not has_auth.any():
        is_http = pd.Series(True, index=df.index)

    return pd.DataFrame({
        'src_ip': df['src_ip'] if 'src_ip' in df.columns else '0.0.0.0',
        'status': status_num,
        'method': method,
        'bytes': bytes_num,
        'user_agent': ua,
        'url': url,
        'is_http': is_http,
    })


# ============================================================================
# CORE 14 WEB FEATURE EXTRACTION FUNCTIONS
# ============================================================================

def calculate_http_req_rate(df: pd.DataFrame, window_seconds: float = 60.0) -> pd.Series:
    """Calculates web request rate (requests per second) per src_ip.

    Signal for: Volume intensity / baseline load. Scale-invariant to window duration.
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    duration = max(float(window_seconds), 1.0)
    attrs = _extract_http_attributes(df)
    http_mask = attrs['is_http']
    counts = attrs[http_mask].groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)
    return counts / duration


def calculate_http_status_ratios(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series]:
    """Calculates 4xx error ratio and 5xx error ratio per src_ip.

    Signal for:
        - 4xx: Directory scanning, fuzzing (Gobuster), or bad web-login attempts.
        - 5xx: Backend server crash (SQL injection crash, RCE error, resource exhaustion).
    Returns:
        Tuple[pd.Series, pd.Series]: (http_4xx_ratio, http_5xx_ratio).
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        empty = pd.Series(dtype=float)
        return empty, empty

    attrs = _extract_http_attributes(df)
    valid_attrs = attrs[attrs['is_http']]
    if valid_attrs.empty:
        zeros = pd.Series(0.0, index=total_ips, dtype=float)
        return zeros, zeros

    total_reqs = valid_attrs.groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)

    is_4xx = (valid_attrs['status'] >= 400) & (valid_attrs['status'] < 500)
    is_5xx = (valid_attrs['status'] >= 500) & (valid_attrs['status'] < 600)

    count_4xx = valid_attrs[is_4xx].groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)
    count_5xx = valid_attrs[is_5xx].groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)

    ratio_4xx = np.where(total_reqs > 0, count_4xx / total_reqs, 0.0)
    ratio_5xx = np.where(total_reqs > 0, count_5xx / total_reqs, 0.0)

    return pd.Series(ratio_4xx, index=total_ips, dtype=float), pd.Series(ratio_5xx, index=total_ips, dtype=float)


def calculate_http_post_ratio(df: pd.DataFrame) -> pd.Series:
    """Calculates ratio of HTTP POST requests per src_ip.

    Signal for: Web login brute force (login forms predominantly use HTTP POST).
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    valid_attrs = attrs[attrs['is_http']]
    if valid_attrs.empty:
        return pd.Series(0.0, index=total_ips, dtype=float)

    total_reqs = valid_attrs.groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)
    is_post = valid_attrs['method'] == 'POST'
    count_post = valid_attrs[is_post].groupby('src_ip').size().reindex(total_ips, fill_value=0.0).astype(float)

    ratio_post = np.where(total_reqs > 0, count_post / total_reqs, 0.0)
    return pd.Series(ratio_post, index=total_ips, dtype=float)


def calculate_distinct_user_agent(df: pd.DataFrame) -> pd.Series:
    """Calculates number of distinct User-Agent strings per src_ip.

    Signal for: Automated scanners cycling User-Agents to evade simple WAF filters.
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    valid_ua = attrs[attrs['is_http'] & (attrs['user_agent'] != 'unknown') & attrs['user_agent'].notna()]
    if valid_ua.empty:
        return pd.Series(0.0, index=total_ips, dtype=float)
    distinct_ua = valid_ua.groupby('src_ip')['user_agent'].nunique().reindex(total_ips, fill_value=0.0).astype(float)
    return distinct_ua


def calculate_bytes_sent_mean(df: pd.DataFrame) -> pd.Series:
    """Calculates mean response size in bytes per src_ip.

    Signal for: Error responses (401, 403, 302) have highly uniform response size signatures.
    """
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    valid_bytes = attrs[attrs['is_http']]
    if valid_bytes.empty:
        return pd.Series(0.0, index=total_ips, dtype=float)
    mean_bytes = valid_bytes.groupby('src_ip')['bytes'].mean().reindex(total_ips, fill_value=0.0).astype(float)
    return mean_bytes


# ============================================================================
# BACKWARD COMPATIBILITY ALIASES
# ============================================================================

def calculate_request_rate(df: pd.DataFrame, window_minutes: int = 1) -> pd.Series:
    """Legacy alias: requests per minute."""
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)
    counts = df.groupby('src_ip').size().astype(float)
    total_ips = df['src_ip'].dropna().unique()
    return (counts / float(max(window_minutes, 1))).reindex(total_ips, fill_value=0.0)


def calculate_status_4xx_rate(df: pd.DataFrame) -> pd.Series:
    """Legacy alias: 4xx ratio."""
    r4, _ = calculate_http_status_ratios(df)
    return r4


def calculate_url_frequency(df: pd.DataFrame) -> pd.Series:
    """Legacy alias: URL uniqueness ratio."""
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    total = attrs.groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)
    unique_urls = attrs.groupby('src_ip')['url'].nunique().reindex(total_ips, fill_value=0).astype(float)
    return np.where(total > 0, unique_urls / total, 0.0)


def calculate_user_agent_entropy(df: pd.DataFrame) -> pd.Series:
    """Legacy alias: User-Agent entropy."""
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    entropies = {}
    for ip in total_ips:
        subset = attrs[attrs['src_ip'] == ip]
        if subset.empty:
            entropies[ip] = 0.0
            continue
        counts = subset['user_agent'].value_counts()
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs + 1e-9))
        entropies[ip] = float(entropy)
    return pd.Series(entropies, dtype=float)


def calculate_method_distribution(df: pd.DataFrame) -> pd.Series:
    """Legacy alias: ratio of non-GET/POST HTTP methods."""
    total_ips = df['src_ip'].dropna().unique() if ('src_ip' in df.columns and not df.empty) else []
    if df.empty or 'src_ip' not in df.columns:
        return pd.Series(dtype=float)

    attrs = _extract_http_attributes(df)
    total = attrs.groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)
    is_other = ~attrs['method'].isin(['GET', 'POST'])
    count_other = attrs[is_other].groupby('src_ip').size().reindex(total_ips, fill_value=0).astype(float)
    return np.where(total > 0, count_other / total, 0.0)
