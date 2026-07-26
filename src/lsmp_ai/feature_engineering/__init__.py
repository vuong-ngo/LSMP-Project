# ============================================================================
# file: feature_engineering/__init__.py
# Description: Feature engineering module for extracting and preprocessing security features from logs
# ============================================================================

from lsmp_ai.feature_engineering.feature_pipeline import FeaturePipeline, extract_features_from_logs
from lsmp_ai.feature_engineering.build_features import build_features_from_csv, build_features_from_db
from lsmp_ai.feature_engineering.auth_features import (
    calculate_login_fail_count,
    calculate_unique_failed_ip_count,
    calculate_fail_success_ratio,
    calculate_ip_entropy,
)
from lsmp_ai.feature_engineering.web_features import (
    calculate_request_rate,
    calculate_status_4xx_rate,
    calculate_url_frequency,
    calculate_user_agent_entropy,
    calculate_method_distribution,
)
from lsmp_ai.feature_engineering.behavior_features import (
    calculate_time_window_count,
    calculate_burst_rate,
    calculate_ip_switch_frequency,
)

__all__ = [
    "FeaturePipeline",
    "extract_features_from_logs",
    "build_features_from_csv",
    "build_features_from_db",
    "calculate_login_fail_count",
    "calculate_unique_failed_ip_count",
    "calculate_fail_success_ratio",
    "calculate_ip_entropy",
    "calculate_request_rate",
    "calculate_status_4xx_rate",
    "calculate_url_frequency",
    "calculate_user_agent_entropy",
    "calculate_method_distribution",
    "calculate_time_window_count",
    "calculate_burst_rate",
    "calculate_ip_switch_frequency",
]
