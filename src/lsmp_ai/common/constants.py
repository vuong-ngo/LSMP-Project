# ============================================================================
# file: common/constants.py
# Description: Constants for LSMP AI module.
# ============================================================================

# Labels
LABEL_NORMAL = "Normal"
LABEL_ANOMALY = "Anomaly"
LABEL_UNKNOWN = "Unknown"

# Label sources
SOURCE_LAB_SCENARIO = "lab_scenario"
SOURCE_WAZUH_RULE_WEAK = "wazuh_rule_weak"
SOURCE_ANALYST_CONFIRMED = "analyst_confirmed"
SOURCE_IP_REPUTATION = "ip_reputation"
SOURCE_BASELINE_NORMAL = "baseline_normal"

# Default schema table names (matching schema.sql)
TABLE_LOG_EVENT = "log_event"
TABLE_FEATURE_VECTORS = "feature_vectors"
TABLE_ANOMALY_RESULT = "anomaly_result"
TABLE_RISK_SCORE = "risk_score"
TABLE_ATTACK_SCENARIOS = "attack_scenarios"
TABLE_EVALUATION_METRICS = "evaluation_metrics"

# Legacy aliases for backward compatibility
TABLE_RAW_LOGS = TABLE_LOG_EVENT
TABLE_WAZUH_ALERTS = TABLE_LOG_EVENT
TABLE_MODEL_PREDICTIONS = TABLE_RISK_SCORE
TABLE_LABELS = TABLE_ANOMALY_RESULT
TABLE_AGENTS = "agents"  # not in current schema but kept for compat

# Model constants
DEFAULT_MODEL_VERSION = "cascade-v1.0"

FEATURE_COLUMNS = [
    "login_fail_count",
    "unique_failed_ip_count",
    "fail_success_ratio",
    "ip_entropy",
    "hour_of_day",
    "request_rate",
    "status_4xx_rate",
    "url_frequency",
    "user_agent_entropy",
    "method_distribution",
    "time_window_count",
    "burst_rate",
    "sliding_window_count",
    "ip_switch_frequency"
]

