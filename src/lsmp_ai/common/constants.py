# ============================================================================
# file: common/constants.py
# Description: Constants for LSMP AI module.
# ============================================================================

# Labels
LABEL_NORMAL = "Normal"
LABEL_ANOMALY = "Anomaly"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_UNCERTAIN = "Uncertain"
LABEL_UNKNOWN = "Unknown"

# Decision Status
STATUS_CONFIDENT = "CONFIDENT"
STATUS_UNCERTAIN = "UNCERTAIN"
STATUS_ABSTAINED = "ABSTAINED"

# Standard raw-to-canonical label mapping
LABEL_NORMAL_ALIASES = {"benign", "normal", "clean", "0", "0.0", "inlier"}
LABEL_ANOMALY_ALIASES = {"attack", "anomaly", "1", "1.0", "-1", "-1.0", "outlier"}
LABEL_SUSPICIOUS_ALIASES = {"suspicious"}
LABEL_UNKNOWN_ALIASES = {"unknown", "uncertain", "none", "nan", "null", "undefined", ""}

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
    "auth_fail_count",
    "auth_success_count",
    "auth_fail_ratio",
    "distinct_username",
    "fail_interarrival_mean",
    "fail_interarrival_std",
    "http_req_rate",
    "http_4xx_ratio",
    "http_5xx_ratio",
    "http_post_ratio",
    "distinct_user_agent",
    "bytes_sent_mean",
    "global_active_ips",
    "burst_rate"
]
