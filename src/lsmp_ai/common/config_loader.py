# ============================================================================
# file: common/config_loader.py
# Description: Load configuration files for LSMP AI module.
# ============================================================================

# ===== Import modules =====
import os
import yaml
from typing import Any, Dict, List
from lsmp_ai.common.exceptions import ConfigurationError
from lsmp_ai.common.logger import logger

# ===== Data Configuration =====
class DataConfig:
    def __init__(self, train_ratio: float = 0.7, test_ratio: float = 0.3, time_window_minutes: int = 1):
        self.train_ratio = train_ratio
        self.test_ratio = test_ratio
        self.time_window_minutes = time_window_minutes
        self.features = [
            "login_fail_count", "unique_failed_ip_count", "fail_success_ratio", "ip_entropy", "hour_of_day",
            "request_rate", "status_4xx_rate", "url_frequency", "user_agent_entropy", "method_distribution",
            "time_window_count", "burst_rate", "sliding_window_count", "ip_switch_frequency"
        ]

# ===== Sub-Configuration =====
class SubConfig:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

# ===== Model Configuration =====
class ModelConfig:
    def __init__(self, model_store_path: str = None, iforest_params: dict = None, ocsvm_params: dict = None, cascade_params: dict = None):
        self.model_store_path = model_store_path or os.getenv("MODEL_DIR", "models_store")

        # Determine parameters
        iforest_dict = {
            "n_estimators": [100],
            "max_samples": ["auto"],
            "contamination": [0.05],
            "random_state": [42]
        }
        if iforest_params:
            iforest_dict.update(iforest_params)

        ocsvm_dict = {
            "kernel": ["rbf"],
            "nu": [0.05],
            "gamma": ["scale"]
        }
        if ocsvm_params:
            ocsvm_dict.update(ocsvm_params)

        cascade_dict = {
            "iforest_anomaly_threshold": -0.6,
            "iforest_normal_threshold": -0.45,
            "threshold_percentile": 80,
            "model_version": "cascade-v1.0"
        }
        if cascade_params:
            cascade_dict.update(cascade_params)


        # Standardize parameter dictionary values to list for index subscript compatibility [0]
        for d in [iforest_dict, ocsvm_dict, cascade_dict]:
            for k, v in d.items():
                if not isinstance(v, list):
                    d[k] = [v]

        self.iforest = SubConfig(**iforest_dict)
        self.ocsvm = SubConfig(**ocsvm_dict)
        self.cascade = SubConfig(**cascade_dict)

        # Build flattened dictionary params for the main cascade models
        self.iforest_params = {
            "n_estimators": self.iforest.n_estimators[0],
            "max_samples": self.iforest.max_samples[0],
            "contamination": self.iforest.contamination[0],
            "random_state": self.iforest.random_state[0]
        }
        self.ocsvm_params = {
            "kernel": self.ocsvm.kernel[0],
            "nu": self.ocsvm.nu[0],
            "gamma": self.ocsvm.gamma[0]
        }
        self.cascade_params = {
            "iforest_anomaly_threshold": self.cascade.iforest_anomaly_threshold[0],
            "iforest_normal_threshold": self.cascade.iforest_normal_threshold[0],
            "threshold_percentile": self.cascade.threshold_percentile[0],
            "model_version": self.cascade.model_version[0]
        }

# ===== Configure Loader =====
class ConfigLoader:
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            # Default directory structure: projects/LSMP-AIModel/configs
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            self.config_dir = os.path.join(base_dir, "configs")
        else:
            self.config_dir = config_dir

        self.data_config = self._load_yaml("data_config.yaml")
        self.model_config = self._load_yaml("model_config.yaml")
        self.risk_config = self._load_yaml("risk_config.yaml")
        self.logging_config = self._load_yaml("logging.yaml", optional=True)

    def _load_yaml(self, filename: str, optional: bool = False) -> Dict[str, Any]:
        filepath = os.path.join(self.config_dir, filename)
        if not os.path.exists(filepath):
            if optional:
                logger.info(f"Optional configuration file not found, using defaults: {filepath}")
                return {}
            raise ConfigurationError(f"Configuration file not found: {filepath}")
        try:
            with open(filepath, "r") as f:
                config = yaml.safe_load(f)
                logger.info(f"Successfully loaded configuration: {filepath}")
                return config or {}
        except Exception as e:
            if optional:
                logger.warning(f"Failed to parse optional configuration {filename}: {e}. Using defaults.")
                return {}
            raise ConfigurationError(f"Failed to parse {filename}: {e}")

    @property
    def features(self) -> List[str]:
        return self.data_config.get("data", {}).get("features", [])

    @property
    def time_window_minutes(self) -> int:
        return self.data_config.get("data", {}).get("time_window_minutes", 1)

    @property
    def train_test_split_ratio(self) -> float:
        return self.data_config.get("data", {}).get("train_test_split_ratio", self.data_config.get("train_ratio", 0.7))

    @property
    def train_ratio(self) -> float:
        return self.data_config.get("train_ratio", 0.7)

    @property
    def test_ratio(self) -> float:
        return self.data_config.get("test_ratio", 0.3)

    @property
    def raw_data_path(self) -> str:
        return self.data_config.get("raw_data_path", "data/raw")

    @property
    def processed_data_path(self) -> str:
        return self.data_config.get("processed_data_path", "data/processed")

    @property
    def external_data_path(self) -> str:
        return self.data_config.get("external_data_path", "data/external")

    @property
    def feature_version(self) -> str:
        return self.data_config.get("feature_version", "v1")

    @property
    def db_tables(self) -> Dict[str, str]:
        data_section = self.data_config.get("data", {})
        return {
            "wazuh_alerts": data_section.get("db_table_wazuh_alerts", "log_event"),
            "feature_vectors": data_section.get("db_table_features", "feature_vectors"),
            "model_predictions": data_section.get("db_table_predictions", "risk_score"),
            "labels": data_section.get("db_table_labels", "anomaly_result")
        }

    @property
    def iforest_params(self) -> Dict[str, Any]:
        params = self.model_config.get("isolation_forest") or self.model_config.get("iforest", {})
        if not params or not isinstance(params, dict):
            return {"n_estimators": 100, "max_samples": "auto", "contamination": 0.05, "random_state": 42}
        return {k: (v[0] if isinstance(v, list) and len(v) > 0 else v) for k, v in params.items()}

    @property
    def ocsvm_params(self) -> Dict[str, Any]:
        params = self.model_config.get("one_class_svm") or self.model_config.get("ocsvm", {})
        if not params or not isinstance(params, dict):
            return {"kernel": "rbf", "nu": 0.05, "gamma": "scale"}
        return {k: (v[0] if isinstance(v, list) and len(v) > 0 else v) for k, v in params.items()}

    @property
    def cascade_params(self) -> Dict[str, Any]:
        params = self.model_config.get("cascade", {})
        if not params or not isinstance(params, dict):
            return {"iforest_anomaly_threshold": -0.6, "iforest_normal_threshold": -0.45, "threshold_percentile": 80, "model_version": "cascade-v1.0"}
        return {k: (v[0] if isinstance(v, list) and len(v) > 0 else v) for k, v in params.items()}

    @property
    def grid_search_params(self) -> Dict[str, Any]:
        return self.model_config.get("grid_search", {})

    @property
    def model_store_path(self) -> str:
        return self.model_config.get("model_store_path", "models_store")

    @property
    def risk_params(self) -> Dict[str, Any]:
        return self.risk_config.get("risk_scoring", {})

    @property
    def risk_classification_params(self) -> Dict[str, Any]:
        return self.risk_config.get("classification", {})

    @property
    def logging_params(self) -> Dict[str, Any]:
        return self.logging_config or {
            "level": "INFO",
            "file": "logs/lsmp_ai.log",
            "max_bytes": 10485760,
            "backup_count": 5
        }

    @property
    def data(self) -> DataConfig:
        return DataConfig(
            train_ratio=self.train_ratio,
            test_ratio=self.test_ratio,
            time_window_minutes=self.time_window_minutes
        )

    @property
    def model(self) -> ModelConfig:
        return ModelConfig(
            model_store_path=self.model_store_path,
            iforest_params=self.iforest_params,
            ocsvm_params=self.ocsvm_params,
            cascade_params=self.cascade_params
        )

# Global singleton configuration loader
try:
    config = ConfigLoader()
except Exception as e:
    logger.warning(f"Could not initialize global ConfigLoader (might be running tests or outside package dir): {e}")
    config = None
