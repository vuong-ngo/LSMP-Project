# ============================================================================
# file: src/lsmp_ai/common/config_loader.py
# Description: Null-Safe Configuration Loader for LSMP AI Module.
#              Guarantees fallback defaults to prevent null config exceptions.
# ============================================================================

# ===== Import modules =====
import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

from lsmp_ai.common.logger import logger
from lsmp_ai.common.constants import FEATURE_COLUMNS


# ===== Data Configuration Object =====
class DataConfig:
    def __init__(self, train_ratio: float = 0.7, test_ratio: float = 0.3, time_window_minutes: int = 1, features: Optional[List[str]] = None):
        self.train_ratio = train_ratio
        self.test_ratio = test_ratio
        self.time_window_minutes = time_window_minutes
        self.features = features or list(FEATURE_COLUMNS)


# ===== Sub-Configuration =====
class SubConfig:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# ===== Model Configuration Object =====
class ModelConfig:
    def __init__(self, model_store_path: str = None, iforest_params: dict = None, ocsvm_params: dict = None, cascade_params: dict = None):
        self.model_store_path = model_store_path or os.getenv("MODEL_DIR", "models_store")

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
            "model_version": "cascade-v2.0-clean"
        }
        if cascade_params:
            cascade_dict.update(cascade_params)

        for d in [iforest_dict, ocsvm_dict, cascade_dict]:
            for k, v in d.items():
                if not isinstance(v, list):
                    d[k] = [v]

        self.iforest = SubConfig(**iforest_dict)
        self.ocsvm = SubConfig(**ocsvm_dict)
        self.cascade = SubConfig(**cascade_dict)

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


# ===== Configure Loader Singleton =====
class ConfigLoader:
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            base_dir = Path(__file__).resolve().parent.parent.parent.parent
            self.config_dir = str(base_dir / "configs")
        else:
            self.config_dir = config_dir

        self._raw_data_config = self._load_yaml("data_config.yaml")
        self._raw_model_config = self._load_yaml("model_config.yaml")
        self._raw_risk_config = self._load_yaml("risk_config.yaml")
        self._raw_logging_config = self._load_yaml("logging.yaml")

    def _load_yaml(self, filename: str) -> Dict[str, Any]:
        filepath = os.path.join(self.config_dir, filename)
        if not os.path.exists(filepath):
            logger.info(f"Config file not found ({filepath}), using default fallback parameters.")
            return {}
        try:
            with open(filepath, "r") as f:
                content = yaml.safe_load(f)
                return content if isinstance(content, dict) else {}
        except Exception as e:
            logger.warning(f"Could not load config file {filename}: {e}. Using fallback defaults.")
            return {}

    @property
    def data_config(self) -> DataConfig:
        data_section = self._raw_data_config.get("data", {})
        feats = data_section.get("features", list(FEATURE_COLUMNS))
        return DataConfig(
            train_ratio=self._raw_data_config.get("train_ratio", 0.7),
            test_ratio=self._raw_data_config.get("test_ratio", 0.3),
            time_window_minutes=data_section.get("time_window_minutes", 1),
            features=feats
        )

    @property
    def model_config(self) -> ModelConfig:
        return ModelConfig(
            model_store_path=self._raw_model_config.get("model_store_path", "models_store"),
            iforest_params=self._raw_model_config.get("isolation_forest"),
            ocsvm_params=self._raw_model_config.get("one_class_svm"),
            cascade_params=self._raw_model_config.get("cascade")
        )

    @property
    def data(self) -> DataConfig:
        return self.data_config

    @property
    def model(self) -> ModelConfig:
        return self.model_config

    @property
    def features(self) -> List[str]:
        data_section = self._raw_data_config.get("data", {})
        return data_section.get("features", list(FEATURE_COLUMNS))

    @property
    def time_window_minutes(self) -> int:
        return self._raw_data_config.get("data", {}).get("time_window_minutes", 1)

    @property
    def train_ratio(self) -> float:
        return self._raw_data_config.get("train_ratio", 0.7)

    @property
    def test_ratio(self) -> float:
        return self._raw_data_config.get("test_ratio", 0.3)

    @property
    def db_tables(self) -> Dict[str, str]:
        data_section = self._raw_data_config.get("data", {})
        return {
            "wazuh_alerts": data_section.get("db_table_wazuh_alerts", "log_event"),
            "feature_vectors": data_section.get("db_table_features", "feature_vectors"),
            "model_predictions": data_section.get("db_table_predictions", "risk_score"),
            "labels": data_section.get("db_table_labels", "anomaly_result")
        }

    @property
    def iforest_params(self) -> Dict[str, Any]:
        params = self._raw_model_config.get("isolation_forest") or self._raw_model_config.get("iforest", {})
        if not params or not isinstance(params, dict):
            return {"n_estimators": 100, "max_samples": "auto", "contamination": 0.05, "random_state": 42}
        return params

    @property
    def ocsvm_params(self) -> Dict[str, Any]:
        params = self._raw_model_config.get("one_class_svm") or self._raw_model_config.get("ocsvm", {})
        if not params or not isinstance(params, dict):
            return {"kernel": "rbf", "nu": 0.05, "gamma": "scale"}
        return params

    @property
    def cascade_params(self) -> Dict[str, Any]:
        params = self._raw_model_config.get("cascade", {})
        if not params or not isinstance(params, dict):
            return {"iforest_anomaly_threshold": -0.6, "iforest_normal_threshold": -0.45, "threshold_percentile": 80, "model_version": "cascade-v2.0-clean"}
        return params

    @property
    def risk_params(self) -> Dict[str, Any]:
        params = self._raw_risk_config.get("risk_scoring", {})
        if not params or not isinstance(params, dict):
            return {"alpha": 0.6, "beta": 0.4, "max_wazuh_level": 15.0}
        return params

    @property
    def risk_classification_params(self) -> Dict[str, Any]:
        params = self._raw_risk_config.get("classification", {})
        if not params or not isinstance(params, dict):
            return {"low_threshold": 25.0, "medium_threshold": 50.0, "high_threshold": 80.0, "critical_threshold": 100.0}
        return params

    @property
    def risk(self) -> SubConfig:
        r_params = self.risk_params
        c_params = self.risk_classification_params
        merged = {**r_params, **c_params}
        return SubConfig(**merged)

    @property
    def logging_params(self) -> Dict[str, Any]:
        return self._raw_logging_config or {
            "level": "INFO",
            "file": "logs/lsmp_ai.log",
            "max_bytes": 10485760,
            "backup_count": 5
        }


# Global Null-Safe Singleton Instance
try:
    config = ConfigLoader()
except Exception as _e:
    logger.warning(f"Initializing fallback ConfigLoader: {_e}")
    config = ConfigLoader(config_dir="/invalid_fallback_path")
