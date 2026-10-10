# ============================================================================
# file: models/isolation_forest_model.py
# Description: Production-ready Isolation Forest model for rapid anomaly screening in LSMP.
# Based on Liu et al. (2008), Isolation Forest.
# ============================================================================
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from typing import Union, Dict, Any, Optional
from sklearn.ensemble import IsolationForest

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config


class IsolationForestModel(BaseModel):
    """Production Isolation Forest anomaly detector for Stage 1 rapid traffic screening.

    Attributes:
        params (Dict[str, Any]): Dictionary of model hyperparameters.
        model (IsolationForest): Underlying scikit-learn IsolationForest estimator.
    """

    def __init__(self, params: Optional[Dict[str, Any]] = None, **kwargs):
        """Initializes IsolationForestModel with configuration defaults and overrides.

        Args:
            params (Dict[str, Any], optional): Hyperparameters dictionary. Defaults to None.
            **kwargs: Keyword argument overrides for hyperparameters.
        """
        all_params = {}
        if params is not None:
            all_params.update(params)
        all_params.update(kwargs)

        if not all_params:
            if config and hasattr(config, "iforest_params") and config.iforest_params:
                all_params = dict(config.iforest_params)
            else:
                all_params = {
                    "n_estimators": 200,
                    "max_samples": 256,
                    "contamination": 0.05,
                    "random_state": 42,
                    "n_jobs": -1,
                }
        self.params = all_params
        valid_keys = {
            "n_estimators", "max_samples", "contamination", "max_features",
            "bootstrap", "n_jobs", "random_state", "verbose", "warm_start"
        }
        sk_params = {k: v for k, v in self.params.items() if k in valid_keys}
        self.model = IsolationForest(**sk_params)

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'IsolationForestModel':
        """Fits the Isolation Forest estimator on feature data.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            y (Any, optional): Ignored. Maintained for interface uniformity.

        Returns:
            IsolationForestModel: Fitted model instance (self).
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        logger.info(f"Training Isolation Forest with parameters: {self.params}")
        self.model.fit(X_arr)
        logger.info("Isolation Forest training complete.")
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predicts anomaly labels (1 for normal inlier, -1 for anomalous outlier).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of predicted class integers (1 or -1).
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.predict(X_arr)

    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes raw scikit-learn anomaly scores (higher is more normal).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of float anomaly scores.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.score_samples(X_arr)

    def decision_function(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes decision function values. Negative values indicate anomalies.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of decision values.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.decision_function(X_arr)

    def anomaly_score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes anomaly score where higher values represent greater abnormality (-decision_function).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of continuous anomaly scores.
        """
        return -self.decision_function(X)

    def save(self, filepath: str) -> None:
        """Serializes and saves the model binary to disk.

        Args:
            filepath (str): Destination file path.
        """
        joblib.dump(self.model, filepath)
        logger.info(f"Saved Isolation Forest model to {filepath}")

    def load(self, filepath: str) -> 'IsolationForestModel':
        """Deserializes and restores model state from disk.

        Args:
            filepath (str): Source file path.

        Returns:
            IsolationForestModel: Restored model instance (self).
        """
        self.model = joblib.load(filepath)
        logger.info(f"Loaded Isolation Forest model from {filepath}")
        return self


# Canonical alias
IForestModel = IsolationForestModel
