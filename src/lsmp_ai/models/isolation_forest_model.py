# ============================================================================
# file: models/isolation_forest_model.py
# Description: Implemenation of Isolation Forest model for anomaly detection in LSMP.
# ============================================================================

# ===== IMPORT MODULES =====
import joblib
import numpy as np
import pandas as pd
from typing import Union, Dict, Any
from sklearn.ensemble import IsolationForest

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config

# ===== Isolation Forest Model =====
class IsolationForestModel(BaseModel):
    """Isolation Forest implementation for anomaly detection in LSMP.

    This model isolates anomalies by randomly selecting a feature and then randomly
    selecting a split value between the maximum and minimum values of the selected feature.
    Since recursive partitioning can be represented by a tree structure, the number of
    splittings required to isolate a sample is equivalent to the path length from the
    root node to the terminating node. This path length, averaged over a forest of such
    random trees, is a measure of abnormality and our decision function.

    Attributes:
        params (Dict[str, Any]): Dictionary of hyperparameters passed to the
            underlying scikit-learn IsolationForest estimator.
        model (IsolationForest): The scikit-learn IsolationForest instance.
    """

    def __init__(self, params: Dict[str, Any] = None, **kwargs):
        """Initializes the Isolation Forest model.

        Loads defaults from config if not provided, merging with explicit overrides.

        Args:
            params (Dict[str, Any], optional): Dictionary of configurations. Defaults to None.
            **kwargs: Additional key-value arguments representing hyperparameters to override.
        """
        all_params = {}
        if params is not None:
            all_params.update(params)
        all_params.update(kwargs)

        if not all_params:
            all_params = config.iforest_params if config else {
                "n_estimators": 100,
                "max_samples": "auto",
                "contamination": 0.05,
                "random_state": 42
            }
        self.params = all_params
        self.model = IsolationForest(**self.params)


    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'IsolationForestModel':
        """Fits the Isolation Forest model on normal behavioral features.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape
                (n_samples, n_features) representing the training data.
            y (Any, optional): Ignored. Included for API consistency with BaseModel.

        Returns:
            IsolationForestModel: The fitted model instance (self).
        """
        logger.info(f"Training Isolation Forest with parameters: {self.params}")
        self.model.fit(X)
        logger.info("Isolation Forest training complete.")
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predicts the anomaly labels for the given samples.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix to predict.

        Returns:
            np.ndarray: A 1D array of shape (n_samples,) containing predicted labels.
                Returns 1 for normal samples (inliers) and -1 for anomalous samples (outliers).
        """
        return self.model.predict(X)

    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes raw anomaly scores for each sample.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: A 1D array of shape (n_samples,) representing anomaly scores.
                Values range from [-1, 0]. The lower the score, the more anomalous the sample.
        """
        return self.model.score_samples(X)

    def save(self, filepath: str) -> None:
        """Serializes and saves the scikit-learn model using joblib.

        Args:
            filepath (str): Destination file path.
        """
        joblib.dump(self.model, filepath)
        logger.info(f"Saved Isolation Forest model to {filepath}")

    def load(self, filepath: str) -> 'IsolationForestModel':
        """Loads a serialized model state using joblib.

        Args:
            filepath (str): Source file path.

        Returns:
            IsolationForestModel: The loaded model instance (self).
        """
        self.model = joblib.load(filepath)
        logger.info(f"Loaded Isolation Forest model from {filepath}")
        return self

IForestModel = IsolationForestModel
