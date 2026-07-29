# ============================================================================
# file: models/ocsvm_model.py
# Description: Implementation of One-Class SVM model for anomaly detection in LSMP.
# ============================================================================

# ===== IMPORT MODULES =====
import joblib
import numpy as np
import pandas as pd
from typing import Union, Dict, Any
from sklearn.svm import OneClassSVM

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config

# ===== OCSVM Model Class =====
class OCSVMModel(BaseModel):
    """One-Class Support Vector Machine (OCSVM) implementation for anomaly detection in LSMP.

    One-Class SVM learns a decision boundary that encapsulates the normal data points.
    Outliers or anomalous samples fall outside this boundary in high-dimensional feature space.

    Attributes:
        params (Dict[str, Any]): Dictionary of hyperparameters passed to the
            underlying scikit-learn OneClassSVM estimator.
        model (OneClassSVM): The scikit-learn OneClassSVM instance.
    """

    def __init__(self, params: Dict[str, Any] = None, **kwargs):
        """Initializes the One-Class SVM model.

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
            all_params = config.ocsvm_params if config else {
                "kernel": "rbf",
                "nu": 0.05,
                "gamma": "scale"
            }
        self.params = all_params
        self.model = OneClassSVM(**self.params)

    # Maximum training samples for OCSVM to prevent O(n²)-O(n³) compute explosion
    MAX_TRAIN_SAMPLES = 50000

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'OCSVMModel':
        """Fits the One-Class SVM model on normal behavioral features.

        If the training data exceeds MAX_TRAIN_SAMPLES, a random subsample is used
        to prevent excessive training time (OCSVM has O(n²)-O(n³) complexity).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape
                (n_samples, n_features) representing the training data.
            y (Any, optional): Ignored. Included for API consistency with BaseModel.

        Returns:
            OCSVMModel: The fitted model instance (self).
        """
        n_samples = len(X) if hasattr(X, '__len__') else X.shape[0]
        if n_samples > self.MAX_TRAIN_SAMPLES:
            logger.warning(
                f"OCSVM training data ({n_samples:,} samples) exceeds limit ({self.MAX_TRAIN_SAMPLES:,}). "
                f"Subsampling to {self.MAX_TRAIN_SAMPLES:,} samples to prevent O(n²) compute explosion."
            )
            rng = np.random.RandomState(42)
            indices = rng.choice(n_samples, size=self.MAX_TRAIN_SAMPLES, replace=False)
            X = X.iloc[indices] if isinstance(X, pd.DataFrame) else X[indices]

        logger.info(f"Training One-Class SVM with parameters: {self.params}")
        self.model.fit(X)
        logger.info("One-Class SVM training complete.")
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
        """Computes raw decision function anomaly scores for each sample.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: A 1D array of shape (n_samples,) representing anomaly scores.
                Lower/negative values indicate anomalies, higher positive values indicate inliers.
        """
        scores = self.model.decision_function(X)
        return np.asarray(scores).ravel()

    def save(self, filepath: str) -> None:
        """Serializes and saves the scikit-learn model using joblib.

        Args:
            filepath (str): Destination file path.

        Returns:
            None
        """
        joblib.dump(self.model, filepath)
        logger.info(f"Saved One-Class SVM model to {filepath}")

    def load(self, filepath: str) -> 'OCSVMModel':
        """Loads a serialized model state using joblib.

        Args:
            filepath (str): Source file path.

        Returns:
            OCSVMModel: The loaded model instance (self).
        """
        self.model = joblib.load(filepath)
        logger.info(f"Loaded One-Class SVM model from {filepath}")
        return self
