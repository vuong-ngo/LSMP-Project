# ============================================================================
# file: models/ocsvm_model.py
# Description: Production-grade One-Class Support Vector Machine for Stage 2 boundary evaluation.
# Based on Schölkopf et al., One-Class SVM.
# ============================================================================
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from typing import Union, Dict, Any, Optional
from sklearn.svm import OneClassSVM

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.common.logger import logger
from lsmp_ai.common.config_loader import config


class OCSVMModel(BaseModel):
    """Production One-Class Support Vector Machine for Stage 2 precision boundary verification.

    Attributes:
<<<<<<< HEAD
        params (Dict[str, Any]): Dictionary of hyperparameters passed to the 
            underlying scikit-learn OneClassSVM estimator.
        model (OneClassSVM): The scikit-learn OneClassSVM instance.
=======
        params (Dict[str, Any]): Dictionary of model hyperparameters.
        model (OneClassSVM): Underlying scikit-learn OneClassSVM estimator.
>>>>>>> origin/feature/ai-model-ocsvm
    """

    MAX_TRAIN_SAMPLES: int = 50000

    def __init__(self, params: Optional[Dict[str, Any]] = None, **kwargs):
        """Initializes OCSVMModel with configuration defaults and overrides.

        Args:
            params (Dict[str, Any], optional): Hyperparameters dictionary. Defaults to None.
            **kwargs: Keyword argument overrides for hyperparameters.
        """
        all_params = {}
        if params is not None:
            all_params.update(params)
        all_params.update(kwargs)
        
        if not all_params:
            if config and hasattr(config, "ocsvm_params") and config.ocsvm_params:
                all_params = dict(config.ocsvm_params)
            else:
                all_params = {
                    "kernel": "rbf",
                    "nu": 0.05,
                    "gamma": "scale",
                }
        self.params = all_params
        valid_keys = {"kernel", "degree", "gamma", "coef0", "tol", "nu", "shrinking", "cache_size", "verbose", "max_iter"}
        sk_params = {k: v for k, v in self.params.items() if k in valid_keys}
        self.model = OneClassSVM(**sk_params)

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'OCSVMModel':
        """Fits the One-Class SVM model on benign baseline traffic.

        Includes sample capping protection against quadratic complexity blowups.

        Args:
<<<<<<< HEAD
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape 
                (n_samples, n_features) representing the training data.
            y (Any, optional): Ignored. Included for API consistency with BaseModel.
=======
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.
            y (Any, optional): Ignored. Maintained for interface uniformity.
>>>>>>> origin/feature/ai-model-ocsvm

        Returns:
            OCSVMModel: Fitted model instance (self).
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        n_samples = len(X_arr)
        if n_samples > self.MAX_TRAIN_SAMPLES:
            logger.warning(
                f"OCSVM training set ({n_samples:,} samples) exceeds safety threshold ({self.MAX_TRAIN_SAMPLES:,}). "
                f"Subsampling to prevent O(n²) memory/compute explosion."
            )
            rng = np.random.RandomState(42)
            indices = rng.choice(n_samples, size=self.MAX_TRAIN_SAMPLES, replace=False)
            X_arr = X_arr[indices]

        logger.info(f"Training One-Class SVM with parameters: {self.params}")
        self.model.fit(X_arr)
        logger.info("One-Class SVM training complete.")
        return self
        
    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
<<<<<<< HEAD
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
=======
        """Predicts anomaly labels (1 for normal inlier, -1 for anomalous outlier).
>>>>>>> origin/feature/ai-model-ocsvm

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of predicted class integers (1 or -1).
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.model.predict(X_arr)

    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes raw decision function values for each sample.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of float decision values.
        """
        X_arr = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        scores = self.model.decision_function(X_arr)
        return np.asarray(scores).ravel()
<<<<<<< HEAD
        
=======

    def decision_function(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes scikit-learn decision function."""
        return self.score(X)

    def anomaly_score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes anomaly score where higher values represent greater abnormality (-decision_function).

        Args:
            X (Union[pd.DataFrame, np.ndarray]): Input feature matrix.

        Returns:
            np.ndarray: 1D array of continuous anomaly scores.
        """
        return -self.decision_function(X)

>>>>>>> origin/feature/ai-model-ocsvm
    def save(self, filepath: str) -> None:
        """Serializes and saves the model binary to disk.

        Args:
            filepath (str): Destination file path.
        """
        joblib.dump(self.model, filepath)
        logger.info(f"Saved One-Class SVM model to {filepath}")
        
    def load(self, filepath: str) -> 'OCSVMModel':
        """Deserializes and restores model state from disk.

        Args:
            filepath (str): Source file path.

        Returns:
            OCSVMModel: Restored model instance (self).
        """
        self.model = joblib.load(filepath)
        logger.info(f"Loaded One-Class SVM model from {filepath}")
        return self
