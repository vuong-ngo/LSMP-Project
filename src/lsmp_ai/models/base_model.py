# ============================================================================
# file: models/base_model.py
# Description: Abstract Base Class (ABC) defining the standard interface for all machine learning
# models implemented in the Log Security Monitoring Platform (LSMP).
# ============================================================================

# ===== IMPORT MODULES =====
from abc import ABC, abstractmethod
import numpy as np
import pandas as pd
from typing import Any, Union

# ===== Abstract Base Class for Models =====
class BaseModel(ABC):
    """Abstract Base Class (ABC) defining the standard interface for all machine learning
    models implemented in the Log Security Monitoring Platform (LSMP).

    All model implementations (e.g., Isolation Forest, One-Class SVM, or Cascade Models)
    must inherit from this class and implement its abstract methods to ensure
    compatibility with the training and inference pipelines.
    """

    @abstractmethod
    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Any = None) -> 'BaseModel':
        """Fits the machine learning model on the training dataset.

        For unsupervised models (like Isolation Forest or One-Class SVM), the labels `y`
        are typically ignored or default to None. For semi-supervised or supervised models,
        `y` may contain ground-truth labels.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape
                (n_samples, n_features) representing the training data.
            y (Any, optional): Target values/labels of shape (n_samples,). Defaults to None.

        Returns:
            BaseModel: The fitted model instance (self) to allow method chaining.

        Raises:
            ValueError: If the input features X are invalid, empty, or contain incorrect shapes.
        """
        pass

    @abstractmethod
    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Predicts the anomaly labels for the given test data.

        The model infers whether each sample in X is normal or an anomaly based on the
        learned parameters during training.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape
                (n_samples, n_features) representing the sample data to predict.

        Returns:
            np.ndarray: A 1D array of shape (n_samples,) containing predicted labels.
                Typically, it returns 1 (or "Normal") for inliers/normal behavior, and
                -1 (or "Anomaly") for outliers/anomalous behavior depending on the specific model convention.

        Raises:
            ValueError: If the model has not been fitted yet, or if the input data shapes
                do not match the training dimensions.
        """
        pass

    @abstractmethod
    def score(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Computes the raw anomaly scores for the input dataset.

        A quantitative metric reflecting the degree of abnormality of each sample.
        Higher values typically represent normal samples, while lower or negative values
        indicate anomalies, matching the standard scikit-learn decision function convention.

        Args:
            X (Union[pd.DataFrame, np.ndarray]): The input feature matrix of shape
                (n_samples, n_features) to compute scores for.

        Returns:
            np.ndarray: A 1D array of shape (n_samples,) containing the computed anomaly
                scores for each sample.

        Raises:
            ValueError: If the model has not been fitted, or if features are invalid.
        """
        pass

    @abstractmethod
    def save(self, filepath: str) -> None:
        """Serializes and saves the trained model state to a file on disk.

        Saves model weights, hyperparameter configurations, and metadata so that the model
        can be reloaded for inference without retraining.

        Args:
            filepath (str): The absolute or relative path to the destination file.

        Raises:
            IOError: If writing to the specified file path fails.
            ValueError: If the model has not been trained/fitted before saving.
        """
        pass

    @abstractmethod
    def load(self, filepath: str) -> 'BaseModel':
        """Loads and deserializes a saved model state from disk.

        Restores the model's weights, parameters, and configuration to resume inference
        or training.

        Args:
            filepath (str): The path to the saved model file.

        Returns:
            BaseModel: The deserialized model instance loaded with the saved state.

        Raises:
            FileNotFoundError: If the specified model file does not exist.
            IOError: If the model file is corrupted or failed to read.
        """
        pass
