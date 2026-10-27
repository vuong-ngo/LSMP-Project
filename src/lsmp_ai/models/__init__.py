# ============================================================================
# file: models/__init__.py
# Description: Production Anomaly Detection Models Package for LSMP.
# Provides Isolation Forest, One-Class SVM, Two-Stage Cascade Detector,
# ModelRegistry, and Hyperparameter Optimization.
# ============================================================================
from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.models.isolation_forest_model import IsolationForestModel, IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.models.hyperparameter_search import (
    HyperparameterSearch,
    grid_search_iforest,
    grid_search_ocsvm,
    grid_search_cascade,
    grid_search_gate_rate,
)

__all__ = [
    "BaseModel",
    "IsolationForestModel",
    "IForestModel",
    "OCSVMModel",
    "CascadeModel",
    "ModelRegistry",
    "HyperparameterSearch",
    "grid_search_iforest",
    "grid_search_ocsvm",
    "grid_search_cascade",
    "grid_search_gate_rate",
]
