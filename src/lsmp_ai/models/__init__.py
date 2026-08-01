# ============================================================================
# file: models/__init__.py
# Description: Anomaly detection models module providing Isolation Forest, OCSVM,
#              CascadeModel, ModelRegistry, and Hyperparameter Search.
# ============================================================================

from lsmp_ai.models.base_model import BaseModel
from lsmp_ai.models.isolation_forest_model import IsolationForestModel, IForestModel
from lsmp_ai.models.ocsvm_model import OCSVMModel
from lsmp_ai.models.cascade_model import CascadeModel
from lsmp_ai.models.registry import ModelRegistry
from lsmp_ai.models.hyperparameter_search import (
    grid_search_iforest,
    grid_search_ocsvm,
    grid_search_cascade,
)

__all__ = [
    "BaseModel",
    "IsolationForestModel",
    "IForestModel",
    "OCSVMModel",
    "CascadeModel",
    "ModelRegistry",
    "grid_search_iforest",
    "grid_search_ocsvm",
    "grid_search_cascade",
]
