# ============================================================================
# file: models/registry.py
# Description: Central Model Registry for managing, versioning, saving, and loading LSMP models.
# ============================================================================

# ===== IMPORT MODULES =====
import os
import json
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from lsmp_ai.common.logger import logger
from lsmp_ai.common.exceptions import ModelNotFoundError
from lsmp_ai.models.cascade_model import CascadeModel


# ===== Model Registry =====
class ModelRegistry:
    """Central registry manager for serializing, cataloging, versioning, and reloading trained models.

    Attributes:
        registry_dir (str): Root directory path where model artifacts, manifests, and catalog index are stored.
    """

    def __init__(self, registry_dir: Optional[str] = None):
        """Initializes the ModelRegistry instance.

        Args:
            registry_dir (Optional[str], optional): Custom model store path. Defaults to MODEL_DIR env or 'models_store'.
        """
        self.registry_dir = registry_dir or os.getenv(
            "MODEL_DIR", 
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 
                "models_store"
            )
        )
        os.makedirs(self.registry_dir, exist_ok=True)

    def register_model(self, model: CascadeModel, metrics: Optional[Dict[str, float]] = None) -> str:
        """Saves a trained CascadeModel into a versioned folder and updates the central registry index.

        Args:
            model (CascadeModel): The fitted CascadeModel instance to register.
            metrics (Optional[Dict[str, float]], optional): Evaluation metrics dictionary to log in manifest.

        Returns:
            str: Registered model version identifier string.
        """
        version = model.model_version
        model_dir = os.path.join(self.registry_dir, version)

        # If a registered version already exists (marked by manifest.json), backup before overwriting
        if os.path.exists(model_dir) and os.path.exists(os.path.join(model_dir, "manifest.json")):
            backup_dir = f"{model_dir}_backup_{int(datetime.now().timestamp())}"
            logger.info(f"Version {version} already exists. Backing up to {backup_dir}")
            shutil.move(model_dir, backup_dir)
        else:
            os.makedirs(model_dir, exist_ok=True)

        # Save model binaries (joblib submodels & metadata.json)
        model.save(model_dir)

        # Build version manifest
        manifest = {
            "version": version,
            "registered_at": datetime.now().isoformat(),
            "metrics": metrics or {},
            "hyperparameters": {
                "iforest_anomaly_threshold": model.anomaly_threshold,
                "iforest_normal_threshold": model.normal_threshold,
                "iforest_params": getattr(model.iforest_model, "params", {}),
                "ocsvm_params": getattr(model.ocsvm_model, "params", {})
            }
        }

        with open(os.path.join(model_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=4)

        # Update main catalog index file
        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        catalog = {}
        if os.path.exists(catalog_path):
            try:
                with open(catalog_path, "r") as f:
                    catalog = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read model catalog: {e}. Recreating index.")

        catalog[version] = manifest
        catalog["latest_version"] = version

        with open(catalog_path, "w") as f:
            json.dump(catalog, f, indent=4)

        logger.info(f"Model version {version} registered successfully.")
        return version

    def load_model(self, version: Optional[str] = None) -> CascadeModel:
        """Loads a deserialized CascadeModel instance corresponding to the specified version (or latest).

        Args:
            version (Optional[str], optional): Specific version string to load. Defaults to latest if None.

        Returns:
            CascadeModel: The loaded model instance with restored parameters and submodels.

        Raises:
            ModelNotFoundError: If requested model version or model store directory does not exist.
        """
        catalog_path = os.path.join(self.registry_dir, "catalog.json")

        if not version:
            if os.path.exists(catalog_path):
                try:
                    with open(catalog_path, "r") as f:
                        catalog = json.load(f)
                    version = catalog.get("latest_version")
                except Exception as e:
                    logger.warning(f"Error reading model catalog to resolve latest version: {e}")

            if not version:
                subdirs = [
                    d for d in os.listdir(self.registry_dir) 
                    if os.path.isdir(os.path.join(self.registry_dir, d)) and not d.endswith("_backup")
                ]
                if not subdirs:
                    raise ModelNotFoundError("No models found in the model store.")
                subdirs.sort()
                version = subdirs[-1]

        model_dir = os.path.join(self.registry_dir, version)
        if not os.path.exists(model_dir):
            raise ModelNotFoundError(f"Model version directory not found: {model_dir}")

        model = CascadeModel()
        model.load(model_dir)
        logger.info(f"Loaded model version {version} from registry.")
        return model

    def list_versions(self) -> List[str]:
        """Lists all registered model versions from the central catalog index.

        Returns:
            List[str]: List of version strings.
        """
        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        if os.path.exists(catalog_path):
            try:
                with open(catalog_path, "r") as f:
                    catalog = json.load(f)
                return [k for k in catalog.keys() if k != "latest_version"]
            except Exception as e:
                logger.error(f"Error listing catalog versions: {e}")
        return []

    def get_manifest(self, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves manifest metadata dictionary for a given model version (or latest).

        Args:
            version (Optional[str], optional): Specific model version. Defaults to latest if None.

        Returns:
            Optional[Dict[str, Any]]: Manifest metadata dictionary if found, else None.
        """
        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        if os.path.exists(catalog_path):
            try:
                with open(catalog_path, "r") as f:
                    catalog = json.load(f)
                target_version = version or catalog.get("latest_version")
                return catalog.get(target_version) if target_version else None
            except Exception as e:
                logger.error(f"Error getting catalog manifest: {e}")
        return None

    def get_latest_version_manifest(self) -> Optional[Dict[str, Any]]:
        """Backward-compatible helper to get manifest for the latest registered version."""
        return self.get_manifest(None)

    def load_version(self, version: str) -> CascadeModel:
        """Backward-compatible helper to load a specific version."""
        return self.load_model(version)

    def load_latest(self) -> CascadeModel:
        """Backward-compatible helper to load the latest version."""
        return self.load_model(None)
