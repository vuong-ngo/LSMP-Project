# ============================================================================
# file: models/registry.py
# Description: Production Model Registry for serializing, cataloging, versioning,
#              and restoring trained LSMP models.
# ============================================================================
from __future__ import annotations

import os
import json
import shutil
from datetime import datetime
from typing import Dict, Any, Optional, List

from lsmp_ai.common.logger import logger
from lsmp_ai.common.exceptions import ModelNotFoundError
from lsmp_ai.models.cascade_model import CascadeModel


class ModelRegistry:
    """Central registry manager for versioning, storing, cataloging, and reloading models.

    Attributes:
        registry_dir (str): Root directory where model artifacts, manifests, and catalog reside.
    """

    def __init__(self, registry_dir: Optional[str] = None):
        """Initializes the ModelRegistry instance.

        Args:
            registry_dir (Optional[str], optional): Model store directory path.
                Defaults to MODEL_DIR env variable or 'models_store'.
        """
        self.registry_dir = registry_dir or os.getenv(
            "MODEL_DIR",
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                "models_store",
            ),
        )
        os.makedirs(self.registry_dir, exist_ok=True)

    def register_model(self, model: CascadeModel, metrics: Optional[Dict[str, Any]] = None) -> str:
        """Serializes and catalogs a trained CascadeModel instance into the registry.

        Args:
            model (CascadeModel): The fitted model instance to register.
            metrics (Optional[Dict[str, Any]], optional): Evaluation metrics to record.

        Returns:
            str: The registered model version string.
        """
        version = model.model_version
        model_dir = os.path.join(self.registry_dir, version)

        # Handle version collisions by archiving existing manifest
        if os.path.exists(model_dir) and os.path.exists(os.path.join(model_dir, "manifest.json")):
            backup_dir = f"{model_dir}_backup_{int(datetime.now().timestamp())}"
            logger.info(f"Version {version} already exists. Backing up existing directory to {backup_dir}")
            shutil.move(model_dir, backup_dir)

        os.makedirs(model_dir, exist_ok=True)

        # 1. Save model binaries
        model.save(model_dir)

        # 2. Build metadata manifest
        manifest = {
            "version": version,
            "registered_at": datetime.now().isoformat(),
            "metrics": metrics or {},
            "hyperparameters": {
                "gate_rate": getattr(model, "gate_rate", 0.20),
                "gate_threshold": getattr(model, "gate_threshold", 0.0),
                "threshold": getattr(model, "threshold", 0.5),
                "w_stage1": getattr(model, "w_stage1", 0.4),
                "iforest_anomaly_threshold": getattr(model, "anomaly_threshold", model.gate_threshold),
                "iforest_normal_threshold": getattr(model, "normal_threshold", 0.0),
                "iforest_params": getattr(model.iforest_model, "params", {}),
                "ocsvm_params": getattr(model.ocsvm_model, "params", {}),
            },
        }

        manifest_path = os.path.join(model_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

        # 3. Update global catalog index
        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        catalog: Dict[str, Any] = {}
        if os.path.exists(catalog_path):
            try:
                with open(catalog_path, "r") as f:
                    catalog = json.load(f)
            except Exception as e:
                logger.warning(f"Error reading catalog index: {e}. Reinitializing catalog.")

        catalog[version] = manifest
        catalog["latest_version"] = version

        with open(catalog_path, "w") as f:
            json.dump(catalog, f, indent=4)

        logger.info(f"Successfully registered model version '{version}' to registry.")
        return version

    def load_model(self, version: Optional[str] = None) -> CascadeModel:
        """Loads and deserializes a CascadeModel instance by version (or latest).

        Args:
            version (Optional[str], optional): Specific version identifier.
                If None, resolves to the latest version in catalog.

        Returns:
            CascadeModel: The fully restored model instance.

        Raises:
            ModelNotFoundError: If requested model directory does not exist.
        """
        catalog_path = os.path.join(self.registry_dir, "catalog.json")

        if not version:
            if os.path.exists(catalog_path):
                try:
                    with open(catalog_path, "r") as f:
                        catalog = json.load(f)
                    version = catalog.get("latest_version")
                except Exception as e:
                    logger.warning(f"Failed to read catalog for latest version: {e}")

            if not version:
                subdirs = [
                    d for d in os.listdir(self.registry_dir)
                    if os.path.isdir(os.path.join(self.registry_dir, d)) and not d.endswith("_backup")
                ]
                if not subdirs:
                    raise ModelNotFoundError("No registered models found in registry.")
                subdirs.sort()
                version = subdirs[-1]

        model_dir = os.path.join(self.registry_dir, version)
        if not os.path.exists(model_dir):
            raise ModelNotFoundError(f"Model version directory not found: {model_dir}")

        model = CascadeModel()
        model.load(model_dir)
        logger.info(f"Loaded CascadeModel version '{version}' from registry.")
        return model

    def list_versions(self) -> List[str]:
        """Lists all registered model versions from the catalog.

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
        """Retrieves manifest metadata dictionary for a model version.

        Args:
            version (Optional[str], optional): Specific version string, or None for latest.

        Returns:
            Optional[Dict[str, Any]]: Metadata manifest dictionary if found, else None.
        """
        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        if os.path.exists(catalog_path):
            try:
                with open(catalog_path, "r") as f:
                    catalog = json.load(f)
                target = version or catalog.get("latest_version")
                return catalog.get(target) if target else None
            except Exception as e:
                logger.error(f"Error reading manifest from catalog: {e}")
        return None

    def get_latest_version_manifest(self) -> Optional[Dict[str, Any]]:
        """Helper to get manifest for the latest registered model version."""
        return self.get_manifest(None)

    def load_version(self, version: str) -> CascadeModel:
        """Helper to load a specific model version."""
        return self.load_model(version)

    def load_latest(self) -> CascadeModel:
        """Helper to load the latest registered model version."""
        return self.load_model(None)
