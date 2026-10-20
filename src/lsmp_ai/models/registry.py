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

            # Retention policy: keep only the 2 most recent backups to prevent disk buildup
            try:
                old_backups = sorted([
                    os.path.join(self.registry_dir, d) for d in os.listdir(self.registry_dir)
                    if d.startswith(f"{version}_backup_") and os.path.isdir(os.path.join(self.registry_dir, d))
                ])
                while len(old_backups) > 2:
                    to_remove = old_backups.pop(0)
                    shutil.rmtree(to_remove, ignore_errors=True)
                    logger.info(f"Pruned old model backup: {to_remove}")
            except Exception as prune_err:
                logger.warning(f"Could not prune old model backups: {prune_err}")

        os.makedirs(model_dir, exist_ok=True)

        # 1. Save model binaries
        model.save(model_dir)

        # 2. Build metadata manifest with cryptographic SHA-256 artifact hashes (S2 defense)
        from lsmp_ai.common.security import compute_file_sha256, secure_file_permissions, secure_directory_permissions
        secure_directory_permissions(model_dir, 0o750)

        artifact_hashes = {}
        for fname in ["iforest.joblib", "ocsvm.joblib", "feature_pipeline.joblib"]:
            fpath = os.path.join(model_dir, fname)
            if os.path.exists(fpath):
                secure_file_permissions(fpath, 0o640)
                artifact_hashes[fname] = compute_file_sha256(fpath)

        manifest = {
            "version": version,
            "registered_at": datetime.now().isoformat(),
            "metrics": metrics or {},
            "artifact_hashes": artifact_hashes,
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
        secure_file_permissions(manifest_path, 0o640)

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
        secure_file_permissions(catalog_path, 0o640)

        logger.info(f"Successfully registered model version '{version}' to registry.")
        return version

    def load_model(self, version: Optional[str] = None) -> CascadeModel:
        """Loads and deserializes a CascadeModel instance by version (or latest).
        Verifies SHA-256 artifact integrity before deserialization.

        Args:
            version (Optional[str], optional): Specific version identifier.
                If None, resolves to the latest version in catalog.

        Returns:
            CascadeModel: The fully restored model instance.

        Raises:
            ModelNotFoundError: If requested model directory does not exist.
            SecurityError: If an artifact has been tampered with or corrupted.
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
                    if os.path.isdir(os.path.join(self.registry_dir, d))
                    and "_backup" not in d
                    and not d.startswith(".")
                ]
                if not subdirs:
                    raise ModelNotFoundError("No registered models found in registry.")
                subdirs.sort()
                version = subdirs[-1]

        import re
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", version):
            raise ValueError(f"Invalid model version identifier format: {version}")

        resolved_registry = os.path.realpath(self.registry_dir)
        model_dir = os.path.realpath(os.path.join(self.registry_dir, version))
        if not model_dir.startswith(resolved_registry) or not os.path.exists(model_dir):
            raise ModelNotFoundError(f"Model version directory not found or unauthorized: {model_dir}")

        manifest_path = os.path.join(model_dir, "manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    manifest_data = json.load(f)
                art_hashes = manifest_data.get("artifact_hashes")
                if art_hashes:
                    from lsmp_ai.common.security import verify_artifacts_in_dir
                    verify_artifacts_in_dir(model_dir, art_hashes)
            except Exception as e:
                from lsmp_ai.common.exceptions import SecurityError
                if isinstance(e, SecurityError):
                    raise
                logger.warning(f"Manifest verification warning for {version}: {e}")

        model = CascadeModel()
        model.load(model_dir)
        logger.info(f"Loaded CascadeModel version '{version}' from registry.")
        return model

    def refresh_artifact_manifest(self, version: str) -> Dict[str, Any]:
        """Refresh hashes after auxiliary artifacts are added to a model version."""
        model_dir = os.path.realpath(os.path.join(self.registry_dir, version))
        registry_root = os.path.realpath(self.registry_dir)
        if not model_dir.startswith(registry_root) or not os.path.isdir(model_dir):
            raise ModelNotFoundError(f"Model version directory not found: {model_dir}")

        from lsmp_ai.common.security import compute_file_sha256

        manifest_path = os.path.join(model_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise ModelNotFoundError(f"Model manifest not found: {manifest_path}")
        with open(manifest_path, "r") as stream:
            manifest = json.load(stream)

        artifact_hashes = dict(manifest.get("artifact_hashes") or {})
        for fname in ("iforest.joblib", "ocsvm.joblib", "feature_pipeline.joblib"):
            path = os.path.join(model_dir, fname)
            if os.path.exists(path):
                artifact_hashes[fname] = compute_file_sha256(path)
        manifest["artifact_hashes"] = artifact_hashes

        with open(manifest_path, "w") as stream:
            json.dump(manifest, stream, indent=4)

        catalog_path = os.path.join(self.registry_dir, "catalog.json")
        if os.path.exists(catalog_path):
            with open(catalog_path, "r") as stream:
                catalog = json.load(stream)
            catalog[version] = manifest
            with open(catalog_path, "w") as stream:
                json.dump(catalog, stream, indent=4)
        return manifest

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
