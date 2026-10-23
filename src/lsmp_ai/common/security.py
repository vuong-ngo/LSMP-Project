# ============================================================================
# file: common/security.py
# Description: Cryptographic artifact integrity verification and permission hardening.
# ============================================================================

import os
import hashlib
import secrets
from pathlib import Path
from typing import Union, Dict, Optional

from lsmp_ai.common.exceptions import SecurityError
from lsmp_ai.common.logger import logger


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """Computes SHA-256 cryptographic hash of a file on disk.

    Args:
        filepath: Path to the target file.

    Returns:
        Hexadecimal SHA-256 hash string.
    """
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_file_integrity(filepath: Union[str, Path], expected_hash: str) -> bool:
    """Verifies that a file on disk matches its expected SHA-256 hash in constant time.

    Args:
        filepath: Path to the file to verify.
        expected_hash: Expected hexadecimal SHA-256 digest.

    Returns:
        True if the file matches the expected hash, False otherwise.
    """
    if not os.path.exists(filepath):
        return False
    actual_hash = compute_file_sha256(filepath)
    return secrets.compare_digest(actual_hash.lower().strip(), str(expected_hash).lower().strip())


def verify_artifacts_in_dir(model_dir: Union[str, Path], artifact_hashes: Dict[str, str]) -> None:
    """Verifies all model artifacts in a directory against their recorded SHA-256 digests.

    Args:
        model_dir: Path to directory containing model files.
        artifact_hashes: Mapping from filename to expected SHA-256 digest.

    Raises:
        SecurityError: If an artifact is missing or has an unexpected checksum.
    """
    p_dir = Path(model_dir)
    for filename, expected_hash in artifact_hashes.items():
        artifact_path = p_dir / filename
        if not artifact_path.exists():
            raise SecurityError(f"Required model artifact '{filename}' not found in '{model_dir}'.")
        if not verify_file_integrity(artifact_path, expected_hash):
            actual = compute_file_sha256(artifact_path)
            raise SecurityError(
                f"Security integrity check FAILED for artifact '{filename}'! "
                f"Expected SHA-256: {expected_hash}, got: {actual}. "
                "Deserialization aborted to prevent arbitrary code execution (RCE)."
            )
        logger.debug(f"Artifact integrity verified: {filename} (SHA-256: {expected_hash[:12]}...)")


def secure_file_permissions(filepath: Union[str, Path], mode: int = 0o640) -> None:
    """Restricts file permissions to prevent unauthorized writes or tampering."""
    try:
        os.chmod(filepath, mode)
    except Exception as e:
        logger.warning(f"Could not set permissions {oct(mode)} on '{filepath}': {e}")


def secure_directory_permissions(dirpath: Union[str, Path], mode: int = 0o750) -> None:
    """Restricts directory permissions to owner and trusted group only."""
    try:
        os.chmod(dirpath, mode)
    except Exception as e:
        logger.warning(f"Could not set directory permissions {oct(mode)} on '{dirpath}': {e}")
