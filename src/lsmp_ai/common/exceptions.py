# ============================================================================
# file: common/exceptions.py
# Description: Custom exceptions for LSMP AI module.
# ============================================================================

# ===== Exceptions =====
class LSMPError(Exception):
    """Base exception for all LSMP errors."""
    pass

class ConfigurationError(LSMPError):
    """Raised when there is an issue with configuration loading or values."""
    pass

ConfigError = ConfigurationError


class DataValidationError(LSMPError):
    """Raised when data fails schema validation or ingestion expectations."""
    pass

class DatabaseConnectionError(LSMPError):
    """Raised when connecting to or executing queries on PostgreSQL fails."""
    pass

class ModelNotFoundError(LSMPError):
    """Raised when a requested model is not found in the registry or disk."""
    pass

class ModelTrainingError(LSMPError):
    """Raised when model training fails."""
    pass
