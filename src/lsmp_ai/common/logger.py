# ============================================================================
# file: common/logger.py
# Description: Setup logger for LSMP AI module.
# ============================================================================

# ===== Import modules =====
import logging
import os
import sys

from logging.handlers import RotatingFileHandler
from pathlib import Path

# ===== Setup logger =====
def setup_logger(name: str = "lsmp_ai") -> logging.Logger:
    """Sets up a unified, rotating logger for the LSMP AI module with size-bounded log files (S9 defense)."""
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times if logger is already set up
    if logger.handlers:
        return logger
        
    log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    logger.setLevel(log_level)
    
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Stream Handler (stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    
    # Rotating File Handler with size bounds and restricted permissions (S9 defense)
    base_dir = Path(__file__).resolve().parent.parent.parent
    log_dir = base_dir / "logs"
    log_path = log_dir / "lsmp_ai.log"

    max_bytes = 10 * 1024 * 1024  # 10 MB default
    backup_count = 5
    config_yaml = base_dir / "configs" / "logging.yaml"
    if config_yaml.exists():
        try:
            import yaml
            with open(config_yaml, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
                max_bytes = int(cfg.get("max_bytes", max_bytes))
                backup_count = int(cfg.get("backup_count", backup_count))
        except Exception:
            pass

    max_bytes = int(os.getenv("LSMP_LOG_MAX_BYTES", str(max_bytes)))
    backup_count = int(os.getenv("LSMP_LOG_BACKUP_COUNT", str(backup_count)))

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(log_dir, 0o750)
        except Exception:
            pass
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        if log_path.exists():
            try:
                os.chmod(log_path, 0o640)
            except Exception:
                pass
    except Exception as e:
        # If we can't write to directory, ignore file logging
        logger.warning(f"Could not create rotating file log handler at {log_path}: {e}")
        
    return logger

logger = setup_logger()

