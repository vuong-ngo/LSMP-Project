# ============================================================================
# file: common/logger.py
# Description: Setup logger for LSMP AI module.
# ============================================================================

# ===== Import modules =====
import logging
import os
import sys

# ===== Setup logger =====
def setup_logger(name: str = "lsmp_ai") -> logging.Logger:
    """Sets up a unified logger for the LSMP AI module."""
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
    
    # File Handler (Optional - log to models or project log file)
    log_file_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = os.path.join(log_file_dir, "lsmp_ai.log")
    try:
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        # If we can't write to directory, ignore file logging
        logger.warning(f"Could not create file log handler at {log_path}: {e}")
        
    return logger

logger = setup_logger()
