# !/usr/bin/env python3

import logging
from datetime import datetime
from pathlib import Path


def setup_logging(
        log_dir: str = "logs",
        log_level: int = logging.DEBUG
) -> logging.Logger:
    """Configure application logging to a single file ONLY (no console).

    Args:
        log_dir: Directory where logs will be stored
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    # Generate timestamped log filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"app_{timestamp}.log"

    # Configure root logger
    logger = logging.getLogger("encryption_app")
    logger.setLevel(log_level)

    # Clear any existing handlers
    logger.handlers.clear()

    # File formatter with full details
    file_formatter = logging.Formatter(
        # fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        # fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        # datefmt="%Y-%m-%d %H:%M:%S"
        
        fmt="%(asctime)s | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s",
        datefmt="%H:%M:%S"
    )

    # File handler (ALL logs go here)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Log startup info
    # logger.info("=" * 60)
    logger.info(f"Application started | Log file: {log_file}")
    # logger.info("=" * 60)

    # Store log path for reference
    logger.log_file = str(log_file)

    return logger

# Convenience function to get the configured logger
def get_logger(name: str = None) -> logging.Logger:
    """Get logger instance with optional submodule name.

    Args:
        name: Optional submodule name (e.g., "key", "aes", "pgp", "xor")

    Returns:
        Logger instance
    """
    base_logger = logging.getLogger("encryption_app")
    if name:
        return base_logger.getChild(name)
    return base_logger