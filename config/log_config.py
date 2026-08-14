# !/usr/bin/env python3

import logging
from logging.handlers import RotatingFileHandler
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
    log_file = log_path / "app.log"

    # Configure root logger
    logger = logging.getLogger(__name__)

    # Clear any existing handlers
    logger.handlers.clear()

    # File handler (ALL logs go here)
    # Replace FileHandler with RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=25_000_000,  # 25 MB per file
        backupCount=5,        # Keep 5 old files (app.log.1, app.log.2, etc.)
        encoding="utf-8",
    )

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s.%(msecs)03d | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s() | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=log_file,
        filemode="w",
        encoding="utf-8"
    )

    logger.addHandler(file_handler)

    # Log startup info
    logger.info(f"=== Application started ===")
    logger.info(f"Log file: [ '{log_file}' ]")

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
