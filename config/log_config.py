#!/usr/bin/env python3

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(
        log_dir: str = "logs",
        log_file_name: str = "app.log",
        log_level: int = logging.DEBUG,
        backup_count: int = 5,
        max_bytes: int = 10 * 1024 * 1024
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

    if log_path and not log_path.exists():
        log_path.mkdir(exist_ok=True)

    # Generate timestamped log filename
    log_file = log_path / log_file_name

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    if root_logger.hasHandlers():
        # Clear any existing handlers
        root_logger.handlers.clear()

    formatter = logging.Formatter(
        # level=logging.DEBUG,
        fmt="%(asctime)s.%(msecs)03d | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s() | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        # filename=log_file,
        # filemode="w",
        # encoding="utf-8"
    )

    # File handler (ALL logs go here)
    # Replace FileHandler with RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        # Keep 5 old files (app.log.1, app.log.2, etc.)
        backupCount=backup_count,
        encoding="utf-8",
    )

    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)

    # Log startup info
    root_logger.info(f"=== Application started ===")
    root_logger.info(f"Log file → [ '{log_file}' ]")

    # Store log path for reference
    root_logger.log_file = str(log_file)

    # IMPORTANT: Prevent propagation issues
    root_logger.propagate = True

    return root_logger


# Convenience function to get the configured logger
def get_logger(name: str = None) -> logging.Logger:
    """Get logger instance with optional submodule name.

    Args:
        name: Optional submodule name (e.g., "key", "aes", "pgp", "xor")

    Returns:
        Logger instance
    """
    base_logger = logging.getLogger("vector_cli")
    if name:
        return base_logger.getChild(name)
    return base_logger
