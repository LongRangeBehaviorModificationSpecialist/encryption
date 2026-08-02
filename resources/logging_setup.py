from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import sys


def setup_logging():
    # Configure the ROOT logger (affects all loggers in the app)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    app_log_file_name = f"encryption_{timestamp}.log"

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    log_format = logging.Formatter(
                fmt="%(asctime)s  %(levelname)-7s  %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                )

    if not logger.handlers:
        # File handler (DEBUG level - captures everything)
        file_handler = RotatingFileHandler(
            app_log_file_name,
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8"
            )
        # file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(log_format)
        logger.addHandler(file_handler)

        # Console handler (INFO level - user-facing)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(log_format)
        logger.addHandler(console_handler)

        logger.info(f"Log file : {app_log_file_name}")

    return logger