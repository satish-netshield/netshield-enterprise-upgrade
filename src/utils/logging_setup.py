"""Configure separate application and security audit logs."""

import logging
from pathlib import Path


def _build_file_handler(log_path: Path) -> logging.FileHandler:
    """Create a consistently formatted file handler."""
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )
    return handler


def configure_logger(name: str, log_path: Path) -> logging.Logger:
    """Create or return a named file logger without duplicate handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        logger.addHandler(_build_file_handler(log_path))

    return logger
