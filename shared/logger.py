"""
shared/logger.py
----------------
Centralised logging factory.

Rules enforced here:
  - Message *content* is NEVER logged (enforced by convention; callers must not
    pass payload data to log calls).
  - Separate handlers for console (INFO+) and rotating file (DEBUG+).
  - Both server and client import this module to get a consistent format.
"""

import logging
import logging.handlers
import os
from pathlib import Path


def get_logger(name: str, log_file: str | None = None, level: str = "INFO") -> logging.Logger:
    """
    Return a named logger with console + optional rotating-file handlers.

    Parameters
    ----------
    name     : logger name (usually __name__ of the calling module)
    log_file : absolute path for the rotating log file; None = no file handler
    level    : minimum severity string, e.g. "DEBUG", "INFO", "WARNING"
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if the logger already exists
    if logger.handlers:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(logging.DEBUG)  # capture everything; handlers filter

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(numeric_level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Rotating file handler (10 MB × 5 backups)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
