"""
NEXUS-STRIKE Logging System
Structured logging with console, file, and JSON output.
"""
import logging
import sys
import os
from nexus.foundation.config import config

def setup_logging():
    """Configure structured logging with multiple outputs."""
    level = getattr(logging, config.nexus_log_level.upper(), logging.INFO)
    root = logging.getLogger("nexus")
    root.setLevel(level)

    # Console handler (Rich formatted)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    console_handler.setLevel(level)
    root.addHandler(console_handler)

    # File handler (detailed)
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(log_dir, "nexus.log"))
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
    ))
    file_handler.setLevel(logging.DEBUG)
    root.addHandler(file_handler)

    return root

logger = setup_logging()