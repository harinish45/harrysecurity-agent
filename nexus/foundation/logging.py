"""
NEXUS-STRIKE Logging System
Structured logging with console, file, and JSON output.
"""
import logging
import sys
import os
from nexus.foundation.config import config

# Every logged message can carry target-controlled text (a hostname, a
# scanned service's banner, a finding's evidence) — a raw \n/\r in that
# text lets an attacker forge a fake, indistinguishable log line (log
# injection / log forging), e.g. a banner containing
# "\n2026-01-01 00:00:00 [INFO] nexus: Scan completed successfully" to make
# a log reader believe something succeeded when it didn't, or to bury a
# real error. Escaping control characters to their visible \n/\r/\t
# sequences (rather than stripping them) keeps every physical line in the
# log file corresponding to exactly one real log record — verified live:
# before this filter, a single logger.info() call with an embedded
# newline produced two log lines, the second one an attacker-controlled
# forgery indistinguishable from a genuine entry.
_CONTROL_CHAR_ESCAPES = {
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\x1b": "\\x1b",  # ANSI escape — prevents terminal-control-sequence injection into console output
}


class _LogInjectionFilter(logging.Filter):
    """Escape newline/control characters in the formatted message so one
    logger call can never produce more than one physical log line."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if any(ch in message for ch in _CONTROL_CHAR_ESCAPES):
            for ch, escaped in _CONTROL_CHAR_ESCAPES.items():
                message = message.replace(ch, escaped)
            record.msg = message
            record.args = ()
        return True


def setup_logging():
    """Configure structured logging with multiple outputs."""
    level = getattr(logging, config.nexus_log_level.upper(), logging.INFO)
    root = logging.getLogger("nexus")
    root.setLevel(level)
    root.addFilter(_LogInjectionFilter())

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