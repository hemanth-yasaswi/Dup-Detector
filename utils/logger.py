"""
Provides get_logger(name) — the only logging entry point in the application.
All modules must use this instead of configuring their own loggers.
"""

import logging
import os
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

LOG_DIR    = "logs"
LOG_FILE   = os.path.join(LOG_DIR, "ddas.log")
MAX_BYTES  = 5 * 1024 * 1024   # 5 MB per file
BACKUP_COUNT = 3                # keep ddas.log, ddas.log.1, ddas.log.2


class JsonFormatter(logging.Formatter):
    """
    Formats each log record as a single-line JSON object.

    Output fields:
      timestamp : ISO 8601 string
      level     : DEBUG / INFO / WARNING / ERROR / CRITICAL
      module    : logger name (typically __name__ of caller)
      message   : the log message string
      exc_info  : exception traceback string, only present if exception was logged
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":     record.levelname,
            "module":    record.name,
            "message":   record.getMessage(),
        }
        if record.exc_info:
            try:
                payload["exc_info"] = self.formatException(record.exc_info)
            except Exception:
                payload["exc_info"] = "<exception formatting failed>"

        try:
            return json.dumps(payload, ensure_ascii=False)
        except Exception:
            # Last-resort fallback — never raise from a formatter
            return (
                f'{{"timestamp":"{payload.get("timestamp","?")}","level":"{payload.get("level","?")}","module":"{payload.get("module","?")}",'
                f'"message":"<json serialisation failed>"}}'
            )


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger for the given name.

    Behaviour:
    - Creates logs/ directory if it does not exist.
    - Attaches a RotatingFileHandler writing JSON-formatted records.
    - Attaches a StreamHandler writing plain text to stdout.
    - Safe to call multiple times with the same name — handlers are
      never duplicated (guard: if logger.handlers: return logger).
    - Root log level: DEBUG (handlers may filter independently).

    File handler level  : DEBUG
    Console handler level: INFO
    """
    logger = logging.getLogger(name)

    # Guard: never add duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Ensure the log directory exists before attaching the file handler
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError:
        pass  # If we cannot create the dir, the file handler creation below will also fail gracefully

    # --- File handler (JSON, DEBUG+) ---
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)
    except Exception:
        pass  # Cannot log the failure — we are the logger

    # --- Console handler (plain text, INFO+) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Prevent log records from propagating to the root logger
    logger.propagate = False

    return logger
