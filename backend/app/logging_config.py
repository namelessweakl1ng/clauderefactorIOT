"""Opt-in structured (JSON) logging.

Set ``LOG_FORMAT=json`` to emit one JSON object per log line (timestamp, level,
logger, message) for ingestion by a log stack; unset, logging is left at its
default human-readable format so local runs and tests are unchanged.
"""

import json
import logging
import os
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    """Install the JSON formatter when LOG_FORMAT=json; otherwise no-op."""
    if os.getenv("LOG_FORMAT", "").lower() != "json":
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
