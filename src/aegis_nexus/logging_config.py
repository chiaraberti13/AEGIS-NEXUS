"""Structured JSON application logging, safe against log injection.

Each record is emitted as a single JSON object. Because the message and any
values are JSON-encoded, attacker-controlled content that reaches a log line
(an IP, a username, a payload fragment) cannot forge a new log line or inject
extra fields: newlines and control characters are escaped and the field set is
fixed. Enable it with ``AEGIS_LOG_FORMAT=json``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

_HANDLER_TAG = "aegis-json"
# Fixed top-level field set; attacker content only ever lands in values.
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName",
}


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            # Rendered as a single escaped string value; never a structured field.
            payload["exception"] = self.formatException(record.exc_info)
        # Allow explicit developer-provided extras, but only JSON-serializable
        # scalars/containers and never overriding a reserved field.
        for key, value in record.__dict__.items():
            if key in _RESERVED or key in payload or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = str(value)
            payload[key] = value
        # ensure_ascii + default json escaping neutralizes newlines/controls.
        return json.dumps(payload, ensure_ascii=True, default=str)


def build_json_handler() -> logging.Handler:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    handler.set_name(_HANDLER_TAG)
    return handler


def configure_app_logging(app: object) -> None:
    """Attach a single JSON handler to the Flask app logger (idempotent)."""
    logger = getattr(app, "logger", None)
    if logger is None:
        return
    logger.handlers = [h for h in logger.handlers if h.get_name() != _HANDLER_TAG]
    logger.addHandler(build_json_handler())
    logger.propagate = False
    logger.setLevel(logging.INFO)
