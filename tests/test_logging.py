from __future__ import annotations

import json
import logging

from aegis_nexus.app import create_app
from aegis_nexus.logging_config import JsonLogFormatter, configure_app_logging


def _record(msg, *args, **kwargs):
    return logging.LogRecord("aegis.test", logging.INFO, __file__, 10, msg, args, kwargs.get("exc_info"))


def test_json_formatter_emits_single_valid_json_line():
    formatter = JsonLogFormatter()
    out = formatter.format(_record("hello world"))
    assert "\n" not in out
    parsed = json.loads(out)
    assert parsed["message"] == "hello world"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "aegis.test"
    assert parsed["timestamp"].endswith("+00:00")


def test_log_injection_cannot_forge_lines_or_fields():
    formatter = JsonLogFormatter()
    hostile = 'user=%s'
    out = formatter.format(_record(hostile, 'a"}\n{"evil":1,"level":"CRITICAL"'))
    # Single physical line, parses to exactly one object.
    assert out.count("\n") == 0
    parsed = json.loads(out)
    # The forged field never becomes a top-level key; it stays inside message.
    assert "evil" not in parsed
    assert parsed["level"] == "INFO"
    assert 'evil' in parsed["message"]


def test_exception_is_rendered_as_string_value():
    formatter = JsonLogFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = logging.LogRecord("aegis.test", logging.ERROR, __file__, 10, "failed", (), sys.exc_info())
    parsed = json.loads(formatter.format(record))
    assert "boom" in parsed["exception"]


def test_create_app_json_logging_is_idempotent(tmp_path):
    cfg = {
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "aegis.db"),
        "INGEST_API_KEY": "s",
        "LOG_FORMAT": "json",
    }
    app = create_app(cfg)
    json_handlers = [h for h in app.logger.handlers if h.get_name() == "aegis-json"]
    assert len(json_handlers) == 1
    assert isinstance(json_handlers[0].formatter, JsonLogFormatter)
    # Re-applying must not stack duplicate handlers.
    configure_app_logging(app)
    assert len([h for h in app.logger.handlers if h.get_name() == "aegis-json"]) == 1
