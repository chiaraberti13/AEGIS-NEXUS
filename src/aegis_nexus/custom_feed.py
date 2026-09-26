from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SUPPORTED_FIELDS = {
    "type",
    "value",
    "labels",
    "confidence",
    "description",
    "reference",
    "first_seen",
    "last_seen",
    "valid_from",
    "valid_until",
}
MAX_CONFIG_BYTES = 16 * 1024


class CustomFeedAdapterError(ValueError):
    pass


def _path_parts(value: Any, *, required: bool = False) -> tuple[str, ...] | None:
    if value in (None, ""):
        if required:
            raise CustomFeedAdapterError("adapter_path_required")
        return None
    if not isinstance(value, str) or len(value) > 512:
        raise CustomFeedAdapterError("invalid_adapter_path")
    parts = tuple(value.split("."))
    if not parts or any(not part or len(part) > 128 for part in parts):
        raise CustomFeedAdapterError("invalid_adapter_path")
    return parts


def _lookup(root: Any, path: tuple[str, ...] | None) -> Any:
    current = root
    if path is None:
        return None
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class CustomFeedAdapter:
    """Declaratively map an operator-supplied JSON feed into AEGIS indicator records."""

    def __init__(self, config: dict[str, Any]):
        if not isinstance(config, dict):
            raise CustomFeedAdapterError("adapter_config_must_be_object")
        allowed = {
            "items_path",
            "source",
            "source_path",
            "generated_at_path",
            "fields",
            "fixed_type",
            "type_map",
        }
        if set(config) - allowed:
            raise CustomFeedAdapterError("unsupported_adapter_config_key")

        self.items_path = _path_parts(config.get("items_path"), required=True)
        self.source = str(config.get("source") or "").strip()[:256] or None
        self.source_path = _path_parts(config.get("source_path"))
        self.generated_at_path = _path_parts(config.get("generated_at_path"))

        fields = config.get("fields")
        if not isinstance(fields, dict):
            raise CustomFeedAdapterError("adapter_fields_must_be_object")
        if set(fields) - SUPPORTED_FIELDS:
            raise CustomFeedAdapterError("unsupported_adapter_field")
        self.fields: dict[str, tuple[str, ...]] = {}
        for target, source_path in fields.items():
            path = _path_parts(source_path, required=True)
            assert path is not None
            self.fields[target] = path

        self.fixed_type = str(config.get("fixed_type") or "").strip().lower()[:16] or None
        if "value" not in self.fields:
            raise CustomFeedAdapterError("adapter_value_field_required")
        if "type" not in self.fields and not self.fixed_type:
            raise CustomFeedAdapterError("adapter_type_or_fixed_type_required")

        type_map = config.get("type_map") or {}
        if not isinstance(type_map, dict) or len(type_map) > 64:
            raise CustomFeedAdapterError("invalid_adapter_type_map")
        self.type_map: dict[str, str] = {}
        for source_type, target_type in type_map.items():
            source_text = str(source_type).strip().lower()[:64]
            target_text = str(target_type).strip().lower()[:16]
            if not source_text or not target_text:
                raise CustomFeedAdapterError("invalid_adapter_type_map")
            self.type_map[source_text] = target_text

    def adapt(self, payload: dict[str, Any], *, max_indicators: int) -> dict[str, Any]:
        items = _lookup(payload, self.items_path)
        if not isinstance(items, list):
            raise CustomFeedAdapterError("adapter_items_path_must_resolve_to_list")
        if len(items) > max_indicators:
            raise CustomFeedAdapterError("too_many_indicators")

        indicators: list[dict[str, Any]] = []
        for raw in items:
            if not isinstance(raw, dict):
                continue
            item: dict[str, Any] = {}
            for target, path in self.fields.items():
                value = _lookup(raw, path)
                if value is not None:
                    item[target] = value
            if self.fixed_type:
                item["type"] = self.fixed_type
            elif "type" in item:
                upstream_type = str(item["type"]).strip().lower()
                item["type"] = self.type_map.get(upstream_type, upstream_type)
            if "value" not in item or "type" not in item:
                continue
            indicators.append(item)

        source = self.source or _lookup(payload, self.source_path)
        generated_at = _lookup(payload, self.generated_at_path)
        result: dict[str, Any] = {"indicators": indicators}
        if source not in (None, ""):
            result["source"] = str(source)[:256]
        if generated_at not in (None, ""):
            result["generated_at"] = str(generated_at)[:128]
        return result


def load_custom_feed_adapter_config(*, raw_json: str = "", file_path: str = "") -> dict[str, Any] | None:
    if raw_json and file_path:
        raise CustomFeedAdapterError("configure_only_one_adapter_source")
    if not raw_json and not file_path:
        return None
    if file_path:
        path = Path(file_path).expanduser()
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise CustomFeedAdapterError("adapter_config_too_large")
        text = raw.decode("utf-8")
    else:
        encoded = raw_json.encode("utf-8")
        if len(encoded) > MAX_CONFIG_BYTES:
            raise CustomFeedAdapterError("adapter_config_too_large")
        text = raw_json
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CustomFeedAdapterError("invalid_adapter_json") from exc
    if not isinstance(parsed, dict):
        raise CustomFeedAdapterError("adapter_config_must_be_object")
    CustomFeedAdapter(parsed)
    return parsed
