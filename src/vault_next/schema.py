"""Strict executable subset of the checked-in Phase 1 JSON Schemas."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from vault_next.errors import ErrorCode, Issue, ValidationError

SUPPORTED_KEYWORDS = frozenset(
    {
        "$id",
        "$schema",
        "additionalProperties",
        "const",
        "description",
        "enum",
        "format",
        "items",
        "maxLength",
        "minItems",
        "minLength",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
        "uniqueItems",
    }
)


def load_schema(path: Path) -> dict[str, Any]:
    """Load a schema and fail closed if it uses an unsupported keyword."""

    schema = json.loads(path.read_text(encoding="utf-8"))
    _check_schema_keywords(schema, "$schema")
    return schema


def _check_schema_keywords(schema: Any, path: str) -> None:
    if not isinstance(schema, dict):
        raise ValidationError(
            [Issue(ErrorCode.SCHEMA_INVALID, path, "schema node must be an object")]
        )
    issues: list[Issue] = []
    for keyword in schema:
        if keyword not in SUPPORTED_KEYWORDS:
            issues.append(
                Issue(
                    ErrorCode.SCHEMA_UNSUPPORTED_KEYWORD,
                    f"{path}/{keyword}",
                    f"unsupported schema keyword: {keyword}",
                )
            )
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        issues.append(Issue(ErrorCode.SCHEMA_INVALID, f"{path}/properties", "must be an object"))
    else:
        for name, child in properties.items():
            try:
                _check_schema_keywords(child, f"{path}/properties/{name}")
            except ValidationError as exc:
                issues.extend(exc.issues)
    items = schema.get("items")
    if items is not None:
        try:
            _check_schema_keywords(items, f"{path}/items")
        except ValidationError as exc:
            issues.extend(exc.issues)
    if issues:
        raise ValidationError(issues)


def validate(instance: Any, schema: dict[str, Any]) -> tuple[Issue, ...]:
    """Return deterministically ordered structural issues."""

    return tuple(sorted(_validate_node(instance, schema, "$")))


def require_valid(instance: Any, schema: dict[str, Any]) -> None:
    """Raise when *instance* fails structural validation."""

    issues = validate(instance, schema)
    if issues:
        raise ValidationError(issues)


def _validate_node(instance: Any, schema: dict[str, Any], path: str) -> Iterable[Issue]:
    issues: list[Issue] = []
    allowed_types = schema.get("type")
    if allowed_types is not None:
        names = [allowed_types] if isinstance(allowed_types, str) else allowed_types
        if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
            return [Issue(ErrorCode.SCHEMA_INVALID, path, "schema type must be string or list")]
        if not any(_matches_type(instance, name) for name in names):
            return [
                Issue(ErrorCode.SCHEMA_TYPE, path, f"expected {' or '.join(names)}")
            ]

    if "const" in schema and instance != schema["const"]:
        issues.append(Issue(ErrorCode.SCHEMA_CONST, path, "value does not match const"))
    if "enum" in schema and instance not in schema["enum"]:
        issues.append(Issue(ErrorCode.SCHEMA_ENUM, path, "value is not in enum"))

    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            issues.append(Issue(ErrorCode.SCHEMA_LENGTH, path, "string is too short"))
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            issues.append(Issue(ErrorCode.SCHEMA_LENGTH, path, "string is too long"))
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, instance) is None:
            issues.append(Issue(ErrorCode.SCHEMA_PATTERN, path, "string does not match pattern"))
        if schema.get("format") == "date-time" and not _is_aware_datetime(instance):
            issues.append(Issue(ErrorCode.SCHEMA_FORMAT, path, "expected timezone-aware date-time"))

    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            issues.append(Issue(ErrorCode.SCHEMA_LENGTH, path, "array is too short"))
        if schema.get("uniqueItems"):
            rendered = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(rendered) != len(set(rendered)):
                issues.append(Issue(ErrorCode.SCHEMA_INVALID, path, "array items are not unique"))
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                issues.extend(_validate_node(item, item_schema, f"{path}/{index}"))

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for name in required:
            if name not in instance:
                issues.append(
                    Issue(ErrorCode.SCHEMA_REQUIRED, f"{path}/{name}", "required property missing")
                )
        properties = schema.get("properties", {})
        for name, value in instance.items():
            child_path = f"{path}/{_escape_pointer(name)}"
            if name in properties:
                issues.extend(_validate_node(value, properties[name], child_path))
            elif schema.get("additionalProperties") is False:
                issues.append(
                    Issue(ErrorCode.SCHEMA_ADDITIONAL_PROPERTY, child_path, "property is not allowed")
                )
    return issues


def _matches_type(value: Any, name: str) -> bool:
    mapping = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "object": lambda item: isinstance(item, dict),
        "string": lambda item: isinstance(item, str),
    }
    matcher = mapping.get(name)
    return matcher(value) if matcher else False


def _is_aware_datetime(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")

