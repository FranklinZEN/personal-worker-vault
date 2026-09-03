"""Restricted deterministic JSON serialization and SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vault_next.errors import ErrorCode, Issue, ValidationError

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]


def _validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ValidationError(
            [Issue(ErrorCode.CANONICAL_FLOAT_FORBIDDEN, path, "floats are not canonical")]
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}/{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(
                    [Issue(ErrorCode.CANONICAL_TYPE_INVALID, path, "object keys must be strings")]
                )
            _validate_value(item, f"{path}/{_escape_pointer(key)}")
        return
    raise ValidationError(
        [
            Issue(
                ErrorCode.CANONICAL_TYPE_INVALID,
                path,
                f"unsupported canonical type: {type(value).__name__}",
            )
        ]
    )


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def canonical_bytes(value: JsonValue) -> bytes:
    """Return the Phase 1 canonical UTF-8 representation without a newline."""

    _validate_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return a lowercase full SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: JsonValue) -> str:
    """Hash a canonical JSON value."""

    return sha256_hex(canonical_bytes(value))

