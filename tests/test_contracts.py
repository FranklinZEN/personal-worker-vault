"""Unit tests for canonical contracts, identifiers, and schema execution."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vault_next.canonical import canonical_bytes
from vault_next.errors import ErrorCode, ValidationError
from vault_next.ids import ULIDFactory, encode_ulid, validate_id
from vault_next.schema import load_schema, validate
from tests.helpers import SCHEMA_ROOT


class CanonicalContractTests(unittest.TestCase):
    def test_canonical_json_is_sorted_compact_and_rejects_float(self) -> None:
        self.assertEqual(canonical_bytes({"z": 1, "a": "é"}), b'{"a":"\xc3\xa9","z":1}')
        with self.assertRaises(ValidationError) as caught:
            canonical_bytes({"ambiguous": 0.1})
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.CANONICAL_FLOAT_FORBIDDEN)

    def test_ulid_is_monotonic_and_prefixed(self) -> None:
        factory = ULIDFactory(now_ms=lambda: 1_000, random_source=lambda length: b"\0" * length)
        first = factory.new("event")
        second = factory.new("event")
        self.assertLess(first, second)
        validate_id(first, "event")
        self.assertEqual(len(encode_ulid(1_000, b"\0" * 10)), 26)

    def test_every_checked_in_schema_uses_supported_keywords(self) -> None:
        for schema_root in sorted(SCHEMA_ROOT.parent.glob("v[0-9]*")):
            for path in sorted(schema_root.rglob("*.schema.json")):
                schema = load_schema(path)
                self.assertEqual(validate({}, schema)[0].code, ErrorCode.SCHEMA_REQUIRED)

    def test_every_active_event_type_has_a_payload_schema(self) -> None:
        for schema_root in sorted(SCHEMA_ROOT.parent.glob("v[0-9]*")):
            event_schema = load_schema(schema_root / "event.schema.json")
            event_contract = event_schema["properties"]["event_type"]
            event_types = (
                event_contract["enum"]
                if "enum" in event_contract
                else [event_contract["const"]]
            )
            for event_type in event_types:
                payload_name = event_type.replace(".", "-").replace("_", "-")
                self.assertTrue(
                    (schema_root / "events" / f"{payload_name}.schema.json").is_file(),
                    event_type,
                )

    def test_unknown_schema_keyword_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.schema.json"
            path.write_text(json.dumps({"type": "object", "mystery": True}), encoding="utf-8")
            with self.assertRaises(ValidationError) as caught:
                load_schema(path)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.SCHEMA_UNSUPPORTED_KEYWORD)


if __name__ == "__main__":
    unittest.main()
