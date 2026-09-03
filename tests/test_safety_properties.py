"""Deterministic property-style checks for Phase 1 invariants."""

from __future__ import annotations

import itertools
import unittest
from datetime import UTC, datetime

from vault_next.canonical import canonical_bytes
from vault_next.errors import ErrorCode, ValidationError
from vault_next.ids import ULIDFactory
from vault_next.packages import (
    PackagePointer,
    validate_package_pointer,
    validate_pointer_transition,
)
from vault_next.triage import merge_configuration
from tests.helpers import Harness


class SafetyPropertyTests(unittest.TestCase):
    def test_500_ids_in_one_millisecond_are_unique_and_sorted(self) -> None:
        factory = ULIDFactory(now_ms=lambda: 10_000, random_source=lambda length: b"\0" * length)
        identifiers = [factory.new("event") for _ in range(500)]
        self.assertEqual(len(set(identifiers)), 500)
        self.assertEqual(identifiers, sorted(identifiers))

    def test_object_insertion_order_never_changes_canonical_bytes(self) -> None:
        pairs = [("delta", 4), ("alpha", 1), ("charlie", 3), ("bravo", 2)]
        encodings = {
            canonical_bytes(dict(permutation)) for permutation in itertools.permutations(pairs)
        }
        self.assertEqual(len(encodings), 1)

    def test_governance_values_cannot_be_weakened_by_later_triage_layers(self) -> None:
        merged = merge_configuration(
            {
                "governance": {"permissions": "default-deny", "depth": "standard"},
                "named_profile": {"permissions": "allow-all", "depth": "deep"},
                "owner_instruction": {"protected_paths": [], "depth": "concise"},
            }
        )
        self.assertEqual(merged["permissions"], "default-deny")
        self.assertEqual(merged["depth"], "concise")
        self.assertNotIn("protected_paths", merged)

    def test_active_package_requires_approval_and_version_digest_is_immutable(self) -> None:
        harness = Harness()
        try:
            candidate = PackagePointer("skill", "synthetic-skill", "1.0", "a" * 64)
            validate_package_pointer(candidate, harness.schemas)
            invalid_active = PackagePointer(
                "skill",
                "synthetic-skill",
                "1.0",
                "a" * 64,
                status="active",
            )
            with self.assertRaises(ValidationError):
                validate_package_pointer(invalid_active, harness.schemas)
            active = PackagePointer(
                "skill",
                "synthetic-skill",
                "1.0",
                "a" * 64,
                status="active",
                approval_ref=harness.ids.new("approval"),
                activated_at=datetime(2026, 9, 1, tzinfo=UTC),
            )
            validate_package_pointer(active, harness.schemas)
            mutated = PackagePointer(**{**active.__dict__, "digest": "b" * 64})
            with self.assertRaises(ValidationError) as caught:
                validate_pointer_transition(active, mutated)
            self.assertEqual(
                caught.exception.issues[0].code,
                ErrorCode.PACKAGE_VERSION_IMMUTABLE,
            )
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()

