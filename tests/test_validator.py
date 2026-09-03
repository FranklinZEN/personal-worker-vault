"""Integration tests for repository-wide validation evidence."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode
from vault_next.fixtures import (
    run_synthetic_phase2,
    run_synthetic_phase3,
    run_synthetic_phase3a,
    run_synthetic_session,
)
from vault_next.policy import Proposal
from vault_next.records import build_audit_record
from vault_next.validator import KernelValidator
from tests.helpers import Harness, SCHEMA_ROOT


class KernelValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_valid_synthetic_run_produces_versioned_evidence(self) -> None:
        run_synthetic_session(self.harness.runtime_root, SCHEMA_ROOT)
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertTrue(report.passed)
        self.assertEqual(report.semantic_event_count, 6)
        self.assertEqual(report.operational_record_count, 1)
        self.assertEqual(report.projection_count, 1)
        self.assertEqual(len(report.semantic_fixture_hash), 64)

    def test_phase2_synthetic_fixture_is_deterministic_and_valid(self) -> None:
        with TemporaryDirectory(prefix="vault-next-phase2-a-") as first_directory:
            first = run_synthetic_phase2(Path(first_directory), SCHEMA_ROOT)
        with TemporaryDirectory(prefix="vault-next-phase2-b-") as second_directory:
            second = run_synthetic_phase2(Path(second_directory), SCHEMA_ROOT)
        self.assertEqual(first.to_record(), second.to_record())
        self.assertEqual(first.event_count, 22)
        self.assertEqual(first.projection_count, 4)

    def test_phase3_synthetic_fixture_is_deterministic_and_valid(self) -> None:
        with TemporaryDirectory(prefix="vault-next-phase3-a-") as first_directory:
            first = run_synthetic_phase3(Path(first_directory), SCHEMA_ROOT)
        with TemporaryDirectory(prefix="vault-next-phase3-b-") as second_directory:
            second = run_synthetic_phase3(Path(second_directory), SCHEMA_ROOT)
        self.assertEqual(first.to_record(), second.to_record())
        self.assertEqual(first.active_package_count, 20)
        self.assertGreater(first.event_count, 10)

    def test_phase3a_synthetic_fixture_is_deterministic_and_valid(self) -> None:
        with TemporaryDirectory(prefix="vault-next-phase3a-a-") as first_directory:
            first = run_synthetic_phase3a(Path(first_directory), SCHEMA_ROOT)
        with TemporaryDirectory(prefix="vault-next-phase3a-b-") as second_directory:
            second = run_synthetic_phase3a(Path(second_directory), SCHEMA_ROOT)
        self.assertEqual(first.to_record(), second.to_record())
        self.assertEqual(len(first.artifact_content_hashes), 2)
        self.assertGreater(first.event_count, 20)

    def test_cross_ledger_unknown_event_reference_is_detected(self) -> None:
        self.harness.start()
        proposal = Proposal(
            operation_class="write",
            targets=(str(self.harness.runtime_root / "generated"),),
            consequence_class="ordinary",
            actor_id="runtime",
        ).finalized()
        policy = self.harness.policy.evaluate(proposal, now=self.harness.current).to_record()
        policy.pop("schema_version")
        audit = build_audit_record(
            operation_class="write",
            target_summary="invented generated target",
            input_digest=canonical_sha256({"synthetic": True}),
            policy=policy,
            attempt_status="attempted",
            result="succeeded",
            semantic_event_refs=["event_00000000000000000000000000"],
            attempted_at=self.harness.tick(),
            id_factory=self.harness.ids,
        )
        self.harness.operational.append(audit)
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertFalse(report.passed)
        self.assertIn(ErrorCode.EVENT_REFERENCE_MISSING, {issue.code for issue in report.issues})

    def test_projection_tamper_is_reported(self) -> None:
        result = run_synthetic_session(self.harness.runtime_root, SCHEMA_ROOT)
        result.projection_path.write_bytes(b"{}\n")
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertFalse(report.passed)
        self.assertEqual(report.issues[0].code, ErrorCode.PROJECTION_TAMPERED)

    def test_phase3a_artifact_tamper_is_reported(self) -> None:
        run_synthetic_phase3a(self.harness.runtime_root, SCHEMA_ROOT)
        object_path = next(
            (self.harness.paths.artifact_root / "objects" / "sha256").glob("*/*")
        )
        object_path.write_bytes(b"tampered synthetic artifact")
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertFalse(report.passed)
        self.assertIn(
            ErrorCode.ARTIFACT_REFERENCE_INVALID,
            {issue.code for issue in report.issues},
        )


if __name__ == "__main__":
    unittest.main()
