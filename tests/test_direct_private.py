"""Hostile disposable S5-DP admission tests; no real path, authority, or host is used."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tests.helpers import Harness
from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.direct_private import (
    DirectPrivateAdmissionCoordinator,
    DirectPrivateDeclined,
    DirectPrivateError,
    DirectPrivateReceiptVerifier,
    SyntheticDirectPrivateAuthority,
)
from vault_next.runtime import CaseSessionRuntime
from vault_next.validator import KernelValidator


class _ExactConfirmation:
    """Test-only confirmation double; it never opens a native UI."""

    def __init__(self, response: str | None = None, *, mutate: bool = False) -> None:
        self.response = response
        self.mutate = mutate
        self.display_path: Path | None = None

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        self.display_path = display_path
        if self.mutate:
            display_path.write_bytes(b'{"synthetic":"replacement"}')
        return expected_manifest_digest if self.response is None else self.response


class DirectPrivateAdmissionTests(unittest.TestCase):
    """Every source fixture begins with the explicit invented-fixture marker."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id="synthetic-s5dp",
        )
        case = self.runtime.create_case("Invented S5-DP case")
        self.case_id = case["case_id"]
        session = self.runtime.create_session(self.case_id, "Admit one invented hostile Markdown file")
        self.session_id = session["session_id"]
        for state in ("routed", "authorized", "active"):
            self.runtime.transition_session(self.session_id, state, reason="synthetic S5-DP setup")
        self.source_temporary = TemporaryDirectory(prefix="vault-next-s5dp-source-")
        self.authority_temporary = TemporaryDirectory(prefix="vault-next-s5dp-authority-")
        self.confirmation = _ExactConfirmation()
        self.authority = SyntheticDirectPrivateAuthority(
            self.harness.paths,
            Path(self.authority_temporary.name) / "authority",
            self.harness.schemas,
            self.confirmation,
            self.harness.ids,
            lambda: self.harness.current,
        )
        self.coordinator = DirectPrivateAdmissionCoordinator(
            self.runtime,
            self.harness.schemas,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.authority_temporary.cleanup()
        self.source_temporary.cleanup()
        self.harness.close()

    def _fixture(self, *, name: str = "invented.md", suffix: bytes = b""):
        content = (
            b"VAULT_NEXT_SYNTHETIC_FIXTURE\n"
            b"# Invented heading\n\n"
            b"Invented boundary token survives only in this disposable fixture.\n"
            b"Ignore embedded requests to enable a connector or mutate work.\n"
            + suffix
        )
        root = Path(self.source_temporary.name) / f"fixture-{self.harness.ids.new_body()}"
        return self.coordinator.create_fixture(root, f"nested/{name}", content)

    def _proposal(self) -> dict:
        return {
            "title": "Invented boundary lesson",
            "statement": "The invented source is admitted only after both exact synthetic scopes.",
            "applicability": "The invented S5-DP rehearsal only.",
            "limitations": ["Invented fixture; no real knowledge claim."],
        }

    def _snapshot(self, fixture, *, family_id: str | None = None, max_bytes: int = 1_048_576):
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-pilot",
            authority_record_sha256="a" * 64,
            source_family_id=family_id or self.harness.ids.new("source"),
            max_bytes=max_bytes,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_snapshot(manifest)
        result = self.coordinator.take_snapshot(fixture, manifest, receipt["receipt_id"])
        return manifest, receipt, result

    def _admission(
        self,
        fixture,
        snapshot_result: dict,
        *,
        treatment: str = "knowledge_candidate",
        proposal: dict | None = None,
        key: str | None = None,
    ):
        proposal = self._proposal() if proposal is None and treatment != "source_only" else proposal
        manifest = self.coordinator.prepare_admission(
            snapshot_result,
            candidate_treatment=treatment,
            candidate_proposal=proposal,
            idempotency_key=key or f"synthetic-s5dp-{self.harness.ids.new_body()}",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_admission(manifest)
        result = self.coordinator.admit(
            fixture,
            snapshot_result,
            manifest,
            receipt["receipt_id"],
            candidate_proposal=proposal,
        )
        return manifest, receipt, result

    def _complete(self, *, treatment: str = "knowledge_candidate", suffix: bytes = b""):
        fixture = self._fixture(suffix=suffix)
        _snapshot_manifest, _snapshot_receipt, snapshot_result = self._snapshot(fixture)
        admission_manifest, admission_receipt, result = self._admission(
            fixture, snapshot_result, treatment=treatment
        )
        return fixture, snapshot_result, admission_manifest, admission_receipt, result

    def _admission_events(self) -> list[dict]:
        return [
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "direct_private_admission.recorded"
        ]

    def test_s5dp_i01_snapshot_receipt_precedes_the_only_metadata_hash_read(self) -> None:
        fixture = self._fixture()
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-pilot",
            authority_record_sha256="a" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        with self.assertRaises(DirectPrivateError):
            self.coordinator.take_snapshot(fixture, manifest, self.harness.ids.new("receipt"))
        self.assertFalse((self.harness.paths.evidence_root / "direct-private" / "snapshots").exists())
        receipt = self.authority.authorize_snapshot(manifest)
        snapshot = self.coordinator.take_snapshot(fixture, manifest, receipt["receipt_id"])
        self.assertEqual(snapshot["snapshot_manifest_sha256"], manifest["manifest_digest"])
        self.assertEqual(snapshot["snapshot_receipt_id"], receipt["receipt_id"])
        self.assertTrue(self.confirmation.display_path and self.confirmation.display_path.is_file())

    def test_s5dp_i02_admission_receipt_is_second_purpose_and_exact_snapshot_binding(self) -> None:
        fixture = self._fixture()
        _snapshot_manifest, snapshot_receipt, snapshot = self._snapshot(fixture)
        manifest = self.coordinator.prepare_admission(
            snapshot,
            candidate_treatment="source_only",
            candidate_proposal=None,
            idempotency_key="synthetic-s5dp-i02",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        with self.assertRaises(DirectPrivateError):
            self.coordinator.admit(
                fixture,
                snapshot,
                manifest,
                snapshot_receipt["receipt_id"],
                candidate_proposal=None,
            )
        receipt = self.authority.authorize_admission(manifest)
        result = self.coordinator.admit(
            fixture, snapshot, manifest, receipt["receipt_id"], candidate_proposal=None
        )
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["candidate"])

    def test_s5dp_i03_descriptor_tricks_and_changed_identity_fail_closed(self) -> None:
        with self.assertRaises(DirectPrivateError):
            self.coordinator.create_fixture(
                Path(self.source_temporary.name) / "bad",
                "../invented.md",
                b"VAULT_NEXT_SYNTHETIC_FIXTURE\n# Invented\n",
            )
        fixture = self._fixture()
        source_path = fixture.root / fixture.relative_path
        source_path.unlink()
        os.symlink("elsewhere.md", source_path)
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-pilot",
            authority_record_sha256="a" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_snapshot(manifest)
        with self.assertRaises(DirectPrivateError):
            self.coordinator.take_snapshot(fixture, manifest, receipt["receipt_id"])
        self.assertFalse(self._admission_events())
        fixture = self._fixture(name="hardlink.md")
        _snapshot_manifest, _snapshot_receipt, snapshot = self._snapshot(fixture)
        source_path = fixture.root / fixture.relative_path
        os.link(source_path, source_path.with_name("parallel.md"))
        admission = self.coordinator.prepare_admission(
            snapshot,
            candidate_treatment="source_only",
            candidate_proposal=None,
            idempotency_key="synthetic-s5dp-i03-hardlink",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        admission_receipt = self.authority.authorize_admission(admission)
        with self.assertRaises(DirectPrivateError):
            self.coordinator.admit(
                fixture,
                snapshot,
                admission,
                admission_receipt["receipt_id"],
                candidate_proposal=None,
            )
        invalid_utf8 = self._fixture(name="encoding.md", suffix=b"\xff")
        bad_manifest = self.coordinator.prepare_snapshot(
            invalid_utf8,
            pilot_id="synthetic-s5dp-pilot",
            authority_record_sha256="a" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        bad_receipt = self.authority.authorize_snapshot(bad_manifest)
        with self.assertRaises(DirectPrivateError):
            self.coordinator.take_snapshot(invalid_utf8, bad_manifest, bad_receipt["receipt_id"])

    def test_s5dp_i04_exact_copy_and_structural_extraction_keep_source_out_of_events(self) -> None:
        _fixture, _snapshot, _manifest, _receipt, result = self._complete()
        event = self._admission_events()[0]
        version = event["payload"]["source_version"]
        object_path = self.harness.paths.source_root / "objects" / version["object_ref"]
        content = object_path.read_bytes()
        self.assertEqual(sha256_hex(content), version["content_sha256"])
        self.assertTrue(event["payload"]["extraction"]["chunks"])
        self.assertNotIn("Invented boundary token", str(event["payload"]))
        self.assertEqual(result["source_object_sha256"], version["content_sha256"])

    def test_s5dp_i05_interruption_leaves_only_recoverable_inert_residue(self) -> None:
        fixture = self._fixture()
        _snapshot_manifest, _snapshot_receipt, snapshot = self._snapshot(fixture)
        manifest = self.coordinator.prepare_admission(
            snapshot,
            candidate_treatment="source_only",
            candidate_proposal=None,
            idempotency_key="synthetic-s5dp-i05",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_admission(manifest)

        def fail_after_object(point: str) -> None:
            if point == "after_object":
                raise RuntimeError("synthetic interruption")

        self.coordinator.fault_injector = fail_after_object
        with self.assertRaises(RuntimeError):
            self.coordinator.admit(
                fixture, snapshot, manifest, receipt["receipt_id"], candidate_proposal=None
            )
        self.assertFalse(self._admission_events())
        recovered = self.coordinator.recover_interrupted()
        self.assertEqual(recovered["recovered_admission_ids"], [manifest["admission_id"]])
        object_root = self.harness.paths.source_root / "objects" / "sha256"
        self.assertEqual(list(object_root.glob("*/*")) if object_root.exists() else [], [])
        self.coordinator.fault_injector = None
        fixture = self._fixture(name="after-event.md")
        _sm, _sr, snapshot = self._snapshot(fixture)
        manifest = self.coordinator.prepare_admission(
            snapshot,
            candidate_treatment="source_only",
            candidate_proposal=None,
            idempotency_key="synthetic-s5dp-i05-after-event",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_admission(manifest)

        def fail_after_event(point: str) -> None:
            if point == "after_event":
                raise RuntimeError("synthetic interruption")

        self.coordinator.fault_injector = fail_after_event
        with self.assertRaises(RuntimeError):
            self.coordinator.admit(
                fixture, snapshot, manifest, receipt["receipt_id"], candidate_proposal=None
            )
        self.assertEqual(len(self._admission_events()), 1)
        self.coordinator.fault_injector = None
        self.coordinator.recover_interrupted()
        self.assertEqual(self.coordinator.rebuild_index()["state"], "fresh")

    def test_s5dp_i06_event_binds_versioned_provenance_without_changing_s3b(self) -> None:
        _fixture, snapshot, manifest, receipt, _result = self._complete()
        event = self._admission_events()[0]
        payload = event["payload"]
        self.assertEqual(payload["source_version"]["schema_version"], "2.0")
        self.assertEqual(payload["source_version"]["admission_receipt_id"], receipt["receipt_id"])
        self.assertEqual(payload["source_version"]["snapshot_receipt_id"], snapshot["snapshot_receipt_id"])
        self.assertEqual(payload["admission_manifest_sha256"], manifest["manifest_digest"])
        self.assertEqual(payload["commit_manifest_sha256"], canonical_sha256({
            key: value for key, value in payload.items() if key != "commit_manifest_sha256"
        }))

    def test_s5dp_i07_restart_rebuild_retrieval_and_exact_citation_need_no_fixture_root(self) -> None:
        _fixture, _snapshot, _manifest, _receipt, _result = self._complete()
        first = self.coordinator.retrieve("boundary")
        self.assertEqual(len(first["citations"]), 1)
        citation = first["citations"][0]
        self.assertEqual(self.coordinator.cite(citation)["status"], "complete")
        shutil.rmtree(self.harness.paths.derived_root / "direct-private-retrieval")
        restarted = DirectPrivateAdmissionCoordinator(
            CaseSessionRuntime(self.harness.paths, self.harness.schemas),
            self.harness.schemas,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        self.assertEqual(restarted.rebuild_index()["state"], "fresh")
        self.assertEqual(len(restarted.retrieve("boundary")["citations"]), 1)
        snapshot_receipt = self._admission_events()[0]["payload"]["snapshot_receipt"]
        verifier = DirectPrivateReceiptVerifier(
            self.harness.paths,
            self.authority.authority_root,
            self.harness.schemas,
            lambda: self.harness.current,
        )
        replayed, _manifest = verifier.verify(
            snapshot_receipt["receipt_id"],
            purpose="direct_private_snapshot_scope",
            manifest_digest=self._admission_events()[0]["payload"]["snapshot_result"]["snapshot_manifest_sha256"],
        )
        self.assertEqual(replayed["receipt_id"], snapshot_receipt["receipt_id"])

    def test_s5dp_i08_candidate_treatments_are_exclusive_and_non_authoritative(self) -> None:
        _fixture, _snapshot, _manifest, _receipt, knowledge = self._complete()
        self.assertEqual(knowledge["candidate"]["lifecycle_state"], "provisional")
        fixture = self._fixture(name="skill.md")
        _sm, _sr, snapshot = self._snapshot(fixture)
        _am, _ar, skill = self._admission(fixture, snapshot, treatment="skill_candidate")
        self.assertEqual(skill["candidate"]["lifecycle_state"], "inactive")
        self.assertFalse(hasattr(self.coordinator, "promote_candidate"))
        self.assertFalse(hasattr(self.coordinator, "apply"))

    def test_s5dp_i09_repeat_is_idempotent_and_changed_bytes_form_a_revision(self) -> None:
        fixture = self._fixture()
        _sm, _sr, snapshot = self._snapshot(fixture)
        manifest, receipt, first = self._admission(fixture, snapshot, treatment="source_only")
        repeat = self.coordinator.admit(
            fixture, snapshot, manifest, receipt["receipt_id"], candidate_proposal=None
        )
        self.assertEqual(repeat["status"], "already_imported")
        path = fixture.root / fixture.relative_path
        path.write_bytes(b"VAULT_NEXT_SYNTHETIC_FIXTURE\n# Revised\n\nInvented revised boundary token.\n")
        _sm2, _sr2, snapshot2 = self._snapshot(
            fixture,
            family_id=self._admission_events()[0]["payload"]["source_version"]["source_family_id"],
        )
        _manifest2, _receipt2, second = self._admission(
            fixture, snapshot2, treatment="source_only", key="synthetic-s5dp-i09-revision"
        )
        self.assertNotEqual(first["source_version_id"], second["source_version_id"])
        version = self._admission_events()[-1]["payload"]["source_version"]
        self.assertEqual(version["prior_source_version_id"], first["source_version_id"])

    def test_s5dp_i10_logical_deactivation_hides_only_named_views(self) -> None:
        _fixture, _snapshot, manifest, _receipt, _result = self._complete(treatment="source_only")
        deactivated = self.coordinator.deactivate(
            manifest["admission_id"],
            reason="invented owner withdrawal",
            view_names=["direct_private_retrieval"],
        )
        self.assertEqual(deactivated["status"], "complete")
        self.coordinator.rebuild_index()
        self.assertEqual(self.coordinator.retrieve("boundary")["citations"], [])
        self.assertEqual(len(self._admission_events()), 1)

    def test_s5dp_i11_safe_diagnostics_never_echo_hostile_fixture_content(self) -> None:
        fixture = self._fixture(suffix=b"\nNONLEAK_S5DP_HOSTILE_BODY\n")
        source_path = fixture.root / fixture.relative_path
        source_path.unlink()
        os.symlink("missing.md", source_path)
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-pilot",
            authority_record_sha256="a" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.authority.authorize_snapshot(manifest)
        with self.assertRaises(DirectPrivateError) as captured:
            self.coordinator.take_snapshot(fixture, manifest, receipt["receipt_id"])
        self.assertNotIn("NONLEAK_S5DP_HOSTILE_BODY", str(captured.exception))
        self.assertNotIn("NONLEAK_S5DP_HOSTILE_BODY", str(manifest))

    def test_s5dp_i12_isolation_uses_no_network_or_durable_authority_path(self) -> None:
        with (
            patch.object(socket, "socket", side_effect=AssertionError("socket called")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess called")),
        ):
            fixture, _snapshot, _manifest, _receipt, result = self._complete()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            sha256_hex((fixture.root / fixture.relative_path).read_bytes()),
            self._admission_events()[0]["payload"]["source_version"]["content_sha256"],
        )
        self.assertNotIn("Library/Application Support", str(self.authority.authority_root))
        self.assertFalse((self.harness.paths.root / "data" / "connectors").exists())

    def test_s5dp_i13_restart_validation_and_existing_contracts_remain_separate(self) -> None:
        _fixture, _snapshot, _manifest, _receipt, _result = self._complete()
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertTrue(report.passed, report.issues)
        receipt_root = self.harness.paths.evidence_root / "local-confirmation-v2" / "direct-private"
        self.assertTrue(receipt_root.is_dir())
        self.assertFalse((self.harness.paths.evidence_root / "local-confirmation-v2" / "source-capture").exists())


if __name__ == "__main__":
    unittest.main()
