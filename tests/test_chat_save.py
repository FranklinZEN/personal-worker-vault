"""S5CF-T07–T10/T12 tests for the optional synthetic U1 Chat-first save path."""

from __future__ import annotations

from datetime import timedelta
import unittest

from tests.chat_fixtures import (
    ExactDigestConfirmation,
    FixtureMeetingDebriefAnalyzer,
    active_runtime,
    ingress_coordinator,
    save_authority,
    synthetic_text,
    transport,
)
from tests.helpers import Harness
from vault_next.chat_save import ChatSaveCoordinator, ChatSaveDeclined, ChatSaveError
from vault_next.preservation import SyntheticPreservationCoordinator
from vault_next.runtime import CaseSessionRuntime
from vault_next.validator import KernelValidator


class ChatSaveTests(unittest.TestCase):
    """Each U1 test uses one fresh temporary runtime and an injected fake exact-digest UI."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime, self.session_id = active_runtime(self.harness)
        self.ingress, self.router, self.analyzer = ingress_coordinator(self.harness)
        self.execution = self.ingress.run(transport("paste"))
        self.authority, self.confirmation = save_authority(self.runtime, self.harness)
        self.saver = ChatSaveCoordinator(
            self.runtime,
            self.harness.schemas,
            self.router,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.harness.close()

    def _manifest_and_receipt(self, execution=None) -> tuple[dict, dict]:
        selected = execution or self.execution
        manifest = self.saver.prepare(
            selected,
            session_id=self.session_id,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        return manifest, self.authority.authorize(manifest)

    def test_s5cf_t07_one_complete_confirmation_is_sufficient_for_atomic_save(self) -> None:
        manifest, receipt = self._manifest_and_receipt()
        result = self.saver.save(self.execution, manifest, receipt["receipt_id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(self.confirmation.display_paths), 1)
        self.assertEqual(result["save"]["save_id"], manifest["save_id"])
        self.assertEqual(len(self.saver._save_events()), 1)

    def test_s5cf_t08_decline_binding_expiry_display_and_precommit_faults_stay_invisible(self) -> None:
        declined = ExactDigestConfirmation(response="incorrect")
        authority, _ui = save_authority(self.runtime, self.harness, declined)
        manifest = self.saver.prepare(
            self.execution,
            session_id=self.session_id,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        with self.assertRaises(ChatSaveDeclined):
            authority.authorize(manifest)
        self.assertEqual(self.saver._save_events(), [])

        mutating = ExactDigestConfirmation(mutate_display=True)
        authority, _ui = save_authority(self.runtime, self.harness, mutating)
        mutated_manifest = self.saver.prepare(
            self.execution,
            session_id=self.session_id,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        with self.assertRaises(ChatSaveError):
            authority.authorize(mutated_manifest)
        self.assertEqual(self.saver._save_events(), [])

        wrong_runtime = dict(manifest)
        wrong_runtime["runtime_id"] = "f" * 64
        wrong_runtime["manifest_digest"] = "0" * 64
        with self.assertRaises(ChatSaveError):
            self.saver.save(self.execution, wrong_runtime, "receipt_missing")

        expiring_manifest = self.saver.prepare(
            self.execution,
            session_id=self.session_id,
            expires_at=self.harness.current + timedelta(seconds=1),
        )
        self.harness.current += timedelta(seconds=2)
        with self.assertRaises(ChatSaveDeclined):
            self.authority.authorize(expiring_manifest)
        self.assertEqual(self.saver._save_events(), [])

        def interrupted(point: str) -> None:
            if point == "after_objects":
                raise RuntimeError("invented interruption")

        faulting = ChatSaveCoordinator(
            self.runtime,
            self.harness.schemas,
            self.router,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            fault_injector=interrupted,
        )
        fault_manifest, fault_receipt = self._manifest_and_receipt()
        with self.assertRaises(RuntimeError):
            faulting.save(self.execution, fault_manifest, fault_receipt["receipt_id"])
        self.assertEqual(self.saver._save_events(), [])
        self.assertEqual(faulting.recover()["recovered_stages"], 1)

    def test_s5cf_t09_restart_reverifies_receipt_save_and_rebuilds_without_transport(self) -> None:
        manifest, receipt = self._manifest_and_receipt()
        completed = self.saver.save(self.execution, manifest, receipt["receipt_id"])
        fresh_runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id="synthetic-s5cf-restart",
        )
        fresh_authority, _ui = save_authority(fresh_runtime, self.harness, self.confirmation)
        fresh = ChatSaveCoordinator(
            fresh_runtime,
            self.harness.schemas,
            self.router,
            fresh_authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        verification = fresh.verify_restart()
        citations = fresh.retrieve("Invented")
        self.assertEqual(completed["save"]["event_id"], fresh._save_events()[0]["event_id"])
        self.assertEqual(verification["save_count"], 1)
        self.assertTrue(citations["citations"])

    def test_s5cf_t10_exact_rerun_is_idempotent_but_changed_source_method_or_result_versions(self) -> None:
        manifest, receipt = self._manifest_and_receipt()
        self.assertEqual(self.saver.save(self.execution, manifest, receipt["receipt_id"])["status"], "complete")
        self.assertEqual(self.saver.save(self.execution, manifest, receipt["receipt_id"])["status"], "already_saved")

        changed_source = self.ingress.run(
            transport("attachment", synthetic_text() + b"\nInvented changed source.\n")
        )
        source_manifest, source_receipt = self._manifest_and_receipt(changed_source)
        self.assertEqual(
            self.saver.save(changed_source, source_manifest, source_receipt["receipt_id"])["status"],
            "complete",
        )

        alternate, _router, _analyzer = ingress_coordinator(
            self.harness,
            FixtureMeetingDebriefAnalyzer(variant="result-change"),
            method_version="0.1.1",
        )
        changed_method_and_result = alternate.run(transport("local_file"))
        method_manifest, method_receipt = self._manifest_and_receipt(changed_method_and_result)
        self.assertEqual(
            self.saver.save(
                changed_method_and_result,
                method_manifest,
                method_receipt["receipt_id"],
            )["status"],
            "complete",
        )
        self.assertEqual(len(self.saver._save_events()), 3)

    def test_s5cf_t12_new_event_is_kernel_valid_and_preserves_prior_synthetic_boundaries(self) -> None:
        manifest, receipt = self._manifest_and_receipt()
        self.saver.save(self.execution, manifest, receipt["receipt_id"])
        report = KernelValidator(self.harness.paths, self.harness.schemas).validate()
        self.assertTrue(report.passed)
        event_types = {event["event_type"] for event in self.saver._save_events()}
        self.assertEqual(event_types, {"chat_ingress.save_committed"})
        self.assertFalse((self.harness.paths.source_root / "objects").exists())
        case_id = self.runtime._session(self.session_id).case_id
        preservation = SyntheticPreservationCoordinator(self.harness.paths, self.harness.schemas)
        envelope_root = self.harness.runtime_root.parent / "s5cf-envelope"
        sealed = preservation.seal([case_id], envelope_root)
        roles = {item["role"] for item in sealed.manifest["files"]}
        self.assertTrue({"chat_ingress_sources", "chat_ingress_artifacts"}.issubset(roles))
