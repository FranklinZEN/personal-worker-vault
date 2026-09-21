"""F1-T01–T13 and W1-T01–T09 hostile-synthetic private-foundation tests."""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.chat_fixtures import (
    ExactDigestConfirmation,
    active_runtime,
    ingress_coordinator,
    minimal_docx,
    transport,
)
from tests.helpers import Harness
from vault_next.errors import ValidationError
from vault_next.private_foundation import (
    PrivateFoundationCoordinator,
    PrivateFoundationDeclined,
    PrivateFoundationError,
    SyntheticDirectFixture,
    SyntheticExistingV2Authority,
    validate_synthetic_bundle_layout,
)


class PrivateFoundationTests(unittest.TestCase):
    """Every assertion uses invented material, a fresh runtime, and an injected fake v2 UI."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime, self.session_id = active_runtime(self.harness, correlation_id="synthetic-f1")
        self.ingress, self.router, _analyzer = ingress_coordinator(self.harness)
        self.execution = self.ingress.run(transport("paste"))
        self.ui = ExactDigestConfirmation()
        self.authority = SyntheticExistingV2Authority(
            self.runtime,
            self.harness.schemas,
            self.ui,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        self.coordinator = PrivateFoundationCoordinator(
            self.runtime,
            self.harness.schemas,
            self.router,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.harness.close()

    def _package(self, lifecycle: str = "inactive") -> dict:
        return self.coordinator.meeting_candidate_package(lifecycle=lifecycle)

    def _relations(self) -> list[dict]:
        return [
            {
                "assertion_id": self.harness.ids.new("relationship_ledger"),
                "origin_version_id": "source-version-invented",
                "target_version_id": "meeting-version-invented",
                "type": "debriefs",
                "source_anchor": "paragraph:1",
                "state": "reported",
            }
        ]

    def _proposal(self, execution=None, package=None, relations=None) -> tuple[dict, dict, list[dict]]:
        package = package or self._package()
        relations = relations if relations is not None else self._relations()
        manifest = self.coordinator.prepare_chat_save(
            execution or self.execution,
            session_id=self.session_id,
            candidate_package=package,
            relationships=relations,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        return manifest, package, relations

    def _admit(self, execution=None) -> tuple[dict, dict, dict, list[dict]]:
        manifest, package, relations = self._proposal(execution)
        receipt = self.authority.authorize(manifest)
        result = self.coordinator.admit_chat(
            execution or self.execution,
            manifest,
            receipt["receipt_id"],
            candidate_package=package,
            relationships=relations,
        )
        return result, manifest, package, relations

    def test_f1_t01_parallel_contracts_reject_each_other(self) -> None:
        manifest, _package, _relations = self._proposal()
        with self.assertRaises(ValidationError):
            self.harness.schemas.require("chat-save-manifest", manifest)
        synthetic = dict(manifest)
        synthetic["synthetic_only"] = True
        with self.assertRaises(ValidationError):
            self.harness.schemas.require("private-foundation-manifest", synthetic)

    def test_f1_t02_t03_exact_proposal_display_replay_and_mutation_are_fenced(self) -> None:
        manifest, package, relations = self._proposal()
        receipt = self.authority.authorize(manifest)
        changed = self.ingress.run(
            transport("paste", b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nchanged invented source\n")
        )
        with self.assertRaises(PrivateFoundationError):
            self.coordinator.admit_chat(
                changed,
                manifest,
                receipt["receipt_id"],
                candidate_package=package,
                relationships=relations,
            )
        result = self.coordinator.admit_chat(
            self.execution,
            manifest,
            receipt["receipt_id"],
            candidate_package=package,
            relationships=relations,
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            self.coordinator.admit_chat(
                self.execution,
                manifest,
                receipt["receipt_id"],
                candidate_package=package,
                relationships=relations,
            )["status"],
            "already_admitted",
        )
        declined_ui = ExactDigestConfirmation(response="wrong")
        declined = SyntheticExistingV2Authority(
            self.runtime,
            self.harness.schemas,
            declined_ui,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        rejected_manifest, _p, _r = self._proposal()
        with self.assertRaises(PrivateFoundationDeclined):
            declined.authorize(rejected_manifest)

    def test_f1_t04_two_direct_private_receipts_fence_observation_and_copy(self) -> None:
        fixture = SyntheticDirectFixture(
            "invented.md",
            "text/markdown",
            ".md",
            b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n# Invented\n",
            "a" * 64,
        )
        snapshot_manifest = self.coordinator.prepare_direct_snapshot(
            fixture, expires_at=self.harness.current + timedelta(minutes=5)
        )
        self.assertEqual(fixture.reads, [])
        with self.assertRaises(PrivateFoundationError):
            self.coordinator.observe_direct_snapshot(fixture, snapshot_manifest, "receipt_missing")
        snapshot_receipt = self.authority.authorize(snapshot_manifest)
        snapshot = self.coordinator.observe_direct_snapshot(
            fixture, snapshot_manifest, snapshot_receipt["receipt_id"]
        )
        self.assertEqual(fixture.reads, ["observed"])
        admission = self.coordinator.prepare_direct_admission(
            snapshot,
            candidate_package=self._package(),
            relationships=self._relations(),
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        self.assertEqual(admission["purpose"], "direct_private_source_admission")
        self.assertNotEqual(
            snapshot_receipt["receipt_id"], self.authority.authorize(admission)["receipt_id"]
        )

    def test_f1_t05_t06_profiles_and_layout_fail_closed(self) -> None:
        markdown = self.ingress.run(
            transport(
                "attachment",
                b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\n# Invented markdown\n",
                label="invented.md",
                media_type="text/markdown",
                extension=".md",
            )
        )
        docx = self.ingress.run(
            transport(
                "local_file",
                minimal_docx(),
                label="invented.docx",
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                extension=".docx",
            )
        )
        self.assertEqual(
            {
                self.execution.evidence.record()["profile_id"],
                markdown.evidence.record()["profile_id"],
                docx.evidence.record()["profile_id"],
            },
            {"plain_text", "markdown_text", "docx_wordprocessingml"},
        )
        with TemporaryDirectory(prefix="vault-next-f1-layout-", dir="/private/tmp") as temporary:
            root = Path(temporary)
            bundle, stage = root / "bundle", root / "stage"
            bundle.mkdir(mode=0o700)
            stage.mkdir(mode=0o700)
            os.chmod(bundle, 0o700)
            os.chmod(stage, 0o700)
            validate_synthetic_bundle_layout(bundle, stage)
            with self.assertRaises(PrivateFoundationError):
                validate_synthetic_bundle_layout(bundle, bundle / "nested")
            os.chmod(stage, 0o755)
            with self.assertRaises(PrivateFoundationError):
                validate_synthetic_bundle_layout(bundle, stage)

    def test_f1_t07_t09_t10_t11_one_event_restart_idempotence_and_deactivation(self) -> None:
        result, manifest, package, relations = self._admit()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [event["event_type"] for event in self.coordinator._events("private_admission.recorded")],
            ["private_admission.recorded"],
        )
        self.assertEqual(self.coordinator.verify_restart()["status"], "complete")
        self.assertEqual(
            self.coordinator.admit_chat(
                self.execution,
                manifest,
                self.authority.authorize(manifest)["receipt_id"],
                candidate_package=package,
                relationships=relations,
            )["status"],
            "already_admitted",
        )
        changed = self.ingress.run(
            transport("paste", b"VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE\nnew invented version\n")
        )
        self.assertEqual(self._admit(changed)[0]["status"], "complete")
        event = self.coordinator.deactivate(self.session_id, manifest["admission_id"])
        self.assertEqual(event["event_type"], "private_admission.deactivated")
        self.assertEqual(len(self.coordinator._events("private_admission.recorded")), 2)

    def test_f1_t08_t12_t13_fault_recovery_and_safe_diagnostics(self) -> None:
        def interrupt(point: str) -> None:
            if point == "after_objects":
                raise RuntimeError("invented interruption")

        faulting = PrivateFoundationCoordinator(
            self.runtime,
            self.harness.schemas,
            self.router,
            self.authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            fault_injector=interrupt,
        )
        manifest, package, relations = self._proposal()
        receipt = self.authority.authorize(manifest)
        with self.assertRaises(RuntimeError):
            faulting.admit_chat(
                self.execution,
                manifest,
                receipt["receipt_id"],
                candidate_package=package,
                relationships=relations,
            )
        self.assertEqual(faulting._events("private_admission.recorded"), [])
        self.assertEqual(faulting.recover()["recovered_stages"], 1)
        with self.assertRaises(PrivateFoundationError) as captured:
            faulting._require_fixture(
                SyntheticDirectFixture("bad", "text/plain", ".txt", b"", "b" * 64)
            )
        self.assertNotIn("VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE", str(captured.exception))

    def test_w1_t01_through_t09_bounded_granular_candidate_rehearsal(self) -> None:
        package = self._package()
        packet = []
        for index, section in enumerate(
            (
                "topic_chronology",
                "claims",
                "decisions",
                "proposals",
                "disagreements",
                "commitments",
                "dependencies",
                "risks",
                "questions",
            ),
            start=1,
        ):
            packet.append(
                {
                    "source_version_id": f"invented-source-{index}",
                    "anchor": f"paragraph:{index}",
                    "section": section,
                    "statement": f"Invented {section} statement.",
                    "relation_type": "reports_decision" if section == "decisions" else "summarizes",
                    "target_version_id": "invented-meeting",
                    "state": "reported",
                }
            )
        result = self.coordinator.rehearse_meeting_workflow(package, packet)
        self.assertEqual(result["candidate_lifecycle"], "needs_refinement")
        self.assertEqual(len(result["relationship_assertions"]), 9)
        self.assertTrue(
            all("citation" in item for values in result["sections"].values() for item in values)
        )
        self.assertFalse(hasattr(self.coordinator, "activate"))
        self.assertFalse(hasattr(self.coordinator, "apply"))
        with self.assertRaises(PrivateFoundationError):
            self.coordinator.rehearse_meeting_workflow(package, packet + [packet[0]])
