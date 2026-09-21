"""Hostile tests for the host-neutral ephemeral working-artifact lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from tests.test_private_admission import FakeArchiveAuthority
from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.private_admission import PrivateAdmissionInput, PrivateAdmissionPublisher
from vault_next.private_workspace import PrivateBundleLayout, build_u1_manifest
from vault_next.working_artifact import (
    WorkingArtifactCoordinator,
    WorkingArtifactError,
    clean_review_markdown,
)


class WorkingArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-working-artifact-", dir="/private/tmp")
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "review"
        self.evidence_digest = sha256_hex(b"VAULT_NEXT_HOSTILE_FIXTURE selected evidence")
        self.coordinator = WorkingArtifactCoordinator(
            self.root,
            self.harness.schemas,
            citation_catalog={
                "paragraph:1": self.evidence_digest,
                "paragraph:2": "b" * 64,
                "paragraph:000125": self.evidence_digest,
                "paragraph:000127": "c" * 64,
                "paragraph:000131": "d" * 64,
            },
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        self.provenance = ({"ref": "source_version_invented", "digest": self.evidence_digest},)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def create(self, *, kind: str = "meeting_debrief", key: str = "create-1"):
        return self.coordinator.create(
            artifact_kind=kind,
            display_alias=f"Invented {kind}",
            markdown="# Invented result\n\nCited fixture claim.\n",
            citations=("paragraph:1",),
            provenance=self.provenance,
            idempotency_key=key,
        )

    def test_wa_t01_supported_outputs_are_separate_ephemeral_markdown(self) -> None:
        kinds = (
            "meeting_debrief", "meeting_continuity", "meeting_preparation", "deep_dive",
            "decision", "knowledge", "outbound",
        )
        views = [self.create(kind=kind, key=f"create-{kind}") for kind in kinds]
        self.assertEqual(len({view.artifact_id for view in views}), len(kinds))
        self.assertEqual(len({view.markdown_path for view in views}), len(kinds))
        paths = (view.markdown_path for view in views)
        self.assertTrue(all(path.is_file() and path.is_relative_to(self.root) for path in paths))
        for view in views:
            rendered = view.markdown_path.read_text()
            self.assertTrue(rendered.startswith("# Invented result"))
            self.assertNotIn("vault-next-generated", rendered)
            self.assertNotIn("paragraph:", rendered)
            stem = view.markdown_path.with_suffix("")
            self.assertTrue(stem.with_suffix(".metadata.json").is_file())
            self.assertTrue(stem.with_suffix(".citations.md").is_file())
        manifest = self.coordinator.verify()
        self.assertTrue(manifest["no_automatic_persistence"])
        self.assertEqual(manifest["u1_states"], ["review_copy", "final"])
        self.assertEqual(manifest["u2_state"], "released")

    def test_wa_t02_revisions_are_immutable_exact_and_idempotent(self) -> None:
        first = self.create()
        original = first.markdown_path.read_bytes()
        resumed = WorkingArtifactCoordinator(
            self.root,
            self.harness.schemas,
            citation_catalog=self.coordinator.citation_catalog,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            resume=True,
        )
        second = resumed.revise(
            first.artifact_id,
            prior_revision_id=first.revision_id,
            markdown="# Invented result\n\nMore granular cited fixture claim.\n",
            citations=("paragraph:1", "paragraph:2"),
            change_summary="Add invented detail",
            idempotency_key="revise-1",
        )
        replay = resumed.revise(
            first.artifact_id,
            prior_revision_id=first.revision_id,
            markdown="# Invented result\n\nMore granular cited fixture claim.\n",
            citations=("paragraph:1", "paragraph:2"),
            change_summary="Add invented detail",
            idempotency_key="revise-1",
        )
        self.assertEqual(replay, second)
        self.assertEqual(first.markdown_path.read_bytes(), original)
        self.assertNotEqual(first.markdown_path, second.markdown_path)
        with self.assertRaises(WorkingArtifactError):
            resumed.revise(
                first.artifact_id,
                prior_revision_id=first.revision_id,
                markdown="# Conflicting retry\n",
                citations=("paragraph:1",),
                change_summary="Conflicting retry",
                idempotency_key="revise-1",
            )
        with self.assertRaises(WorkingArtifactError):
            resumed.revise(
                first.artifact_id,
                prior_revision_id=first.revision_id,
                markdown="# Stale new attempt\n",
                citations=("paragraph:1",),
                change_summary="Stale",
                idempotency_key="revise-stale",
            )

    def test_wa_t03_citation_and_provenance_bindings_fail_closed(self) -> None:
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.create(
                artifact_kind="meeting_debrief",
                display_alias="Bad citation",
                markdown="# Bad\n",
                citations=("paragraph:missing",),
                provenance=self.provenance,
                idempotency_key="bad-citation",
            )
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.create(
                artifact_kind="meeting_debrief",
                display_alias="Bad provenance",
                markdown="# Bad\n",
                citations=("paragraph:1",),
                provenance=({"ref": "selected", "digest": "not-a-digest"},),
                idempotency_key="bad-provenance",
            )
        view = self.create()
        manifest = json.loads(self.coordinator.manifest_path.read_text())
        manifest["artifacts"][0]["revisions"][0]["citation_bindings"][0]["evidence_sha256"] = "c" * 64
        material = {**manifest, "manifest_digest": "0" * 64}
        manifest["manifest_digest"] = canonical_sha256(material)
        self.coordinator.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.verify()
        self.assertTrue(view.markdown_path.exists())

    def test_wa_t04_tamper_unsafe_root_and_symlink_fail_closed(self) -> None:
        view = self.create()
        view.markdown_path.write_text("tampered", encoding="utf-8")
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.verify()
        with self.assertRaises(WorkingArtifactError):
            WorkingArtifactCoordinator(
                Path("/Users/elena/vault-next/not-disposable"),
                self.harness.schemas,
                citation_catalog={"paragraph:1": self.evidence_digest},
            )
        target = self.parent / "target"
        target.mkdir()
        link = self.parent / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(WorkingArtifactError):
            WorkingArtifactCoordinator(
                link / "review",
                self.harness.schemas,
                citation_catalog={"paragraph:1": self.evidence_digest},
            )

    def test_wa_t05_u1_selection_binds_exact_revision_and_u2_is_isolated(self) -> None:
        view = self.create()
        review_copy = self.coordinator.select_for_u1(
            view.artifact_id, view.revision_id, target_state="review_copy"
        )
        final = self.coordinator.select_for_u1(
            view.artifact_id, view.revision_id, target_state="final"
        )
        self.assertNotEqual(review_copy.record["selection_digest"], final.record["selection_digest"])
        self.assertEqual(final.record["revision_digest"], view.revision_digest)
        self.assertEqual(final.record["citation_bindings"][0]["evidence_sha256"], self.evidence_digest)
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.select_for_u1(
                view.artifact_id, view.revision_id, target_state="released"
            )

    def test_wa_t06_selected_revision_uses_unchanged_u1_publication(self) -> None:
        view = self.create()
        selection = self.coordinator.select_for_u1(
            view.artifact_id, view.revision_id, target_state="final"
        )
        item = self.coordinator.workspace_item(selection)
        source = b"VAULT_NEXT_HOSTILE_FIXTURE selected evidence"
        citation_text = (("paragraph:1", "Invented selected evidence."),)
        package = {
            "schema_version": "1.0",
            "candidate_id": self.harness.ids.new("skill_candidate"),
            "family": "meeting_workflow",
            "package_version": "1.0",
            "ingress_profiles": ["plain_text"],
            "required_sections": ["claims"],
            "prohibitions": ["no_activation"],
            "lifecycle": "inactive",
        }
        relation = {
            "assertion_id": self.harness.ids.new("relationship_ledger"),
            "origin_version_id": self.harness.ids.new("source_version"),
            "target_version_id": view.revision_id,
            "type": "debriefs",
            "source_anchor": "paragraph:1",
            "state": "reported",
        }
        artifact = {
            "schema_version": "1.0",
            "artifact_kind": "working_artifact_selection",
            "u0_result_sha256": view.content_sha256,
            "working_artifact_selection": selection.record,
            "citation_text": [list(row) for row in citation_text],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item)],
        }
        manifest = build_u1_manifest(
            ids=self.harness.ids,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"),
            ingress_envelope_sha256="1" * 64,
            source_sha256=sha256_hex(source),
            source_size=len(source),
            u0_result_sha256=view.content_sha256,
            artifact_sha256=canonical_sha256(artifact),
            candidate_package_sha256=canonical_sha256(package),
            relationship_ledger_sha256=canonical_sha256([relation]),
            profile_id="plain_text",
            safe_label="invented.txt",
            citations=("paragraph:1",),
            schemas=self.harness.schemas,
        )
        packet = PrivateAdmissionInput(
            manifest=manifest,
            source_bytes=source,
            source_version={
                "source_version_id": relation["origin_version_id"],
                "content_sha256": sha256_hex(source),
                "byte_count": len(source),
            },
            artifact=artifact,
            candidate_package=package,
            relationship_assertions=(relation,),
            citation_text=citation_text,
            workspace_items=(item,),
        )
        bundle = self.parent / "bundle"
        bundle.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(bundle, create=True)
        authority = FakeArchiveAuthority(self.harness)
        publisher = PrivateAdmissionPublisher(
            bundle,
            self.harness.schemas,
            authority,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        receipt = authority.authorize_chat_first_u1_save(manifest)
        self.assertEqual(publisher.publish(packet, receipt["receipt_id"]).status, "complete")
        self.assertEqual(publisher.verify_restart()["event_count"], 1)
        page = next((bundle / "workspace" / "Meetings").rglob("*.md"))
        self.assertIn("Status: final.", page.read_text())

    def test_wa_t07_evaluation_gates_remain_independent_and_non_authoritative(self) -> None:
        view = self.create()
        review = self.coordinator.evaluation_record(
            view.artifact_id,
            view.revision_id,
            platform_integrity="pass",
            workflow_experience="partial",
            artifact_disposition="revise",
            skill_candidate_state="needs_refinement",
            skill_candidate_version="meeting-debrief/0.3.0",
        )
        self.assertEqual(review["platform_integrity"], "pass")
        self.assertEqual(review["workflow_experience"], "partial")
        self.assertEqual(review["artifact_disposition"], "revise")
        self.assertFalse(review["activation_authority"])

    def test_wa_t08_raw_paragraph_references_move_to_companion_without_claim_change(self) -> None:
        raw = (
            "# Meeting record\n\n"
            "- Obtain written confirmation before implementation. "
            "(paragraph:000125, paragraph:000127)\n"
            "- Preserve this claim exactly. (paragraph:000131)\n"
        )
        citations = (
            "paragraph:000125",
            "paragraph:000127",
            "paragraph:000131",
            "paragraph:1",
        )
        cleaned = clean_review_markdown(raw, citations)
        self.assertEqual(
            cleaned,
            "# Meeting record\n\n"
            "- Obtain written confirmation before implementation.\n"
            "- Preserve this claim exactly.\n",
        )
        view = self.coordinator.create(
            artifact_kind="meeting_debrief",
            display_alias="Clean record",
            markdown=cleaned,
            citations=citations,
            provenance=self.provenance,
            idempotency_key="clean-record",
        )
        self.assertNotIn("paragraph:", view.markdown_path.read_text())
        companion = view.markdown_path.with_suffix("").with_suffix(".citations.md").read_text()
        self.assertIn("paragraph:000125", companion)
        self.assertIn("paragraph:1", companion)
        self.assertIn(self.evidence_digest, companion)

    def test_wa_t09_sidecar_tamper_fails_closed(self) -> None:
        view = self.create()
        metadata = view.markdown_path.with_suffix("").with_suffix(".metadata.json")
        original_metadata = metadata.read_bytes()
        metadata.write_text("{}", encoding="utf-8")
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.verify()
        metadata.write_bytes(original_metadata)
        evidence = view.markdown_path.with_suffix("").with_suffix(".citations.md")
        evidence.write_text("# Substituted evidence\n", encoding="utf-8")
        with self.assertRaises(WorkingArtifactError):
            self.coordinator.verify()


if __name__ == "__main__":
    unittest.main()
