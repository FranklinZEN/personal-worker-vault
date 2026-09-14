"""Hostile synthetic S4-D selective-preservation rehearsal tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests import test_knowledge_library as _knowledge_library
from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.committee_evaluation import SyntheticCommitteeEvaluationCoordinator
from vault_next.errors import ValidationError
from vault_next.evidence import SyntheticEvidenceStore
from vault_next.knowledge_library import SyntheticKnowledgeLibraryCoordinator
from vault_next.preservation import SyntheticPreservationCoordinator
from vault_next.runtime import CaseSessionRuntime


class SyntheticPreservationTests(unittest.TestCase):
    """Use only one invented case and fresh disposable roots for every rehearsal."""

    def setUp(self) -> None:
        self.fixtures = _knowledge_library.SyntheticKnowledgeLibraryTests("runTest")
        self.fixtures.setUp()
        self.runtime = self.fixtures.runtime
        self.paths = self.fixtures.harness.paths
        self.case_id = self.fixtures.case_id
        self.session_id = self.fixtures.session_id
        self.library = self.fixtures.library
        self.scratch = TemporaryDirectory(prefix="vault-next-s4d-")
        self.scratch_root = Path(self.scratch.name)
        self.source = self.fixtures._source(b"# Invented Atlas\nA reversible blue constraint.")
        self.candidate = self.library.record_candidate(
            self.session_id, self.fixtures._proposal(self.source)
        )["candidate"]
        self.candidate_id = self.candidate["candidate_id"]
        SyntheticEvidenceStore(
            self.paths,
            self.fixtures.harness.schemas,
            id_factory=self.fixtures.harness.ids,
            clock=self.fixtures.harness.tick,
            correlation_id="synthetic-s4d-evidence",
        ).register(
            case_id=self.case_id,
            session_id=self.session_id,
            content=b"Invented preservation evidence only.",
            display_name="invented-s4d-evidence.txt",
        )
        self.work_item_id = self.fixtures.harness.ids.new("work_item")
        self.runtime.record_reasoning_event(
            self.session_id,
            "work_item.recorded",
            {
                "work_item_id": self.work_item_id,
                "statement": "Invented preserved work item.",
                "status": "open",
                "source_kind": "owner_instruction",
                "priority": "normal",
                "due_on": None,
                "next_review_on": None,
                "blocker": None,
                "explicit_confirmation": True,
            },
            subject_refs=[self.work_item_id],
            actor={"type": "owner", "id": "invented-owner"},
        )
        self.committee = SyntheticCommitteeEvaluationCoordinator(self.runtime)
        self.run_id = self.committee.create_run(self.session_id, self._packet())["committee_run_id"]
        self.first = self.committee.record_first_pass(
            self.session_id, self.run_id, self._finding("evidence_reader", "supports")
        )
        self.second = self.committee.record_first_pass(
            self.session_id, self.run_id, self._finding("counter_reader", "challenges")
        )
        self.committee.synthesize(
            self.session_id,
            self.run_id,
            {
                "recommendation": "Keep the invented question open.",
                "unaddressed_gaps": ["No real-world evidence exists."],
                "change_of_mind_condition": "New invented fixture evidence is required.",
                "deltas": [{"kind": "conflict_retained", "finding_id": self.first["finding_id"]}],
            },
        )
        self.coordinator = SyntheticPreservationCoordinator(
            self.paths, self.fixtures.harness.schemas
        )

    def tearDown(self) -> None:
        self.scratch.cleanup()
        self.fixtures.tearDown()

    def _packet(self) -> dict:
        marks = self.library.watermarks([self.candidate_id])
        return {
            "question": "What does the invented Atlas exercise preserve?",
            "purpose": "Compare invented fixture findings only.",
            "execution_mode": "fixture_supplied_sequential",
            "role_cards": [
                {
                    "role_id": "evidence_reader",
                    "lens": "Trace invented evidence.",
                    "allowed_claim_categories": ["evidence"],
                    "non_purpose": ["No authority."],
                },
                {
                    "role_id": "counter_reader",
                    "lens": "Trace invented limitations.",
                    "allowed_claim_categories": ["counterevidence"],
                    "non_purpose": ["No authority."],
                },
            ],
            "s4a_baseline": {
                "package_id": "skill_evidence_mapping",
                "version": "0.1.0",
                "digest": "a" * 64,
                "baseline_digest": "b" * 64,
                "candidate_ids": [self.candidate_id],
            },
            "s4b_scope": {
                "candidate_ids": [self.candidate_id],
                "candidate_watermark": marks["candidate_watermark"],
                "source_watermark": marks["source_watermark"],
                "search_result_digest": canonical_sha256({"invented": "s4d"}),
                "confidentiality_space": "synthetic-atlas",
            },
            "first_pass_budget_bytes": 512,
            "challenge_budget_bytes": 512,
            "synthesis_budget_bytes": 512,
        }

    def _finding(self, role_id: str, conclusion: str) -> dict:
        return {
            "role_id": role_id,
            "claim_id": "claim-blue",
            "conclusion": conclusion,
            "statement": f"Invented {role_id} says {conclusion}.",
            "evidence_candidate_ids": [self.candidate_id],
            "limitations": ["Invented fixture only."],
        }

    def _seal(self, name: str = "envelope") -> Path:
        return self.coordinator.seal([self.case_id], self.scratch_root / name).envelope_root

    def test_s4d_t01_selective_manifest_binds_s1_to_s4c_fixture_state(self) -> None:
        envelope = self._seal()
        manifest = json.loads((envelope / "manifest.json").read_bytes())
        self.assertEqual([self.case_id], manifest["case_ids"])
        self.assertEqual(manifest["manifest_sha256"], canonical_sha256({
            key: value for key, value in manifest.items() if key != "manifest_sha256"
        }))
        self.assertEqual({"semantic", "sources", "evidence"}, {item["role"] for item in manifest["files"]})
        self.assertTrue(
            any(
                event["event_type"] == "committee.dissent_recorded"
                for event in self.runtime.semantic.read_all()
            )
        )

    def test_s4d_t02_envelope_rejects_unknown_case_and_interrupted_stage(self) -> None:
        with self.assertRaises(ValidationError):
            self.coordinator.seal(["case_unknown"], self.scratch_root / "unknown")
        target = self.scratch_root / "interrupted"
        stage = target.with_name(".interrupted.s4d-stage")
        stage.mkdir()
        with self.assertRaises(ValidationError):
            self.coordinator.seal([self.case_id], target)
        self.assertFalse(target.exists())

        source_object = (
            self.paths.source_root
            / "objects"
            / f"sha256/{self.source['content_sha256'][:2]}/{self.source['content_sha256']}"
        )
        outside = self.scratch_root / "outside.txt"
        outside.write_bytes(b"hostile outside fixture")
        source_object.unlink()
        source_object.symlink_to(outside)
        with self.assertRaises(ValidationError):
            self.coordinator.seal([self.case_id], self.scratch_root / "symlink")

    def test_s4d_t03_clean_restore_replays_exact_selected_state(self) -> None:
        envelope = self._seal()
        result = self.coordinator.restore(envelope, self.scratch_root / "restored")
        restarted = CaseSessionRuntime(
            self.paths.__class__(Path(result["destination_root"]), protected_roots=self.paths.protected_roots),
            self.fixtures.harness.schemas,
        )
        self.assertEqual(self.runtime.semantic.read_all(), restarted.semantic.read_all())
        self.assertEqual("preserved", result["status"])
        self.assertEqual("unavailable: no authority material is preserved", result["authority"])

    def test_s4d_t04_restore_never_reads_unavailable_original_root(self) -> None:
        envelope = self._seal()
        moved = self.scratch_root / "unavailable-original"
        os.replace(self.paths.root, moved)
        result = self.coordinator.restore(envelope, self.scratch_root / "restored")
        self.assertEqual("preserved", result["status"])
        self.assertFalse(self.paths.root.exists())

    def test_s4d_t05_derived_state_is_explicitly_rebuild_required(self) -> None:
        envelope = self._seal()
        result = self.coordinator.restore(envelope, self.scratch_root / "restored")
        root = Path(result["destination_root"])
        self.assertFalse((root / "data" / "derived").exists())
        self.assertEqual(
            [
                "source-fts5",
                "knowledge-library-fts5",
                "chat-ingress-fts5",
                "readable-projections",
            ],
            result["rebuild_required"],
        )
        restarted = CaseSessionRuntime(
            self.paths.__class__(root, protected_roots=self.paths.protected_roots),
            self.fixtures.harness.schemas,
        )
        library = SyntheticKnowledgeLibraryCoordinator(restarted, self.fixtures.harness.schemas)
        marks = library.watermarks([self.candidate_id])
        rebuilt = library.rebuild(
            self.session_id,
            {
                "purpose": "learning",
                "candidate_ids": [self.candidate_id],
                "record_kinds": ["knowledge_candidate"],
                "confidentiality_space": "synthetic-atlas",
                "expected_candidate_watermark": marks["candidate_watermark"],
                "expected_source_watermark": marks["source_watermark"],
                "query": "reversible",
                "response_budget": 4,
                "rebuild_nonce": "s4d-rebuild",
            },
        )
        self.assertEqual("complete", rebuilt["status"])

    def test_s4d_t06_tampered_envelope_never_publishes_destination(self) -> None:
        envelope = self._seal()
        entry = json.loads((envelope / "manifest.json").read_bytes())["files"][0]
        path = envelope / "files" / entry["relative_path"]
        path.write_bytes(b"hostile tamper")
        destination = self.scratch_root / "restored"
        with self.assertRaises(ValidationError):
            self.coordinator.restore(envelope, destination)
        self.assertFalse(destination.exists())

    def test_s4d_t06_manifest_path_escape_never_publishes_destination(self) -> None:
        envelope = self._seal()
        manifest_path = envelope / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][0]["relative_path"] = "../outside.jsonl"
        material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        manifest["manifest_sha256"] = canonical_sha256(material)
        manifest_path.write_bytes(canonical_bytes(manifest))
        destination = self.scratch_root / "restored"
        with self.assertRaises(ValidationError):
            self.coordinator.restore(envelope, destination)
        self.assertFalse(destination.exists())

    def test_s4d_t07_restore_does_not_resume_interrupted_stage(self) -> None:
        envelope = self._seal()
        destination = self.scratch_root / "restored"
        destination.with_name(".restored.s4d-stage").mkdir()
        with self.assertRaises(ValidationError):
            self.coordinator.restore(envelope, destination)
        self.assertFalse(destination.exists())

    def test_s4d_t08_manifest_excludes_authority_staging_and_derived_material(self) -> None:
        envelope = self._seal()
        manifest = json.loads((envelope / "manifest.json").read_bytes())
        paths = {item["relative_path"] for item in manifest["files"]}
        self.assertFalse(any("staging" in path or "derived" in path or "key" in path for path in paths))
        self.assertFalse((envelope / "files" / "data" / "staging").exists())

    def test_s4d_t09_existing_s3b_s4b_s4c_state_remains_available_after_restart(self) -> None:
        envelope = self._seal()
        result = self.coordinator.restore(envelope, self.scratch_root / "restored")
        runtime = CaseSessionRuntime(
            self.paths.__class__(Path(result["destination_root"]), protected_roots=self.paths.protected_roots),
            self.fixtures.harness.schemas,
        )
        committee = SyntheticCommitteeEvaluationCoordinator(runtime)
        state = committee._run(self.session_id, self.run_id)[1]
        self.assertIn(self.first["finding_id"], state["findings"])
        self.assertTrue(state["dissents"])
