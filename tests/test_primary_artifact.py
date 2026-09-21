"""PA-01–PA-08 hostile-synthetic primary-artifact and context-selection tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.primary_artifact import (
    ContextCandidate,
    ContextSelectionCoordinator,
    ContextSelectionRequest,
    PrimaryArtifactCoordinator,
    PrimaryArtifactError,
    SupportArtifactDraft,
)
from vault_next.working_artifact import WorkingArtifactCoordinator


_MARKER = "VAULT_NEXT_HOSTILE_FIXTURE"


class PrimaryArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(
            prefix="vault-next-primary-artifact-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name) / "review"
        self.catalog = {
            "fixture:transcript:1": sha256_hex(f"{_MARKER} transcript one".encode()),
            "fixture:history:1": sha256_hex(f"{_MARKER} history one".encode()),
            "fixture:decision:1": sha256_hex(f"{_MARKER} decision one".encode()),
        }
        self.new_input = self._candidate(
            "new-transcript",
            role="new",
            kind="source",
            alias="Invented Soup transcript",
            sequence=0,
            committed=False,
            restart=False,
        )
        self.prior_debrief = self._candidate(
            "prior-debrief",
            role="history",
            kind="artifact",
            alias="Soup program",
            sequence=4,
            related=(self.new_input.ref_id,),
        )
        self.prior_decision = self._candidate(
            "prior-decision",
            role="history",
            kind="decision",
            alias="Soup program",
            sequence=6,
        )
        self.unrelated = self._candidate(
            "unrelated",
            role="history",
            kind="knowledge",
            alias="Other program",
            sequence=9,
        )
        self.candidates = (
            self.new_input,
            self.prior_debrief,
            self.prior_decision,
            self.unrelated,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _candidate(
        self,
        name: str,
        *,
        role: str,
        kind: str,
        alias: str,
        sequence: int,
        related: tuple[str, ...] = (),
        committed: bool = True,
        restart: bool = True,
    ) -> ContextCandidate:
        return ContextCandidate(
            ref_id=f"{name}-ref",
            version_id=f"{name}-v1",
            display_alias=alias,
            kind=kind,  # type: ignore[arg-type]
            role=role,  # type: ignore[arg-type]
            content_sha256=sha256_hex(f"{_MARKER} {name}".encode()),
            aliases=(alias, name),
            related_refs=related,
            recorded_sequence=sequence,
            committed=committed,
            restart_verified=restart,
        ).sealed()

    def _request(self, **changes: object) -> ContextSelectionRequest:
        return replace(
            ContextSelectionRequest(
                request_id=self.harness.ids.new("request"),
                request_text="Debrief this invented Soup meeting with relevant prior context.",
                requested_outcome="meeting",
                primary_artifact_kind="meeting_debrief",
                skill_id="meeting-debrief",
                skill_version="0.3.0",
                skill_state="inactive",
                new_item_ids=(self.new_input.ref_id,),
                target_aliases=("Soup program",),
            ),
            **changes,
        )

    def _selection(self, **changes: object) -> dict[str, object]:
        coordinator = ContextSelectionCoordinator(self.candidates, self.harness.schemas)
        return coordinator.select(self._request(**changes)).manifest

    def _runtime(
        self, selection: dict[str, object] | None = None
    ) -> tuple[WorkingArtifactCoordinator, PrimaryArtifactCoordinator]:
        selected = selection or self._selection()
        workbench = WorkingArtifactCoordinator(
            self.root,
            self.harness.schemas,
            citation_catalog=self.catalog,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        primary = PrimaryArtifactCoordinator(
            workbench,
            self.harness.schemas,
            selected,  # type: ignore[arg-type]
            id_factory=self.harness.ids,
        )
        return workbench, primary

    def _package(self) -> tuple[WorkingArtifactCoordinator, PrimaryArtifactCoordinator, object]:
        workbench, coordinator = self._runtime()
        package = coordinator.create(
            primary_display_alias="Invented Soup Meeting Debrief",
            primary_markdown="# Meeting Debrief\n\nThe fixture decision remained proposed.\n",
            primary_citations=("fixture:transcript:1",),
            supporting=(
                SupportArtifactDraft(
                    "work_continuity",
                    "Invented Soup Continuity",
                    "continuity",
                    "# Continuity\n\nPrior fixture context remains reported.\n",
                    ("fixture:history:1",),
                ),
                SupportArtifactDraft(
                    "decision",
                    "Invented Soup Decision Ledger",
                    "decision_ledger",
                    "# Decision Ledger\n\nNo owner-confirmed decision exists.\n",
                    ("fixture:decision:1",),
                ),
            ),
            idempotency_key="pa-create",
        )
        return workbench, coordinator, package

    def test_pa_01_natural_request_binds_visible_skill_and_one_primary_contract(self) -> None:
        selection = self._selection()
        self.assertEqual(selection["skill"]["skill_id"], "meeting-debrief")  # type: ignore[index]
        self.assertEqual(selection["skill"]["version"], "0.3.0")  # type: ignore[index]
        self.assertTrue(selection["skill"]["visible"])  # type: ignore[index]
        self.assertEqual(selection["primary_artifact_kind"], "meeting_debrief")
        _, coordinator, package = self._package()
        self.assertEqual(package.record["primary"]["artifact_kind"], "meeting_debrief")
        self.assertTrue(package.record["primary_first"])
        self.assertEqual(len(package.record["supporting_artifacts"]), 2)
        coordinator.verify()

    def test_pa_02_new_only_has_zero_prior_reads_and_no_hidden_fallback(self) -> None:
        selection = self._selection(
            mode="new_only",
            target_aliases=(),
            default_mode_applied=False,
        )
        self.assertEqual(selection["status"], "complete")
        self.assertEqual(selection["prior_context_reads"], 0)
        self.assertEqual([item["role"] for item in selection["included"]], ["new"])  # type: ignore[index]
        self.assertTrue(selection["no_source_fallback"])
        self.assertEqual(len(selection["excluded"]), 3)

    def test_pa_03_selected_and_bounded_history_are_exact_visible_and_deterministic(self) -> None:
        selected = self._selection(
            mode="selected_history",
            selected_history_ids=(self.prior_debrief.ref_id,),
            default_mode_applied=False,
        )
        self.assertEqual(
            [item["ref_id"] for item in selected["included"]],  # type: ignore[index]
            [self.new_input.ref_id, self.prior_debrief.ref_id],
        )
        bounded = self._selection(history_limit=1)
        self.assertEqual(bounded["mode"], "bounded_relevant_history")
        history = [item for item in bounded["included"] if item["role"] == "history"]  # type: ignore[index]
        self.assertEqual(history[0]["ref_id"], self.prior_decision.ref_id)
        self.assertIn("omitted", bounded["summary"])
        missing = self._selection(
            mode="selected_history",
            selected_history_ids=("missing-history",),
            default_mode_applied=False,
        )
        self.assertEqual(missing["status"], "unavailable")
        self.assertTrue(missing["no_source_fallback"])

    def test_pa_04_primary_revisions_are_immutable_and_package_lineage_is_exact(self) -> None:
        _, coordinator, first = self._package()
        original = first.primary.markdown_path.read_bytes()
        second = coordinator.revise_primary(
            first.primary.artifact_id,
            prior_revision_id=first.primary.revision_id,
            markdown="# Meeting Debrief\n\nThe refined fixture decision remained proposed.\n",
            citations=("fixture:transcript:1",),
            change_summary="Clarify the invented decision status",
            idempotency_key="pa-revise",
        )
        self.assertEqual(first.primary.markdown_path.read_bytes(), original)
        self.assertEqual(second.primary.revision_number, 2)
        self.assertEqual(second.record["package_revision"], 2)
        self.assertEqual(second.record["prior_package_digest"], first.record["package_digest"])
        self.assertEqual(len(coordinator.verify()), 2)

    def test_pa_05_u0_has_no_state_and_u1_selection_is_complete_without_u2(self) -> None:
        _, coordinator, package = self._package()
        self.assertTrue(package.record["no_automatic_persistence"])
        proposal = coordinator.select_for_u1(
            package.primary.artifact_id, target_state="final"
        )
        self.assertTrue(proposal["complete_package"])
        self.assertEqual(len(proposal["supporting_selections"]), 2)
        self.assertTrue(proposal["no_receipt_issued"])
        self.assertFalse(proposal["u2_authority"])
        self.assertFalse((self.root / "receipts").exists())
        with self.assertRaises(PrimaryArtifactError):
            coordinator.select_for_u1(package.primary.artifact_id, target_state="released")

    def test_pa_06_retrieval_returns_primary_first_and_links_support(self) -> None:
        _, coordinator, package = self._package()
        result = coordinator.retrieve(package.primary.artifact_id)
        self.assertEqual(result.primary_markdown_path, package.primary.markdown_path)
        self.assertEqual(result.supporting_markdown_paths[0], package.supporting[0].markdown_path)
        lines = result.navigation_markdown.splitlines()
        self.assertTrue(lines[0].startswith("# Invented Soup Meeting Debrief"))
        self.assertIn(str(package.primary.markdown_path), lines[2])
        self.assertNotIn("fixture:transcript:1", result.primary_markdown_path.read_text())

    def test_pa_07_exact_citations_are_enforced_and_tamper_fails_closed(self) -> None:
        _, coordinator, package = self._package()
        companion = package.primary.markdown_path.with_suffix("").with_suffix(".citations.md")
        self.assertIn("fixture:transcript:1", companion.read_text())
        original = companion.read_bytes()
        companion.write_text("# substituted fixture evidence\n", encoding="utf-8")
        with self.assertRaises(PrimaryArtifactError):
            coordinator.verify()
        companion.write_bytes(original)
        coordinator.verify()

    def test_pa_08_restart_idempotence_and_relationship_tamper_fail_closed(self) -> None:
        _, coordinator, package = self._package()
        first_digest = package.record["package_digest"]
        selection = coordinator.context_selection
        resumed_workbench = WorkingArtifactCoordinator(
            self.root,
            self.harness.schemas,
            citation_catalog=self.catalog,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            resume=True,
        )
        resumed = PrimaryArtifactCoordinator(
            resumed_workbench,
            self.harness.schemas,
            selection,
            id_factory=self.harness.ids,
            resume=True,
        )
        self.assertEqual(
            resumed.retrieve(package.primary.artifact_id).package_digest,
            first_digest,
        )
        exact = resumed.create(
            primary_display_alias="Invented Soup Meeting Debrief",
            primary_markdown="# Meeting Debrief\n\nThe fixture decision remained proposed.\n",
            primary_citations=("fixture:transcript:1",),
            supporting=(
                SupportArtifactDraft(
                    "work_continuity",
                    "Invented Soup Continuity",
                    "continuity",
                    "# Continuity\n\nPrior fixture context remains reported.\n",
                    ("fixture:history:1",),
                ),
                SupportArtifactDraft(
                    "decision",
                    "Invented Soup Decision Ledger",
                    "decision_ledger",
                    "# Decision Ledger\n\nNo owner-confirmed decision exists.\n",
                    ("fixture:decision:1",),
                ),
            ),
            idempotency_key="pa-create",
        )
        self.assertEqual(exact.record["package_digest"], first_digest)
        package_path = next((self.root / "primary-packages").rglob("*.json"))
        record = json.loads(package_path.read_text())
        record["relationships"][0]["target_version_id"] = "substituted-version"
        record["package_digest"] = canonical_sha256(
            {**record, "package_digest": "0" * 64}
        )
        package_path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(PrimaryArtifactError):
            resumed.verify()

    def test_hostile_context_mutation_and_unsealed_history_are_rejected(self) -> None:
        with self.assertRaises(PrimaryArtifactError):
            ContextSelectionCoordinator(
                (replace(self.prior_debrief, content_sha256="f" * 64),),
                self.harness.schemas,
            )
        unverified = replace(
            self.prior_debrief,
            committed=False,
            restart_verified=False,
        )
        unverified = replace(unverified, integrity_sha256=canonical_sha256(unverified._material()))
        with self.assertRaises(PrimaryArtifactError):
            ContextSelectionCoordinator((unverified,), self.harness.schemas)


if __name__ == "__main__":
    unittest.main()
