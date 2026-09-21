"""R1-T01–T10 hostile-synthetic operating-view retrieval tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import sha256_hex
from vault_next.operating_view import (
    CitationBinding,
    OperatingViewCandidate,
    OperatingViewClaim,
    OperatingViewCoordinator,
    OperatingViewRequest,
)
from vault_next.working_artifact import WorkingArtifactCoordinator


_MARKER = "VAULT_NEXT_HOSTILE_FIXTURE"
_WATERMARK = "a" * 64


class OperatingViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-operating-view-", dir="/private/tmp")
        self.root = Path(self.temporary.name)
        self.candidates = (
            self._candidate("continuity", "continuity-1", "Cindy/Activate", 4, "reported"),
            self._candidate("decision_dependency", "ledger-1", "Cindy/Activate", 4, "conflicting"),
            self._candidate("next_evidence", "evidence-1", "Cindy/Activate", 4, "proposed"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _candidate(
        self,
        intent: str,
        item_id: str,
        alias: str,
        sequence: int,
        state: str,
        **changes: object,
    ) -> OperatingViewCandidate:
        anchor = f"{intent}:line:000001-000001"
        digest = sha256_hex(f"{_MARKER} {intent} evidence".encode())
        value = OperatingViewCandidate(
            item_id=item_id,
            version_id=f"{item_id}-v1",
            display_alias=alias,
            subject_aliases=(alias, "activate"),
            intent=intent,  # type: ignore[arg-type]
            state=state,  # type: ignore[arg-type]
            lifecycle="active",
            canonical_event_sequence=sequence,
            canonical_watermark=_WATERMARK,
            index_watermark=_WATERMARK,
            claims=(
                OperatingViewClaim(
                    f"{_MARKER} invented {intent} claim for {alias}.", (anchor,)
                ),
            ),
            citations=(CitationBinding(anchor, digest, "source_version_invented"),),
            workspace_path=f"workspace/Work/cindy-activate/{intent}/{item_id}-v1.md",
            candidate_state="inactive" if intent == "continuity" else None,
        )
        return replace(value, **changes).sealed()

    def _query(self, **changes: object) -> OperatingViewRequest:
        return replace(
            OperatingViewRequest(target="Cindy/Activate", intent="continuity"), **changes
        )

    def test_r1_t01_exact_id_alias_and_workspace_path_resolve_one_target(self) -> None:
        coordinator = OperatingViewCoordinator(self.candidates)
        expected = self.candidates[0].item_id
        for target in (
            "Cindy/Activate",
            self.candidates[0].item_id,
            self.candidates[0].version_id,
            self.candidates[0].workspace_path,
        ):
            result = coordinator.query(self._query(target=target))
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.selected.item_id, expected)  # type: ignore[union-attr]
            self.assertEqual(result.canonical_watermark, _WATERMARK)

    def test_r1_t02_each_intent_prefers_matching_artifact_to_generic_target_match(self) -> None:
        coordinator = OperatingViewCoordinator(self.candidates)
        for intent, expected in (
            ("continuity", "continuity-1"),
            ("decision_dependency", "ledger-1"),
            ("next_evidence", "evidence-1"),
        ):
            result = coordinator.query(self._query(intent=intent))  # type: ignore[arg-type]
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.selected.item_id, expected)  # type: ignore[union-attr]

    def test_r1_t03_material_tie_is_ambiguous_not_a_recency_or_filesystem_guess(self) -> None:
        duplicate = self._candidate("continuity", "continuity-2", "Cindy/Activate", 4, "reported")
        result = OperatingViewCoordinator(self.candidates + (duplicate,)).query(self._query())
        self.assertEqual(result.status, "ambiguous")
        self.assertEqual({item.item_id for item in result.alternatives}, {"continuity-1", "continuity-2"})

    def test_r1_t04_lifecycle_scope_integrity_and_tamper_fail_closed(self) -> None:
        deactivated = self._candidate(
            "continuity", "old", "Old Target", 2, "reported", lifecycle="deactivated"
        )
        result = OperatingViewCoordinator((deactivated,)).query(
            OperatingViewRequest(target="Old Target", intent="continuity")
        )
        self.assertEqual(result.status, "unavailable")
        historical = OperatingViewCoordinator((deactivated,)).query(
            OperatingViewRequest(target="Old Target", intent="continuity", include_history=True)
        )
        self.assertEqual(historical.status, "complete")
        scoped = OperatingViewCoordinator(self.candidates).query(
            self._query(scope_item_ids=("ledger-1",))
        )
        self.assertEqual(scoped.status, "unavailable")
        tampered = replace(self.candidates[0], index_watermark="b" * 64)
        corrupted = OperatingViewCoordinator((tampered,) + self.candidates[1:]).query(self._query())
        self.assertEqual(corrupted.status, "rebuild_required")

    def test_r1_t05_temporal_and_state_labels_stay_distinct(self) -> None:
        current = self._candidate("continuity", "current", "Current Target", 7, "current")
        reported = self._candidate("continuity", "reported", "Current Target", 5, "reported")
        coordinator = OperatingViewCoordinator((current, reported))
        latest = coordinator.query(OperatingViewRequest(target="Current Target", intent="continuity"))
        old = coordinator.query(
            OperatingViewRequest(target="Current Target", intent="continuity", as_of_event_sequence=5)
        )
        self.assertEqual(latest.selected.state, "current")  # type: ignore[union-attr]
        self.assertEqual(old.selected.state, "reported")  # type: ignore[union-attr]
        self.assertIn("State: current.", latest.markdown)
        self.assertIn("State: reported.", old.markdown)

    def test_r1_t06_exact_citations_render_cleanly_and_mutation_requires_rebuild(self) -> None:
        result = OperatingViewCoordinator(self.candidates).query(self._query())
        self.assertNotIn("line:000001", result.markdown)
        self.assertIn("[E1]", result.markdown)
        self.assertIn("line:000001", result.evidence_companion)
        altered_binding = CitationBinding(
            self.candidates[0].citations[0].anchor, "b" * 64, "source_version_invented"
        )
        tampered = replace(self.candidates[0], citations=(altered_binding,))
        failed = OperatingViewCoordinator((tampered,) + self.candidates[1:]).query(self._query())
        self.assertEqual(failed.status, "rebuild_required")

    def test_r1_t07_direct_scope_only_and_budget_overflow_require_narrowing(self) -> None:
        related = self._candidate(
            "continuity", "related", "Other", 5, "reported", related_targets=("Cindy/Activate",)
        )
        result = OperatingViewCoordinator((related,)).query(self._query())
        self.assertEqual(result.status, "complete")
        indirect = self._candidate(
            "continuity", "indirect", "Other", 5, "reported", related_targets=("Different",)
        )
        self.assertEqual(
            OperatingViewCoordinator((indirect,)).query(self._query()).status, "unavailable"
        )
        many = tuple(
            self._candidate("continuity", f"many-{index}", "Budget", index + 1, "reported")
            for index in range(3)
        )
        overflow = OperatingViewCoordinator(many).query(
            OperatingViewRequest(target="Budget", intent="continuity", result_budget=2)
        )
        self.assertEqual(overflow.status, "narrow_scope_required")

    def test_r1_t08_restart_rebuild_is_deterministic_without_source_fallback(self) -> None:
        first = OperatingViewCoordinator(self.candidates).query(self._query())
        rebuilt_catalog = tuple(
            replace(candidate).sealed() for candidate in self.candidates
        )
        rebuilt = OperatingViewCoordinator(rebuilt_catalog).query(self._query())
        self.assertEqual(first.selected.item_id, rebuilt.selected.item_id)  # type: ignore[union-attr]
        self.assertEqual(first.sidecar["citations"], rebuilt.sidecar["citations"])
        self.assertFalse((self.root / "source-fallback").exists())

    def test_r1_t09_query_and_navigation_have_no_persistence_or_authority_effect(self) -> None:
        coordinator = OperatingViewCoordinator(self.candidates)
        before = tuple(self.root.iterdir())
        result = coordinator.query(self._query())
        navigation = coordinator.navigation()
        self.assertEqual(result.status, "complete")
        self.assertEqual(tuple(self.root.iterdir()), before)
        self.assertIn("continuity", navigation)
        self.assertIn("no_u1", result.sidecar["no_authority"])
        self.assertIn("candidate: inactive", navigation["continuity"])

    def test_r1_t10_temporary_revision_preserves_prior_revision_and_stays_u0(self) -> None:
        result = OperatingViewCoordinator(self.candidates).query(self._query())
        review = WorkingArtifactCoordinator(
            self.root / "review",
            self.harness.schemas,
            citation_catalog={
                binding.anchor: binding.evidence_sha256
                for candidate in self.candidates
                for binding in candidate.citations
            },
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        operating = OperatingViewCoordinator(self.candidates)
        first = operating.create_working_preview(result, review, idempotency_key="preview-1")
        original = first.markdown_path.read_bytes()
        revised_result = replace(result, markdown=result.markdown.replace("Evidence-backed", "Refined evidence-backed"))
        second = operating.revise_working_preview(
            revised_result,
            review,
            first,
            change_summary="Clarify invented fixture presentation",
            idempotency_key="preview-2",
        )
        self.assertEqual(first.markdown_path.read_bytes(), original)
        self.assertEqual(second.revision_number, 2)
        self.assertTrue(review.verify()["no_automatic_persistence"])
        self.assertNotIn("paragraph:", second.markdown_path.read_text())


if __name__ == "__main__":
    unittest.main()
