"""Hostile-synthetic tests for the source-free cross-week operating view."""

from __future__ import annotations

from dataclasses import replace
import unittest

from vault_next.cross_week_operating_view import (
    AdmittedWeeklySnapshot,
    CitedWeeklyState,
    CitedStructuredOmission,
    CrossWeekOperatingViewCoordinator,
    CrossWeekOperatingViewError,
    ExplicitTransition,
    StandalonePrimaryArtifact,
    WeeklyCoverageSummary,
)


class CrossWeekOperatingViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.first = self._snapshot("event_week_one", "2026-08-31T00:00:00Z", "2026-09-07T00:00:00Z", "first")
        self.second = self._snapshot("event_week_two", "2026-09-07T00:00:00Z", "2026-09-14T00:00:00Z", "second")
        self.coordinator = CrossWeekOperatingViewCoordinator((self.first, self.second))

    @staticmethod
    def _digest(seed: str) -> str:
        return (seed * 64)[:64]

    def _snapshot(self, event_id: str, start: str, end: str, seed: str) -> AdmittedWeeklySnapshot:
        ref = f"fixture:{seed}:anchor"
        return AdmittedWeeklySnapshot(
            event_id=event_id,
            package_digest=self._digest("a" if seed == "first" else "b"),
            week_start=start,
            week_end=end,
            primary_title=f"{seed.title()} weekly reconstruction",
            primary_artifact_digest=self._digest("c" if seed == "first" else "d"),
            strand_view_digest=self._digest("e" if seed == "first" else "f"),
            project_view_digest=self._digest("1" if seed == "first" else "2"),
            inventory_view_digest=self._digest("3" if seed == "first" else "4"),
            citation_refs=(ref,),
            strands=(CitedWeeklyState("Operations", f"{seed}_open"),),
            projects=(CitedWeeklyState("Project Alpha", f"{seed}_status"),),
            coverage=WeeklyCoverageSummary(3, 1, 1, 1, 0, 0, 1, 0, 0),
        ).sealed()

    def _continuing(self) -> ExplicitTransition:
        return ExplicitTransition(
            "transition-alpha", "project", "continuing", self.first.event_id, "Project Alpha",
            self.second.event_id, "Project Alpha", "prior open", "current gated",
            self.first.project_view_digest, self.second.project_view_digest,
            ("fixture:second:anchor",), "high",
        )

    def test_xw01_renders_explicit_cited_transition_without_io(self) -> None:
        result = self.coordinator.render(
            transitions=(self._continuing(),),
            standalone_primary_artifacts=(
                StandalonePrimaryArtifact(
                    self.first.event_id, "artifact-first", "fixture:first:anchor", "standalone", "no exact edge"
                ),
            ),
            structured_omissions=(
                CitedStructuredOmission(
                    "omission-scope", "project", self.second.event_id, "Unstructured plan",
                    "only present in a cited support view", self.second.project_view_digest,
                    ("fixture:second:anchor",),
                ),
            ),
        )
        self.assertIn("Project Alpha", result.markdown)
        self.assertIn("continuing", result.markdown)
        self.assertIn("fixture:second:anchor", result.evidence_companion)
        self.assertIn("Unstructured plan", result.markdown)
        self.assertTrue(result.sidecar["no_publication"])

    def test_xw02_rejects_tampered_snapshot_binding(self) -> None:
        hostile = replace(self.second, primary_title="changed")
        with self.assertRaises(CrossWeekOperatingViewError):
            CrossWeekOperatingViewCoordinator((self.first, hostile))

    def test_xw03_rejects_non_candidate_or_current_work_snapshot(self) -> None:
        hostile = replace(self.second, candidate_only=False).sealed()
        with self.assertRaises(CrossWeekOperatingViewError):
            CrossWeekOperatingViewCoordinator((self.first, hostile))
        hostile = replace(self.second, no_current_work=False).sealed()
        with self.assertRaises(CrossWeekOperatingViewError):
            CrossWeekOperatingViewCoordinator((self.first, hostile))

    def test_xw04_rejects_automatic_unknown_endpoint_label(self) -> None:
        hostile = replace(self._continuing(), prior_label="Looks similar by filename")
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(hostile,), standalone_primary_artifacts=())

    def test_xw05_continuing_requires_both_bound_view_digests_and_current_anchor(self) -> None:
        hostile = replace(self._continuing(), prior_view_digest=self.second.project_view_digest)
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(hostile,), standalone_primary_artifacts=())
        hostile = replace(self._continuing(), current_citation_refs=("fixture:first:anchor",))
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(hostile,), standalone_primary_artifacts=())

    def test_xw06_new_track_cannot_imply_prior_endpoint(self) -> None:
        hostile = ExplicitTransition(
            "new-alpha", "project", "new_track", self.first.event_id, "Project Alpha",
            self.second.event_id, "Project Alpha", None, "new", None,
            self.second.project_view_digest, ("fixture:second:anchor",), "medium",
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(hostile,), standalone_primary_artifacts=())

    def test_xw07_no_observed_movement_cannot_claim_current_evidence(self) -> None:
        hostile = ExplicitTransition(
            "no-movement", "strand", "no_observed_movement", self.first.event_id, "Operations",
            None, None, "prior state", None, self.first.strand_view_digest, self.second.strand_view_digest,
            ("fixture:second:anchor",), "low",
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(hostile,), standalone_primary_artifacts=())

    def test_xw08_rejects_standalone_outside_scope_or_without_anchor(self) -> None:
        hostile = StandalonePrimaryArtifact(
            "event_unknown", "artifact", "fixture:first:anchor", "standalone", "reason"
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(), standalone_primary_artifacts=(hostile,))
        hostile = StandalonePrimaryArtifact(
            self.first.event_id, "artifact", "fixture:unknown", "standalone", "reason"
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(), standalone_primary_artifacts=(hostile,))

    def test_xw09_rejects_duplicate_transition_or_standalone_identity(self) -> None:
        transition = self._continuing()
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(transition, transition), standalone_primary_artifacts=())
        standalone = StandalonePrimaryArtifact(
            self.first.event_id, "artifact", "fixture:first:anchor", "standalone", "reason"
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(transitions=(), standalone_primary_artifacts=(standalone, standalone))

    def test_xw10_rejects_overlapping_or_duplicate_weeks(self) -> None:
        hostile = replace(self.second, week_start="2026-09-06T00:00:00Z").sealed()
        with self.assertRaises(CrossWeekOperatingViewError):
            CrossWeekOperatingViewCoordinator((self.first, hostile))
        hostile = replace(self.second, event_id=self.first.event_id).sealed()
        with self.assertRaises(CrossWeekOperatingViewError):
            CrossWeekOperatingViewCoordinator((self.first, hostile))

    def test_xw11_rejects_structured_omission_that_is_in_scope_or_uncited(self) -> None:
        represented = CitedStructuredOmission(
            "represented", "project", self.second.event_id, "Project Alpha", "reason",
            self.second.project_view_digest, ("fixture:second:anchor",),
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(
                transitions=(), standalone_primary_artifacts=(), structured_omissions=(represented,)
            )
        uncited = CitedStructuredOmission(
            "uncited", "project", self.second.event_id, "Unstructured plan", "reason",
            self.second.project_view_digest, ("fixture:unknown",),
        )
        with self.assertRaises(CrossWeekOperatingViewError):
            self.coordinator.render(
                transitions=(), standalone_primary_artifacts=(), structured_omissions=(uncited,)
            )


if __name__ == "__main__":
    unittest.main()
