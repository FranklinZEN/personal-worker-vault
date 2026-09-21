"""Hostile-synthetic tests for weekly-plus-rolling-window reconciliation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from vault_next.cross_week_operating_view import (
    AdmittedWeeklySnapshot,
    CitedWeeklyState,
    WeeklyCoverageSummary,
)
from vault_next.historical_rolling_reconciliation import (
    CoverageDispositionUpdate,
    CoverageRegisterEntry,
    EvidenceBoundEndpoint,
    HistoricalRollingReconciliationCoordinator,
    HistoricalRollingReconciliationError,
    RollingRelationship,
)


class HistoricalRollingReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        origin = datetime(2026, 8, 3, tzinfo=timezone.utc)
        self.snapshots = tuple(self._snapshot(index, origin + timedelta(days=7 * index)) for index in range(9))
        self.coordinator = HistoricalRollingReconciliationCoordinator(self.snapshots)
        self.target = self.snapshots[4]
        self.plan = self.coordinator.plan(self.target.event_id)

    @staticmethod
    def _digest(seed: str) -> str:
        return (seed * 64)[:64]

    def _snapshot(self, index: int, start: datetime) -> AdmittedWeeklySnapshot:
        marker = f"{index:x}"
        ref = f"fixture:week-{index}:anchor"
        return AdmittedWeeklySnapshot(
            event_id=f"event_week_{index}",
            package_digest=self._digest(marker),
            week_start=start.isoformat().replace("+00:00", "Z"),
            week_end=(start + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
            primary_title=f"Week {index}",
            primary_artifact_digest=self._digest(f"a{marker}"),
            strand_view_digest=self._digest(f"b{marker}"),
            project_view_digest=self._digest(f"c{marker}"),
            inventory_view_digest=self._digest(f"d{marker}"),
            citation_refs=(ref,),
            strands=(CitedWeeklyState(f"Strand {index}", "observed"),),
            projects=(CitedWeeklyState(f"Project {index}", "observed"),),
            coverage=WeeklyCoverageSummary(2, 1, 1, 0, 0, 0, 0, 0, 0),
        ).sealed()

    def _endpoint(self, index: int, category: str = "project") -> EvidenceBoundEndpoint:
        snapshot = self.snapshots[index]
        if category == "strand":
            label = f"Strand {index}"
            digest = snapshot.strand_view_digest
        elif category == "project":
            label = f"Project {index}"
            digest = snapshot.project_view_digest
        else:
            label = f"Artifact {index}"
            digest = snapshot.inventory_view_digest
        return EvidenceBoundEndpoint(
            snapshot.event_id,
            category,  # type: ignore[arg-type]
            label,
            digest,
            (f"fixture:week-{index}:anchor",),
        )

    def _relationship(self, state: str = "linked") -> RollingRelationship:
        return RollingRelationship(
            relationship_id=f"relationship-{state}",
            state=state,  # type: ignore[arg-type]
            prior_endpoints=(self._endpoint(3),),
            current_endpoints=(self._endpoint(4),),
            rationale="exact admitted evidence supports the candidate relationship",
            confidence="high",
        )

    def _coverage(self) -> CoverageRegisterEntry:
        return CoverageRegisterEntry(
            coverage_identity="coverage-artifact-3",
            version=1,
            event_id=self.snapshots[3].event_id,
            artifact_ref="artifact-3",
            state="intentionally_standalone",
            reason="no exact relationship evidence in the original weekly wave",
            citation_refs=("fixture:week-3:anchor",),
        ).sealed()

    def test_rw01_selects_only_admitted_target_plus_or_minus_three_weeks(self) -> None:
        self.assertEqual(self.plan.admitted_week_offsets, (-3, -2, -1, 0, 1, 2, 3))
        self.assertEqual(self.plan.admitted_event_ids, tuple(f"event_week_{index}" for index in range(1, 8)))
        self.assertNotIn("event_week_0", self.plan.admitted_event_ids)
        self.assertNotIn("event_week_8", self.plan.admitted_event_ids)

    def test_rw02_rejects_mutated_or_expanded_plan(self) -> None:
        hostile = replace(self.plan, admitted_event_ids=self.plan.admitted_event_ids + ("event_week_8",))
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=hostile, relationships=(), coverage_entries=(), coverage_updates=()
            )

    def test_rw03_follow_up_hint_cannot_replace_exact_evidence(self) -> None:
        uncited = replace(self._endpoint(4), citation_refs=())
        hostile = RollingRelationship(
            "hint-only",
            "linked",
            (self._endpoint(3),),
            (uncited,),
            "follow-up file suggests a match",
            "low",
            ("follow-up.md:item-4",),
        )
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan, relationships=(hostile,), coverage_entries=(), coverage_updates=()
            )

    def test_rw04_no_observed_movement_is_not_a_reported_stall(self) -> None:
        no_observation = RollingRelationship(
            "no-observation",
            "no_observed_movement",
            (self._endpoint(3),),
            (),
            "no admitted current-week endpoint exists",
            "medium",
        )
        result = self.coordinator.reconcile(
            plan=self.plan, relationships=(no_observation,), coverage_entries=(), coverage_updates=()
        )
        self.assertEqual(result.relationships[0].state, "no_observed_movement")
        hostile_stall = replace(no_observation, relationship_id="stall", state="stalled")
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan,
                relationships=(hostile_stall,),
                coverage_entries=(),
                coverage_updates=(),
            )

    def test_rw05_resumed_requires_an_intervening_week_and_cited_endpoints(self) -> None:
        resumed = RollingRelationship(
            "resumed",
            "resumed",
            (self._endpoint(2),),
            (self._endpoint(4),),
            "work reappeared after one intervening week",
            "high",
        )
        self.coordinator.reconcile(
            plan=self.plan, relationships=(resumed,), coverage_entries=(), coverage_updates=()
        )
        hostile = replace(resumed, prior_endpoints=(self._endpoint(3),))
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan, relationships=(hostile,), coverage_entries=(), coverage_updates=()
            )

    def test_rw06_merge_and_split_require_correct_evidence_topology(self) -> None:
        merged = RollingRelationship(
            "merged",
            "merged",
            (self._endpoint(2), self._endpoint(3)),
            (self._endpoint(4),),
            "two evidenced tracks converge",
            "medium",
        )
        split = RollingRelationship(
            "split",
            "split",
            (self._endpoint(3),),
            (self._endpoint(4), self._endpoint(5)),
            "one evidenced track produces two tracks",
            "medium",
        )
        self.coordinator.reconcile(
            plan=self.plan, relationships=(merged, split), coverage_entries=(), coverage_updates=()
        )
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan,
                relationships=(replace(merged, prior_endpoints=(self._endpoint(3),)),),
                coverage_entries=(),
                coverage_updates=(),
            )

    def test_rw07_coverage_change_appends_a_bound_version(self) -> None:
        prior = self._coverage()
        relationship = self._relationship()
        update = CoverageDispositionUpdate(
            prior.coverage_identity,
            prior.entry_digest,
            "linked",
            "later admitted evidence now supports a candidate connection",
            ("fixture:week-3:anchor",),
            (relationship.relationship_id,),
        )
        result = self.coordinator.reconcile(
            plan=self.plan,
            relationships=(relationship,),
            coverage_entries=(prior,),
            coverage_updates=(update,),
        )
        appended = result.appended_coverage[0]
        self.assertEqual(appended.version, 2)
        self.assertEqual(appended.prior_entry_digest, prior.entry_digest)
        self.assertEqual(prior.state, "intentionally_standalone")
        self.assertTrue(result.sidecar["no_publication"])

    def test_rw08_rejects_coverage_mutation_duplicate_or_hint_only_link(self) -> None:
        prior = self._coverage()
        relationship = self._relationship()
        update = CoverageDispositionUpdate(
            prior.coverage_identity,
            self._digest("f"),
            "linked",
            "hostile replacement",
            ("fixture:week-3:anchor",),
            (relationship.relationship_id,),
        )
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan,
                relationships=(relationship,),
                coverage_entries=(prior,),
                coverage_updates=(update,),
            )
        hint_only = replace(
            update,
            prior_entry_digest=prior.entry_digest,
            citation_refs=(),
            relationship_ids=(),
            follow_up_hint_refs=("follow-up.md:item",),
        )
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan,
                relationships=(relationship,),
                coverage_entries=(prior,),
                coverage_updates=(hint_only,),
            )

    def test_rw09_final_sweep_is_candidate_only_and_covers_long_range_patterns(self) -> None:
        sweep = self.coordinator.full_history_sweep_plan()
        self.assertIn("orphan", sweep.dimensions)
        self.assertIn("artifact_lineage", sweep.dimensions)
        self.assertIn("many_to_one_decision_convergence", sweep.required_patterns)
        self.assertIn("one_to_many_track_split", sweep.required_patterns)
        self.assertTrue(sweep.candidate_only)
        self.assertTrue(sweep.no_current_work_adoption)

    def test_rw10_exact_rerun_rebuilds_identical_result(self) -> None:
        relationship = self._relationship()
        first = self.coordinator.reconcile(
            plan=self.plan, relationships=(relationship,), coverage_entries=(), coverage_updates=()
        )
        second = self.coordinator.reconcile(
            plan=self.plan, relationships=(relationship,), coverage_entries=(), coverage_updates=()
        )
        self.assertEqual(first.sidecar, second.sidecar)

    def test_rw11_rejects_non_monday_or_non_seven_day_week(self) -> None:
        hostile = replace(self.snapshots[0], week_start="2026-08-04T00:00:00Z").sealed()
        with self.assertRaises(HistoricalRollingReconciliationError):
            HistoricalRollingReconciliationCoordinator((hostile,))
        hostile = replace(self.snapshots[0], week_end="2026-08-09T00:00:00Z").sealed()
        with self.assertRaises(HistoricalRollingReconciliationError):
            HistoricalRollingReconciliationCoordinator((hostile,))

    def test_rw12_rejects_relationship_endpoint_outside_window(self) -> None:
        hostile = RollingRelationship(
            "outside-window",
            "linked",
            (self._endpoint(0),),
            (self._endpoint(4),),
            "chronology alone must not expand the bounded window",
            "low",
        )
        with self.assertRaises(HistoricalRollingReconciliationError):
            self.coordinator.reconcile(
                plan=self.plan, relationships=(hostile,), coverage_entries=(), coverage_updates=()
            )

    def test_rw13_rejects_a_window_with_unaccounted_silent_orphans(self) -> None:
        hostile_coverage = replace(self.target.coverage, silent_orphan_count=1)
        hostile_target = replace(self.target, coverage=hostile_coverage).sealed()
        snapshots = tuple(
            hostile_target if item.event_id == self.target.event_id else item for item in self.snapshots
        )
        coordinator = HistoricalRollingReconciliationCoordinator(snapshots)
        with self.assertRaises(HistoricalRollingReconciliationError):
            coordinator.plan(self.target.event_id)


if __name__ == "__main__":
    unittest.main()
