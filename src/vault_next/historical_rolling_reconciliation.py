"""Source-free rolling reconciliation for admitted historical calendar weeks.

The coordinator plans a target-week migration cycle over only already-admitted weekly summaries.  It
does not discover sources, inspect archive objects, publish supplements, or infer a semantic connection
from chronology, filenames, people, or follow-up hints.  Every relationship is caller-supplied and
bound to exact admitted endpoints and citations.  Coverage changes append a new sealed version while
retaining the prior version's digest.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Literal

from vault_next.canonical import canonical_sha256
from vault_next.cross_week_operating_view import AdmittedWeeklySnapshot


COMPONENT_ID = "historical_rolling_reconciliation"
COMPONENT_VERSION = "0.1.0"
COMPONENT = f"{COMPONENT_ID}/{COMPONENT_VERSION}"
ROLLING_RADIUS_WEEKS = 3
_ZERO_DIGEST = "0" * 64
_CATEGORIES = frozenset({"strand", "project", "artifact", "decision", "work_item"})
_COVERAGE_STATES = frozenset(
    {
        "linked",
        "intentionally_standalone",
        "unsupported",
        "missing_evidence",
        "unresolved_within_window",
    }
)
_RELATIONSHIP_STATES = frozenset(
    {
        "linked",
        "no_observed_movement",
        "paused",
        "resumed",
        "stalled",
        "reversed",
        "completed",
        "superseded",
        "merged",
        "split",
        "candidate_abandoned_or_derailed",
        "new_track",
    }
)


class HistoricalRollingReconciliationError(RuntimeError):
    """The supplied rolling-window plan or evidence binding is unsafe."""


@dataclass(frozen=True)
class RollingWindowPlan:
    """A deterministic ±3-week scope over admitted weekly summaries only."""

    target_event_id: str
    target_week_start: str
    radius_weeks: int
    admitted_event_ids: tuple[str, ...]
    admitted_week_offsets: tuple[int, ...]
    cycle_steps: tuple[str, ...]
    plan_digest: str = _ZERO_DIGEST

    def sealed(self) -> "RollingWindowPlan":
        return replace(self, plan_digest=canonical_sha256(self._material()))

    def _material(self) -> dict[str, object]:
        return {
            "component": COMPONENT,
            "target_event_id": self.target_event_id,
            "target_week_start": self.target_week_start,
            "radius_weeks": self.radius_weeks,
            "admitted_event_ids": list(self.admitted_event_ids),
            "admitted_week_offsets": list(self.admitted_week_offsets),
            "cycle_steps": list(self.cycle_steps),
        }


@dataclass(frozen=True)
class EvidenceBoundEndpoint:
    """An exact admitted endpoint used by a proposed cross-week relationship."""

    event_id: str
    category: Literal["strand", "project", "artifact", "decision", "work_item"]
    label: str
    view_digest: str
    citation_refs: tuple[str, ...]


@dataclass(frozen=True)
class RollingRelationship:
    """One evidence-backed view assertion; it is not itself a canonical relationship."""

    relationship_id: str
    state: Literal[
        "linked",
        "no_observed_movement",
        "paused",
        "resumed",
        "stalled",
        "reversed",
        "completed",
        "superseded",
        "merged",
        "split",
        "candidate_abandoned_or_derailed",
        "new_track",
    ]
    prior_endpoints: tuple[EvidenceBoundEndpoint, ...]
    current_endpoints: tuple[EvidenceBoundEndpoint, ...]
    rationale: str
    confidence: Literal["high", "medium", "low"]
    follow_up_hint_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageRegisterEntry:
    """One append-only relationship-coverage disposition version."""

    coverage_identity: str
    version: int
    event_id: str
    artifact_ref: str
    state: Literal[
        "linked",
        "intentionally_standalone",
        "unsupported",
        "missing_evidence",
        "unresolved_within_window",
    ]
    reason: str
    citation_refs: tuple[str, ...]
    relationship_ids: tuple[str, ...] = ()
    prior_entry_digest: str | None = None
    entry_digest: str = _ZERO_DIGEST

    def sealed(self) -> "CoverageRegisterEntry":
        return replace(self, entry_digest=canonical_sha256(self._material()))

    def _material(self) -> dict[str, object]:
        return {
            "component": COMPONENT,
            "coverage_identity": self.coverage_identity,
            "version": self.version,
            "event_id": self.event_id,
            "artifact_ref": self.artifact_ref,
            "state": self.state,
            "reason": self.reason,
            "citation_refs": list(self.citation_refs),
            "relationship_ids": list(self.relationship_ids),
            "prior_entry_digest": self.prior_entry_digest,
        }


@dataclass(frozen=True)
class CoverageDispositionUpdate:
    """A requested next coverage version; the coordinator creates the sealed entry."""

    coverage_identity: str
    prior_entry_digest: str
    new_state: Literal[
        "linked",
        "intentionally_standalone",
        "unsupported",
        "missing_evidence",
        "unresolved_within_window",
    ]
    reason: str
    citation_refs: tuple[str, ...]
    relationship_ids: tuple[str, ...] = ()
    follow_up_hint_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class RollingReconciliationResult:
    """A no-write candidate reconciliation pack and rebuildable coverage delta."""

    plan: RollingWindowPlan
    relationships: tuple[RollingRelationship, ...]
    prior_coverage: tuple[CoverageRegisterEntry, ...]
    appended_coverage: tuple[CoverageRegisterEntry, ...]
    final_full_history_sweep_required: bool
    sidecar: dict[str, object]


@dataclass(frozen=True)
class FullHistorySweepPlan:
    """The required closure dimensions after all April-present weeks are admitted."""

    dimensions: tuple[str, ...]
    required_patterns: tuple[str, ...]
    candidate_only: bool
    no_current_work_adoption: bool
    plan_digest: str


class HistoricalRollingReconciliationCoordinator:
    """Plan and validate a source-free weekly-plus-rolling reconciliation cycle."""

    def __init__(self, snapshots: tuple[AdmittedWeeklySnapshot, ...]) -> None:
        if not snapshots:
            raise HistoricalRollingReconciliationError("at least one admitted week is required")
        self.snapshots = tuple(sorted(snapshots, key=lambda item: self._week_start(item.week_start)))
        self._validate_snapshots()
        self._by_event = {snapshot.event_id: snapshot for snapshot in self.snapshots}

    def plan(self, target_event_id: str) -> RollingWindowPlan:
        """Select only admitted weeks within target ±3 calendar weeks."""

        target = self._snapshot(target_event_id)
        target_start = self._week_start(target.week_start)
        selected: list[tuple[int, AdmittedWeeklySnapshot]] = []
        for snapshot in self.snapshots:
            offset = (self._week_start(snapshot.week_start) - target_start).days // 7
            if abs(offset) <= ROLLING_RADIUS_WEEKS:
                if snapshot.coverage.silent_orphan_count != 0:
                    raise HistoricalRollingReconciliationError(
                        "admitted rolling-window week lacks complete coverage accounting"
                    )
                selected.append((offset, snapshot))
        return RollingWindowPlan(
            target_event_id=target.event_id,
            target_week_start=target.week_start,
            radius_weeks=ROLLING_RADIUS_WEEKS,
            admitted_event_ids=tuple(snapshot.event_id for _, snapshot in selected),
            admitted_week_offsets=tuple(offset for offset, _ in selected),
            cycle_steps=(
                "calendar_week_reconstruction",
                "coverage_and_orphan_accounting",
                "append_only_admitted_week_comparison",
                "rolling_plus_minus_three_week_reconciliation",
                "owner_review_or_wave_continuation",
            ),
        ).sealed()

    def reconcile(
        self,
        *,
        plan: RollingWindowPlan,
        relationships: tuple[RollingRelationship, ...],
        coverage_entries: tuple[CoverageRegisterEntry, ...],
        coverage_updates: tuple[CoverageDispositionUpdate, ...],
    ) -> RollingReconciliationResult:
        """Validate explicit evidence and create append-only candidate coverage versions."""

        self._validate_plan(plan)
        validated_relationships = tuple(self._relationship(plan, item) for item in relationships)
        relationship_ids = [item.relationship_id for item in validated_relationships]
        if len(set(relationship_ids)) != len(relationship_ids):
            raise HistoricalRollingReconciliationError("relationship id is repeated")

        prior_coverage = tuple(self._coverage_entry(plan, item) for item in coverage_entries)
        by_identity = {item.coverage_identity: item for item in prior_coverage}
        if len(by_identity) != len(prior_coverage):
            raise HistoricalRollingReconciliationError("coverage identity is repeated")

        appended: list[CoverageRegisterEntry] = []
        seen_updates: set[str] = set()
        relationship_id_set = set(relationship_ids)
        for update in coverage_updates:
            if update.coverage_identity in seen_updates:
                raise HistoricalRollingReconciliationError("coverage identity has multiple updates")
            seen_updates.add(update.coverage_identity)
            prior = by_identity.get(update.coverage_identity)
            if prior is None or prior.entry_digest != update.prior_entry_digest:
                raise HistoricalRollingReconciliationError("coverage update predecessor binding changed")
            if update.new_state not in _COVERAGE_STATES or not update.reason.strip():
                raise HistoricalRollingReconciliationError("coverage update is incomplete")
            if set(update.citation_refs) - set(self._snapshot(prior.event_id).citation_refs):
                raise HistoricalRollingReconciliationError("coverage update citation is outside admitted evidence")
            if set(update.relationship_ids) - relationship_id_set:
                raise HistoricalRollingReconciliationError("coverage update names an unavailable relationship")
            if update.new_state == "linked" and (not update.citation_refs or not update.relationship_ids):
                raise HistoricalRollingReconciliationError("linked coverage requires cited relationship evidence")
            if update.follow_up_hint_refs and not update.citation_refs:
                raise HistoricalRollingReconciliationError("follow-up hints cannot establish a coverage change")
            appended.append(
                CoverageRegisterEntry(
                    coverage_identity=prior.coverage_identity,
                    version=prior.version + 1,
                    event_id=prior.event_id,
                    artifact_ref=prior.artifact_ref,
                    state=update.new_state,
                    reason=update.reason,
                    citation_refs=update.citation_refs,
                    relationship_ids=update.relationship_ids,
                    prior_entry_digest=prior.entry_digest,
                ).sealed()
            )

        sidecar: dict[str, object] = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "plan_digest": plan.plan_digest,
            "target_event_id": plan.target_event_id,
            "admitted_window_event_ids": list(plan.admitted_event_ids),
            "relationship_ids": relationship_ids,
            "prior_coverage_digests": [item.entry_digest for item in prior_coverage],
            "appended_coverage_digests": [item.entry_digest for item in appended],
            "candidate_only": True,
            "no_current_work_adoption": True,
            "no_publication": True,
            "final_full_history_sweep_required": True,
        }
        sidecar["result_digest"] = canonical_sha256(sidecar)
        return RollingReconciliationResult(
            plan=plan,
            relationships=validated_relationships,
            prior_coverage=prior_coverage,
            appended_coverage=tuple(appended),
            final_full_history_sweep_required=True,
            sidecar=sidecar,
        )

    @staticmethod
    def full_history_sweep_plan() -> FullHistorySweepPlan:
        """Describe the required April-present closure without accessing any source."""

        dimensions = (
            "orphan",
            "strand",
            "project",
            "person",
            "decision",
            "meeting",
            "conversation",
            "artifact_lineage",
        )
        patterns = (
            "long_latency_resumption",
            "many_to_one_decision_convergence",
            "one_to_many_track_split",
            "supersession",
            "shallow_relationship",
            "missing_evidence",
            "unresolved_standalone_work",
        )
        material = {
            "component": COMPONENT,
            "dimensions": list(dimensions),
            "required_patterns": list(patterns),
            "candidate_only": True,
            "no_current_work_adoption": True,
        }
        return FullHistorySweepPlan(dimensions, patterns, True, True, canonical_sha256(material))

    def _validate_snapshots(self) -> None:
        seen_events: set[str] = set()
        seen_starts: set[datetime] = set()
        for snapshot in self.snapshots:
            start = self._week_start(snapshot.week_start)
            end = self._timestamp(snapshot.week_end)
            if snapshot.event_id in seen_events or start in seen_starts:
                raise HistoricalRollingReconciliationError("admitted week is repeated")
            seen_events.add(snapshot.event_id)
            seen_starts.add(start)
            if end != start + timedelta(days=7):
                raise HistoricalRollingReconciliationError("admitted week is not exactly seven days")
            if snapshot.integrity_sha256 != canonical_sha256(snapshot._material()):
                raise HistoricalRollingReconciliationError("admitted weekly snapshot binding changed")
            if snapshot.candidate_only is not True or snapshot.no_current_work is not True:
                raise HistoricalRollingReconciliationError("rolling reconciliation requires candidate history")
            if (
                not snapshot.event_id
                or not self._digest(snapshot.package_digest)
                or not self._digest(snapshot.primary_artifact_digest)
                or not self._digest(snapshot.strand_view_digest)
                or not self._digest(snapshot.project_view_digest)
                or not self._digest(snapshot.inventory_view_digest)
                or not snapshot.citation_refs
                or len(set(snapshot.citation_refs)) != len(snapshot.citation_refs)
            ):
                raise HistoricalRollingReconciliationError("admitted weekly snapshot is incomplete")

    def _validate_plan(self, plan: RollingWindowPlan) -> None:
        expected = self.plan(plan.target_event_id)
        if plan != expected or plan.plan_digest != canonical_sha256(plan._material()):
            raise HistoricalRollingReconciliationError("rolling-window plan binding changed")

    def _relationship(self, plan: RollingWindowPlan, item: RollingRelationship) -> RollingRelationship:
        if (
            not item.relationship_id
            or item.state not in _RELATIONSHIP_STATES
            or not item.rationale.strip()
            or item.confidence not in {"high", "medium", "low"}
        ):
            raise HistoricalRollingReconciliationError("rolling relationship is incomplete")
        prior = tuple(self._endpoint(plan, endpoint) for endpoint in item.prior_endpoints)
        current = tuple(self._endpoint(plan, endpoint) for endpoint in item.current_endpoints)

        if item.state == "new_track" and (prior or len(current) != 1):
            raise HistoricalRollingReconciliationError("new track requires one current endpoint and no prior")
        if item.state == "no_observed_movement" and (len(prior) != 1 or current):
            raise HistoricalRollingReconciliationError("no observed movement cannot invent current evidence")
        if item.state == "merged" and (len(prior) < 2 or len(current) != 1):
            raise HistoricalRollingReconciliationError("merge requires many prior endpoints and one current")
        if item.state == "split" and (len(prior) != 1 or len(current) < 2):
            raise HistoricalRollingReconciliationError("split requires one prior endpoint and many current")
        if item.state not in {"new_track", "no_observed_movement", "merged", "split"} and (
            len(prior) != 1 or len(current) != 1
        ):
            raise HistoricalRollingReconciliationError("relationship requires one prior and one current endpoint")
        if item.state == "resumed" and self._endpoint_gap(prior[0], current[0]) < 2:
            raise HistoricalRollingReconciliationError("resumed requires at least one intervening calendar week")
        if item.state in {"paused", "stalled", "completed", "candidate_abandoned_or_derailed"} and not current:
            raise HistoricalRollingReconciliationError("reported state requires cited current evidence")
        if item.follow_up_hint_refs and not any(endpoint.citation_refs for endpoint in (*prior, *current)):
            raise HistoricalRollingReconciliationError("follow-up hints cannot establish a relationship")
        return item

    def _endpoint(self, plan: RollingWindowPlan, endpoint: EvidenceBoundEndpoint) -> EvidenceBoundEndpoint:
        if endpoint.event_id not in plan.admitted_event_ids:
            raise HistoricalRollingReconciliationError("relationship endpoint is outside rolling window")
        snapshot = self._snapshot(endpoint.event_id)
        if endpoint.category not in _CATEGORIES or not endpoint.label.strip() or not endpoint.citation_refs:
            raise HistoricalRollingReconciliationError("relationship endpoint is incomplete")
        expected_digest = self._view_digest(snapshot, endpoint.category)
        if endpoint.view_digest != expected_digest:
            raise HistoricalRollingReconciliationError("relationship endpoint view binding changed")
        if set(endpoint.citation_refs) - set(snapshot.citation_refs):
            raise HistoricalRollingReconciliationError("relationship citation is outside admitted evidence")
        if endpoint.category in {"strand", "project"}:
            states = snapshot.strands if endpoint.category == "strand" else snapshot.projects
            if endpoint.label not in {state.label for state in states}:
                raise HistoricalRollingReconciliationError("relationship state label is not admitted")
        return endpoint

    def _coverage_entry(self, plan: RollingWindowPlan, entry: CoverageRegisterEntry) -> CoverageRegisterEntry:
        if (
            not entry.coverage_identity
            or entry.version < 1
            or entry.event_id not in plan.admitted_event_ids
            or not entry.artifact_ref
            or entry.state not in _COVERAGE_STATES
            or not entry.reason.strip()
            or entry.entry_digest != canonical_sha256(entry._material())
        ):
            raise HistoricalRollingReconciliationError("coverage entry binding is invalid")
        if set(entry.citation_refs) - set(self._snapshot(entry.event_id).citation_refs):
            raise HistoricalRollingReconciliationError("coverage entry citation is outside admitted evidence")
        if entry.version == 1 and entry.prior_entry_digest is not None:
            raise HistoricalRollingReconciliationError("initial coverage entry cannot name a predecessor")
        if entry.version > 1 and not self._digest(entry.prior_entry_digest):
            raise HistoricalRollingReconciliationError("later coverage entry requires predecessor digest")
        return entry

    def _endpoint_gap(self, prior: EvidenceBoundEndpoint, current: EvidenceBoundEndpoint) -> int:
        prior_start = self._week_start(self._snapshot(prior.event_id).week_start)
        current_start = self._week_start(self._snapshot(current.event_id).week_start)
        return (current_start - prior_start).days // 7

    def _snapshot(self, event_id: str) -> AdmittedWeeklySnapshot:
        try:
            return self._by_event[event_id]
        except KeyError as exc:
            raise HistoricalRollingReconciliationError("event is not an admitted weekly snapshot") from exc

    @staticmethod
    def _view_digest(snapshot: AdmittedWeeklySnapshot, category: str) -> str:
        if category == "strand":
            return snapshot.strand_view_digest
        if category == "project":
            return snapshot.project_view_digest
        return snapshot.inventory_view_digest

    @staticmethod
    def _week_start(value: str) -> datetime:
        timestamp = HistoricalRollingReconciliationCoordinator._timestamp(value)
        if (
            timestamp.weekday() != 0
            or timestamp.hour != 0
            or timestamp.minute != 0
            or timestamp.second != 0
            or timestamp.microsecond != 0
        ):
            raise HistoricalRollingReconciliationError("weekly start must be Monday 00:00 UTC")
        return timestamp

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HistoricalRollingReconciliationError("weekly timestamp is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise HistoricalRollingReconciliationError("weekly timestamp must be UTC")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _digest(value: str | None) -> bool:
        return bool(value and len(value) == 64 and all(char in "0123456789abcdef" for char in value))
