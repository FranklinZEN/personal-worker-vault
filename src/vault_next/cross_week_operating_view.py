"""Source-free, primary-first operating views across admitted historical weeks.

This module deliberately consumes *only* caller-supplied, already-admitted weekly package summaries.  It
never discovers a week, opens an immutable source object, changes an event, issues a receipt, or turns an
evidence-backed comparison into a canonical relationship.  A caller has to state every cross-week mapping
explicitly and bind it to retained support-view digests; labels, dates, and people are never matched here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Literal

from vault_next.canonical import canonical_sha256


COMPONENT_ID = "cross_week_operating_view"
COMPONENT_VERSION = "0.1.0"
COMPONENT = f"{COMPONENT_ID}/{COMPONENT_VERSION}"
_ZERO_DIGEST = "0" * 64
_SYNTHETIC_MARKER = "VAULT_NEXT_HOSTILE_FIXTURE"
_CATEGORIES = frozenset({"strand", "project"})
_CLASSIFICATIONS = frozenset(
    {
        "continuing",
        "candidate_continuity",
        "new_track",
        "no_observed_movement",
        "stalled_reported",
        "reversal",
        "completion",
    }
)
_STANDALONE_STATUSES = frozenset({"linked", "standalone", "unsupported", "missing_evidence"})


class CrossWeekOperatingViewError(RuntimeError):
    """A supplied derived weekly summary or explicit transition is unsafe or incomplete."""


@dataclass(frozen=True)
class CitedWeeklyState:
    """One retained strand or project state from a sealed weekly package."""

    label: str
    status: str


@dataclass(frozen=True)
class WeeklyCoverageSummary:
    """Counts from the existing complete per-item ledger; no source reader is involved."""

    selected_count: int
    primary_linked_count: int
    primary_standalone_count: int
    meeting_linked_count: int
    meeting_standalone_count: int
    meeting_unsupported_count: int
    conversation_linked_count: int
    conversation_standalone_count: int
    silent_orphan_count: int


@dataclass(frozen=True)
class AdmittedWeeklySnapshot:
    """An immutable, verified summary supplied by a narrow bundle reader.

    ``sealed`` is intentionally separate from a future production reader: tests and a no-write U0 adapter
    can inject this summary, while a later publisher can reuse the exact same digest contract.
    """

    event_id: str
    package_digest: str
    week_start: str
    week_end: str
    primary_title: str
    primary_artifact_digest: str
    strand_view_digest: str
    project_view_digest: str
    inventory_view_digest: str
    citation_refs: tuple[str, ...]
    strands: tuple[CitedWeeklyState, ...]
    projects: tuple[CitedWeeklyState, ...]
    coverage: WeeklyCoverageSummary
    candidate_only: bool = True
    no_current_work: bool = True
    synthetic_only: bool = True
    fixture_marker: str = _SYNTHETIC_MARKER
    integrity_sha256: str = _ZERO_DIGEST

    def sealed(self) -> "AdmittedWeeklySnapshot":
        return replace(self, integrity_sha256=canonical_sha256(self._material()))

    def _material(self) -> dict[str, object]:
        return {
            "component": COMPONENT,
            "event_id": self.event_id,
            "package_digest": self.package_digest,
            "week_start": self.week_start,
            "week_end": self.week_end,
            "primary_title": self.primary_title,
            "primary_artifact_digest": self.primary_artifact_digest,
            "strand_view_digest": self.strand_view_digest,
            "project_view_digest": self.project_view_digest,
            "inventory_view_digest": self.inventory_view_digest,
            "citation_refs": list(self.citation_refs),
            "strands": [state.__dict__ for state in self.strands],
            "projects": [state.__dict__ for state in self.projects],
            "coverage": self.coverage.__dict__,
            "candidate_only": self.candidate_only,
            "no_current_work": self.no_current_work,
            "synthetic_only": self.synthetic_only,
            "fixture_marker": self.fixture_marker,
        }


@dataclass(frozen=True)
class ExplicitTransition:
    """One caller-supplied comparison; it is a view claim, not a canonical relationship assertion."""

    transition_id: str
    category: Literal["strand", "project"]
    classification: Literal[
        "continuing",
        "candidate_continuity",
        "new_track",
        "no_observed_movement",
        "stalled_reported",
        "reversal",
        "completion",
    ]
    prior_event_id: str | None
    prior_label: str | None
    current_event_id: str | None
    current_label: str | None
    prior_summary: str | None
    current_summary: str | None
    prior_view_digest: str | None
    current_view_digest: str | None
    current_citation_refs: tuple[str, ...] = ()
    confidence: Literal["high", "medium", "low"] = "medium"
    omissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class StandalonePrimaryArtifact:
    """One primary artifact's relationship state, retained without inventing a link."""

    event_id: str
    artifact_ref: str
    citation_ref: str
    status: Literal["linked", "standalone", "unsupported", "missing_evidence"]
    reason: str


@dataclass(frozen=True)
class CitedStructuredOmission:
    """A cited detail present in a support view but absent from the structured weekly state list."""

    omission_id: str
    category: Literal["strand", "project"]
    event_id: str
    label: str
    reason: str
    view_digest: str
    citation_refs: tuple[str, ...]


@dataclass(frozen=True)
class CrossWeekOperatingView:
    """A temporary U0 view plus its compact exact-binding companion."""

    title: str
    markdown: str
    evidence_companion: str
    sidecar: dict[str, object]


class CrossWeekOperatingViewCoordinator:
    """Render an explicit, citation-bound cross-week view without semantic auto-linking."""

    def __init__(self, snapshots: tuple[AdmittedWeeklySnapshot, ...]) -> None:
        self.snapshots = snapshots
        self._validate_snapshots()

    def render(
        self,
        *,
        transitions: tuple[ExplicitTransition, ...],
        standalone_primary_artifacts: tuple[StandalonePrimaryArtifact, ...],
        structured_omissions: tuple[CitedStructuredOmission, ...] = (),
        title: str = "Cross-Week Operating View",
    ) -> CrossWeekOperatingView:
        """Render only explicit mappings and complete standalone accounting as a temporary U0 artifact."""

        if not title.strip():
            raise CrossWeekOperatingViewError("cross-week view title is required")
        validated_transitions = tuple(self._transition(item) for item in transitions)
        if len({item.transition_id for item in validated_transitions}) != len(validated_transitions):
            raise CrossWeekOperatingViewError("cross-week transition id is repeated")
        standalone = tuple(self._standalone(item) for item in standalone_primary_artifacts)
        if len({(item.event_id, item.artifact_ref) for item in standalone}) != len(standalone):
            raise CrossWeekOperatingViewError("standalone primary artifact is repeated")
        omissions = tuple(self._omission(item) for item in structured_omissions)
        if len({item.omission_id for item in omissions}) != len(omissions):
            raise CrossWeekOperatingViewError("structured omission id is repeated")

        prior_ids = tuple(snapshot.event_id for snapshot in self.snapshots[:-1])
        current_id = self.snapshots[-1].event_id
        summary = self._summary(validated_transitions, standalone, omissions)
        markdown = self._markdown(title, validated_transitions, standalone, omissions, summary)
        evidence_companion = self._evidence_companion(validated_transitions, standalone, omissions)
        sidecar = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "title": title,
            "event_ids": [snapshot.event_id for snapshot in self.snapshots],
            "package_digests": [snapshot.package_digest for snapshot in self.snapshots],
            "prior_event_ids": list(prior_ids),
            "current_event_id": current_id,
            "transition_ids": [item.transition_id for item in validated_transitions],
            "structured_omissions": [
                {
                    "omission_id": item.omission_id,
                    "category": item.category,
                    "event_id": item.event_id,
                    "label": item.label,
                    "reason": item.reason,
                    "view_digest": item.view_digest,
                    "citation_refs": list(item.citation_refs),
                }
                for item in omissions
            ],
            "standalone_primary_artifacts": [
                {
                    "event_id": item.event_id,
                    "artifact_ref": item.artifact_ref,
                    "citation_ref": item.citation_ref,
                    "status": item.status,
                    "reason": item.reason,
                }
                for item in standalone
            ],
            "candidate_only": True,
            "no_current_work": True,
            "no_publication": True,
        }
        sidecar["view_digest"] = canonical_sha256(sidecar)
        return CrossWeekOperatingView(title, markdown, evidence_companion, sidecar)

    def _validate_snapshots(self) -> None:
        if len(self.snapshots) < 2:
            raise CrossWeekOperatingViewError("cross-week view requires at least two admitted weeks")
        event_ids: set[str] = set()
        package_digests: set[str] = set()
        previous_end: datetime | None = None
        for snapshot in self.snapshots:
            if snapshot.event_id in event_ids or snapshot.package_digest in package_digests:
                raise CrossWeekOperatingViewError("weekly event or package is repeated")
            event_ids.add(snapshot.event_id)
            package_digests.add(snapshot.package_digest)
            self._snapshot(snapshot)
            start = self._timestamp(snapshot.week_start)
            end = self._timestamp(snapshot.week_end)
            if end <= start or (previous_end is not None and start < previous_end):
                raise CrossWeekOperatingViewError("weekly order overlaps or is invalid")
            previous_end = end

    def _snapshot(self, snapshot: AdmittedWeeklySnapshot) -> None:
        if (
            not snapshot.event_id
            or not self._digest(snapshot.package_digest)
            or not snapshot.primary_title
            or not self._digest(snapshot.primary_artifact_digest)
            or not self._digest(snapshot.strand_view_digest)
            or not self._digest(snapshot.project_view_digest)
            or not self._digest(snapshot.inventory_view_digest)
            or not snapshot.citation_refs
            or not snapshot.strands
            or not snapshot.projects
            or snapshot.candidate_only is not True
            or snapshot.no_current_work is not True
            or snapshot.integrity_sha256 != canonical_sha256(snapshot._material())
        ):
            raise CrossWeekOperatingViewError("admitted weekly snapshot binding is invalid")
        if snapshot.synthetic_only and snapshot.fixture_marker != _SYNTHETIC_MARKER:
            raise CrossWeekOperatingViewError("synthetic weekly snapshot lacks hostile marker")
        if len(set(snapshot.citation_refs)) != len(snapshot.citation_refs):
            raise CrossWeekOperatingViewError("weekly citation reference is repeated")
        for state in (*snapshot.strands, *snapshot.projects):
            if not state.label.strip() or not state.status.strip():
                raise CrossWeekOperatingViewError("weekly state is incomplete")
        coverage = snapshot.coverage
        if (
            coverage.selected_count < 1
            or min(
                coverage.primary_linked_count,
                coverage.primary_standalone_count,
                coverage.meeting_linked_count,
                coverage.meeting_standalone_count,
                coverage.meeting_unsupported_count,
                coverage.conversation_linked_count,
                coverage.conversation_standalone_count,
                coverage.silent_orphan_count,
            )
            < 0
        ):
            raise CrossWeekOperatingViewError("weekly coverage summary is invalid")

    def _transition(self, transition: ExplicitTransition) -> ExplicitTransition:
        if (
            not transition.transition_id
            or transition.category not in _CATEGORIES
            or transition.classification not in _CLASSIFICATIONS
            or transition.confidence not in {"high", "medium", "low"}
        ):
            raise CrossWeekOperatingViewError("cross-week transition shape is invalid")
        prior = self._find(transition.prior_event_id) if transition.prior_event_id else None
        current = self._find(transition.current_event_id) if transition.current_event_id else None
        if transition.classification in {
            "continuing", "candidate_continuity", "stalled_reported", "reversal", "completion"
        }:
            if prior is None or current is None or not transition.prior_label or not transition.current_label:
                raise CrossWeekOperatingViewError("cross-week comparison requires exact prior and current endpoints")
            if prior.event_id == current.event_id:
                raise CrossWeekOperatingViewError("cross-week comparison cannot stay within one event")
            self._state(prior, transition.category, transition.prior_label)
            self._state(current, transition.category, transition.current_label)
            if not self._view_digest(prior, transition.category, transition.prior_view_digest):
                raise CrossWeekOperatingViewError("prior transition view binding changed")
            if not self._view_digest(current, transition.category, transition.current_view_digest):
                raise CrossWeekOperatingViewError("current transition view binding changed")
            if (
                not transition.current_citation_refs
                or set(transition.current_citation_refs) - set(current.citation_refs)
            ):
                raise CrossWeekOperatingViewError("current transition citation is absent from admitted week")
        elif transition.classification == "new_track":
            if (
                prior is not None
                or transition.prior_label is not None
                or current is None
                or not transition.current_label
            ):
                raise CrossWeekOperatingViewError("new track cannot imply a prior endpoint")
            self._state(current, transition.category, transition.current_label)
            if not self._view_digest(current, transition.category, transition.current_view_digest):
                raise CrossWeekOperatingViewError("new-track view binding changed")
            if (
                not transition.current_citation_refs
                or set(transition.current_citation_refs) - set(current.citation_refs)
            ):
                raise CrossWeekOperatingViewError("new-track citation is absent from admitted week")
        else:  # no_observed_movement
            if (
                prior is None
                or not transition.prior_label
                or current is not None
                or transition.current_label is not None
            ):
                raise CrossWeekOperatingViewError("no-observed-movement must name only an admitted prior endpoint")
            self._state(prior, transition.category, transition.prior_label)
            if not self._view_digest(prior, transition.category, transition.prior_view_digest):
                raise CrossWeekOperatingViewError("prior no-movement view binding changed")
            if transition.current_view_digest is not None or transition.current_citation_refs:
                raise CrossWeekOperatingViewError("absence cannot carry invented current evidence")
        return transition

    def _standalone(self, artifact: StandalonePrimaryArtifact) -> StandalonePrimaryArtifact:
        snapshot = self._find(artifact.event_id)
        if (
            not artifact.artifact_ref
            or not artifact.reason.strip()
            or artifact.status not in _STANDALONE_STATUSES
            or artifact.citation_ref not in snapshot.citation_refs
        ):
            raise CrossWeekOperatingViewError("standalone primary artifact lacks exact admitted evidence")
        return artifact

    def _omission(self, omission: CitedStructuredOmission) -> CitedStructuredOmission:
        if (
            not omission.omission_id
            or omission.category not in _CATEGORIES
            or not omission.label.strip()
            or not omission.reason.strip()
            or not omission.citation_refs
        ):
            raise CrossWeekOperatingViewError("structured omission shape is invalid")
        snapshot = self._find(omission.event_id)
        if not self._view_digest(snapshot, omission.category, omission.view_digest):
            raise CrossWeekOperatingViewError("structured omission view binding changed")
        if set(omission.citation_refs) - set(snapshot.citation_refs):
            raise CrossWeekOperatingViewError("structured omission citation is absent from admitted week")
        states = snapshot.strands if omission.category == "strand" else snapshot.projects
        if omission.label in {state.label for state in states}:
            raise CrossWeekOperatingViewError("structured omission is already represented")
        return omission

    def _find(self, event_id: str | None) -> AdmittedWeeklySnapshot:
        for snapshot in self.snapshots:
            if snapshot.event_id == event_id:
                return snapshot
        raise CrossWeekOperatingViewError("cross-week endpoint is outside admitted scope")

    @staticmethod
    def _state(snapshot: AdmittedWeeklySnapshot, category: str, label: str) -> None:
        states = snapshot.strands if category == "strand" else snapshot.projects
        if label not in {state.label for state in states}:
            raise CrossWeekOperatingViewError("cross-week endpoint label is not in the admitted weekly view")

    @staticmethod
    def _view_digest(snapshot: AdmittedWeeklySnapshot, category: str, digest: str | None) -> bool:
        expected = snapshot.strand_view_digest if category == "strand" else snapshot.project_view_digest
        return digest == expected

    def _summary(
        self,
        transitions: tuple[ExplicitTransition, ...],
        standalone: tuple[StandalonePrimaryArtifact, ...],
        omissions: tuple[CitedStructuredOmission, ...],
    ) -> dict[str, int]:
        return {
            "transition_count": len(transitions),
            "continuing_count": sum(item.classification == "continuing" for item in transitions),
            "candidate_continuity_count": sum(
                item.classification == "candidate_continuity" for item in transitions
            ),
            "new_track_count": sum(item.classification == "new_track" for item in transitions),
            "no_observed_movement_count": sum(
                item.classification == "no_observed_movement" for item in transitions
            ),
            "standalone_primary_count": sum(item.status == "standalone" for item in standalone),
            "unsupported_primary_count": sum(item.status == "unsupported" for item in standalone),
            "structured_omission_count": len(omissions),
        }

    def _markdown(
        self,
        title: str,
        transitions: tuple[ExplicitTransition, ...],
        standalone: tuple[StandalonePrimaryArtifact, ...],
        omissions: tuple[CitedStructuredOmission, ...],
        summary: dict[str, int],
    ) -> str:
        lines = [f"# {title}", "", "Temporary derived review. It does not change any weekly event.", ""]
        lines.extend(["## Included weeks", ""])
        for snapshot in self.snapshots:
            lines.append(
                f"- {snapshot.week_start[:10]} to {snapshot.week_end[:10]} — "
                f"{snapshot.primary_title} (`{snapshot.event_id}`)"
            )
        lines.extend(["", "## Transition summary", ""])
        lines.append(
            f"- {summary['continuing_count']} continuing; "
            f"{summary['candidate_continuity_count']} candidate continuity; "
            f"{summary['new_track_count']} new tracks; "
            f"{summary['no_observed_movement_count']} no-observed-movement outcomes."
        )
        for category, heading in (("strand", "Strand transitions"), ("project", "Project transitions")):
            lines.extend(["", f"## {heading}", ""])
            rows = [item for item in transitions if item.category == category]
            if not rows:
                lines.append("- No explicit transitions were supplied.")
                continue
            lines.extend(["| Prior | Current | Result |", "|---|---|---|"])
            for item in rows:
                prior = item.prior_label or "—"
                current = item.current_label or "—"
                result = item.classification.replace("_", " ")
                if item.current_summary:
                    result += f" — {item.current_summary}"
                elif item.prior_summary:
                    result += f" — {item.prior_summary}"
                lines.append(f"| {prior} | {current} | {result} |")
        lines.extend(["", "## Primary-artifact relationship accounting", ""])
        lines.append(
            f"- Explicit standalone primary artifacts in this view: {summary['standalone_primary_count']}. "
            "They remain preserved and cited, but are not given invented links."
        )
        lines.append(f"- Unsupported primary artifacts: {summary['unsupported_primary_count']}.")
        lines.extend(["", "## Missing structured representation", ""])
        if omissions:
            for item in omissions:
                lines.append(f"- **{item.category}:** {item.label} — {item.reason}")
        else:
            lines.append("- No cited support-view detail is missing from the structured weekly state lists.")
        lines.extend(["", "## Interpretation boundary", ""])
        lines.append(
            "A continuing or candidate-continuity row is an explicit, citation-bound view comparison. "
            "It is not a new canonical relationship. New tracks and no-observed-movement outcomes remain "
            "separate until a later source-bounded relationship review supplies exact evidence."
        )
        return "\n".join(lines) + "\n"

    def _evidence_companion(
        self,
        transitions: tuple[ExplicitTransition, ...],
        standalone: tuple[StandalonePrimaryArtifact, ...],
        omissions: tuple[CitedStructuredOmission, ...],
    ) -> str:
        lines = ["# Cross-Week Operating View — Evidence Companion", ""]
        lines.append("## Bound weekly views")
        lines.append("")
        for snapshot in self.snapshots:
            lines.append(
                f"- `{snapshot.event_id}`: strands `{snapshot.strand_view_digest}`, "
                f"projects `{snapshot.project_view_digest}`, inventory `{snapshot.inventory_view_digest}`."
            )
        lines.extend(["", "## Explicit transition evidence", ""])
        for item in transitions:
            current_refs = ", ".join(f"`{ref}`" for ref in item.current_citation_refs) or "none"
            lines.append(
                f"- `{item.transition_id}`: {item.classification}; prior view "
                f"`{item.prior_view_digest or 'none'}`; current view "
                f"`{item.current_view_digest or 'none'}`; current anchors {current_refs}."
            )
        lines.extend(["", "## Explicit standalone primary artifacts", ""])
        for artifact in standalone:
            lines.append(
                f"- `{artifact.event_id}` / `{artifact.artifact_ref}` — {artifact.status}; "
                f"`{artifact.citation_ref}`; {artifact.reason}"
            )
        lines.extend(["", "## Cited structured omissions", ""])
        for item in omissions:
            lines.append(
                f"- `{item.omission_id}`: `{item.event_id}` / `{item.view_digest}`; "
                + ", ".join(f"`{ref}`" for ref in item.citation_refs)
                + f"; {item.reason}"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise CrossWeekOperatingViewError("weekly timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise CrossWeekOperatingViewError("weekly timestamp lacks timezone")
        return parsed

    @staticmethod
    def _digest(value: str) -> bool:
        return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
