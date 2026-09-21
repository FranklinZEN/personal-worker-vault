"""Deterministic, host-neutral operating views over supplied committed records.

``operating_view_query/0.1`` deliberately has no source, bundle, FTS, network, model, receipt, or
event writer dependency.  A caller supplies already verified candidate descriptions from a derived
reader.  This coordinator checks their immutable bindings, resolves one bounded natural request, and
renders an ephemeral clean Markdown preview plus an optional evidence companion.  It never treats a
derived result as canonical state and never creates current work or effect authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from vault_next.canonical import canonical_sha256
from vault_next.working_artifact import WorkingArtifactCoordinator, WorkingArtifactView


COMPONENT_ID = "operating_view_query"
COMPONENT_VERSION = "0.1.0"
COMPONENT = f"{COMPONENT_ID}/{COMPONENT_VERSION}"
_ZERO_HASH = "0" * 64
_SYNTHETIC_MARKER = "VAULT_NEXT_HOSTILE_FIXTURE"
_INTENTS = frozenset({"continuity", "decision_dependency", "next_evidence"})
_STATES = frozenset({"reported", "proposed", "current", "completed", "conflicting", "unknown"})
_LIFECYCLES = frozenset({"active", "deactivated", "superseded", "fenced"})
_CANDIDATE_STATES = frozenset({"inactive", "needs_refinement", "not_applicable", "declined"})
_STATUSES = frozenset(
    {"complete", "unavailable", "ambiguous", "narrow_scope_required", "rebuild_required"}
)
_KIND_BY_INTENT = {
    "continuity": "work_continuity",
    "decision_dependency": "decision",
    "next_evidence": "work_preparation",
}


class OperatingViewError(RuntimeError):
    """A deterministic operating-view request or supplied derived record is invalid."""


@dataclass(frozen=True)
class CitationBinding:
    """One exact source anchor used by one or more displayed synthetic claims."""

    anchor: str
    evidence_sha256: str
    source_version_id: str


@dataclass(frozen=True)
class OperatingViewClaim:
    """A reader-facing claim with exact evidence anchors, not an inferred fact."""

    text: str
    citations: tuple[str, ...]


@dataclass(frozen=True)
class OperatingViewCandidate:
    """One immutable, already-committed artifact description supplied by a derived reader."""

    item_id: str
    version_id: str
    display_alias: str
    subject_aliases: tuple[str, ...]
    intent: Literal["continuity", "decision_dependency", "next_evidence"]
    state: Literal["reported", "proposed", "current", "completed", "conflicting", "unknown"]
    lifecycle: Literal["active", "deactivated", "superseded", "fenced"]
    canonical_event_sequence: int
    canonical_watermark: str
    index_watermark: str
    claims: tuple[OperatingViewClaim, ...]
    citations: tuple[CitationBinding, ...]
    related_targets: tuple[str, ...] = ()
    workspace_path: str | None = None
    candidate_state: Literal["inactive", "needs_refinement", "not_applicable", "declined"] | None = None
    effective_context: str | None = None
    committed: bool = True
    restart_verified: bool = True
    synthetic_only: bool = True
    fixture_marker: str = _SYNTHETIC_MARKER
    integrity_sha256: str = _ZERO_HASH

    def sealed(self) -> "OperatingViewCandidate":
        """Return this synthetic fixture candidate with its exact immutable binding."""

        return replace(self, integrity_sha256=canonical_sha256(self._material()))

    def _material(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "version_id": self.version_id,
            "display_alias": self.display_alias,
            "subject_aliases": list(self.subject_aliases),
            "intent": self.intent,
            "state": self.state,
            "lifecycle": self.lifecycle,
            "canonical_event_sequence": self.canonical_event_sequence,
            "canonical_watermark": self.canonical_watermark,
            "index_watermark": self.index_watermark,
            "claims": [
                {"text": claim.text, "citations": list(claim.citations)} for claim in self.claims
            ],
            "citations": [
                {
                    "anchor": citation.anchor,
                    "evidence_sha256": citation.evidence_sha256,
                    "source_version_id": citation.source_version_id,
                }
                for citation in self.citations
            ],
            "related_targets": list(self.related_targets),
            "workspace_path": self.workspace_path,
            "candidate_state": self.candidate_state,
            "effective_context": self.effective_context,
            "committed": self.committed,
            "restart_verified": self.restart_verified,
            "synthetic_only": self.synthetic_only,
            "fixture_marker": self.fixture_marker,
            "component": COMPONENT,
        }


@dataclass(frozen=True)
class OperatingViewRequest:
    """One bounded natural request after host parsing; no arbitrary search expression is accepted."""

    target: str
    intent: Literal["continuity", "decision_dependency", "next_evidence"]
    as_of_event_sequence: int | None = None
    effective_context: str | None = None
    result_budget: int = 8
    scope_item_ids: tuple[str, ...] = ()
    include_history: bool = False


@dataclass(frozen=True)
class OperatingViewResult:
    """One read-only clean preview plus machine-readable selection/citation bindings."""

    status: Literal[
        "complete", "unavailable", "ambiguous", "narrow_scope_required", "rebuild_required"
    ]
    request: OperatingViewRequest
    canonical_watermark: str | None
    selected: OperatingViewCandidate | None
    alternatives: tuple[OperatingViewCandidate, ...]
    markdown: str
    evidence_companion: str
    sidecar: dict[str, object]


class OperatingViewCoordinator:
    """Resolve supplied hostile fixture candidates with deterministic, explainable selection."""

    def __init__(self, candidates: tuple[OperatingViewCandidate, ...]) -> None:
        self.candidates = candidates

    def query(self, request: OperatingViewRequest) -> OperatingViewResult:
        """Return a U0-only preview; it neither reads nor writes any runtime or private bundle."""

        self._validate_request(request)
        integrity = self._integrity_failure()
        if integrity is not None:
            return self._result("rebuild_required", request, None, (), integrity)
        target = _normalize(request.target)
        eligible = tuple(candidate for candidate in self.candidates if self._eligible(candidate, request))
        matches = tuple(
            (self._selection_key(candidate, request, target), candidate)
            for candidate in eligible
            if self._target_rank(candidate, target) is not None
        )
        if not matches:
            return self._result("unavailable", request, None, (), "No verified in-scope candidate matches the target.")
        if len(matches) > request.result_budget:
            return self._result(
                "narrow_scope_required",
                request,
                None,
                (),
                "The verified candidate set exceeds the declared result budget.",
            )
        ordered = tuple(sorted(matches, key=lambda item: (item[0], item[1].item_id, item[1].version_id)))
        best_key = ordered[0][0]
        best = tuple(candidate for key, candidate in ordered if key == best_key)
        material_ids = {(candidate.item_id, candidate.version_id) for candidate in best}
        if len(material_ids) > 1:
            return self._result(
                "ambiguous",
                request,
                None,
                best,
                "More than one materially distinct verified candidate has the same deterministic rank.",
            )
        return self._result("complete", request, best[0], (), None)

    def navigation(self) -> dict[str, str]:
        """Render logical generated navigation pages only; the caller decides later projection I/O."""

        integrity = self._integrity_failure()
        if integrity is not None:
            raise OperatingViewError("operating-view navigation requires a verified derived catalog")
        pages: dict[str, str] = {}
        for intent in sorted(_INTENTS):
            selected = [
                candidate
                for candidate in self.candidates
                if candidate.intent == intent and candidate.lifecycle == "active"
            ]
            lines = [f"# {intent.replace('_', ' ').title()}", "", "Generated operating-view navigation.", ""]
            for candidate in sorted(selected, key=lambda value: (value.display_alias.casefold(), value.item_id)):
                state = candidate.state
                candidate_label = (
                    f"; candidate: {candidate.candidate_state}" if candidate.candidate_state else ""
                )
                location = candidate.workspace_path or "derived view unavailable"
                lines.append(
                    f"- [{candidate.display_alias}]({location}) — {state}{candidate_label}; "
                    f"recorded event {candidate.canonical_event_sequence}."
                )
            if not selected:
                lines.append("- No verified active views are available.")
            pages[intent] = "\n".join(lines) + "\n"
        return pages

    def create_working_preview(
        self,
        result: OperatingViewResult,
        coordinator: WorkingArtifactCoordinator,
        *,
        idempotency_key: str,
    ) -> WorkingArtifactView:
        """Create one disposable revision from a complete result; no U1 selection is attempted."""

        candidate = self._require_complete(result)
        return coordinator.create(
            artifact_kind=_KIND_BY_INTENT[candidate.intent],
            display_alias=f"{candidate.display_alias} — {candidate.intent.replace('_', ' ')}",
            markdown=result.markdown,
            citations=tuple(binding.anchor for binding in candidate.citations),
            provenance=(
                {
                    "ref": f"{candidate.item_id}@{candidate.version_id}",
                    "digest": candidate.integrity_sha256,
                },
            ),
            idempotency_key=idempotency_key,
        )

    def revise_working_preview(
        self,
        result: OperatingViewResult,
        coordinator: WorkingArtifactCoordinator,
        prior: WorkingArtifactView,
        *,
        change_summary: str,
        idempotency_key: str,
    ) -> WorkingArtifactView:
        """Append a new temporary revision of a prior preview; source and canonical state stay unchanged."""

        candidate = self._require_complete(result)
        return coordinator.revise(
            prior.artifact_id,
            prior_revision_id=prior.revision_id,
            markdown=result.markdown,
            citations=tuple(binding.anchor for binding in candidate.citations),
            change_summary=change_summary,
            idempotency_key=idempotency_key,
        )

    def _eligible(self, candidate: OperatingViewCandidate, request: OperatingViewRequest) -> bool:
        if not candidate.committed or not candidate.restart_verified:
            return False
        # R1 has no generic source-excerpt fallback.  Returning a ledger in response to a
        # continuity request would look helpful but would silently change the operating-view contract.
        if candidate.intent != request.intent:
            return False
        if candidate.canonical_event_sequence > (request.as_of_event_sequence or candidate.canonical_event_sequence):
            return False
        if request.scope_item_ids and candidate.item_id not in request.scope_item_ids:
            return False
        if candidate.lifecycle != "active" and not request.include_history:
            return False
        if request.effective_context is not None and candidate.effective_context != request.effective_context:
            return False
        return True

    @staticmethod
    def _target_rank(candidate: OperatingViewCandidate, target: str) -> int | None:
        exact = {
            _normalize(candidate.item_id),
            _normalize(candidate.version_id),
            _normalize(candidate.display_alias),
            *(_normalize(alias) for alias in candidate.subject_aliases),
        }
        if candidate.workspace_path is not None:
            exact.add(_normalize(candidate.workspace_path))
        if target in exact:
            return 0
        if target in {_normalize(value) for value in candidate.related_targets}:
            return 1
        return None

    def _selection_key(
        self, candidate: OperatingViewCandidate, request: OperatingViewRequest, target: str
    ) -> tuple[int, int, int, int]:
        rank = self._target_rank(candidate, target)
        assert rank is not None
        intent_rank = 0 if candidate.intent == request.intent else 1
        effective_rank = 0 if request.effective_context == candidate.effective_context else 1
        return (rank, intent_rank, effective_rank, -candidate.canonical_event_sequence)

    def _integrity_failure(self) -> str | None:
        if not self.candidates:
            return "The supplied derived catalog is empty."
        watermarks = {candidate.canonical_watermark for candidate in self.candidates}
        if len(watermarks) != 1:
            return "The supplied derived catalog has no single canonical watermark."
        for candidate in self.candidates:
            try:
                self._validate_candidate(candidate)
            except OperatingViewError as exc:
                return str(exc)
        return None

    @staticmethod
    def _validate_request(request: OperatingViewRequest) -> None:
        if (
            request.intent not in _INTENTS
            or not isinstance(request.target, str)
            or not _normalize(request.target)
            or len(request.target.encode("utf-8")) > 240
            or request.result_budget < 1
            or request.result_budget > 32
            or (request.as_of_event_sequence is not None and request.as_of_event_sequence < 1)
            or len(request.scope_item_ids) != len(set(request.scope_item_ids))
            or any(not value for value in request.scope_item_ids)
        ):
            raise OperatingViewError("operating-view request is invalid")

    @staticmethod
    def _validate_candidate(candidate: OperatingViewCandidate) -> None:
        if (
            candidate.intent not in _INTENTS
            or candidate.state not in _STATES
            or candidate.lifecycle not in _LIFECYCLES
            or candidate.candidate_state not in _CANDIDATE_STATES | {None}
            or not candidate.item_id
            or not candidate.version_id
            or not candidate.display_alias
            or not candidate.subject_aliases
            or candidate.canonical_event_sequence < 1
            or not _is_digest(candidate.canonical_watermark)
            or candidate.index_watermark != candidate.canonical_watermark
            or not candidate.committed
            or not candidate.restart_verified
            or not candidate.synthetic_only
            or candidate.fixture_marker != _SYNTHETIC_MARKER
            or candidate.integrity_sha256 != canonical_sha256(candidate._material())
        ):
            raise OperatingViewError(
                "The supplied derived candidate requires rebuild or is outside the synthetic contract."
            )
        if candidate.workspace_path is not None and not _safe_workspace_path(candidate.workspace_path):
            raise OperatingViewError("The supplied derived candidate workspace path is invalid.")
        if not candidate.claims or not candidate.citations:
            raise OperatingViewError("The supplied derived candidate has no claim-bearing evidence.")
        catalog: dict[str, CitationBinding] = {}
        for binding in candidate.citations:
            if (
                not binding.anchor
                or not _is_digest(binding.evidence_sha256)
                or not binding.source_version_id
                or binding.anchor in catalog
            ):
                raise OperatingViewError("The supplied derived candidate citation binding is invalid.")
            catalog[binding.anchor] = binding
        for claim in candidate.claims:
            if (
                not claim.text.strip()
                or _SYNTHETIC_MARKER not in claim.text
                or not claim.citations
                or len(claim.citations) != len(set(claim.citations))
                or any(anchor not in catalog for anchor in claim.citations)
            ):
                raise OperatingViewError(
                    "The supplied derived candidate claim is uncited or outside the fixture contract."
                )

    def _result(
        self,
        status: Literal[
            "complete", "unavailable", "ambiguous", "narrow_scope_required", "rebuild_required"
        ],
        request: OperatingViewRequest,
        selected: OperatingViewCandidate | None,
        alternatives: tuple[OperatingViewCandidate, ...],
        reason: str | None,
    ) -> OperatingViewResult:
        if status not in _STATUSES:
            raise OperatingViewError("operating-view result status is invalid")
        watermark = selected.canonical_watermark if selected else self._watermark()
        if selected is None:
            markdown = self._noncomplete_markdown(status, request, reason)
            sidecar = {
                "component": COMPONENT,
                "status": status,
                "intent": request.intent,
                "target": request.target,
                "canonical_watermark": watermark,
                "alternatives": [self._safe_label(value) for value in alternatives],
                "reason": reason,
                "ephemeral": True,
                "no_automatic_persistence": True,
            }
            return OperatingViewResult(status, request, watermark, None, alternatives, markdown, "", sidecar)
        citation_numbers = {binding.anchor: index for index, binding in enumerate(selected.citations, start=1)}
        lines = [
            f"# {selected.display_alias}",
            "",
            f"Operating view: {request.intent.replace('_', ' ')}.",
            f"State: {selected.state}. Recorded event: {selected.canonical_event_sequence}.",
        ]
        if selected.candidate_state:
            lines.append(f"Method candidate: {selected.candidate_state}; no activation authority.")
        if selected.effective_context:
            lines.append(f"Effective context: {selected.effective_context}.")
        lines.extend(["", "## Evidence-backed view", ""])
        for claim in selected.claims:
            refs = " ".join(f"[E{citation_numbers[anchor]}]" for anchor in claim.citations)
            lines.append(f"- {claim.text} {refs}")
        lines.extend(
            [
                "",
                "## Scope and limits",
                "",
                "- This is a read-only, ephemeral view of committed selected material.",
                "- Reported, current, conflicting and unknown states are not interchangeable.",
                "- Open the optional evidence companion for exact anchors and digests.",
                "",
            ]
        )
        sidecar = {
            "component": COMPONENT,
            "status": "complete",
            "intent": request.intent,
            "target": request.target,
            "canonical_watermark": selected.canonical_watermark,
            "selected": {
                "item_id": selected.item_id,
                "version_id": selected.version_id,
                "integrity_sha256": selected.integrity_sha256,
                "selection_keys": {
                    "target_rank": self._target_rank(selected, _normalize(request.target)),
                    "intent": selected.intent,
                    "event_sequence": selected.canonical_event_sequence,
                    "effective_context": selected.effective_context,
                },
            },
            "citations": [
                {
                    "ordinal": citation_numbers[binding.anchor],
                    "anchor": binding.anchor,
                    "evidence_sha256": binding.evidence_sha256,
                    "source_version_id": binding.source_version_id,
                }
                for binding in selected.citations
            ],
            "ephemeral": True,
            "no_automatic_persistence": True,
            "no_authority": ["no_u1", "no_u2", "no_s2", "no_activation", "no_current_work"],
        }
        return OperatingViewResult(
            "complete",
            request,
            selected.canonical_watermark,
            selected,
            (),
            "\n".join(lines),
            self._evidence_companion(selected, citation_numbers),
            sidecar,
        )

    def _watermark(self) -> str | None:
        if not self.candidates:
            return None
        watermarks = {candidate.canonical_watermark for candidate in self.candidates}
        return next(iter(watermarks)) if len(watermarks) == 1 else None

    @staticmethod
    def _safe_label(candidate: OperatingViewCandidate) -> dict[str, str]:
        return {"item_id": candidate.item_id, "display_alias": candidate.display_alias}

    @staticmethod
    def _noncomplete_markdown(status: str, request: OperatingViewRequest, reason: str | None) -> str:
        title = status.replace("_", " ").title()
        detail = reason or "The requested view cannot be safely produced."
        return (
            f"# {title}\n\n"
            f"Requested operating view: {request.intent.replace('_', ' ')} for `{request.target}`.\n\n"
            f"{detail}\n\n"
            "No source, canonical record, candidate, current work item, receipt or action was created.\n"
        )

    @staticmethod
    def _evidence_companion(
        candidate: OperatingViewCandidate, numbers: dict[str, int]
    ) -> str:
        lines = [
            "# Evidence companion",
            "",
            "This companion binds the clean operating view to exact synthetic evidence anchors and digests.",
            "",
            "| Evidence | Source anchor | Source version | Evidence digest |",
            "| --- | --- | --- | --- |",
        ]
        for binding in candidate.citations:
            lines.append(
                f"| E{numbers[binding.anchor]} | `{binding.anchor}` | `{binding.source_version_id}` | "
                f"`{binding.evidence_sha256}` |"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _require_complete(result: OperatingViewResult) -> OperatingViewCandidate:
        if result.status != "complete" or result.selected is None:
            raise OperatingViewError("only a complete operating view can become a temporary working artifact")
        return result.selected


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _safe_workspace_path(value: str) -> bool:
    return (
        value.startswith("workspace/")
        and ".." not in value.split("/")
        and "\\" not in value
        and "\x00" not in value
        and len(value.encode("utf-8")) <= 512
    )
