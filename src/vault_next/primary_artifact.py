"""Shared context selection and primary-artifact-first U0 coordination.

This component accepts only caller-supplied hostile synthetic descriptors and Markdown. It creates
an ephemeral context manifest, composes one primary working artifact with linked supporting
artifacts, and produces a complete selection for a later U1 proposal. It never reads a source or
private bundle, issues a receipt, persists canonical state, invokes a model, or performs U2 work.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from vault_next.canonical import canonical_bytes, canonical_sha256
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.records import SchemaRegistry
from vault_next.working_artifact import (
    WorkingArtifactCoordinator,
    WorkingArtifactError,
    WorkingArtifactView,
)


COMPONENT_ID = "vault-next-primary-artifact"
COMPONENT_VERSION = "0.1.0"
COMPONENT = f"{COMPONENT_ID}/{COMPONENT_VERSION}"
_ZERO_HASH = "0" * 64
_SYNTHETIC_MARKER = "VAULT_NEXT_HOSTILE_FIXTURE"
_MODES = frozenset({"new_only", "selected_history", "bounded_relevant_history"})
_OUTCOMES = frozenset(
    {"meeting", "work", "deep_dive", "decision", "knowledge", "executive_report"}
)
_KINDS = frozenset(
    {"source", "artifact", "work", "decision", "knowledge", "conversation_evidence"}
)
_ARTIFACT_KINDS = frozenset(
    {"meeting_debrief", "work_continuity", "deep_dive", "decision", "knowledge", "outbound"}
)
_SKILL_STATES = frozenset({"inactive", "evaluating", "active"})
_DISCLOSURES = frozenset({"local_only", "visible_hosted_reasoning"})


class PrimaryArtifactError(RuntimeError):
    """The shared context or primary-artifact contract was violated."""


@dataclass(frozen=True)
class ContextCandidate:
    """One caller-supplied synthetic descriptor; it carries no content-read capability."""

    ref_id: str
    version_id: str
    display_alias: str
    kind: Literal[
        "source", "artifact", "work", "decision", "knowledge", "conversation_evidence"
    ]
    role: Literal["new", "history"]
    content_sha256: str
    aliases: tuple[str, ...]
    related_refs: tuple[str, ...]
    recorded_sequence: int
    committed: bool
    restart_verified: bool
    synthetic_only: bool = True
    fixture_marker: str = _SYNTHETIC_MARKER
    integrity_sha256: str = _ZERO_HASH

    def sealed(self) -> ContextCandidate:
        """Return the descriptor with an exact integrity binding."""

        return replace(self, integrity_sha256=canonical_sha256(self._material()))

    def _material(self) -> dict[str, Any]:
        return {
            "ref_id": self.ref_id,
            "version_id": self.version_id,
            "display_alias": self.display_alias,
            "kind": self.kind,
            "role": self.role,
            "content_sha256": self.content_sha256,
            "aliases": list(self.aliases),
            "related_refs": list(self.related_refs),
            "recorded_sequence": self.recorded_sequence,
            "committed": self.committed,
            "restart_verified": self.restart_verified,
            "synthetic_only": self.synthetic_only,
            "fixture_marker": self.fixture_marker,
            "component": COMPONENT,
        }


@dataclass(frozen=True)
class ContextSelectionRequest:
    """One already-parsed natural request with an explicit context policy."""

    request_id: str
    request_text: str
    requested_outcome: Literal[
        "meeting", "work", "deep_dive", "decision", "knowledge", "executive_report"
    ]
    primary_artifact_kind: Literal[
        "meeting_debrief", "work_continuity", "deep_dive", "decision", "knowledge", "outbound"
    ]
    skill_id: str
    skill_version: str
    skill_state: Literal["inactive", "evaluating", "active"]
    mode: Literal["new_only", "selected_history", "bounded_relevant_history"] = (
        "bounded_relevant_history"
    )
    new_item_ids: tuple[str, ...] = ()
    selected_history_ids: tuple[str, ...] = ()
    target_aliases: tuple[str, ...] = ()
    excluded_ids: tuple[str, ...] = ()
    history_kinds: tuple[str, ...] = ()
    history_limit: int = 4
    disclosure: Literal["local_only", "visible_hosted_reasoning"] = (
        "visible_hosted_reasoning"
    )
    default_mode_applied: bool = True


@dataclass(frozen=True)
class ContextSelectionResult:
    """A digest-bound visible selection plus the exact included descriptors."""

    manifest: dict[str, Any]
    included: tuple[ContextCandidate, ...]


@dataclass(frozen=True)
class SupportArtifactDraft:
    """One clean Markdown support view linked beneath the primary artifact."""

    artifact_kind: str
    display_alias: str
    support_role: str
    markdown: str
    citations: tuple[str, ...]


@dataclass(frozen=True)
class PrimaryArtifactPackage:
    """One primary-first ephemeral package and its workbench views."""

    record: dict[str, Any]
    primary: WorkingArtifactView
    supporting: tuple[WorkingArtifactView, ...]


@dataclass(frozen=True)
class PrimaryArtifactRetrieval:
    """Read-only primary-first navigation over one verified ephemeral package."""

    primary_markdown_path: Path
    supporting_markdown_paths: tuple[Path, ...]
    navigation_markdown: str
    package_digest: str


class ContextSelectionCoordinator:
    """Select synthetic new/prior descriptors with no ambient or source fallback."""

    def __init__(self, candidates: tuple[ContextCandidate, ...], schemas: SchemaRegistry) -> None:
        self.schemas = schemas
        self.candidates = candidates
        self._index: dict[str, ContextCandidate] = {}
        for candidate in candidates:
            self._require_candidate(candidate)
            if candidate.ref_id in self._index:
                raise PrimaryArtifactError("context candidate identity is duplicated")
            self._index[candidate.ref_id] = candidate

    def select(self, request: ContextSelectionRequest) -> ContextSelectionResult:
        """Return the bounded visible context selection for one U0 artifact run."""

        self._require_request(request)
        unavailable: list[str] = []
        excluded: list[dict[str, str]] = []
        included: list[tuple[ContextCandidate, str]] = []

        for ref_id in request.new_item_ids:
            candidate = self._index.get(ref_id)
            if candidate is None or candidate.role != "new":
                unavailable.append(f"new input unavailable: {ref_id}")
                continue
            included.append((candidate, "explicit new input"))

        prior_reads = 0
        if request.mode == "new_only":
            excluded.extend(
                {"ref_id": candidate.ref_id, "reason": "new_only excludes prior context"}
                for candidate in self.candidates
                if candidate.role == "history"
            )
        elif request.mode == "selected_history":
            for ref_id in request.selected_history_ids:
                candidate = self._index.get(ref_id)
                if candidate is None or candidate.role != "history":
                    unavailable.append(f"selected history unavailable: {ref_id}")
                    continue
                prior_reads += 1
                included.append((candidate, "explicit selected history"))
            selected = set(request.selected_history_ids)
            excluded.extend(
                {"ref_id": candidate.ref_id, "reason": "not explicitly selected"}
                for candidate in self.candidates
                if candidate.role == "history" and candidate.ref_id not in selected
            )
        else:
            ranked = self._bounded_history(request, excluded)
            chosen = ranked[: request.history_limit]
            prior_reads = len(chosen)
            included.extend((candidate, reason) for _, candidate, reason in chosen)
            excluded.extend(
                {"ref_id": candidate.ref_id, "reason": "bounded history limit"}
                for _, candidate, _ in ranked[request.history_limit :]
            )
            if not chosen:
                unavailable.append("no bounded relevant history matched; no fallback used")

        if request.excluded_ids:
            explicitly_excluded = set(request.excluded_ids)
            included = [
                item for item in included if item[0].ref_id not in explicitly_excluded
            ]
            known_excluded = {item["ref_id"] for item in excluded}
            excluded.extend(
                {"ref_id": ref_id, "reason": "explicitly excluded"}
                for ref_id in request.excluded_ids
                if ref_id not in known_excluded
            )

        included_candidates = tuple(candidate for candidate, _ in included)
        included_records = [
            {
                "ref_id": candidate.ref_id,
                "version_id": candidate.version_id,
                "display_alias": candidate.display_alias,
                "kind": candidate.kind,
                "role": candidate.role,
                "content_sha256": candidate.content_sha256,
                "recorded_sequence": candidate.recorded_sequence,
                "reason": reason,
            }
            for candidate, reason in included
        ]
        blocking_unavailable = any(
            value.startswith(("new input unavailable:", "selected history unavailable:"))
            for value in unavailable
        )
        status = "unavailable" if blocking_unavailable or not included_records else "complete"
        summary = (
            f"Mode {request.mode}: included {len(included_records)} item(s), omitted "
            f"{len(excluded)} item(s), unavailable {len(unavailable)}; prior reads {prior_reads}."
        )
        manifest: dict[str, Any] = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "request_id": request.request_id,
            "request_text": request.request_text.strip(),
            "requested_outcome": request.requested_outcome,
            "primary_artifact_kind": request.primary_artifact_kind,
            "skill": {
                "skill_id": request.skill_id,
                "version": request.skill_version,
                "state": request.skill_state,
                "visible": True,
            },
            "mode": request.mode,
            "default_mode_applied": request.default_mode_applied,
            "new_item_ids": list(request.new_item_ids),
            "selected_history_ids": list(request.selected_history_ids),
            "target_aliases": list(request.target_aliases),
            "included": included_records,
            "excluded": _deduplicate_exclusions(excluded),
            "unavailable": unavailable,
            "prior_context_reads": prior_reads,
            "processing": {
                "disclosure": request.disclosure,
                "retention": "u0_ephemeral",
            },
            "status": status,
            "summary": summary,
            "no_source_fallback": True,
            "u0_only": True,
            "selection_digest": _ZERO_HASH,
        }
        manifest["selection_digest"] = canonical_sha256(manifest)
        self.verify(manifest)
        return ContextSelectionResult(manifest, included_candidates)

    def verify(self, manifest: dict[str, Any]) -> None:
        """Verify one shared selection without resolving another source."""

        self.schemas.require("context-selection-manifest", manifest)
        if manifest["selection_digest"] != canonical_sha256(
            {**manifest, "selection_digest": _ZERO_HASH}
        ):
            raise PrimaryArtifactError("context selection digest changed")
        if manifest["mode"] == "new_only" and (
            manifest["prior_context_reads"] != 0
            or any(item["role"] == "history" for item in manifest["included"])
        ):
            raise PrimaryArtifactError("new_only context included prior material")
        if manifest["status"] == "complete" and not manifest["included"]:
            raise PrimaryArtifactError("complete context selection is empty")

    def _bounded_history(
        self,
        request: ContextSelectionRequest,
        excluded: list[dict[str, str]],
    ) -> list[tuple[tuple[int, int, str], ContextCandidate, str]]:
        targets = {_normalized(value) for value in request.target_aliases}
        new_refs = set(request.new_item_ids)
        kinds = set(request.history_kinds)
        explicit_exclusions = set(request.excluded_ids)
        ranked: list[tuple[tuple[int, int, str], ContextCandidate, str]] = []
        for candidate in self.candidates:
            if candidate.role != "history":
                continue
            if candidate.ref_id in explicit_exclusions:
                excluded.append(
                    {"ref_id": candidate.ref_id, "reason": "explicitly excluded"}
                )
                continue
            if kinds and candidate.kind not in kinds:
                excluded.append(
                    {"ref_id": candidate.ref_id, "reason": "kind outside bounded request"}
                )
                continue
            aliases = {_normalized(candidate.display_alias)} | {
                _normalized(value) for value in candidate.aliases
            }
            related = set(candidate.related_refs)
            if targets & aliases:
                rank, reason = 0, "exact bounded subject alias"
            elif new_refs & related:
                rank, reason = 1, "direct relationship to selected new input"
            elif targets & {_normalized(value) for value in related}:
                rank, reason = 2, "direct bounded subject relationship"
            else:
                excluded.append(
                    {"ref_id": candidate.ref_id, "reason": "not bounded relevant history"}
                )
                continue
            ranked.append(
                ((rank, -candidate.recorded_sequence, candidate.ref_id), candidate, reason)
            )
        return sorted(ranked, key=lambda item: item[0])

    def _require_candidate(self, candidate: ContextCandidate) -> None:
        if (
            not candidate.ref_id
            or not candidate.version_id
            or not candidate.display_alias.strip()
            or candidate.kind not in _KINDS
            or candidate.role not in {"new", "history"}
            or not _is_digest(candidate.content_sha256)
            or candidate.recorded_sequence < 0
            or not candidate.synthetic_only
            or candidate.fixture_marker != _SYNTHETIC_MARKER
            or candidate.integrity_sha256 != canonical_sha256(candidate._material())
        ):
            raise PrimaryArtifactError("context candidate is invalid or unsealed")
        if candidate.role == "history" and (
            not candidate.committed or not candidate.restart_verified
        ):
            raise PrimaryArtifactError("history candidate is not committed and restart verified")
        if len(candidate.aliases) != len(set(candidate.aliases)) or len(
            candidate.related_refs
        ) != len(set(candidate.related_refs)):
            raise PrimaryArtifactError("context candidate aliases or relationships are duplicated")

    @staticmethod
    def _require_request(request: ContextSelectionRequest) -> None:
        if (
            not request.request_text.strip()
            or request.requested_outcome not in _OUTCOMES
            or request.primary_artifact_kind not in _ARTIFACT_KINDS
            or request.mode not in _MODES
            or request.skill_state not in _SKILL_STATES
            or not request.skill_id
            or not request.skill_version
            or request.disclosure not in _DISCLOSURES
            or request.history_limit < 1
            or request.history_limit > 8
        ):
            raise PrimaryArtifactError("context selection request is invalid")
        if not request.request_id.startswith("request_"):
            raise PrimaryArtifactError("context selection request identity is invalid")
        values = (
            request.new_item_ids,
            request.selected_history_ids,
            request.target_aliases,
            request.excluded_ids,
            request.history_kinds,
        )
        if any(len(value) != len(set(value)) for value in values):
            raise PrimaryArtifactError("context selection request contains duplicate values")
        if request.mode == "new_only" and request.selected_history_ids:
            raise PrimaryArtifactError("new_only may not name selected history")
        if request.mode != "selected_history" and request.selected_history_ids:
            raise PrimaryArtifactError("selected history IDs require selected_history mode")
        if request.mode == "selected_history" and request.default_mode_applied:
            raise PrimaryArtifactError("an explicit history selection cannot be the default mode")
        if set(request.selected_history_ids) & set(request.excluded_ids):
            raise PrimaryArtifactError("selected history cannot also be explicitly excluded")
        if any(kind not in _KINDS for kind in request.history_kinds):
            raise PrimaryArtifactError("context history kind is invalid")


class PrimaryArtifactCoordinator:
    """Compose and verify one primary U0 artifact plus linked supporting views."""

    def __init__(
        self,
        workbench: WorkingArtifactCoordinator,
        schemas: SchemaRegistry,
        context_selection: dict[str, Any],
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        resume: bool = False,
    ) -> None:
        self.workbench = workbench
        self.schemas = schemas
        self.ids = id_factory
        self.root = workbench.root
        self.context_path = self.root / "context-selection.json"
        self.package_root = self.root / "primary-packages"
        _verify_context_record(schemas, context_selection)
        if context_selection["status"] != "complete":
            raise PrimaryArtifactError("an unavailable context selection cannot create an artifact")
        self.context_selection = context_selection
        if resume:
            if self.context_path.is_symlink() or not self.context_path.is_file():
                raise PrimaryArtifactError("primary-artifact context record is unavailable")
            if self.context_path.read_bytes() != canonical_bytes(context_selection):
                raise PrimaryArtifactError("primary-artifact context record changed")
            self.verify()
            return
        if self.context_path.exists() or self.context_path.is_symlink():
            raise PrimaryArtifactError("primary-artifact context record already exists")
        _write_new(self.context_path, canonical_bytes(context_selection))
        self.package_root.mkdir(mode=0o700)

    def create(
        self,
        *,
        primary_display_alias: str,
        primary_markdown: str,
        primary_citations: tuple[str, ...],
        supporting: tuple[SupportArtifactDraft, ...],
        idempotency_key: str,
    ) -> PrimaryArtifactPackage:
        """Create one primary working revision and zero or more linked support revisions."""

        request_digest = canonical_sha256(
            {
                "operation": "create",
                "context_selection_digest": self.context_selection["selection_digest"],
                "primary_artifact_kind": self.context_selection["primary_artifact_kind"],
                "primary_display_alias": primary_display_alias,
                "primary_markdown": primary_markdown,
                "primary_citations": list(primary_citations),
                "supporting": [
                    {
                        "artifact_kind": item.artifact_kind,
                        "display_alias": item.display_alias,
                        "support_role": item.support_role,
                        "markdown": item.markdown,
                        "citations": list(item.citations),
                    }
                    for item in supporting
                ],
            }
        )
        existing = self._idempotent_package(idempotency_key, request_digest)
        if existing is not None:
            return self._package_view(existing)
        _require_key(idempotency_key)
        roles = [item.support_role for item in supporting]
        if len(roles) != len(set(roles)):
            raise PrimaryArtifactError("primary-artifact support roles are duplicated")
        provenance = (
            {
                "ref": f"context-selection:{self.context_selection['request_id']}",
                "digest": self.context_selection["selection_digest"],
            },
        )
        try:
            primary = self.workbench.create(
                artifact_kind=self.context_selection["primary_artifact_kind"],
                display_alias=primary_display_alias,
                markdown=primary_markdown,
                citations=primary_citations,
                provenance=provenance,
                idempotency_key=f"{idempotency_key}:primary",
            )
            support_views = tuple(
                self.workbench.create(
                    artifact_kind=item.artifact_kind,
                    display_alias=item.display_alias,
                    markdown=item.markdown,
                    citations=item.citations,
                    provenance=provenance,
                    idempotency_key=f"{idempotency_key}:support:{index}",
                )
                for index, item in enumerate(supporting, start=1)
            )
        except WorkingArtifactError as exc:
            raise PrimaryArtifactError(str(exc)) from exc
        record = self._record(
            primary=primary,
            support_views=support_views,
            support_roles=tuple(roles),
            package_revision=1,
            prior_package_digest=None,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        self._write_package(record)
        return PrimaryArtifactPackage(record, primary, support_views)

    def revise_primary(
        self,
        primary_artifact_id: str,
        *,
        prior_revision_id: str,
        markdown: str,
        citations: tuple[str, ...],
        change_summary: str,
        idempotency_key: str,
    ) -> PrimaryArtifactPackage:
        """Append one primary revision while preserving the exact linked support revisions."""

        latest = self._latest_for(primary_artifact_id)
        request_digest = canonical_sha256(
            {
                "operation": "revise_primary",
                "prior_package_digest": latest["package_digest"],
                "prior_revision_id": prior_revision_id,
                "markdown": markdown,
                "citations": list(citations),
                "change_summary": change_summary,
            }
        )
        existing = self._idempotent_package(idempotency_key, request_digest)
        if existing is not None:
            return self._package_view(existing)
        _require_key(idempotency_key)
        if latest["primary"]["revision_id"] != prior_revision_id:
            raise PrimaryArtifactError("primary-artifact revision base is stale")
        try:
            revised = self.workbench.revise(
                primary_artifact_id,
                prior_revision_id=prior_revision_id,
                markdown=markdown,
                citations=citations,
                change_summary=change_summary,
                idempotency_key=f"{idempotency_key}:primary",
            )
        except WorkingArtifactError as exc:
            raise PrimaryArtifactError(str(exc)) from exc
        supports = tuple(self._view_for_ref(item) for item in latest["supporting_artifacts"])
        record = self._record(
            primary=revised,
            support_views=supports,
            support_roles=tuple(item["support_role"] for item in latest["supporting_artifacts"]),
            package_revision=latest["package_revision"] + 1,
            prior_package_digest=latest["package_digest"],
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        self._write_package(record)
        return PrimaryArtifactPackage(record, revised, supports)

    def retrieve(self, target: str) -> PrimaryArtifactRetrieval:
        """Return exactly one verified primary artifact before its linked support views."""

        records = self.verify()
        matches = [
            record
            for record in records
            if target in {record["primary"]["artifact_id"], record["primary"]["display_alias"]}
        ]
        latest = _latest_packages(matches)
        if not latest:
            raise PrimaryArtifactError("primary artifact is unavailable")
        if len(latest) != 1:
            raise PrimaryArtifactError("primary artifact target is ambiguous")
        record = latest[0]
        primary = self._view_for_ref(record["primary"])
        supports = tuple(
            self._view_for_ref(item) for item in record["supporting_artifacts"]
        )
        lines = [
            f"# {primary.display_alias}",
            "",
            f"Primary: {primary.markdown_path}",
            "",
            "## Supporting package",
            "",
        ]
        lines.extend(
            f"- {item['support_role']}: {view.markdown_path}"
            for item, view in zip(record["supporting_artifacts"], supports, strict=True)
        )
        if not supports:
            lines.append("- No additional support artifacts.")
        return PrimaryArtifactRetrieval(
            primary.markdown_path,
            tuple(view.markdown_path for view in supports),
            "\n".join(lines) + "\n",
            record["package_digest"],
        )

    def select_for_u1(
        self, primary_artifact_id: str, *, target_state: str
    ) -> dict[str, Any]:
        """Describe a complete exact package for later confirmation; issue no receipt."""

        package = self._latest_for(primary_artifact_id)
        try:
            primary = self.workbench.select_for_u1(
                primary_artifact_id,
                package["primary"]["revision_id"],
                target_state=target_state,
            )
            supporting = [
                self.workbench.select_for_u1(
                    item["artifact_id"], item["revision_id"], target_state=target_state
                )
                for item in package["supporting_artifacts"]
            ]
        except WorkingArtifactError as exc:
            raise PrimaryArtifactError(str(exc)) from exc
        record = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": "chat_first_u1_primary_artifact_save_proposal",
            "package_digest": package["package_digest"],
            "context_selection_digest": package["context_selection_digest"],
            "target_state": target_state,
            "primary_selection": primary.record,
            "supporting_selections": [item.record for item in supporting],
            "complete_package": True,
            "requires_confirmation": True,
            "no_receipt_issued": True,
            "u2_authority": False,
            "selection_digest": _ZERO_HASH,
        }
        record["selection_digest"] = canonical_sha256(record)
        self.schemas.require("primary-artifact-u1-selection", record)
        return record

    def verify(self) -> tuple[dict[str, Any], ...]:
        """Verify context, workbench revisions, packages, links and primary-first ordering."""

        _verify_context_record(self.schemas, self.context_selection)
        try:
            self.workbench.verify()
        except WorkingArtifactError as exc:
            raise PrimaryArtifactError(str(exc)) from exc
        if self.context_path.is_symlink() or not self.context_path.is_file():
            raise PrimaryArtifactError("primary-artifact context record is unavailable")
        if self.context_path.read_bytes() != canonical_bytes(self.context_selection):
            raise PrimaryArtifactError("primary-artifact context record changed")
        if self.package_root.is_symlink() or not self.package_root.is_dir():
            raise PrimaryArtifactError("primary-artifact package root is unavailable")
        records: list[dict[str, Any]] = []
        lineage: dict[str, list[dict[str, Any]]] = {}
        for path in sorted(self.package_root.rglob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise PrimaryArtifactError("primary-artifact package path is unsafe")
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PrimaryArtifactError("primary-artifact package is invalid") from exc
            self._verify_record(record)
            records.append(record)
            lineage.setdefault(record["primary"]["artifact_id"], []).append(record)
        for packages in lineage.values():
            ordered = sorted(packages, key=lambda item: item["package_revision"])
            expected_prior = None
            for number, record in enumerate(ordered, start=1):
                if (
                    record["package_revision"] != number
                    or record["prior_package_digest"] != expected_prior
                ):
                    raise PrimaryArtifactError("primary-artifact package lineage changed")
                expected_prior = record["package_digest"]
        return tuple(records)

    def _record(
        self,
        *,
        primary: WorkingArtifactView,
        support_views: tuple[WorkingArtifactView, ...],
        support_roles: tuple[str, ...],
        package_revision: int,
        prior_package_digest: str | None,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any]:
        primary_ref = self._artifact_ref(primary)
        support_refs = []
        relationships = []
        for role, view in zip(support_roles, support_views, strict=True):
            item = self._artifact_ref(view)
            item["support_role"] = role
            support_refs.append(item)
            relationship = {
                "assertion_id": self.ids.new("relationship_ledger"),
                "origin_version_id": view.revision_id,
                "target_version_id": primary.revision_id,
                "type": "supports",
                "source_anchor": self.context_selection["selection_digest"],
                "state": "asserted",
            }
            self.schemas.require("relationship-assertion", relationship)
            relationships.append(relationship)
        record: dict[str, Any] = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "context_selection_digest": self.context_selection["selection_digest"],
            "skill": self.context_selection["skill"],
            "package_revision": package_revision,
            "prior_package_digest": prior_package_digest,
            "primary": primary_ref,
            "supporting_artifacts": support_refs,
            "relationships": relationships,
            "retrieval_order": [
                primary.artifact_id,
                *(view.artifact_id for view in support_views),
            ],
            "primary_first": True,
            "no_automatic_persistence": True,
            "u1_requires_confirmation": True,
            "u2_authority": False,
            "idempotency_key": idempotency_key,
            "request_digest": request_digest,
            "package_digest": _ZERO_HASH,
        }
        record["package_digest"] = canonical_sha256(record)
        self._verify_record(record)
        return record

    def _verify_record(self, record: dict[str, Any]) -> None:
        self.schemas.require("primary-artifact-package", record)
        if record["package_digest"] != canonical_sha256(
            {**record, "package_digest": _ZERO_HASH}
        ):
            raise PrimaryArtifactError("primary-artifact package digest changed")
        if record["context_selection_digest"] != self.context_selection["selection_digest"]:
            raise PrimaryArtifactError("primary-artifact context binding changed")
        expected_order = [record["primary"]["artifact_id"]] + [
            item["artifact_id"] for item in record["supporting_artifacts"]
        ]
        if record["retrieval_order"] != expected_order:
            raise PrimaryArtifactError("primary-artifact retrieval order changed")
        primary = self._view_for_ref(record["primary"])
        for item, relationship in zip(
            record["supporting_artifacts"], record["relationships"], strict=True
        ):
            support = self._view_for_ref(item)
            self.schemas.require("relationship-assertion", relationship)
            if (
                relationship["origin_version_id"] != support.revision_id
                or relationship["target_version_id"] != primary.revision_id
                or relationship["type"] != "supports"
                or relationship["source_anchor"] != record["context_selection_digest"]
            ):
                raise PrimaryArtifactError("primary-artifact support relationship changed")
        if len(record["supporting_artifacts"]) != len(record["relationships"]):
            raise PrimaryArtifactError("primary-artifact support relationship count changed")

    def _artifact_ref(self, view: WorkingArtifactView) -> dict[str, Any]:
        revision = self._revision_record(view.artifact_id, view.revision_id)
        return {
            "artifact_id": view.artifact_id,
            "revision_id": view.revision_id,
            "revision_number": view.revision_number,
            "artifact_kind": view.artifact_kind,
            "display_alias": view.display_alias,
            "content_sha256": view.content_sha256,
            "revision_digest": view.revision_digest,
            "relative_path": revision["relative_path"],
            "lifecycle_state": "working",
        }

    def _revision_record(self, artifact_id: str, revision_id: str) -> dict[str, Any]:
        manifest = self.workbench.verify()
        for artifact in manifest["artifacts"]:
            if artifact["artifact_id"] != artifact_id:
                continue
            for revision in artifact["revisions"]:
                if revision["revision_id"] == revision_id:
                    return revision
        raise PrimaryArtifactError("primary-artifact revision is unavailable")

    def _view_for_ref(self, reference: dict[str, Any]) -> WorkingArtifactView:
        revision = self._revision_record(reference["artifact_id"], reference["revision_id"])
        manifest = self.workbench.verify()
        artifact = next(
            item
            for item in manifest["artifacts"]
            if item["artifact_id"] == reference["artifact_id"]
        )
        view = WorkingArtifactView(
            artifact_id=artifact["artifact_id"],
            revision_id=revision["revision_id"],
            revision_number=revision["revision_number"],
            artifact_kind=artifact["artifact_kind"],
            display_alias=artifact["display_alias"],
            markdown_path=self.root / revision["relative_path"],
            content_sha256=revision["content_sha256"],
            revision_digest=revision["revision_digest"],
        )
        expected = {key: value for key, value in reference.items() if key != "support_role"}
        if self._artifact_ref(view) != expected:
            raise PrimaryArtifactError("primary-artifact revision reference changed")
        return view

    def _latest_for(self, artifact_id: str) -> dict[str, Any]:
        records = [
            record
            for record in self.verify()
            if record["primary"]["artifact_id"] == artifact_id
        ]
        if not records:
            raise PrimaryArtifactError("primary-artifact package is unavailable")
        return max(records, key=lambda item: item["package_revision"])

    def _idempotent_package(
        self, idempotency_key: str, request_digest: str
    ) -> dict[str, Any] | None:
        _require_key(idempotency_key)
        matches = [
            record
            for record in self.verify()
            if record["idempotency_key"] == idempotency_key
        ]
        if not matches:
            return None
        if len(matches) != 1 or matches[0]["request_digest"] != request_digest:
            raise PrimaryArtifactError("primary-artifact idempotency key was reused")
        return matches[0]

    def _package_view(self, record: dict[str, Any]) -> PrimaryArtifactPackage:
        return PrimaryArtifactPackage(
            record,
            self._view_for_ref(record["primary"]),
            tuple(self._view_for_ref(item) for item in record["supporting_artifacts"]),
        )

    def _write_package(self, record: dict[str, Any]) -> None:
        directory = self.package_root / record["primary"]["artifact_id"]
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / (
            f"{record['package_revision']:04d}-{record['package_digest']}.json"
        )
        _write_new(target, canonical_bytes(record))


def _verify_context_record(schemas: SchemaRegistry, record: dict[str, Any]) -> None:
    schemas.require("context-selection-manifest", record)
    if record["selection_digest"] != canonical_sha256(
        {**record, "selection_digest": _ZERO_HASH}
    ):
        raise PrimaryArtifactError("context selection digest changed")
    if record["status"] != "complete":
        return
    if not record["included"]:
        raise PrimaryArtifactError("complete context selection is empty")


def _latest_packages(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        artifact_id = record["primary"]["artifact_id"]
        previous = latest.get(artifact_id)
        if previous is None or record["package_revision"] > previous["package_revision"]:
            latest[artifact_id] = record
    return list(latest.values())


def _deduplicate_exclusions(values: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result = []
    for value in values:
        if value["ref_id"] in seen:
            continue
        seen.add(value["ref_id"])
        result.append(value)
    return result


def _normalized(value: str) -> str:
    return " ".join(value.casefold().split())


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _require_key(value: str) -> None:
    if not value or len(value.encode("utf-8")) > 220:
        raise PrimaryArtifactError("primary-artifact idempotency key is invalid")


def _write_new(path: Path, data: bytes) -> None:
    if path.is_symlink() or path.exists():
        raise PrimaryArtifactError("primary-artifact output already exists")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short primary-artifact write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
