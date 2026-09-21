"""Host-neutral U0 working-artifact review and revision boundary.

The coordinator owns only a disposable Markdown workbench beneath ``/private/tmp``.  It accepts
caller-supplied generated Markdown and citation/provenance bindings, creates immutable revisions,
and can describe one exact revision for a later ``chat_first_u1_save`` proposal.  It never reads a
source, writes the private bundle, invokes an authority, releases content, or performs a U2 effect.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import PrivateWorkspaceItem
from vault_next.readable_projections import (
    HEADER_PREFIX,
    HEADER_SUFFIX,
    parse_markdown_projection_header,
    verify_markdown_projection,
)
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT_ID = "vault-next-working-artifact"
COMPONENT_VERSION = "0.2.0"
COMPONENT = f"{COMPONENT_ID}/{COMPONENT_VERSION}"
_DISPOSABLE_PARENT = Path("/private/tmp")
_ZERO_HASH = "0" * 64
_MAX_MARKDOWN_BYTES = 1_048_576
_KINDS = {
    "meeting_debrief": ("meeting", "debriefs"),
    "meeting_continuity": ("work", "reported"),
    "meeting_preparation": ("meeting", "preparations"),
    "work_continuity": ("work", "reported"),
    "work_preparation": ("work", "reported"),
    "deep_dive": ("knowledge", "deep-dives"),
    "decision": ("decision", "reported"),
    "knowledge": ("knowledge", "articles"),
    "timeline": ("knowledge", "assertions"),
    "outbound": ("meeting", "outbound"),
}
_U1_STATES = frozenset({"review_copy", "final"})
_RAW_CITATION_GROUP = re.compile(
    r"[ \t]*\((paragraph:[0-9]{6}(?:,[ \t]*paragraph:[0-9]{6})*)\)"
)
_RAW_CITATION_TOKEN = re.compile(r"paragraph:[0-9]{6}")


class WorkingArtifactError(RuntimeError):
    """The ephemeral working-artifact contract was violated."""


@dataclass(frozen=True)
class WorkingArtifactView:
    artifact_id: str
    revision_id: str
    revision_number: int
    artifact_kind: str
    display_alias: str
    markdown_path: Path
    content_sha256: str
    revision_digest: str


@dataclass(frozen=True)
class WorkingArtifactSelection:
    """One exact working revision proposed for a later U1 confirmation."""

    record: dict[str, Any]
    markdown: str


class WorkingArtifactCoordinator:
    """Create and revise separate U0 Markdown artifacts without durable persistence."""

    def __init__(
        self,
        workbench_root: Path,
        schemas: SchemaRegistry,
        *,
        citation_catalog: dict[str, str],
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        resume: bool = False,
    ) -> None:
        self.root = (
            _open_disposable_root(workbench_root)
            if resume
            else _initialize_disposable_root(workbench_root)
        )
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock
        self.citation_catalog = _validate_citation_catalog(citation_catalog)
        self.manifest_path = self.root / "manifest.json"
        if resume:
            self.verify()
            return
        if self.manifest_path.exists() or self.manifest_path.is_symlink():
            raise WorkingArtifactError("working-artifact root is not fresh")
        self._write_manifest(
            {
                "schema_version": "1.0",
                "component": COMPONENT,
                "session_id": self.ids.new("session"),
                "workbench_root_id": sha256_hex(str(self.root).encode("utf-8")),
                "artifacts": [],
                "no_automatic_persistence": True,
                "u1_states": ["review_copy", "final"],
                "u2_state": "released",
                "manifest_digest": _ZERO_HASH,
            }
        )

    def create(
        self,
        *,
        artifact_kind: str,
        display_alias: str,
        markdown: str,
        citations: tuple[str, ...],
        provenance: tuple[dict[str, str], ...],
        idempotency_key: str,
    ) -> WorkingArtifactView:
        """Create one new stable artifact with immutable working revision 1."""

        manifest = self.verify()
        self._require_kind_alias(artifact_kind, display_alias)
        normalized = _validate_markdown(markdown)
        selected_citations = self._require_citations(citations)
        selected_provenance = _validate_provenance(provenance)
        request_digest = canonical_sha256(
            {
                "operation": "create",
                "artifact_kind": artifact_kind,
                "display_alias": display_alias,
                "content_sha256": sha256_hex(normalized.encode("utf-8")),
                "citations": list(selected_citations),
                "provenance": list(selected_provenance),
            }
        )
        existing = self._idempotent_revision(manifest, idempotency_key, request_digest)
        if existing is not None:
            return self._view(manifest, existing)
        artifact_id = self.ids.new("artifact")
        revision = self._revision_record(
            artifact_id=artifact_id,
            prior_revision_id=None,
            revision_number=1,
            markdown=normalized,
            citations=selected_citations,
            provenance=selected_provenance,
            change_summary="Initial working artifact",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        self._write_revision(revision, display_alias, artifact_kind, normalized)
        manifest["artifacts"].append(
            {
                "artifact_id": artifact_id,
                "artifact_kind": artifact_kind,
                "display_alias": display_alias,
                "lifecycle_state": "working",
                "current_revision_id": revision["revision_id"],
                "revisions": [revision],
            }
        )
        self._write_manifest(manifest)
        return self._view(manifest, revision)

    def revise(
        self,
        artifact_id: str,
        *,
        prior_revision_id: str,
        markdown: str,
        citations: tuple[str, ...],
        change_summary: str,
        idempotency_key: str,
    ) -> WorkingArtifactView:
        """Append one immutable working revision from the exact current revision."""

        manifest = self.verify()
        artifact = self._artifact(manifest, artifact_id)
        normalized = _validate_markdown(markdown)
        selected_citations = self._require_citations(citations)
        if not change_summary.strip() or len(change_summary.encode("utf-8")) > 2048:
            raise WorkingArtifactError("working-artifact change summary is invalid")
        prior = self._revision(artifact, prior_revision_id)
        request_digest = canonical_sha256(
            {
                "operation": "revise",
                "artifact_id": artifact_id,
                "prior_revision_id": prior_revision_id,
                "content_sha256": sha256_hex(normalized.encode("utf-8")),
                "citations": list(selected_citations),
                "change_summary": change_summary,
            }
        )
        existing = self._idempotent_revision(manifest, idempotency_key, request_digest)
        if existing is not None:
            return self._view(manifest, existing)
        if artifact["current_revision_id"] != prior_revision_id:
            raise WorkingArtifactError("working-artifact revision base is stale")
        revision = self._revision_record(
            artifact_id=artifact_id,
            prior_revision_id=prior_revision_id,
            revision_number=prior["revision_number"] + 1,
            markdown=normalized,
            citations=selected_citations,
            provenance=tuple(prior["provenance"]),
            change_summary=change_summary,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
        self._write_revision(
            revision, artifact["display_alias"], artifact["artifact_kind"], normalized
        )
        artifact["revisions"].append(revision)
        artifact["current_revision_id"] = revision["revision_id"]
        self._write_manifest(manifest)
        return self._view(manifest, revision)

    def select_for_u1(
        self, artifact_id: str, revision_id: str, *, target_state: str
    ) -> WorkingArtifactSelection:
        """Describe one exact revision for U1; this does not authorize or save it."""

        manifest = self.verify()
        artifact = self._artifact(manifest, artifact_id)
        revision = self._revision(artifact, revision_id)
        if target_state not in _U1_STATES:
            if target_state == "released":
                raise WorkingArtifactError("working-artifact release requires separate U2 authority")
            raise WorkingArtifactError("working-artifact U1 target state is invalid")
        record = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": "chat_first_u1_save",
            "artifact_id": artifact_id,
            "artifact_kind": artifact["artifact_kind"],
            "display_alias": artifact["display_alias"],
            "selected_revision_id": revision_id,
            "revision_number": revision["revision_number"],
            "revision_digest": revision["revision_digest"],
            "content_sha256": revision["content_sha256"],
            "citations": list(revision["citations"]),
            "citation_bindings": copy.deepcopy(revision["citation_bindings"]),
            "provenance": copy.deepcopy(revision["provenance"]),
            "target_state": target_state,
            "requires_confirmation": True,
            "release_requires": "U2",
            "selection_digest": _ZERO_HASH,
        }
        record["selection_digest"] = canonical_sha256(record)
        self.schemas.require("working-artifact-selection", record)
        return WorkingArtifactSelection(record, self._read_revision_markdown(revision))

    def workspace_item(self, selection: WorkingArtifactSelection) -> PrivateWorkspaceItem:
        """Map a selected revision into the existing derived P1/U1 item vocabulary."""

        self.schemas.require("working-artifact-selection", selection.record)
        if selection.record["selection_digest"] != canonical_sha256(
            {**selection.record, "selection_digest": _ZERO_HASH}
        ):
            raise WorkingArtifactError("working-artifact selection digest changed")
        if sha256_hex(selection.markdown.encode("utf-8")) != selection.record["content_sha256"]:
            raise WorkingArtifactError("working-artifact selected Markdown changed")
        family, view = _KINDS[selection.record["artifact_kind"]]
        return PrivateWorkspaceItem(
            item_id=selection.record["artifact_id"],
            version_id=selection.record["selected_revision_id"],
            family=family,
            view=view,
            status=selection.record["target_state"],
            display_alias=selection.record["display_alias"],
            canonical_object_sha256=_ZERO_HASH,
            admission_event_id="event-pending",
            body=selection.markdown,
            citations=tuple(selection.record["citations"]),
            candidate_inactive=False,
        )

    def evaluation_record(
        self,
        artifact_id: str,
        revision_id: str,
        *,
        platform_integrity: str,
        workflow_experience: str,
        artifact_disposition: str,
        skill_candidate_state: str,
        skill_candidate_version: str | None,
    ) -> dict[str, Any]:
        """Return four independent review gates; no score or gate substitutes for another."""

        manifest = self.verify()
        artifact = self._artifact(manifest, artifact_id)
        revision = self._revision(artifact, revision_id)
        record = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "artifact_id": artifact_id,
            "revision_id": revision_id,
            "revision_digest": revision["revision_digest"],
            "platform_integrity": platform_integrity,
            "workflow_experience": workflow_experience,
            "artifact_disposition": artifact_disposition,
            "skill_candidate_state": skill_candidate_state,
            "skill_candidate_version": skill_candidate_version,
            "independent_gates": True,
            "activation_authority": False,
        }
        self.schemas.require("working-artifact-evaluation", record)
        return record

    def verify(self) -> dict[str, Any]:
        """Verify the complete ephemeral manifest, lineage, and every Markdown revision."""

        if self.manifest_path.is_symlink() or not self.manifest_path.is_file():
            raise WorkingArtifactError("working-artifact manifest is unavailable")
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkingArtifactError("working-artifact manifest is invalid") from exc
        self.schemas.require("working-artifact-session", manifest)
        if manifest["manifest_digest"] != canonical_sha256(
            {**manifest, "manifest_digest": _ZERO_HASH}
        ):
            raise WorkingArtifactError("working-artifact manifest digest changed")
        if manifest["workbench_root_id"] != sha256_hex(str(self.root).encode("utf-8")):
            raise WorkingArtifactError("working-artifact root binding changed")
        seen_artifacts: set[str] = set()
        seen_revisions: set[str] = set()
        for artifact in manifest["artifacts"]:
            if artifact["artifact_id"] in seen_artifacts:
                raise WorkingArtifactError("working-artifact identity is duplicated")
            seen_artifacts.add(artifact["artifact_id"])
            expected_prior = None
            for number, revision in enumerate(artifact["revisions"], start=1):
                if revision["revision_id"] in seen_revisions:
                    raise WorkingArtifactError("working-artifact revision identity is duplicated")
                seen_revisions.add(revision["revision_id"])
                if (
                    revision["artifact_id"] != artifact["artifact_id"]
                    or revision["revision_number"] != number
                    or revision["prior_revision_id"] != expected_prior
                    or revision["revision_digest"]
                    != canonical_sha256({**revision, "revision_digest": _ZERO_HASH})
                ):
                    raise WorkingArtifactError("working-artifact revision lineage changed")
                expected_bindings = [
                    {"anchor": anchor, "evidence_sha256": self.citation_catalog.get(anchor)}
                    for anchor in revision["citations"]
                ]
                if revision["citation_bindings"] != expected_bindings or any(
                    binding["evidence_sha256"] is None for binding in expected_bindings
                ):
                    raise WorkingArtifactError("working-artifact citation binding changed")
                self._verify_revision_file(revision)
                expected_prior = revision["revision_id"]
            if artifact["current_revision_id"] != expected_prior:
                raise WorkingArtifactError("working-artifact current revision changed")
        return manifest

    def _revision_record(
        self,
        *,
        artifact_id: str,
        prior_revision_id: str | None,
        revision_number: int,
        markdown: str,
        citations: tuple[str, ...],
        provenance: tuple[dict[str, str], ...],
        change_summary: str,
        idempotency_key: str,
        request_digest: str,
    ) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key.encode("utf-8")) > 256:
            raise WorkingArtifactError("working-artifact idempotency key is invalid")
        created = self.clock()
        if created.tzinfo is None or created.utcoffset() is None:
            raise WorkingArtifactError("working-artifact clock is invalid")
        revision_id = self.ids.new("artifact_version")
        relative_path = (
            f"artifacts/{artifact_id}/revisions/{revision_number:04d}-{revision_id}.md"
        )
        metadata_relative_path = relative_path.removesuffix(".md") + ".metadata.json"
        evidence_relative_path = relative_path.removesuffix(".md") + ".citations.md"
        citation_bindings = [
            {"anchor": anchor, "evidence_sha256": self.citation_catalog[anchor]}
            for anchor in citations
        ]
        record = {
            "revision_id": revision_id,
            "artifact_id": artifact_id,
            "revision_number": revision_number,
            "prior_revision_id": prior_revision_id,
            "content_sha256": sha256_hex(markdown.encode("utf-8")),
            "citations": list(citations),
            "citation_bindings": citation_bindings,
            "provenance": list(provenance),
            "change_summary": change_summary,
            "created_at": timestamp(created),
            "relative_path": relative_path,
            "presentation_profile": "clean_markdown_sidecar/v1",
            "metadata_relative_path": metadata_relative_path,
            "evidence_relative_path": evidence_relative_path,
            "evidence_sha256": sha256_hex(
                _evidence_companion(citation_bindings).encode("utf-8")
            ),
            "idempotency_key": idempotency_key,
            "request_digest": request_digest,
            "revision_digest": _ZERO_HASH,
        }
        record["revision_digest"] = canonical_sha256(record)
        return record

    def _write_revision(
        self, revision: dict[str, Any], display_alias: str, artifact_kind: str, markdown: str
    ) -> None:
        target = _inside(self.root, self.root / revision["relative_path"])
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        del display_alias, artifact_kind
        _write_new(target, markdown.encode("utf-8"))
        metadata_path = _inside(self.root, self.root / revision["metadata_relative_path"])
        evidence_path = _inside(self.root, self.root / revision["evidence_relative_path"])
        _write_new(metadata_path, canonical_bytes(revision))
        _write_new(evidence_path, _evidence_companion(revision["citation_bindings"]).encode("utf-8"))

    def _verify_revision_file(self, revision: dict[str, Any]) -> None:
        target = _inside(self.root, self.root / revision["relative_path"])
        if target.is_symlink() or not target.is_file():
            raise WorkingArtifactError("working-artifact revision file is unavailable")
        content = target.read_text(encoding="utf-8")
        sidecar_keys = {
            "presentation_profile",
            "metadata_relative_path",
            "evidence_relative_path",
            "evidence_sha256",
        }
        present = sidecar_keys.intersection(revision)
        if present:
            if present != sidecar_keys:
                raise WorkingArtifactError("working-artifact sidecar binding is incomplete")
            if revision["presentation_profile"] != "clean_markdown_sidecar/v1":
                raise WorkingArtifactError("working-artifact presentation profile is unsupported")
            if content.startswith(HEADER_PREFIX) or _RAW_CITATION_TOKEN.search(content):
                raise WorkingArtifactError("working-artifact review Markdown is not clean")
            if sha256_hex(content.encode("utf-8")) != revision["content_sha256"]:
                raise WorkingArtifactError("working-artifact Markdown content changed")
            metadata_path = _inside(self.root, self.root / revision["metadata_relative_path"])
            evidence_path = _inside(self.root, self.root / revision["evidence_relative_path"])
            if any(path.is_symlink() or not path.is_file() for path in (metadata_path, evidence_path)):
                raise WorkingArtifactError("working-artifact sidecar is unavailable")
            if metadata_path.read_bytes() != canonical_bytes(revision):
                raise WorkingArtifactError("working-artifact metadata sidecar changed")
            evidence = evidence_path.read_bytes()
            if (
                sha256_hex(evidence) != revision["evidence_sha256"]
                or evidence != _evidence_companion(revision["citation_bindings"]).encode("utf-8")
            ):
                raise WorkingArtifactError("working-artifact evidence companion changed")
            return
        if not verify_markdown_projection(content):
            raise WorkingArtifactError("working-artifact Markdown projection changed")
        metadata = parse_markdown_projection_header(content)["metadata"]
        expected = {
            "artifact_id": revision["artifact_id"],
            "revision_id": revision["revision_id"],
            "revision_number": revision["revision_number"],
            "prior_revision_id": revision["prior_revision_id"],
            "revision_digest": revision["revision_digest"],
            "content_sha256": revision["content_sha256"],
            "citations": revision["citations"],
            "citation_bindings": revision["citation_bindings"],
            "provenance": revision["provenance"],
            "lifecycle_state": "working",
            "ephemeral": True,
            "no_automatic_persistence": True,
            "do_not_edit": True,
        }
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise WorkingArtifactError("working-artifact Markdown binding changed")
        if sha256_hex(_markdown_body(content).encode("utf-8")) != revision["content_sha256"]:
            raise WorkingArtifactError("working-artifact Markdown content changed")

    def _read_revision_markdown(self, revision: dict[str, Any]) -> str:
        self._verify_revision_file(revision)
        content = (self.root / revision["relative_path"]).read_text(encoding="utf-8")
        if revision.get("presentation_profile") == "clean_markdown_sidecar/v1":
            return content
        return _markdown_body(content)

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        material = copy.deepcopy(manifest)
        material["component"] = COMPONENT
        material["manifest_digest"] = _ZERO_HASH
        material["manifest_digest"] = canonical_sha256(material)
        self.schemas.require("working-artifact-session", material)
        _replace_file(self.manifest_path, canonical_bytes(material))

    def _require_kind_alias(self, artifact_kind: str, display_alias: str) -> None:
        if artifact_kind not in _KINDS:
            raise WorkingArtifactError("working-artifact kind is unsupported")
        if not display_alias.strip() or len(display_alias.encode("utf-8")) > 240:
            raise WorkingArtifactError("working-artifact display alias is invalid")

    def _require_citations(self, citations: tuple[str, ...]) -> tuple[str, ...]:
        if not citations or len(citations) != len(set(citations)):
            raise WorkingArtifactError("working-artifact citations are missing or duplicated")
        if any(anchor not in self.citation_catalog for anchor in citations):
            raise WorkingArtifactError("working-artifact citation is outside selected evidence")
        return citations

    @staticmethod
    def _artifact(manifest: dict[str, Any], artifact_id: str) -> dict[str, Any]:
        matches = [item for item in manifest["artifacts"] if item["artifact_id"] == artifact_id]
        if len(matches) != 1:
            raise WorkingArtifactError("working-artifact identity is unavailable")
        return matches[0]

    @staticmethod
    def _revision(artifact: dict[str, Any], revision_id: str) -> dict[str, Any]:
        matches = [item for item in artifact["revisions"] if item["revision_id"] == revision_id]
        if len(matches) != 1:
            raise WorkingArtifactError("working-artifact revision is unavailable")
        return matches[0]

    def _idempotent_revision(
        self, manifest: dict[str, Any], idempotency_key: str, request_digest: str
    ) -> dict[str, Any] | None:
        matches = [
            revision
            for artifact in manifest["artifacts"]
            for revision in artifact["revisions"]
            if revision["idempotency_key"] == idempotency_key
            or revision["request_digest"] == request_digest
        ]
        if not matches:
            return None
        if len(matches) != 1 or any(
            revision["idempotency_key"] != idempotency_key
            or revision["request_digest"] != request_digest
            for revision in matches
        ):
            raise WorkingArtifactError("working-artifact request binding conflicts")
        return matches[0]

    def _view(self, manifest: dict[str, Any], revision: dict[str, Any]) -> WorkingArtifactView:
        artifact = self._artifact(manifest, revision["artifact_id"])
        return WorkingArtifactView(
            artifact_id=artifact["artifact_id"],
            revision_id=revision["revision_id"],
            revision_number=revision["revision_number"],
            artifact_kind=artifact["artifact_kind"],
            display_alias=artifact["display_alias"],
            markdown_path=self.root / revision["relative_path"],
            content_sha256=revision["content_sha256"],
            revision_digest=revision["revision_digest"],
        )


def _initialize_disposable_root(root: Path) -> Path:
    if not root.is_absolute():
        raise WorkingArtifactError("working-artifact root must be absolute")
    try:
        parts = root.relative_to(_DISPOSABLE_PARENT).parts
    except ValueError as exc:
        raise WorkingArtifactError("working-artifact root must be beneath /private/tmp") from exc
    if not parts:
        raise WorkingArtifactError("working-artifact root cannot be /private/tmp")
    probe = _DISPOSABLE_PARENT
    for part in parts:
        probe = probe / part
        if probe.exists() and probe.is_symlink():
            raise WorkingArtifactError("working-artifact root cannot traverse a symlink")
    if root.exists():
        if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
            raise WorkingArtifactError("working-artifact root must be a fresh empty directory")
    else:
        root.mkdir(mode=0o700, parents=True)
    os.chmod(root, 0o700)
    return root.resolve(strict=True)


def _open_disposable_root(root: Path) -> Path:
    if not root.is_absolute():
        raise WorkingArtifactError("working-artifact root must be absolute")
    try:
        parts = root.relative_to(_DISPOSABLE_PARENT).parts
    except ValueError as exc:
        raise WorkingArtifactError("working-artifact root must be beneath /private/tmp") from exc
    if not parts:
        raise WorkingArtifactError("working-artifact root cannot be /private/tmp")
    probe = _DISPOSABLE_PARENT
    for part in parts:
        probe = probe / part
        if probe.is_symlink():
            raise WorkingArtifactError("working-artifact root cannot traverse a symlink")
    if not root.is_dir():
        raise WorkingArtifactError("working-artifact root is unavailable")
    return root.resolve(strict=True)


def _validate_citation_catalog(catalog: dict[str, str]) -> dict[str, str]:
    if not catalog:
        raise WorkingArtifactError("working-artifact selected evidence is required")
    result: dict[str, str] = {}
    for anchor, digest in catalog.items():
        if (
            not anchor
            or "/" in anchor
            or "\\" in anchor
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise WorkingArtifactError("working-artifact citation catalog is invalid")
        result[anchor] = digest
    return result


def _validate_provenance(values: tuple[dict[str, str], ...]) -> tuple[dict[str, str], ...]:
    if not values:
        raise WorkingArtifactError("working-artifact provenance is required")
    result: list[dict[str, str]] = []
    for value in values:
        if set(value) != {"ref", "digest"} or not value["ref"] or len(value["digest"]) != 64:
            raise WorkingArtifactError("working-artifact provenance is invalid")
        if any(character not in "0123456789abcdef" for character in value["digest"]):
            raise WorkingArtifactError("working-artifact provenance digest is invalid")
        result.append(dict(value))
    if len({item["ref"] for item in result}) != len(result):
        raise WorkingArtifactError("working-artifact provenance is duplicated")
    return tuple(result)


def _validate_markdown(markdown: str) -> str:
    if not isinstance(markdown, str) or not markdown.strip() or "\x00" in markdown:
        raise WorkingArtifactError("working-artifact Markdown is invalid")
    normalized = markdown if markdown.endswith("\n") else markdown + "\n"
    if normalized.startswith(HEADER_PREFIX) or _RAW_CITATION_TOKEN.search(normalized):
        raise WorkingArtifactError("working-artifact review Markdown contains machine metadata")
    if len(normalized.encode("utf-8")) > _MAX_MARKDOWN_BYTES:
        raise WorkingArtifactError("working-artifact Markdown exceeds the bounded size")
    return normalized


def clean_review_markdown(markdown: str, citations: tuple[str, ...]) -> str:
    """Remove only exact raw paragraph citation groups while retaining every claim byte otherwise."""

    allowed = set(citations)
    observed: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        anchors = {value.strip() for value in match.group(1).split(",")}
        if not anchors or not anchors.issubset(allowed):
            raise WorkingArtifactError("working-artifact body citation is outside selected evidence")
        observed.update(anchors)
        return ""

    cleaned = _RAW_CITATION_GROUP.sub(replace, markdown)
    if not observed.issubset(allowed):
        raise WorkingArtifactError("working-artifact body citation is outside selected evidence")
    return _validate_markdown(cleaned)


def _evidence_companion(bindings: list[dict[str, str]]) -> str:
    lines = [
        "# Evidence companion",
        "",
        "This optional file contains the exact source anchors and immutable evidence digests.",
        "The meeting record is intentionally kept free of machine-facing citation identifiers.",
        "",
        "| Evidence | Source anchor | Evidence digest |",
        "| --- | --- | --- |",
    ]
    for number, binding in enumerate(bindings, start=1):
        lines.append(
            f"| E{number:03d} | `{binding['anchor']}` | `{binding['evidence_sha256']}` |"
        )
    return "\n".join(lines) + "\n"


def _render_page(metadata: dict[str, Any], markdown: str) -> str:
    envelope = {"kind": "working_artifact", "parameters": {}, "metadata": metadata}
    return HEADER_PREFIX + canonical_bytes(envelope).decode("utf-8") + HEADER_SUFFIX + markdown


def _markdown_body(content: str) -> str:
    _header, separator, body = content.partition("\n")
    if not separator:
        raise WorkingArtifactError("working-artifact Markdown body is unavailable")
    return body


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise WorkingArtifactError("working-artifact path escaped its workbench") from exc
    return resolved


def _write_new(path: Path, material: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise WorkingArtifactError("working-artifact immutable target already exists")
    with path.open("xb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _replace_file(path: Path, material: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise WorkingArtifactError("working-artifact temporary manifest is unavailable")
    with temporary.open("xb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
