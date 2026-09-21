"""Hostile-synthetic P1 Markdown workspace projection.

The coordinator intentionally accepts only synthetic workspace items backed by committed F1 fixture
events.  Its output is a disposable, derived Markdown view; it is never a canonical writer, source
reader, receipt issuer, or host adapter.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.records import SchemaRegistry
from vault_next.readable_projections import (
    HEADER_PREFIX,
    HEADER_SUFFIX,
    parse_markdown_projection_header,
    verify_markdown_projection,
)
from vault_next.runtime import CaseSessionRuntime


COMPONENT_ID = "vault-next-workspace-projection"
COMPONENT_VERSION = "0.1.0"
_SYNTHETIC_MARKER = "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE"
_DISPOSABLE_PARENT = Path("/private/tmp")
_FAMILIES = frozenset({"conversation", "meeting", "decision", "knowledge", "work", "person", "skill"})
_VIEWS = {
    "conversation": frozenset({"transcripts"}),
    "meeting": frozenset({"sources", "debriefs", "preparations", "outbound"}),
    "decision": frozenset({"reported", "owner-confirmed"}),
    "knowledge": frozenset({"articles", "deep-dives", "assertions"}),
    "work": frozenset({"reported", "current"}),
    "person": frozenset({"observations"}),
    "skill": frozenset({"package", "evaluations"}),
}
_STATUSES = frozenset(
    {
        "inactive", "reported", "current", "historical", "needs_refinement", "unavailable",
        "review_copy", "final",
    }
)
_CHAT_CLASSES = frozenset(
    {
        "hosted_chat_pasted_transcript",
        "hosted_chat_export_file",
        "hosted_chat_attachment",
        "hosted_chat_accessible_export",
    }
)
_ZERO_HASH = "0" * 64


class WorkspaceProjectionError(RuntimeError):
    """A P1 synthetic workspace cannot be safely generated."""


@dataclass(frozen=True)
class WorkspaceLink:
    target_id: str
    target_version_id: str
    relationship_assertion_id: str
    label: str


@dataclass(frozen=True)
class WorkspaceItem:
    """One supplied hostile fixture page backed by a committed F1 source object."""

    item_id: str
    version_id: str
    family: str
    view: str
    display_alias: str
    status: str
    source_event_id: str
    canonical_object_sha256: str
    body: str
    citations: tuple[str, ...] = ()
    links: tuple[WorkspaceLink, ...] = ()
    acquisition_class: str | None = None
    confirmed_state_fixture: bool = False
    synthetic_only: bool = True


@dataclass(frozen=True)
class WorkspaceBuildResult:
    workspace_root: Path
    manifest: dict[str, Any]
    page_paths: dict[tuple[str, str], Path]
    tampered_paths: tuple[Path, ...]
    active_page_count: int


class SyntheticWorkspaceProjectionCoordinator:
    """Render an atomically published Markdown workspace from committed hostile F1 fixtures only."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        schemas: SchemaRegistry,
        *,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.schemas = schemas
        self.fault_injector = fault_injector

    def build(self, items: Iterable[WorkspaceItem], workspace_root: Path) -> WorkspaceBuildResult:
        """Validate and publish one disposable generated workspace."""

        root = _validate_disposable_root(workspace_root)
        committed = self._committed_sources()
        ordered = sorted(tuple(items), key=lambda item: (item.family, item.item_id, item.version_id))
        if not ordered:
            raise WorkspaceProjectionError("P1 requires at least one supplied synthetic item")
        self._validate_items(ordered, committed)
        page_paths = self._page_paths(ordered)
        manifest = self._manifest(ordered, committed, root, page_paths)
        self.schemas.require("synthetic-workspace-projection-manifest", manifest)
        stage: Path | None = Path(tempfile.mkdtemp(prefix=".vault-next-p1-stage-", dir=root.parent))
        try:
            self._fault("after_stage_created")
            self._render_stage(stage, ordered, manifest, page_paths, committed)
            self._fault("before_publish")
            tampered = self._publish(stage, root, page_paths)
            stage = None
            return WorkspaceBuildResult(
                root,
                manifest,
                {key: root / path for key, path in page_paths.items()},
                tuple(tampered),
                sum(1 for item in ordered if committed[item.source_event_id]["active"]),
            )
        finally:
            if stage is not None and stage.exists():
                _remove_disposable_tree(stage)

    def rebuild(self, items: Iterable[WorkspaceItem], workspace_root: Path) -> WorkspaceBuildResult:
        """Rebuild only from supplied committed fixture records; no source fallback exists."""

        return self.build(items, workspace_root)

    def verify(self, result: WorkspaceBuildResult) -> None:
        """Verify generated page digests and their canonical build bindings."""

        root = _validate_disposable_root(result.workspace_root)
        manifest = result.manifest
        self.schemas.require("synthetic-workspace-projection-manifest", manifest)
        if manifest["workspace_root_id"] != sha256_hex(str(root).encode("utf-8")):
            raise WorkspaceProjectionError("P1 workspace root binding changed")
        for page in manifest["pages"]:
            relative = Path(page["relative_path"])
            path = root / relative
            _require_relative(root, path)
            if path.is_symlink() or not path.is_file():
                raise WorkspaceProjectionError("P1 generated page is unavailable")
            content = path.read_text(encoding="utf-8")
            if not verify_markdown_projection(content):
                raise WorkspaceProjectionError("P1 generated page digest is invalid")
            envelope = parse_markdown_projection_header(content)
            metadata = envelope["metadata"]
            if metadata.get("workspace_build_digest") != manifest["build_digest"]:
                raise WorkspaceProjectionError("P1 page is bound to a different build")
            if metadata.get("canonical_object_sha256") != page["canonical_object_sha256"]:
                raise WorkspaceProjectionError("P1 page object binding changed")

    def search(self, result: WorkspaceBuildResult, query: str) -> tuple[tuple[str, str], ...]:
        """Return only manifest-selected generated pages matching one bounded local query."""

        if not query or len(query) > 128:
            raise WorkspaceProjectionError("P1 search query is invalid")
        self.verify(result)
        needle = query.casefold()
        matches: list[tuple[str, str]] = []
        for page in result.manifest["pages"]:
            path = _require_relative(result.workspace_root, result.workspace_root / page["relative_path"])
            if needle in path.read_text(encoding="utf-8").casefold():
                matches.append((page["item_id"], page["version_id"]))
        return tuple(matches)

    def _committed_sources(self) -> dict[str, dict[str, Any]]:
        """Return F1 sources visible only through committed admission events."""

        deactivated = {
            event["payload"]["admission_id"]
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "private_admission.deactivated"
        }
        committed: dict[str, dict[str, Any]] = {}
        for event in self.runtime.semantic.read_all():
            if event["event_type"] != "private_admission.recorded":
                continue
            payload = event["payload"]
            self.schemas.require("private-admission-event", payload)
            source = payload["source_version"]
            admission_id = payload["manifest"]["admission_id"]
            path = _require_relative(
                self.runtime.paths.source_root,
                self.runtime.paths.source_root / "private-foundation" / "objects" / source["object_ref"],
            )
            if path.is_symlink() or not path.is_file():
                raise WorkspaceProjectionError("P1 committed fixture source is unavailable")
            material = path.read_bytes()
            if sha256_hex(material) != source["content_sha256"]:
                raise WorkspaceProjectionError("P1 committed fixture source digest changed")
            if _SYNTHETIC_MARKER.encode("utf-8") not in material:
                raise WorkspaceProjectionError("P1 source is not a hostile synthetic fixture")
            committed[event["event_id"]] = {
                "active": admission_id not in deactivated,
                "digests": {
                    source["content_sha256"],
                    payload["result"]["content_sha256"],
                    payload["manifest"]["candidate_package_sha256"],
                    payload["manifest"]["relationship_ledger_sha256"],
                },
                "watermark": event["integrity"]["event_sha256"],
            }
        if not committed:
            raise WorkspaceProjectionError("P1 requires a committed F1 fixture event")
        return committed

    def _validate_items(
        self, items: tuple[WorkspaceItem, ...], committed: dict[str, dict[str, Any]]
    ) -> None:
        seen: set[tuple[str, str]] = set()
        for item in items:
            key = (item.item_id, item.version_id)
            if key in seen:
                raise WorkspaceProjectionError("P1 duplicate item version")
            seen.add(key)
            if (
                not item.synthetic_only
                or item.family not in _FAMILIES
                or item.view not in _VIEWS.get(item.family, frozenset())
                or item.status not in _STATUSES
                or item.source_event_id not in committed
                or item.canonical_object_sha256 not in committed[item.source_event_id]["digests"]
                or not item.item_id
                or not item.version_id
                or not item.display_alias
                or not item.body
                or _SYNTHETIC_MARKER not in item.body
            ):
                raise WorkspaceProjectionError("P1 item is outside the hostile synthetic contract")
            if item.acquisition_class is not None:
                if item.family != "conversation" or item.acquisition_class not in _CHAT_CLASSES:
                    raise WorkspaceProjectionError("P1 conversation acquisition class is invalid")
            if item.family == "conversation" and item.acquisition_class is None:
                raise WorkspaceProjectionError("P1 conversation acquisition class is required")
            if item.status == "current" and not item.confirmed_state_fixture:
                raise WorkspaceProjectionError("P1 current state requires an explicit synthetic fixture")
            if item.family == "decision" and item.view == "owner-confirmed" and not item.confirmed_state_fixture:
                raise WorkspaceProjectionError("P1 owner-confirmed view requires an explicit synthetic fixture")
            for citation in item.citations:
                if not citation or "/" in citation or "\\" in citation:
                    raise WorkspaceProjectionError("P1 citation anchor is invalid")
            for link in item.links:
                if not all((link.target_id, link.target_version_id, link.relationship_assertion_id, link.label)):
                    raise WorkspaceProjectionError("P1 link is invalid")

    def _page_paths(self, items: tuple[WorkspaceItem, ...]) -> dict[tuple[str, str], Path]:
        result: dict[tuple[str, str], Path] = {}
        used: set[Path] = set()
        labels: dict[str, str] = {}
        for item in items:
            token = _alias(item.display_alias, item.item_id)
            labels[item.item_id] = token
            family = {
                "conversation": "Conversations",
                "meeting": "Meetings",
                "decision": "Decisions",
                "knowledge": "Knowledge",
                "work": "Work",
                "person": "People",
                "skill": "Skills",
            }[item.family]
            path = Path(family) / token / item.view / f"{_safe_part(item.version_id)}.md"
            if path in used:
                raise WorkspaceProjectionError("P1 page path collision")
            used.add(path)
            result[(item.item_id, item.version_id)] = path
        return result

    def _manifest(
        self,
        items: tuple[WorkspaceItem, ...],
        committed: dict[str, dict[str, Any]],
        root: Path,
        paths: dict[tuple[str, str], Path],
    ) -> dict[str, Any]:
        pages = []
        for item in items:
            pages.append(
                {
                    "item_id": item.item_id,
                    "version_id": item.version_id,
                    "family": item.family,
                    "view": item.view,
                    "status": "historical" if not committed[item.source_event_id]["active"] else item.status,
                    "source_event_id": item.source_event_id,
                    "canonical_object_sha256": item.canonical_object_sha256,
                    "relative_path": str(paths[(item.item_id, item.version_id)]),
                    "citations": list(item.citations),
                    "link_targets": [
                        {
                            "target_id": link.target_id,
                            "target_version_id": link.target_version_id,
                            "relationship_assertion_id": link.relationship_assertion_id,
                        }
                        for link in item.links
                    ],
                }
            )
        manifest = {
            "schema_version": "1.0",
            "synthetic_only": True,
            "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}",
            "source_event_ids": sorted(committed),
            "source_watermark": canonical_sha256(
                {event_id: committed[event_id]["watermark"] for event_id in sorted(committed)}
            ),
            "workspace_root_id": sha256_hex(str(root).encode("utf-8")),
            "pages": pages,
            "no_source_fallback": True,
            "do_not_edit": True,
            "build_digest": _ZERO_HASH,
        }
        manifest["build_digest"] = canonical_sha256(manifest)
        return manifest

    def _render_stage(
        self,
        stage: Path,
        items: tuple[WorkspaceItem, ...],
        manifest: dict[str, Any],
        paths: dict[tuple[str, str], Path],
        committed: dict[str, dict[str, Any]],
    ) -> None:
        by_key = {(item.item_id, item.version_id): item for item in items}
        for item in items:
            relative = paths[(item.item_id, item.version_id)]
            target = _require_relative(stage, stage / relative)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            status = "historical" if not committed[item.source_event_id]["active"] else item.status
            body = self._body(item, paths, by_key, status)
            metadata = {
                "schema_version": "1.0",
                "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}",
                "item_id": item.item_id,
                "version_id": item.version_id,
                "family": item.family,
                "view": item.view,
                "status": status,
                "canonical_object_sha256": item.canonical_object_sha256,
                "workspace_build_digest": manifest["build_digest"],
                "do_not_edit": True,
                "projection_sha256": _ZERO_HASH,
            }
            content = _render_page(metadata, body)
            metadata["projection_sha256"] = sha256_hex(content.encode("utf-8"))
            _atomic_write(target, _render_page(metadata, body).encode("utf-8"))
        _atomic_write(stage / "README.md", _readme(manifest).encode("utf-8"))
        for name in ("recent-artifacts", "decision-review", "knowledge-freshness", "skill-catalog"):
            view = _require_relative(stage, stage / "_views" / f"{name}.md")
            view.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _atomic_write(view, _view_markdown(name, manifest).encode("utf-8"))

    def _body(
        self,
        item: WorkspaceItem,
        paths: dict[tuple[str, str], Path],
        by_key: dict[tuple[str, str], WorkspaceItem],
        status: str,
    ) -> str:
        lines = [
            f"# {item.display_alias}",
            "",
            f"Status: {status}.",
            f"Source event: {item.source_event_id}.",
            "",
            "## Content",
            "",
            item.body,
            "",
            "## Citations",
            "",
        ]
        if item.citations:
            lines.extend(f"- {citation}" for citation in item.citations)
        else:
            lines.append("- unavailable")
        lines.extend(["", "## Related items", ""])
        if not item.links:
            lines.append("- unavailable")
        for link in item.links:
            target = (link.target_id, link.target_version_id)
            if target not in paths:
                lines.append(
                    f"- {link.label} — unavailable "
                    f"(target={link.target_id}@{link.target_version_id}; "
                    f"relation={link.relationship_assertion_id})."
                )
                continue
            relative = os.path.relpath(paths[target], start=paths[(item.item_id, item.version_id)].parent)
            lines.append(
                f"- [{link.label}]({relative}) "
                f"(target={link.target_id}@{link.target_version_id}; "
                f"relation={link.relationship_assertion_id})"
            )
        return "\n".join(lines) + "\n"

    def _publish(self, stage: Path, root: Path, paths: dict[tuple[str, str], Path]) -> list[Path]:
        for path in stage.rglob("*"):
            if path.is_symlink():
                raise WorkspaceProjectionError("P1 generated staging contains a symlink")
        tampered: list[Path] = []
        backup: Path | None = None
        if root.exists():
            if root.is_symlink() or not root.is_dir():
                raise WorkspaceProjectionError("P1 workspace root is invalid")
            if any(path.is_symlink() for path in root.rglob("*")):
                raise WorkspaceProjectionError("P1 existing workspace contains a symlink")
            for relative in paths.values():
                existing = root / relative
                replacement = stage / relative
                if existing.exists() and existing.is_file() and existing.read_bytes() != replacement.read_bytes():
                    tampered.append(existing)
            backup = root.parent / f".p1-quarantine-{sha256_hex(str(root).encode('utf-8'))[:12]}"
            if backup.exists():
                _remove_disposable_tree(backup)
            os.replace(root, backup)
        try:
            os.replace(stage, root)
        except Exception:
            if backup is not None and backup.exists() and not root.exists():
                os.replace(backup, root)
            raise
        return tampered

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)


def _render_page(metadata: dict[str, Any], body: str) -> str:
    envelope = {"kind": "workspace_page", "parameters": {}, "metadata": metadata}
    return HEADER_PREFIX + canonical_bytes(envelope).decode("utf-8") + HEADER_SUFFIX + body


def _readme(manifest: dict[str, Any]) -> str:
    return (
        "# Vault Next synthetic workspace\n\n"
        "This is a generated hostile-fixture projection, not canonical data.\n\n"
        f"Build: {manifest['build_digest']}\n"
    )


def _view_markdown(name: str, manifest: dict[str, Any]) -> str:
    return (
        f"# {name.replace('-', ' ').title()}\n\n"
        "Generated from manifest-selected hostile fixtures only.\n\n"
        f"Build: {manifest['build_digest']}\n"
    )


def _validate_disposable_root(root: Path) -> Path:
    if not root.is_absolute():
        raise WorkspaceProjectionError("P1 workspace root must be absolute")
    try:
        parts = root.relative_to(_DISPOSABLE_PARENT).parts
    except ValueError as exc:
        raise WorkspaceProjectionError("P1 workspace root must be beneath /private/tmp") from exc
    probe = _DISPOSABLE_PARENT
    for part in parts:
        probe = probe / part
        if probe.exists() and probe.is_symlink():
            raise WorkspaceProjectionError("P1 workspace root cannot traverse a symlink")
    resolved = root.resolve(strict=False)
    if resolved == _DISPOSABLE_PARENT or resolved.name != "workspace":
        raise WorkspaceProjectionError("P1 workspace root must be a disposable workspace directory")
    resolved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return resolved


def _require_relative(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise WorkspaceProjectionError("P1 path escaped its allowed root") from exc
    return resolved


def _safe_part(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    return cleaned or "unnamed"


def _alias(value: str, item_id: str) -> str:
    return f"{_safe_part(value)}--{sha256_hex(item_id.encode('utf-8'))[:8]}"


def _atomic_write(path: Path, material: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise WorkspaceProjectionError("P1 temporary output path is unavailable")
    with temporary.open("xb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _remove_disposable_tree(path: Path) -> None:
    resolved = _validate_disposable_root(path) if path.name == "workspace" else path.resolve(strict=False)
    try:
        resolved.relative_to(_DISPOSABLE_PARENT)
    except ValueError as exc:
        raise WorkspaceProjectionError("P1 cleanup escaped disposable root") from exc
    if resolved.is_symlink():
        raise WorkspaceProjectionError("P1 cleanup target is a symlink")
    shutil.rmtree(resolved)
