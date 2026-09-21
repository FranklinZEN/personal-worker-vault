"""RPI-A real-private workspace and U1 authority boundary.

This production sibling is source-free: it accepts already-committed canonical item descriptions and
an injected purpose-specific authority only.  It never opens a source, scans a folder, invokes a host,
or accesses Keychain material itself.
"""

from __future__ import annotations

import hmac
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.readable_projections import parse_markdown_projection_header
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT_ID = "vault-next-private-workspace-projection"
COMPONENT_VERSION = "0.1.0"
AUTHORITY_ID = "vault-next-local-confirmation/v2"
PURPOSE = "chat_first_u1_save"
_LAYOUT = (
    "canonical", "canonical/events", "canonical/source-objects", "canonical/artifact-objects",
    "canonical/candidate-packages", "canonical/relationships", "staging", "staging/u1-save",
    "receipts", "receipts/chat-first-u1-save", "evidence", "evidence/u1-save",
    "evidence/projection", "derived", "derived/fts5", "derived/workspace-builds", "workspace",
    "workspace/Conversations", "workspace/Meetings", "workspace/Decisions", "workspace/Knowledge",
    "workspace/Work", "workspace/People", "workspace/Skills", "workspace/_views",
    "quarantine", "quarantine/workspace",
)
_FAMILIES = {
    "conversation": "Conversations", "meeting": "Meetings", "decision": "Decisions",
    "knowledge": "Knowledge", "work": "Work", "person": "People", "skill": "Skills",
}
_VIEWS = {
    "conversation": {"transcripts"},
    "meeting": {"sources", "debriefs", "preparations", "outbound"},
    "decision": {"reported", "owner-confirmed"}, "knowledge": {"articles", "deep-dives", "assertions"},
    "work": {"reported", "current"}, "person": {"observations"}, "skill": {"package", "evaluations"},
}
_PROJECTION_STATUSES = {"reported", "historical", "inactive", "unavailable", "review_copy", "final"}


class PrivateWorkspaceError(RuntimeError):
    """A real-private workspace boundary could not be safely satisfied."""


class PrivateWorkspaceDeclined(PrivateWorkspaceError):
    """The purpose-specific U1 authorization was not valid."""


class ExistingV2ChatSaveAuthority(Protocol):
    """Only the chat-save purpose is exposed to the production sibling."""

    def authorize_chat_first_u1_save(self, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def verify_chat_first_u1_save(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PrivateWorkspaceItem:
    """One committed canonical object description; this is not a source capability."""

    item_id: str
    version_id: str
    family: str
    view: str
    status: str
    display_alias: str
    canonical_object_sha256: str
    admission_event_id: str
    body: str
    citations: tuple[str, ...]
    candidate_inactive: bool = False


@dataclass(frozen=True)
class PrivateWorkspaceBuild:
    workspace_root: Path
    manifest: dict[str, Any]
    page_paths: dict[tuple[str, str], Path]


class ChatFirstU1V2Adapter:
    """Fail-closed adapter over an injected already-existing v2 purpose boundary."""

    def __init__(self, authority: ExistingV2ChatSaveAuthority, schemas: SchemaRegistry) -> None:
        self._authority = authority
        self._schemas = schemas

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]:
        _require_manifest(self._schemas, manifest)
        receipt = self._authority.authorize_chat_first_u1_save(manifest)
        self._require_receipt(receipt, manifest)
        return receipt

    def verify(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        _require_manifest(self._schemas, manifest)
        receipt = self._authority.verify_chat_first_u1_save(receipt_id, manifest)
        self._require_receipt(receipt, manifest)
        return receipt

    def _require_receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self._schemas.require("chat-first-u1-save-receipt", receipt)
        expected = {
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise PrivateWorkspaceError("RPI-A v2 receipt binding is invalid")


class PrivateBundleLayout:
    """Validate or create exactly the bounded owner-only data-bundle layout."""

    @staticmethod
    def initialize(root: Path, *, create: bool) -> None:
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise PrivateWorkspaceError("RPI-A private bundle root is unavailable")
        _require_owner_only(root)
        resolved = root.resolve(strict=True)
        if create:
            for relative in _LAYOUT:
                target = _inside(resolved, resolved / relative)
                if target.exists():
                    if target.is_symlink() or not target.is_dir():
                        raise PrivateWorkspaceError("RPI-A private bundle layout is unsafe")
                else:
                    target.mkdir(mode=0o700)
                os.chmod(target, 0o700)
        for relative in _LAYOUT:
            target = _inside(resolved, resolved / relative)
            if not target.exists() or target.is_symlink() or not target.is_dir():
                raise PrivateWorkspaceError("RPI-A private bundle layout is incomplete")
            _require_owner_only(target)

    @staticmethod
    def validate(root: Path) -> None:
        PrivateBundleLayout.initialize(root, create=False)


class RealPrivateWorkspaceProjectionCoordinator:
    """Render an atomic derived workspace only from supplied committed canonical descriptions."""

    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas

    def build(self, bundle_root: Path, items: tuple[PrivateWorkspaceItem, ...]) -> PrivateWorkspaceBuild:
        PrivateBundleLayout.validate(bundle_root)
        root = bundle_root.resolve(strict=True)
        workspace = _inside(root, root / "workspace")
        ordered = self._validate_items(items)
        pages = {key: path for key, path in (( (item.item_id, item.version_id), self._path(item)) for item in ordered)}
        manifest = self._manifest(workspace, ordered, pages)
        self.schemas.require("private-workspace-projection-build", manifest)
        stage_parent = _inside(root, root / "staging" / "u1-save")
        stage = Path(tempfile.mkdtemp(prefix=".workspace-stage-", dir=stage_parent))
        try:
            self._render(stage, ordered, pages, manifest)
            self._publish(stage, workspace, root / "quarantine" / "workspace")
            stage = None
        finally:
            if stage is not None and stage.exists():
                shutil.rmtree(stage)
        result = PrivateWorkspaceBuild(workspace, manifest, {key: workspace / path for key, path in pages.items()})
        self.verify(result)
        return result

    def verify(self, build: PrivateWorkspaceBuild) -> None:
        root = build.workspace_root
        if root.is_symlink() or not root.is_dir():
            raise PrivateWorkspaceError("RPI-A generated workspace is unavailable")
        self.schemas.require("private-workspace-projection-build", build.manifest)
        if build.manifest["workspace_root_id"] != sha256_hex(str(root).encode()):
            raise PrivateWorkspaceError("RPI-A workspace root binding changed")
        for page in build.manifest["pages"]:
            target = _inside(root, root / page["relative_path"])
            if target.is_symlink() or not target.is_file():
                raise PrivateWorkspaceError("RPI-A generated page is unavailable")
            content = target.read_text(encoding="utf-8")
            if not _verify_page(content):
                raise PrivateWorkspaceError("RPI-A generated page integrity is invalid")
            metadata = parse_markdown_projection_header(content)["metadata"]
            if metadata.get("workspace_build_digest") != build.manifest["build_digest"]:
                raise PrivateWorkspaceError("RPI-A generated page build binding changed")
            if metadata.get("canonical_object_sha256") != page["canonical_object_sha256"]:
                raise PrivateWorkspaceError("RPI-A generated page object binding changed")

    def _validate_items(self, items: tuple[PrivateWorkspaceItem, ...]) -> tuple[PrivateWorkspaceItem, ...]:
        if not items:
            raise PrivateWorkspaceError("RPI-A requires committed item descriptions")
        seen: set[tuple[str, str]] = set()
        for item in items:
            key = item.item_id, item.version_id
            if key in seen:
                raise PrivateWorkspaceError("RPI-A duplicate item revision")
            seen.add(key)
            if (
                item.family not in _FAMILIES
                or item.view not in _VIEWS[item.family]
                or item.status not in _PROJECTION_STATUSES
                or not all((item.item_id, item.version_id, item.display_alias, item.admission_event_id, item.body))
                or len(item.canonical_object_sha256) != 64
                or any(citation == "" or "/" in citation or "\\" in citation for citation in item.citations)
            ):
                raise PrivateWorkspaceError("RPI-A item is outside the committed projection contract")
            if item.status == "current" or (item.family == "skill" and not item.candidate_inactive):
                raise PrivateWorkspaceError("RPI-A cannot publish current state or an active skill")
        return tuple(sorted(items, key=lambda item: (item.family, item.item_id, item.version_id)))

    def _path(self, item: PrivateWorkspaceItem) -> Path:
        alias = _safe(item.display_alias)
        suffix = sha256_hex(item.item_id.encode())[:8]
        return Path(_FAMILIES[item.family]) / f"{alias}--{suffix}" / item.view / f"{_safe(item.version_id)}.md"

    def _manifest(
        self,
        root: Path,
        items: tuple[PrivateWorkspaceItem, ...],
        paths: dict[tuple[str, str], Path],
    ) -> dict[str, Any]:
        pages = [
            {
                "item_id": item.item_id, "version_id": item.version_id, "family": item.family,
                "view": item.view, "status": item.status, "admission_event_id": item.admission_event_id,
                "canonical_object_sha256": item.canonical_object_sha256,
                "relative_path": str(paths[(item.item_id, item.version_id)]), "citations": list(item.citations),
            }
            for item in items
        ]
        manifest = {
            "schema_version": "1.0", "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}",
            "workspace_root_id": sha256_hex(str(root).encode()), "pages": pages,
            "no_source_fallback": True, "build_digest": "0" * 64,
        }
        manifest["build_digest"] = canonical_sha256(manifest)
        return manifest

    def _render(
        self,
        stage: Path,
        items: tuple[PrivateWorkspaceItem, ...],
        paths: dict[tuple[str, str], Path],
        manifest: dict[str, Any],
    ) -> None:
        for relative in (
            "Conversations", "Meetings", "Decisions", "Knowledge", "Work", "People", "Skills", "_views"
        ):
            (stage / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        for item in items:
            relative = paths[(item.item_id, item.version_id)]
            target = _inside(stage, stage / relative)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = {
                "schema_version": "1.0", "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}",
                "item_id": item.item_id, "version_id": item.version_id, "family": item.family,
                "view": item.view, "status": item.status, "canonical_object_sha256": item.canonical_object_sha256,
                "workspace_build_digest": manifest["build_digest"], "do_not_edit": True, "projection_sha256": "0" * 64,
            }
            body = "\n".join((
                f"# {item.display_alias}", "", f"Status: {item.status}.", f"Source event: {item.admission_event_id}.",
                "", "## Content", "", item.body, "", "## Citations", "",
                *(f"- {citation}" for citation in item.citations), "",
                "## Lifecycle", "",
                "- Inactive candidate; no activation or U2 authority."
                if item.candidate_inactive
                else "- Source-reported evidence only.",
            )) + "\n"
            first = _render_page(metadata, body)
            metadata["projection_sha256"] = sha256_hex(first.encode())
            _atomic_write(target, _render_page(metadata, body).encode())
        _atomic_write(
            stage / "README.md",
            f"# Vault Next workspace\n\nDerived build: {manifest['build_digest']}.\n".encode(),
        )

    def _publish(self, stage: Path, workspace: Path, quarantine: Path) -> None:
        for path in stage.rglob("*"):
            if path.is_symlink():
                raise PrivateWorkspaceError("RPI-A staging contains a symlink")
        backup = workspace.with_name(".workspace-previous")
        if backup.exists():
            raise PrivateWorkspaceError("RPI-A workspace recovery target is unavailable")
        if workspace.exists():
            os.replace(workspace, backup)
        os.replace(stage, workspace)
        if backup.exists():
            quarantine.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(
                backup,
                quarantine / f"previous-{stage.name.removeprefix('.workspace-stage-')}",
            )


def build_u1_manifest(
    *,
    ids: ULIDFactory = DEFAULT_FACTORY,
    expires_at: datetime,
    bundle_id: str,
    ingress_envelope_sha256: str,
    source_sha256: str,
    source_size: int,
    u0_result_sha256: str,
    artifact_sha256: str,
    candidate_package_sha256: str,
    relationship_ledger_sha256: str | None = None,
    profile_id: str,
    safe_label: str,
    citations: tuple[str, ...],
    schemas: SchemaRegistry,
    wave_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one source-free-testable real U1 proposal from an already-frozen U0 envelope."""
    if expires_at.tzinfo is None or expires_at.utcoffset() is None or expires_at <= aware_utc_now():
        raise PrivateWorkspaceError("RPI-A U1 proposal expiry is invalid")
    manifest = {
        "schema_version": "1.0", "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}", "purpose": PURPOSE,
        "authority_id": AUTHORITY_ID, "admission_id": ids.new("private_admission"), "bundle_id": bundle_id,
        "ingress_envelope_sha256": ingress_envelope_sha256, "source_sha256": source_sha256,
        "source_size": source_size, "u0_result_sha256": u0_result_sha256, "artifact_sha256": artifact_sha256,
        "candidate_package_sha256": candidate_package_sha256, "profile_id": profile_id, "safe_label": safe_label,
        "citations": list(citations), "disclosure": "visible_hosted_reasoning", "retention": "R1_immutable",
        "operations": [
            "stage_immutable_objects", "append_private_admission_event", "rebuild_local_fts5",
            "rebuild_private_workspace",
        ],
        "expires_at": timestamp(expires_at),
    }
    if relationship_ledger_sha256 is not None:
        if len(relationship_ledger_sha256) != 64:
            raise PrivateWorkspaceError("RPI-A relationship ledger digest is invalid")
        manifest["relationship_ledger_sha256"] = relationship_ledger_sha256
    if wave_scope is not None:
        manifest["wave_scope"] = wave_scope
    manifest["manifest_digest"] = canonical_sha256(manifest)
    _require_manifest(schemas, manifest)
    return manifest


def _require_manifest(schemas: SchemaRegistry, manifest: dict[str, Any]) -> None:
    schemas.require("chat-first-u1-save-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if not hmac.compare_digest(manifest["manifest_digest"], canonical_sha256(material)):
        raise PrivateWorkspaceError("RPI-A U1 manifest digest is invalid")


def _inside(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve(strict=False)
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PrivateWorkspaceError("RPI-A path escaped its root") from exc
    return resolved


def _require_owner_only(path: Path) -> None:
    if path.stat().st_mode & 0o077:
        raise PrivateWorkspaceError("RPI-A private path must be owner-only")


def _safe(value: str) -> str:
    result = "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")
    return result or "unnamed"


def _render_page(metadata: dict[str, Any], body: str) -> str:
    from vault_next.readable_projections import HEADER_PREFIX, HEADER_SUFFIX
    envelope = {"metadata": metadata}
    return HEADER_PREFIX + json.dumps(envelope, sort_keys=True, separators=(",", ":")) + HEADER_SUFFIX + body


def _verify_page(content: str) -> bool:
    try:
        envelope = parse_markdown_projection_header(content)
        metadata = dict(envelope["metadata"])
        expected = metadata["projection_sha256"]
        metadata["projection_sha256"] = "0" * 64
        body = content.partition("\n")[2]
        return hmac.compare_digest(expected, sha256_hex(_render_page(metadata, body).encode()))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _atomic_write(path: Path, material: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    with temporary.open("xb") as handle:
        handle.write(material)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
