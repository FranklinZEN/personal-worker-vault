"""S4-D synthetic-only selective preservation and portable-root rehearsal.

This module deliberately has no live-root discovery, backup, migration, authority, or host
integration surface.  It can seal an exact, closed set of already-canonical bytes from a disposable
fixture runtime and restore them only into a new empty disposable runtime path.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ledger import SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry
from vault_next.validator import KernelValidator


_CONTRACT_VERSION = "synthetic-preservation-envelope/0.1.0"
_LAYOUT_VERSION = "s4d-selective-layout/0.1.0"
_OBJECT_EVENT_PATHS = {
    "source.version_registered": ("version", "object_ref", "sources"),
    "evidence.registered": ("metadata", "object_ref", "evidence"),
    "artifact.version_created": ("version", "object_ref", "artifacts"),
    "chat_ingress.save_committed": (
        ("source_version", "object_ref", "chat_ingress_sources"),
        ("debrief_artifact", "object_ref", "chat_ingress_artifacts"),
    ),
}
_ROOTS = {
    "semantic": Path("data/events/semantic"),
    "sources": Path("data/sources/objects"),
    "evidence": Path("data/evidence/objects"),
    "artifacts": Path("data/artifacts/objects"),
    "chat_ingress_sources": Path("data/sources/chat-ingress/objects"),
    "chat_ingress_artifacts": Path("data/artifacts/chat-ingress/objects"),
}


@dataclass(frozen=True)
class PreservationEnvelope:
    """One sealed selective synthetic preservation envelope."""

    envelope_root: Path
    manifest: dict[str, Any]


class SyntheticPreservationCoordinator:
    """Seal and restore a selected synthetic runtime without copying derived or authority state."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.schemas = schemas
        self.semantic = SemanticLedger(paths, schemas)

    def seal(self, case_ids: list[str], envelope_root: Path) -> PreservationEnvelope:
        """Create one immutable envelope from the exact selected fixture runtime state.

        ``envelope_root`` must not exist.  A partial sibling staging directory is intentionally left
        unavailable after an interruption; callers must choose a fresh target for a retry.
        """

        selected = _case_ids(case_ids)
        target = _new_directory(envelope_root, "$envelope_root")
        source_identity = _directory_identity(self.paths.root, "$source")
        events = self.semantic.read_all()
        _require_selected_events(events, selected)
        files = self._selected_files(events)
        manifest = _manifest(selected, events, files)
        stage = target.with_name(f".{target.name}.s4d-stage")
        if stage.exists() or stage.is_symlink():
            raise _invalid("$envelope_root", "interrupted envelope staging already exists; choose a fresh target")
        stage.mkdir(parents=True, mode=0o700)
        try:
            files_root = stage / "files"
            for entry in manifest["files"]:
                source = self.paths.root / entry["relative_path"]
                content = _regular_bytes(source, "$source")
                if len(content) != entry["byte_count"] or sha256_hex(content) != entry["sha256"]:
                    raise _invalid("$source", "canonical fixture bytes changed during envelope seal")
                _write_new(files_root / entry["relative_path"], content)
            _write_new(stage / "manifest.json", canonical_bytes(manifest))
            _fsync_tree(stage)
            if _directory_identity(self.paths.root, "$source") != source_identity:
                raise _invalid("$source", "synthetic source root changed during envelope seal")
            os.replace(stage, target)
        except Exception:
            # Keep incomplete evidence unavailable rather than treating it as a resumable envelope.
            raise
        return PreservationEnvelope(target, manifest)

    def restore(self, envelope_root: Path, destination_root: Path) -> dict[str, Any]:
        """Restore one verified envelope to a fresh root without reading the source runtime."""

        envelope = _existing_directory(envelope_root, "$envelope_root")
        envelope_identity = _directory_identity(envelope, "$envelope")
        target = _new_directory(destination_root, "$destination_root")
        manifest = _read_manifest(envelope)
        stage = target.with_name(f".{target.name}.s4d-stage")
        if stage.exists() or stage.is_symlink():
            raise _invalid("$destination_root", "interrupted restore staging already exists; choose a fresh target")
        stage.mkdir(parents=True, mode=0o700)
        try:
            files_root = envelope / "files"
            for entry in manifest["files"]:
                content = _regular_bytes(files_root / entry["relative_path"], "$envelope")
                if len(content) != entry["byte_count"] or sha256_hex(content) != entry["sha256"]:
                    raise _invalid("$envelope", "envelope file does not match its sealed manifest")
                _write_new(stage / entry["relative_path"], content)
            restored_paths = RuntimePaths(stage, protected_roots=self.paths.protected_roots)
            report = KernelValidator(restored_paths, self.schemas).validate()
            if not report.passed:
                raise _invalid("$destination_root", "restored canonical state did not validate")
            _require_restored_state(restored_paths, self.schemas, manifest)
            _fsync_tree(stage)
            if _directory_identity(envelope, "$envelope") != envelope_identity:
                raise _invalid("$envelope", "sealed envelope root changed during restore")
            os.replace(stage, target)
        except Exception:
            # No partially restored root is published.  Its staging evidence is deliberately inert.
            raise
        return {
            "status": "preserved",
            "destination_root": str(target),
            "manifest_sha256": manifest["manifest_sha256"],
            "rebuild_required": _rebuild_requirements(manifest),
            "authority": "unavailable: no authority material is preserved",
        }

    def _selected_files(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        paths: list[tuple[str, Path]] = []
        for path in sorted(self.paths.semantic_root.glob("*.jsonl")):
            paths.append(("semantic", path))
        for event in events:
            definitions = _OBJECT_EVENT_PATHS.get(event["event_type"])
            if definitions is None:
                continue
            selected = (definitions,) if isinstance(definitions[0], str) else definitions
            for container, key, role in selected:
                try:
                    object_ref = event["payload"][container][key]
                except (KeyError, TypeError) as exc:
                    raise _invalid("$semantic", "selected object reference is malformed") from exc
                if not isinstance(object_ref, str) or not object_ref:
                    raise _invalid("$semantic", "selected object reference is unavailable")
                relative = _ROOTS[role] / object_ref
                paths.append((role, self.paths.root / relative))
        seen: set[Path] = set()
        files: list[dict[str, Any]] = []
        for role, path in sorted(paths, key=lambda item: item[1].as_posix()):
            relative = _relative_runtime_path(self.paths.root, path)
            if relative in seen:
                continue
            seen.add(relative)
            content = _regular_bytes(path, "$source")
            files.append(
                {
                    "role": role,
                    "relative_path": relative.as_posix(),
                    "byte_count": len(content),
                    "sha256": sha256_hex(content),
                }
            )
        if not any(item["role"] == "semantic" for item in files):
            raise _invalid("$source", "selected synthetic runtime has no semantic ledger partition")
        return files


def _manifest(case_ids: list[str], events: list[dict[str, Any]], files: list[dict[str, Any]]) -> dict[str, Any]:
    material = {
        "contract_version": _CONTRACT_VERSION,
        "layout_version": _LAYOUT_VERSION,
        "case_ids": case_ids,
        "semantic_event_sha256": canonical_sha256(events),
        "files": files,
    }
    return {**material, "manifest_sha256": canonical_sha256(material)}


def _read_manifest(envelope: Path) -> dict[str, Any]:
    raw = _regular_bytes(envelope / "manifest.json", "$envelope")
    try:
        import json

        manifest = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _invalid("$envelope", "envelope manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or canonical_bytes(manifest) != raw:
        raise _invalid("$envelope", "envelope manifest is not canonical")
    required = {
        "contract_version",
        "layout_version",
        "case_ids",
        "semantic_event_sha256",
        "files",
        "manifest_sha256",
    }
    if set(manifest) != required or manifest["contract_version"] != _CONTRACT_VERSION:
        raise _invalid("$envelope", "envelope manifest contract is unsupported")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if manifest["manifest_sha256"] != canonical_sha256(material):
        raise _invalid("$envelope", "envelope manifest digest is invalid")
    _case_ids(manifest["case_ids"])
    if not _digest(manifest["semantic_event_sha256"]):
        raise _invalid("$envelope", "envelope semantic watermark is invalid")
    _manifest_files(manifest["files"])
    return manifest


def _require_restored_state(
    paths: RuntimePaths, schemas: SchemaRegistry, manifest: dict[str, Any]
) -> None:
    events = SemanticLedger(paths, schemas).read_all()
    if canonical_sha256(events) != manifest["semantic_event_sha256"]:
        raise _invalid("$destination_root", "restored semantic watermark differs from the envelope")
    _require_selected_events(events, _case_ids(manifest["case_ids"]))


def _rebuild_requirements(manifest: dict[str, Any]) -> list[str]:
    event_hash = manifest["semantic_event_sha256"]
    _ = event_hash  # The fixed declaration deliberately avoids inspecting a source runtime on restore.
    return ["source-fts5", "knowledge-library-fts5", "chat-ingress-fts5", "readable-projections"]


def _require_selected_events(events: list[dict[str, Any]], case_ids: list[str]) -> None:
    allowed = set(case_ids)
    for event in events:
        case_id = event.get("case_id")
        if case_id in allowed:
            continue
        if event["event_type"] == "work_transaction.committed":
            affected = event["payload"].get("affected_case_ids")
            if isinstance(affected, list) and set(affected).issubset(allowed):
                continue
        raise _invalid("$case_ids", "selected envelope cannot include another case's canonical history")


def _manifest_files(value: object) -> None:
    if not isinstance(value, list) or not value:
        raise _invalid("$envelope/files", "envelope must declare one or more files")
    seen: set[str] = set()
    allowed_roles = set(_ROOTS)
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {
            "role",
            "relative_path",
            "byte_count",
            "sha256",
        }:
            raise _invalid("$envelope/files", "envelope file entry is malformed")
        relative = _safe_relative(entry["relative_path"])
        role = entry["role"]
        if role not in allowed_roles or not relative.is_relative_to(_ROOTS[role]):
            raise _invalid("$envelope/files", "envelope file escapes its declared portable class")
        if (
            relative.as_posix() in seen
            or not isinstance(entry["byte_count"], int)
            or entry["byte_count"] < 0
            or not _digest(entry["sha256"])
        ):
            raise _invalid("$envelope/files", "envelope file entry has invalid binding")
        seen.add(relative.as_posix())


def _case_ids(value: object) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise _invalid("$case_ids", "one or more unique selected case IDs are required")
    return sorted(value)


def _safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise _invalid("$relative_path", "portable path must be a nonempty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise _invalid("$relative_path", "portable path is not safely relative")
    return path


def _relative_runtime_path(root: Path, path: Path) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise _invalid("$source", "portable source path escapes the runtime root") from exc
    return _safe_relative(relative.as_posix())


def _new_directory(path: Path, location: str) -> Path:
    if path.is_symlink() or path.exists():
        raise _invalid(location, "target path must be a new non-symlink directory")
    if path.parent.is_symlink():
        raise _invalid(location, "target parent cannot be a symlink")
    return path


def _existing_directory(path: Path, location: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise _invalid(location, "path must be an existing non-symlink directory")
    return path


def _directory_identity(path: Path, location: str) -> tuple[int, int]:
    try:
        details = path.lstat()
    except OSError as exc:
        raise _invalid(location, "required synthetic root is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(details.st_mode):
        raise _invalid(location, "required synthetic root is not a directory")
    return details.st_dev, details.st_ino


def _regular_bytes(path: Path, location: str) -> bytes:
    try:
        details = path.lstat()
    except OSError as exc:
        raise _invalid(location, "required portable file is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise _invalid(location, "portable files must be regular non-hardlinked files")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            content = os.read(descriptor, details.st_size)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise _invalid(location, "portable file could not be safely read") from exc
    if len(content) != details.st_size:
        raise _invalid(location, "portable file changed during read")
    return content


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, content) != len(content):
            raise OSError("short portable write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    for directory in sorted({path.parent for path in root.rglob("*") if path.is_file()} | {root}):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value).issubset(set("0123456789abcdef"))


def _invalid(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
