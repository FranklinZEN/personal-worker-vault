"""Real-private U1 admission publisher with no source-acquisition capability.

The caller supplies one already-frozen byte representation, cited U0 result, candidate package and
purpose-limited v2 evidence.  This module never opens a user path, selects an attachment, invokes
a host or model, or reaches a network service.  Its only writable capability is a validated private
bundle root and its only authority capability is verification/archive of ``chat_first_u1_save``.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import (
    ChatFirstU1V2Adapter,
    PrivateBundleLayout,
    PrivateWorkspaceItem,
    RealPrivateWorkspaceProjectionCoordinator,
)
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


class PrivateAdmissionError(RuntimeError):
    """A real-private publication cannot safely be completed."""


class ChatFirstU1ArchiveAuthority(Protocol):
    """Purpose-only handoff; neither generic signing nor Keychain access is exposed."""

    def verify_chat_first_u1_save(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def read_chat_first_u1_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_chat_first_u1_save(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PrivateAdmissionInput:
    """One entirely in-memory, already frozen U0-to-U1 publication packet."""

    manifest: dict[str, Any]
    source_bytes: bytes
    source_version: dict[str, Any]
    artifact: dict[str, Any]
    candidate_package: dict[str, Any]
    relationship_assertions: tuple[dict[str, Any], ...]
    citation_text: tuple[tuple[str, str], ...]
    workspace_items: tuple[PrivateWorkspaceItem, ...]


@dataclass(frozen=True)
class PrivateAdmissionResult:
    status: str
    event_id: str
    admission_id: str
    receipt_id: str


class PrivateAdmissionPublisher:
    """Publish one exact U1 proposal into the B1 private-bundle layout.

    The canonical event is the visibility watermark.  Objects and receipt evidence may survive an
    interruption before that event, but are inert and cannot appear in FTS or Markdown views.
    """

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ChatFirstU1ArchiveAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.bundle_root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.adapter = ChatFirstU1V2Adapter(authority, schemas)
        self.ids = id_factory
        self.clock = clock
        self.fault_injector = fault_injector
        self.workspace = RealPrivateWorkspaceProjectionCoordinator(schemas)

    def publish(self, packet: PrivateAdmissionInput, receipt_id: str) -> PrivateAdmissionResult:
        """Verify one receipt, atomically publish its frozen packet, then rebuild derived views."""

        PrivateBundleLayout.validate(self.bundle_root)
        root = self.bundle_root.resolve(strict=True)
        self._validate_packet(packet)
        manifest = packet.manifest
        prior = self._matching_event(root, manifest["manifest_digest"])
        if prior is not None:
            self._require_prior_matches(prior, packet, receipt_id)
            self._verify_archived(root, receipt_id, manifest)
            return PrivateAdmissionResult(
                "already_admitted", prior["event_id"], manifest["admission_id"], receipt_id
            )
        receipt = self.adapter.verify(receipt_id, manifest)
        display_bytes, signed_receipt_bytes = self.authority.read_chat_first_u1_save_evidence(
            receipt_id, manifest
        )
        self._validate_evidence(display_bytes, signed_receipt_bytes, receipt, manifest)
        stage_parent = self._inside(root, root / "staging" / "u1-save")
        stage = Path(tempfile.mkdtemp(prefix=f".admission-{manifest['admission_id']}-", dir=stage_parent))
        try:
            self._stage(stage, packet, receipt_id, display_bytes, signed_receipt_bytes)
            self._fault("after_stage")
            self._publish_objects(root, stage, packet)
            self._fault("after_objects")
            self._archive_evidence(root, stage, receipt_id)
            self._fault("after_receipt_archive")
            event = self._event(packet, receipt_id)
            self.schemas.require("private-admission-publication", event)
            self._write_immutable(self._event_path(root, event["event_id"]), canonical_bytes(event))
            self._fault("after_event")
            self._write_immutable(
                self._inside(root, root / "evidence" / "u1-save" / f"{receipt_id}.consumed.json"),
                canonical_bytes(
                    {
                        "schema_version": "1.0",
                        "receipt_id": receipt_id,
                        "admission_id": manifest["admission_id"],
                        "manifest_digest": manifest["manifest_digest"],
                        "event_id": event["event_id"],
                    }
                ),
            )
            self._rebuild(root)
            return PrivateAdmissionResult(
                "complete", event["event_id"], manifest["admission_id"], receipt_id
            )
        finally:
            if stage.exists():
                self._remove_stage(stage)

    def recover(self) -> dict[str, int | str]:
        """Remove only inert staging directories, then rebuild from canonical events."""

        PrivateBundleLayout.validate(self.bundle_root)
        root = self.bundle_root.resolve(strict=True)
        parent = self._inside(root, root / "staging" / "u1-save")
        recovered = 0
        for child in parent.iterdir():
            if child.is_symlink() or not child.is_dir() or not child.name.startswith(".admission-"):
                raise PrivateAdmissionError("private admission staging is unsafe")
            self._remove_stage(child)
            recovered += 1
        self._rebuild(root)
        return {"status": "complete", "recovered_stages": recovered}

    def verify_restart(self) -> dict[str, int | str]:
        """Verify only archived evidence and canonical objects; never reread an original source."""

        PrivateBundleLayout.validate(self.bundle_root)
        root = self.bundle_root.resolve(strict=True)
        events = self._events(root)
        for event in events:
            self.schemas.require("private-admission-publication", event)
            manifest = self._read_json(
                self._inside(root, root / "canonical" / "artifact-objects" / event["manifest_digest"])
            )
            # The manifest copy is intentionally an artifact object with digest recorded by its event.
            if not isinstance(manifest, dict) or not self._manifest_matches(
                manifest, event["manifest_digest"]
            ):
                raise PrivateAdmissionError("canonical admission manifest is invalid")
            self._verify_archived(root, event["receipt_id"], manifest)
            self._verify_object(
                root / "canonical" / "source-objects" / event["source_object_sha256"],
                event["source_object_sha256"],
            )
            self._verify_object(
                root / "canonical" / "artifact-objects" / event["artifact_object_sha256"],
                event["artifact_object_sha256"],
            )
            self._verify_object(
                root / "canonical" / "candidate-packages" / event["candidate_package_object_sha256"],
                event["candidate_package_object_sha256"],
            )
            self._verify_object(
                root / "canonical" / "relationships" / event["relationship_ledger_object_sha256"],
                event["relationship_ledger_object_sha256"],
            )
        self._rebuild(root)
        return {"status": "complete", "event_count": len(events)}

    def _validate_packet(self, packet: PrivateAdmissionInput) -> None:
        if not isinstance(packet.source_bytes, bytes) or not packet.source_bytes:
            raise PrivateAdmissionError("private admission requires frozen nonempty source bytes")
        manifest = packet.manifest
        self.schemas.require("chat-first-u1-save-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest["manifest_digest"] != canonical_sha256(material):
            raise PrivateAdmissionError("private admission manifest digest is invalid")
        if (
            sha256_hex(packet.source_bytes) != manifest["source_sha256"]
            or len(packet.source_bytes) != manifest["source_size"]
        ):
            raise PrivateAdmissionError("private admission source binding changed")
        if (
            not isinstance(packet.source_version, dict)
            or packet.source_version.get("content_sha256") != manifest["source_sha256"]
        ):
            raise PrivateAdmissionError("private admission source version is invalid")
        if canonical_sha256(packet.artifact) != manifest["artifact_sha256"]:
            raise PrivateAdmissionError("private admission artifact binding changed")
        if packet.artifact.get("u0_result_sha256") != manifest["u0_result_sha256"]:
            raise PrivateAdmissionError("private admission U0 result binding changed")
        if packet.artifact.get("citation_text") != [list(row) for row in packet.citation_text]:
            raise PrivateAdmissionError("private admission artifact citation text changed")
        if packet.artifact.get("workspace_items") != [self._item_record(item) for item in packet.workspace_items]:
            raise PrivateAdmissionError("private admission artifact workspace descriptions changed")
        self.schemas.require("method-candidate-package", packet.candidate_package)
        if packet.candidate_package.get("lifecycle") not in {"inactive", "needs_refinement", "declined"}:
            raise PrivateAdmissionError("private admission cannot activate a candidate")
        if canonical_sha256(packet.candidate_package) != manifest["candidate_package_sha256"]:
            raise PrivateAdmissionError("private admission candidate binding changed")
        relationships = list(packet.relationship_assertions)
        for relationship in relationships:
            self.schemas.require("relationship-assertion", relationship)
        if manifest.get("relationship_ledger_sha256") != canonical_sha256(relationships):
            raise PrivateAdmissionError("private admission relationship binding changed")
        anchors = tuple(anchor for anchor, _text in packet.citation_text)
        if anchors != tuple(manifest["citations"]) or len(set(anchors)) != len(anchors):
            raise PrivateAdmissionError("private admission citation anchors changed")
        if not all(isinstance(text, str) and text for _anchor, text in packet.citation_text):
            raise PrivateAdmissionError("private admission citation text is invalid")
        if not packet.workspace_items:
            raise PrivateAdmissionError("private admission requires generated workspace descriptions")

    def _stage(
        self,
        stage: Path,
        packet: PrivateAdmissionInput,
        receipt_id: str,
        display_bytes: bytes,
        signed_receipt_bytes: bytes,
    ) -> None:
        self._write_immutable(stage / "source.bin", packet.source_bytes)
        self._write_immutable(stage / "artifact.json", canonical_bytes(packet.artifact))
        self._write_immutable(stage / "manifest.json", canonical_bytes(packet.manifest))
        self._write_immutable(stage / "candidate-package.json", canonical_bytes(packet.candidate_package))
        self._write_immutable(stage / "relationships.json", canonical_bytes(list(packet.relationship_assertions)))
        self._write_immutable(stage / "citation-text.json", canonical_bytes(self._citation_records(packet)))
        self._write_immutable(stage / f"{receipt_id}.display.json", display_bytes)
        self._write_immutable(stage / f"{receipt_id}.receipt.json", signed_receipt_bytes)

    def _publish_objects(self, root: Path, stage: Path, packet: PrivateAdmissionInput) -> None:
        manifest = packet.manifest
        objects = (
            (
                stage / "source.bin",
                root / "canonical" / "source-objects" / manifest["source_sha256"],
                manifest["source_sha256"],
            ),
            (
                stage / "artifact.json",
                root / "canonical" / "artifact-objects" / manifest["artifact_sha256"],
                manifest["artifact_sha256"],
            ),
            (
                stage / "manifest.json",
                root / "canonical" / "artifact-objects" / manifest["manifest_digest"],
                sha256_hex(canonical_bytes(manifest)),
            ),
            (
                stage / "candidate-package.json",
                root / "canonical" / "candidate-packages" / manifest["candidate_package_sha256"],
                manifest["candidate_package_sha256"],
            ),
            (
                stage / "relationships.json",
                root / "canonical" / "relationships" / manifest["relationship_ledger_sha256"],
                manifest["relationship_ledger_sha256"],
            ),
            (
                stage / "citation-text.json",
                root / "canonical" / "artifact-objects" / canonical_sha256(self._citation_records(packet)),
                canonical_sha256(self._citation_records(packet)),
            ),
        )
        for staged, target, digest in objects:
            self._publish_immutable(staged, self._inside(root, target), digest)

    def _archive_evidence(self, root: Path, stage: Path, receipt_id: str) -> None:
        self._publish_immutable(
            stage / f"{receipt_id}.receipt.json",
            self._inside(root, root / "receipts" / "chat-first-u1-save" / f"{receipt_id}.json"),
            sha256_hex((stage / f"{receipt_id}.receipt.json").read_bytes()),
        )
        self._publish_immutable(
            stage / f"{receipt_id}.display.json",
            self._inside(root, root / "evidence" / "u1-save" / f"{receipt_id}.json"),
            sha256_hex((stage / f"{receipt_id}.display.json").read_bytes()),
        )

    def _event(self, packet: PrivateAdmissionInput, receipt_id: str) -> dict[str, Any]:
        manifest = packet.manifest
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise PrivateAdmissionError("private admission clock is invalid")
        return {
            "schema_version": "1.0",
            "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"],
            "manifest_digest": manifest["manifest_digest"],
            "receipt_id": receipt_id,
            "source_version": packet.source_version,
            "source_object_sha256": manifest["source_sha256"],
            "artifact_object_sha256": manifest["artifact_sha256"],
            "candidate_package_object_sha256": manifest["candidate_package_sha256"],
            "relationship_ledger_object_sha256": manifest["relationship_ledger_sha256"],
            "recorded_at": timestamp(now),
        }

    def _rebuild(self, root: Path) -> None:
        events = self._events(root)
        rows: list[tuple[str, str, str]] = []
        workspace_items: list[PrivateWorkspaceItem] = []
        for event in events:
            manifest = self._read_json(root / "canonical" / "artifact-objects" / event["manifest_digest"])
            self._verify_object(
                root / "canonical" / "source-objects" / event["source_object_sha256"],
                event["source_object_sha256"],
            )
            citation_rows = self._citation_rows_for_event(root, event)
            for anchor, text in citation_rows:
                rows.append((event["event_id"], anchor, text))
            artifact = self._read_json(root / "canonical" / "artifact-objects" / event["artifact_object_sha256"])
            if not isinstance(artifact, dict):
                raise PrivateAdmissionError("private admission artifact is invalid")
            items = artifact.get("workspace_items")
            if not isinstance(items, list):
                raise PrivateAdmissionError("private admission artifact has no workspace descriptions")
            for item in items:
                if not isinstance(item, dict):
                    raise PrivateAdmissionError("private admission workspace description is invalid")
                workspace_items.append(
                    PrivateWorkspaceItem(
                        item_id=item["item_id"], version_id=item["version_id"], family=item["family"],
                        view=item["view"], status=item["status"], display_alias=item["display_alias"],
                        canonical_object_sha256=event["artifact_object_sha256"], admission_event_id=event["event_id"],
                        body=item["body"], citations=tuple(item["citations"]),
                        candidate_inactive=bool(item.get("candidate_inactive", False)),
                    )
                )
            if not isinstance(manifest, dict) or not self._manifest_matches(
                manifest, event["manifest_digest"]
            ):
                raise PrivateAdmissionError("private admission event/manifest binding changed")
        self._build_fts(root, rows)
        if workspace_items:
            self.workspace.build(root, tuple(workspace_items))

    def _citation_rows_for_event(self, root: Path, event: dict[str, Any]) -> list[list[str]]:
        artifact = self._read_json(root / "canonical" / "artifact-objects" / event["artifact_object_sha256"])
        if not isinstance(artifact, dict):
            raise PrivateAdmissionError("private admission artifact is invalid")
        rows = artifact.get("citation_text")
        if (
            not isinstance(rows, list)
            or not all(
                isinstance(row, list)
                and len(row) == 2
                and all(isinstance(value, str) for value in row)
                for row in rows
            )
        ):
            raise PrivateAdmissionError("private admission citation index is unavailable")
        return rows

    @staticmethod
    def _item_record(item: PrivateWorkspaceItem) -> dict[str, Any]:
        return {
            "item_id": item.item_id,
            "version_id": item.version_id,
            "family": item.family,
            "view": item.view,
            "status": item.status,
            "display_alias": item.display_alias,
            "body": item.body,
            "citations": list(item.citations),
            "candidate_inactive": item.candidate_inactive,
        }

    @staticmethod
    def _citation_records(packet: PrivateAdmissionInput) -> list[list[str]]:
        return [list(row) for row in packet.citation_text]

    @staticmethod
    def _manifest_matches(manifest: dict[str, Any], digest: str) -> bool:
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        return manifest.get("manifest_digest") == digest and canonical_sha256(material) == digest

    def _build_fts(self, root: Path, rows: list[tuple[str, str, str]]) -> None:
        target = self._inside(root, root / "derived" / "fts5" / "citations.sqlite3")
        temporary = target.with_name(".citations.sqlite3.tmp")
        if temporary.exists():
            temporary.unlink()
        connection = sqlite3.connect(temporary)
        try:
            connection.execute("CREATE VIRTUAL TABLE citations USING fts5(event_id UNINDEXED, anchor UNINDEXED, text)")
            connection.executemany("INSERT INTO citations VALUES (?, ?, ?)", rows)
            connection.commit()
        finally:
            connection.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    def _matching_event(self, root: Path, digest: str) -> dict[str, Any] | None:
        matches = [event for event in self._events(root) if event["manifest_digest"] == digest]
        if len(matches) > 1:
            raise PrivateAdmissionError("private admission has duplicate event watermarks")
        return matches[0] if matches else None

    def _require_prior_matches(self, event: dict[str, Any], packet: PrivateAdmissionInput, receipt_id: str) -> None:
        manifest = packet.manifest
        if event["receipt_id"] != receipt_id or event["admission_id"] != manifest["admission_id"]:
            raise PrivateAdmissionError("private admission receipt replay is invalid")

    def _verify_archived(self, root: Path, receipt_id: str, manifest: dict[str, Any]) -> None:
        receipt_root = self._inside(root, root / "receipts" / "chat-first-u1-save")
        display_root = self._inside(root, root / "evidence" / "u1-save")
        self.authority.verify_archived_chat_first_u1_save(
            receipt_id, manifest, display_root=display_root, receipt_root=receipt_root
        )

    def _validate_evidence(
        self, display_bytes: bytes, signed_receipt_bytes: bytes, receipt: dict[str, Any], manifest: dict[str, Any]
    ) -> None:
        try:
            display = json.loads(display_bytes)
            signed = json.loads(signed_receipt_bytes)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrivateAdmissionError("private admission authority evidence is invalid") from exc
        if canonical_bytes(display) != display_bytes or canonical_bytes(signed) != signed_receipt_bytes:
            raise PrivateAdmissionError("private admission authority evidence is not immutable canonical data")
        self.schemas.require("chat-first-u1-save-display", display)
        self.schemas.require("chat-first-u1-save-signed-receipt", signed)
        if (
            display.get("manifest") != manifest
            or display.get("receipt") != receipt
            or signed.get("manifest") != manifest
            or signed.get("receipt") != receipt
        ):
            raise PrivateAdmissionError("private admission authority evidence binding changed")

    def _events(self, root: Path) -> list[dict[str, Any]]:
        directory = self._inside(root, root / "canonical" / "events")
        events: list[dict[str, Any]] = []
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                raise PrivateAdmissionError("private admission event horizon is unsafe")
            event = self._read_json(path)
            # A separately purpose-bound multi-source publication shares the canonical event
            # directory but must never be interpreted by this one-source receipt verifier.
            # Its own publisher verifies and rebuilds the combined derived views.
            if isinstance(event, dict) and event.get("publication_type") in {
                "chat_first_u1_multi_source_save",
                "chat_first_u1_multi_source_knowledge_save",
            }:
                continue
            events.append(event)
        return events

    def _event_path(self, root: Path, event_id: str) -> Path:
        return self._inside(root, root / "canonical" / "events" / f"{event_id}.json")

    @staticmethod
    def _inside(root: Path, candidate: Path) -> Path:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise PrivateAdmissionError("private admission path escaped its bundle") from exc
        return resolved

    @staticmethod
    def _write_immutable(path: Path, material: bytes) -> None:
        if path.exists() or path.is_symlink():
            raise PrivateAdmissionError("private admission immutable target already exists")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.parent / f".{path.name}.tmp"
        with temporary.open("xb") as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _publish_immutable(self, staged: Path, target: Path, digest: str) -> None:
        self._verify_object(staged, digest)
        if target.exists():
            self._verify_object(target, digest)
            staged.unlink()
            return
        os.replace(staged, target)

    @staticmethod
    def _verify_object(path: Path, digest: str) -> None:
        if path.is_symlink() or not path.is_file() or sha256_hex(path.read_bytes()) != digest:
            raise PrivateAdmissionError("private admission immutable object is invalid")

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | list[Any]:
        if path.is_symlink() or not path.is_file():
            raise PrivateAdmissionError("private admission canonical object is unavailable")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrivateAdmissionError("private admission canonical JSON is invalid") from exc

    @staticmethod
    def _remove_stage(stage: Path) -> None:
        if stage.is_symlink() or not stage.is_dir():
            raise PrivateAdmissionError("private admission staging is unsafe")
        shutil.rmtree(stage)

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)
