"""Purpose-separated atomic U1 publication for one ordered four-source migration wave.

The one-source ``chat_first_u1_save`` path remains deliberately unchanged.  This sibling accepts
only M1/W1/W2/W3, stages every immutable member before one canonical visibility event, and rebuilds
the shared derived FTS/workspace from both legacy one-source and multi-source events.
"""

from __future__ import annotations

import hmac
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
from vault_next.private_admission import PrivateAdmissionError, PrivateAdmissionPublisher
from vault_next.private_workspace import (
    AUTHORITY_ID,
    PrivateBundleLayout,
    PrivateWorkspaceItem,
    RealPrivateWorkspaceProjectionCoordinator,
)
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-multi-source-u1/1.0.0"
PURPOSE = "chat_first_u1_multi_source_save"
_ROLES = ("M1", "W1", "W2", "W3")
_EXTRA_LAYOUT = (
    "staging/u1-multi-source-save",
    "receipts/chat-first-u1-multi-source-save",
    "evidence/u1-multi-source-save",
)


@dataclass(frozen=True)
class MultiSourcePublicationProfile:
    """The narrow contract that distinguishes one ordered U1 publication family.

    Profiles deliberately share object storage and derived rebuilds but never a receipt purpose,
    manifest schema, event schema, or source-role ordering.  That makes a knowledge wave a sibling
    of S6-W2 rather than a relabelled work-continuity event.
    """

    component: str
    purpose: str
    roles: tuple[str, str, str, str]
    manifest_schema: str
    receipt_schema: str
    display_schema: str
    signed_schema: str
    event_schema: str
    candidate_schema: str
    staging_directory: str
    receipt_directory: str
    evidence_directory: str
    operations: tuple[str, str, str, str]


WORK_CONTINUITY_PROFILE = MultiSourcePublicationProfile(
    component=COMPONENT,
    purpose=PURPOSE,
    roles=_ROLES,
    manifest_schema="chat-first-u1-multi-source-save-manifest",
    receipt_schema="chat-first-u1-multi-source-save-receipt",
    display_schema="chat-first-u1-multi-source-save-display",
    signed_schema="chat-first-u1-multi-source-save-signed-receipt",
    event_schema="multi-source-private-admission-publication",
    candidate_schema="work-continuity-candidate-package",
    staging_directory="staging/u1-multi-source-save",
    receipt_directory="receipts/chat-first-u1-multi-source-save",
    evidence_directory="evidence/u1-multi-source-save",
    operations=(
        "stage_immutable_source_set", "append_multi_source_private_admission_event",
        "rebuild_local_fts5", "rebuild_private_workspace",
    ),
)

KNOWLEDGE_LINEAGE_PROFILE = MultiSourcePublicationProfile(
    component="vault-next-multi-source-knowledge-u1/1.0.0",
    purpose="chat_first_u1_multi_source_knowledge_save",
    roles=("K1", "K2", "K3", "K4"),
    manifest_schema="chat-first-u1-multi-source-knowledge-save-manifest",
    receipt_schema="chat-first-u1-multi-source-knowledge-save-receipt",
    display_schema="chat-first-u1-multi-source-knowledge-save-display",
    signed_schema="chat-first-u1-multi-source-knowledge-save-signed-receipt",
    event_schema="multi-source-knowledge-private-admission-publication",
    candidate_schema="knowledge-lineage-candidate-package",
    staging_directory="staging/u1-multi-source-knowledge-save",
    receipt_directory="receipts/chat-first-u1-multi-source-knowledge-save",
    evidence_directory="evidence/u1-multi-source-knowledge-save",
    operations=(
        "stage_immutable_source_set", "append_multi_source_knowledge_private_admission_event",
        "rebuild_local_fts5", "rebuild_private_workspace",
    ),
)
_PROFILES = (WORK_CONTINUITY_PROFILE, KNOWLEDGE_LINEAGE_PROFILE)


class MultiSourceAdmissionError(RuntimeError):
    """An ordered multi-source U1 packet or its durable publication is invalid."""


class ExistingV2MultiSourceAuthority(Protocol):
    """The v2 identity exposes one additional, purpose-limited confirmation boundary only."""

    def authorize_chat_first_u1_multi_source_save(self, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def verify_chat_first_u1_multi_source_save(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def read_chat_first_u1_multi_source_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...
    def verify_archived_chat_first_u1_multi_source_save(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class MultiSourceItem:
    """One frozen original and its precomputed version/provenance record."""

    role: str
    source_locator: str
    safe_label: str
    source_bytes: bytes
    source_version: dict[str, Any]


@dataclass(frozen=True)
class MultiSourceAdmissionInput:
    """All state that one exact multi-source confirmation is allowed to publish."""

    manifest: dict[str, Any]
    source_items: tuple[MultiSourceItem, ...]
    artifact: dict[str, Any]
    candidate_package: dict[str, Any]
    relationship_assertions: tuple[dict[str, Any], ...]
    citation_text: tuple[tuple[str, str], ...]
    workspace_items: tuple[PrivateWorkspaceItem, ...]


@dataclass(frozen=True)
class MultiSourceAdmissionResult:
    status: str
    event_id: str
    admission_id: str
    receipt_id: str


class MultiSourceU1V2Adapter:
    """Fail-closed adapter for this receipt purpose; it cannot verify one-source evidence."""

    def __init__(
        self,
        authority: ExistingV2MultiSourceAuthority,
        schemas: SchemaRegistry,
        profile: MultiSourcePublicationProfile = WORK_CONTINUITY_PROFILE,
    ) -> None:
        self.authority = authority
        self.schemas = schemas
        self.profile = profile

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]:
        self._manifest(manifest)
        operation = getattr(self.authority, f"authorize_{self.profile.purpose}", None)
        if not callable(operation):
            raise MultiSourceAdmissionError("multi-source U1 authority does not support this purpose")
        receipt = operation(manifest)
        self._receipt(receipt, manifest)
        return receipt

    def verify(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        self._manifest(manifest)
        operation = getattr(self.authority, f"verify_{self.profile.purpose}", None)
        if not callable(operation):
            raise MultiSourceAdmissionError("multi-source U1 authority does not support this purpose")
        receipt = operation(receipt_id, manifest)
        self._receipt(receipt, manifest)
        return receipt

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require(self.profile.manifest_schema, manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if not hmac.compare_digest(manifest["manifest_digest"], canonical_sha256(material)):
            raise MultiSourceAdmissionError("multi-source U1 manifest digest is invalid")
        if manifest["purpose"] != self.profile.purpose or manifest["authority_id"] != AUTHORITY_ID:
            raise MultiSourceAdmissionError("multi-source U1 manifest is outside its purpose boundary")
        if tuple(item["role"] for item in manifest["source_items"]) != self.profile.roles:
            raise MultiSourceAdmissionError("multi-source U1 source order is invalid")
        if canonical_sha256(manifest["source_items"]) != manifest["ingress_set_sha256"]:
            raise MultiSourceAdmissionError("multi-source U1 source-set binding is invalid")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require(self.profile.receipt_schema, receipt)
        expected = {
            "authority_id": AUTHORITY_ID, "purpose": self.profile.purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise MultiSourceAdmissionError("multi-source U1 receipt binding is invalid")


def build_multi_source_u1_manifest(
    *,
    ids: ULIDFactory = DEFAULT_FACTORY,
    expires_at: datetime,
    bundle_id: str,
    source_items: tuple[MultiSourceItem, ...],
    u0_result_sha256: str,
    artifact_sha256: str,
    candidate_package_sha256: str,
    relationship_ledger_sha256: str,
    citations: tuple[str, ...],
    schemas: SchemaRegistry,
    profile: MultiSourcePublicationProfile = WORK_CONTINUITY_PROFILE,
) -> dict[str, Any]:
    """Build the exact proposal that must be displayed before any multi-source save."""

    if expires_at.tzinfo is None or expires_at.utcoffset() is None or expires_at <= aware_utc_now():
        raise MultiSourceAdmissionError("multi-source U1 proposal expiry is invalid")
    items = _manifest_items(source_items, profile)
    manifest = {
        "schema_version": "1.0", "component": profile.component, "purpose": profile.purpose,
        "authority_id": AUTHORITY_ID, "admission_id": ids.new("private_admission"),
        "bundle_id": bundle_id, "ingress_set_sha256": canonical_sha256(items), "source_items": items,
        "u0_result_sha256": u0_result_sha256, "artifact_sha256": artifact_sha256,
        "candidate_package_sha256": candidate_package_sha256,
        "relationship_ledger_sha256": relationship_ledger_sha256,
        "citations": list(citations), "disclosure": "visible_hosted_reasoning", "retention": "R1_immutable",
        "operations": list(profile.operations),
        "expires_at": timestamp(expires_at),
    }
    manifest["manifest_digest"] = canonical_sha256(manifest)
    MultiSourceU1V2Adapter(_SchemaOnlyAuthority(), schemas, profile)._manifest(manifest)
    return manifest


class MultiSourceAdmissionPublisher:
    """Publish an ordered four-source packet with one event as the visibility watermark."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ExistingV2MultiSourceAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        fault_injector: Callable[[str], None] | None = None,
        profile: MultiSourcePublicationProfile = WORK_CONTINUITY_PROFILE,
    ) -> None:
        self.bundle_root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.profile = profile
        self.adapter = MultiSourceU1V2Adapter(authority, schemas, profile)
        self.ids = id_factory
        self.clock = clock
        self.fault_injector = fault_injector
        self.workspace = RealPrivateWorkspaceProjectionCoordinator(schemas)
        self.legacy = PrivateAdmissionPublisher(
            bundle_root, schemas, authority, id_factory=id_factory, clock=clock
        )

    def publish(self, packet: MultiSourceAdmissionInput, receipt_id: str) -> MultiSourceAdmissionResult:
        """Verify one live receipt, then publish all objects before one canonical event."""

        root = self._root(create_extra=True)
        self._validate_packet(packet)
        manifest = packet.manifest
        prior = self._matching_event(root, manifest["manifest_digest"])
        if prior is not None:
            if prior["receipt_id"] != receipt_id or prior["admission_id"] != manifest["admission_id"]:
                raise MultiSourceAdmissionError("multi-source U1 receipt replay is invalid")
            self._verify_archived(root, receipt_id, manifest)
            return MultiSourceAdmissionResult(
                "already_admitted", prior["event_id"], manifest["admission_id"], receipt_id
            )
        receipt = self.adapter.verify(receipt_id, manifest)
        evidence_reader = getattr(self.authority, f"read_{self.profile.purpose}_evidence", None)
        if not callable(evidence_reader):
            raise MultiSourceAdmissionError("multi-source U1 authority does not support evidence handoff")
        display_bytes, signed_bytes = evidence_reader(receipt_id, manifest)
        self._validate_evidence(display_bytes, signed_bytes, receipt, manifest)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".multi-{manifest['admission_id']}-",
                dir=root / self.profile.staging_directory,
            )
        )
        try:
            self._stage(stage, packet, receipt_id, display_bytes, signed_bytes)
            self._fault("after_stage")
            self._publish_objects(root, stage, packet)
            self._fault("after_objects")
            self._archive_evidence(root, stage, receipt_id)
            self._fault("after_receipt_archive")
            event = self._event(packet, receipt_id)
            self.schemas.require(self.profile.event_schema, event)
            self._write_immutable(
                root / "canonical" / "events" / f"{event['event_id']}.json", canonical_bytes(event)
            )
            self._fault("after_event")
            self._write_immutable(
                root / self.profile.evidence_directory / f"{receipt_id}.consumed.json",
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
            return MultiSourceAdmissionResult("complete", event["event_id"], manifest["admission_id"], receipt_id)
        finally:
            if stage.exists():
                self._remove_stage(stage)

    def recover(self) -> dict[str, int | str]:
        root = self._root(create_extra=True)
        recovered = 0
        parent = root / self.profile.staging_directory
        for child in parent.iterdir():
            if child.is_symlink() or not child.is_dir() or not child.name.startswith(".multi-"):
                raise MultiSourceAdmissionError("multi-source staging is unsafe")
            self._remove_stage(child)
            recovered += 1
        self._rebuild(root)
        return {"status": "complete", "recovered_stages": recovered}

    def verify_restart(self) -> dict[str, int | str]:
        root = self._root(create_extra=False)
        # The legacy verifier deliberately ignores purpose-separated multi events; it still proves
        # every pre-existing one-source receipt/object before this path rebuilds the combined views.
        self.legacy.verify_restart()
        events = self._events(root)
        for event in events:
            self._verify_event(root, event)
        self._rebuild(root)
        return {"status": "complete", "event_count": len(events), "legacy_event_count": len(self.legacy._events(root))}

    def _root(self, *, create_extra: bool) -> Path:
        PrivateBundleLayout.validate(self.bundle_root)
        root = self.bundle_root.resolve(strict=True)
        extra_layout = _EXTRA_LAYOUT if self.profile == WORK_CONTINUITY_PROFILE else (
            self.profile.staging_directory, self.profile.receipt_directory, self.profile.evidence_directory,
        )
        for relative in extra_layout:
            target = root / relative
            if create_extra and not target.exists():
                target.mkdir(mode=0o700)
            if not target.exists() or target.is_symlink() or not target.is_dir() or target.stat().st_mode & 0o077:
                raise MultiSourceAdmissionError("multi-source private bundle layout is unsafe")
        return root

    def _validate_packet(self, packet: MultiSourceAdmissionInput) -> None:
        manifest = packet.manifest
        self.adapter._manifest(manifest)
        items = _manifest_items(packet.source_items, self.profile)
        if items != manifest["source_items"]:
            raise MultiSourceAdmissionError("multi-source item binding changed")
        if canonical_sha256(packet.artifact) != manifest["artifact_sha256"]:
            raise MultiSourceAdmissionError("multi-source artifact binding changed")
        if packet.artifact.get("u0_result_sha256") != manifest["u0_result_sha256"]:
            raise MultiSourceAdmissionError("multi-source U0 result binding changed")
        if packet.artifact.get("citation_text") != [list(row) for row in packet.citation_text]:
            raise MultiSourceAdmissionError("multi-source citation text changed")
        if packet.artifact.get("workspace_items") != [
            PrivateAdmissionPublisher._item_record(item) for item in packet.workspace_items
        ]:
            raise MultiSourceAdmissionError("multi-source workspace description changed")
        self.schemas.require(self.profile.candidate_schema, packet.candidate_package)
        if packet.candidate_package.get("lifecycle") != "inactive":
            raise MultiSourceAdmissionError("multi-source publication cannot activate a candidate")
        if canonical_sha256(packet.candidate_package) != manifest["candidate_package_sha256"]:
            raise MultiSourceAdmissionError("multi-source candidate binding changed")
        relationships = list(packet.relationship_assertions)
        for item in relationships:
            self.schemas.require("relationship-assertion", item)
        if canonical_sha256(relationships) != manifest["relationship_ledger_sha256"]:
            raise MultiSourceAdmissionError("multi-source relationship binding changed")
        anchors = tuple(anchor for anchor, _text in packet.citation_text)
        if anchors != tuple(manifest["citations"]) or len(set(anchors)) != len(anchors):
            raise MultiSourceAdmissionError("multi-source citation anchor binding changed")
        if not all(isinstance(text, str) and text for _anchor, text in packet.citation_text):
            raise MultiSourceAdmissionError("multi-source citation text is invalid")
        if not packet.workspace_items:
            raise MultiSourceAdmissionError("multi-source publication requires workspace items")

    def _stage(
        self, stage: Path, packet: MultiSourceAdmissionInput, receipt_id: str, display: bytes, signed: bytes
    ) -> None:
        for item in packet.source_items:
            self._write_immutable(stage / f"source-{item.role}.bin", item.source_bytes)
        self._write_immutable(stage / "artifact.json", canonical_bytes(packet.artifact))
        self._write_immutable(stage / "manifest.json", canonical_bytes(packet.manifest))
        self._write_immutable(stage / "candidate-package.json", canonical_bytes(packet.candidate_package))
        self._write_immutable(
            stage / "relationships.json", canonical_bytes(list(packet.relationship_assertions))
        )
        self._write_immutable(
            stage / "citation-text.json", canonical_bytes([list(row) for row in packet.citation_text])
        )
        self._write_immutable(stage / f"{receipt_id}.display.json", display)
        self._write_immutable(stage / f"{receipt_id}.receipt.json", signed)

    def _publish_objects(self, root: Path, stage: Path, packet: MultiSourceAdmissionInput) -> None:
        manifest = packet.manifest
        for item in manifest["source_items"]:
            self._publish_immutable(
                stage / f"source-{item['role']}.bin",
                root / "canonical" / "source-objects" / item["source_sha256"],
                item["source_sha256"],
            )
        records = (
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
        )
        for staged, target, digest in records:
            self._publish_immutable(staged, target, digest)

    def _archive_evidence(self, root: Path, stage: Path, receipt_id: str) -> None:
        self._publish_immutable(
            stage / f"{receipt_id}.receipt.json",
            root / self.profile.receipt_directory / f"{receipt_id}.json",
            sha256_hex((stage / f"{receipt_id}.receipt.json").read_bytes()),
        )
        self._publish_immutable(
            stage / f"{receipt_id}.display.json",
            root / self.profile.evidence_directory / f"{receipt_id}.json",
            sha256_hex((stage / f"{receipt_id}.display.json").read_bytes()),
        )

    def _event(self, packet: MultiSourceAdmissionInput, receipt_id: str) -> dict[str, Any]:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise MultiSourceAdmissionError("multi-source publisher clock is invalid")
        manifest = packet.manifest
        return {
            "schema_version": "1.0", "publication_type": self.profile.purpose, "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"], "manifest_digest": manifest["manifest_digest"],
            "receipt_id": receipt_id, "source_items": manifest["source_items"],
            "artifact_object_sha256": manifest["artifact_sha256"],
            "candidate_package_object_sha256": manifest["candidate_package_sha256"],
            "relationship_ledger_object_sha256": manifest["relationship_ledger_sha256"], "recorded_at": timestamp(now),
        }

    def _verify_event(self, root: Path, event: dict[str, Any]) -> None:
        self.schemas.require(self.profile.event_schema, event)
        manifest = self._read_json(root / "canonical" / "artifact-objects" / event["manifest_digest"])
        if not isinstance(manifest, dict):
            raise MultiSourceAdmissionError("multi-source manifest object is invalid")
        self.adapter._manifest(manifest)
        if event["admission_id"] != manifest["admission_id"] or event["source_items"] != manifest["source_items"]:
            raise MultiSourceAdmissionError("multi-source event manifest binding changed")
        self._verify_archived(root, event["receipt_id"], manifest)
        for item in event["source_items"]:
            self._verify_object(root / "canonical" / "source-objects" / item["source_sha256"], item["source_sha256"])
        for directory, field in (
            ("artifact-objects", "artifact_object_sha256"), ("candidate-packages", "candidate_package_object_sha256"),
            ("relationships", "relationship_ledger_object_sha256"),
        ):
            self._verify_object(root / "canonical" / directory / event[field], event[field])

    def _rebuild(self, root: Path) -> None:
        # Run the legacy rebuild first to verify retained one-source evidence; then replace the
        # derived projections with a union based solely on immutable canonical objects/events.
        self.legacy.verify_restart()
        rows: list[tuple[str, str, str]] = []
        items: list[PrivateWorkspaceItem] = []
        for event in self.legacy._events(root):
            rows.extend(
                (event["event_id"], anchor, text)
                for anchor, text in self.legacy._citation_rows_for_event(root, event)
            )
            items.extend(
                self._workspace_items_from_artifact(root, event, event["artifact_object_sha256"])
            )
        # A derived database is a projection, not a per-wave silo.  Rebuild every known
        # purpose-separated multi-source event so a later knowledge wave cannot hide S6-W2
        # continuity pages (and vice versa).  Each sibling still verifies through its own schema
        # and archived-receipt purpose before contributing anything.
        for profile in _PROFILES:
            publisher = self if profile == self.profile else MultiSourceAdmissionPublisher(
                self.bundle_root, self.schemas, self.authority, id_factory=self.ids,
                clock=self.clock, profile=profile,
            )
            for event in publisher._events(root):
                publisher._verify_event(root, event)
                artifact = self._read_json(root / "canonical" / "artifact-objects" / event["artifact_object_sha256"])
                if not isinstance(artifact, dict):
                    raise MultiSourceAdmissionError("multi-source artifact object is invalid")
                citation_rows = artifact.get("citation_text")
                if not _valid_citation_rows(citation_rows):
                    raise MultiSourceAdmissionError("multi-source citation index is unavailable")
                rows.extend(self._citation_rows(root, event, citation_rows))
                items.extend(
                    self._workspace_items_from_artifact(root, event, event["artifact_object_sha256"])
                )
        self._build_fts(root, rows)
        if items:
            self.workspace.build(root, tuple(items))

    def _citation_rows(
        self, root: Path, event: dict[str, Any], citation_rows: object
    ) -> list[tuple[str, str, str]]:
        """Rebuild digest-bound rows from immutable text, preserving historic literal-text fixtures.

        The S6-W2 defect stored a 64-character evidence digest as FTS text.  For new digest-bound
        rows, reconstruct the exact anchor text only from the event's immutable source object and
        reject a missing, duplicate, or mismatched anchor.  Older literal-text records remain
        readable because their second field is not a digest and therefore was never this defect.
        """

        assert isinstance(citation_rows, list)
        digests = [(anchor, text) for anchor, text in citation_rows if _sha256_digest(text)]
        if not digests:
            return [(event["event_id"], anchor, text) for anchor, text in citation_rows]
        evidence: dict[str, str] = {}
        from vault_next.content_profiles import ContentProfileRouter

        for member in event["source_items"]:
            raw = member["source_sha256"]
            material = self._verify_object_returning_bytes(root / "canonical" / "source-objects" / raw, raw)
            normalized = ContentProfileRouter(max_anchors=2048).route(
                material, declared_media_type="text/markdown", declared_extension=".md"
            )
            for anchor in normalized.anchors:
                key = f"{member['role']}:{anchor.anchor}"
                if key in evidence:
                    raise MultiSourceAdmissionError("multi-source citation anchor is ambiguous")
                evidence[key] = anchor.text
        rebuilt: list[tuple[str, str, str]] = []
        for anchor, expected in citation_rows:
            if not _sha256_digest(expected):
                rebuilt.append((event["event_id"], anchor, expected))
                continue
            actual = evidence.get(anchor)
            if actual is None or sha256_hex(actual.encode()) != expected:
                raise MultiSourceAdmissionError("multi-source citation evidence does not match immutable source")
            rebuilt.append((event["event_id"], anchor, actual))
        return rebuilt

    def _workspace_items_from_artifact(
        self, root: Path, event: dict[str, Any], digest: str
    ) -> list[PrivateWorkspaceItem]:
        artifact = self._read_json(root / "canonical" / "artifact-objects" / digest)
        if not isinstance(artifact, dict) or not isinstance(artifact.get("workspace_items"), list):
            raise MultiSourceAdmissionError("canonical artifact has no workspace descriptions")
        result: list[PrivateWorkspaceItem] = []
        for item in artifact["workspace_items"]:
            if not isinstance(item, dict):
                raise MultiSourceAdmissionError("canonical workspace description is invalid")
            result.append(
                PrivateWorkspaceItem(
                    item_id=item["item_id"],
                    version_id=item["version_id"],
                    family=item["family"],
                    view=item["view"],
                    status=item["status"],
                    display_alias=item["display_alias"],
                    canonical_object_sha256=digest,
                    admission_event_id=event["event_id"],
                    body=item["body"],
                    citations=tuple(item["citations"]),
                    candidate_inactive=bool(item.get("candidate_inactive", False)),
                )
            )
        return result

    def _events(self, root: Path) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        directory = root / "canonical" / "events"
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                raise MultiSourceAdmissionError("multi-source event horizon is unsafe")
            record = self._read_json(path)
            if isinstance(record, dict) and record.get("publication_type") == self.profile.purpose:
                events.append(record)
        return events

    def _matching_event(self, root: Path, digest: str) -> dict[str, Any] | None:
        matches = [event for event in self._events(root) if event["manifest_digest"] == digest]
        if len(matches) > 1:
            raise MultiSourceAdmissionError("multi-source event watermark is duplicated")
        return matches[0] if matches else None

    def _verify_archived(self, root: Path, receipt_id: str, manifest: dict[str, Any]) -> None:
        operation = getattr(self.authority, f"verify_archived_{self.profile.purpose}", None)
        if not callable(operation):
            raise MultiSourceAdmissionError("multi-source U1 authority does not support archived verification")
        operation(
            receipt_id, manifest,
            display_root=root / self.profile.evidence_directory,
            receipt_root=root / self.profile.receipt_directory,
        )

    def _validate_evidence(
        self, display_bytes: bytes, signed_bytes: bytes, receipt: dict[str, Any], manifest: dict[str, Any]
    ) -> None:
        try:
            display, signed = json.loads(display_bytes), json.loads(signed_bytes)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MultiSourceAdmissionError("multi-source authority evidence is invalid") from exc
        if canonical_bytes(display) != display_bytes or canonical_bytes(signed) != signed_bytes:
            raise MultiSourceAdmissionError("multi-source authority evidence is not immutable canonical data")
        self.schemas.require(self.profile.display_schema, display)
        self.schemas.require(self.profile.signed_schema, signed)
        if any(
            (
                display.get("manifest") != manifest,
                display.get("receipt") != receipt,
                signed.get("manifest") != manifest,
                signed.get("receipt") != receipt,
            )
        ):
            raise MultiSourceAdmissionError("multi-source authority evidence binding changed")

    @staticmethod
    def _write_immutable(path: Path, material: bytes) -> None:
        if path.exists() or path.is_symlink():
            raise MultiSourceAdmissionError("multi-source immutable target already exists")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.parent / f".{path.name}.tmp"
        with temporary.open("xb") as handle:
            handle.write(material)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    @staticmethod
    def _publish_immutable(staged: Path, target: Path, digest: str) -> None:
        MultiSourceAdmissionPublisher._verify_object(staged, digest)
        if target.exists():
            MultiSourceAdmissionPublisher._verify_object(target, digest)
            staged.unlink()
            return
        os.replace(staged, target)

    @staticmethod
    def _verify_object(path: Path, digest: str) -> None:
        if path.is_symlink() or not path.is_file() or sha256_hex(path.read_bytes()) != digest:
            raise MultiSourceAdmissionError("multi-source immutable object is invalid")

    @staticmethod
    def _verify_object_returning_bytes(path: Path, digest: str) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise MultiSourceAdmissionError("multi-source immutable object is invalid")
        material = path.read_bytes()
        if sha256_hex(material) != digest:
            raise MultiSourceAdmissionError("multi-source immutable object is invalid")
        return material

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | list[Any]:
        if path.is_symlink() or not path.is_file():
            raise MultiSourceAdmissionError("multi-source canonical object is unavailable")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MultiSourceAdmissionError("multi-source canonical JSON is invalid") from exc

    @staticmethod
    def _remove_stage(stage: Path) -> None:
        if stage.is_symlink() or not stage.is_dir():
            raise MultiSourceAdmissionError("multi-source staging is unsafe")
        shutil.rmtree(stage)

    @staticmethod
    def _build_fts(root: Path, rows: list[tuple[str, str, str]]) -> None:
        target = root / "derived" / "fts5" / "citations.sqlite3"
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

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)


def _manifest_items(
    items: tuple[MultiSourceItem, ...],
    profile: MultiSourcePublicationProfile = WORK_CONTINUITY_PROFILE,
) -> list[dict[str, Any]]:
    if len(items) != 4 or tuple(item.role for item in items) != profile.roles:
        raise MultiSourceAdmissionError("multi-source packet requires the exact ordered profile source set")
    records: list[dict[str, Any]] = []
    for item in items:
        version = item.source_version
        if (
            not item.source_locator.startswith("/") or not item.safe_label.endswith(".md")
            or not isinstance(item.source_bytes, bytes) or not item.source_bytes
            or not isinstance(version, dict) or version.get("source_version_id") is None
            or version.get("content_sha256") != sha256_hex(item.source_bytes)
            or version.get("byte_count") != len(item.source_bytes)
            or version.get("profile_id") != "markdown_text" or not isinstance(version.get("provenance_sha256"), str)
        ):
            raise MultiSourceAdmissionError("multi-source member is invalid")
        records.append({
            "role": item.role, "source_locator": item.source_locator, "safe_label": item.safe_label,
            "profile_id": "markdown_text", "source_sha256": sha256_hex(item.source_bytes),
            "source_size": len(item.source_bytes), "source_version_id": version["source_version_id"],
            "provenance_sha256": version["provenance_sha256"],
        })
    return records


def _valid_citation_rows(rows: object) -> bool:
    return isinstance(rows, list) and all(
        isinstance(row, list) and len(row) == 2 and all(isinstance(value, str) and value for value in row)
        for row in rows
    )


def _sha256_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


class _SchemaOnlyAuthority:
    """Avoid coupling manifest construction to a real authority object."""

    def authorize_chat_first_u1_multi_source_save(self, manifest: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("schema-only authority cannot authorize")

    def verify_chat_first_u1_multi_source_save(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("schema-only authority cannot verify")

    def read_chat_first_u1_multi_source_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        raise AssertionError("schema-only authority cannot read evidence")

    def verify_archived_chat_first_u1_multi_source_save(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]:
        raise AssertionError("schema-only authority cannot verify archival evidence")
