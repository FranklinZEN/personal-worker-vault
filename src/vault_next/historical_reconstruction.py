"""Candidate-only S6-H2 reconstruction over an already preserved archive parent.

This layer never opens a legacy path or an archive member.  It operates on supplied H1 manifest/event
metadata and later on caller-supplied, exact selected observations.  It has no capability to mark a
historical statement current, activate a skill, promote knowledge, or perform a U2 action.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-historical-reconstruction/1.0.0"
PURPOSE = "historical_reconstruction"
FAMILY = "meeting_workstream_history"
_PREDICATES = frozenset(
    {
        "same_bytes", "revises", "summarizes", "derived_from", "cites", "supports", "contradicts",
        "prepares_for", "debriefs", "discusses", "produced", "reports_decision", "proposes_follow_up",
        "depends_on", "possibly_same_artifact", "possibly_same_workstream", "primary_of", "supports_primary",
    }
)
_BASIS = frozenset(
    {
        "exact_bytes", "export_declared", "explicit_reference", "timestamp_adjacency",
        "content_evidence", "bounded_analysis",
    }
)
_STATUSES = frozenset(
    {"candidate", "source_reported", "structurally_verified", "rejected", "superseded", "owner_confirmed"}
)


class HistoricalReconstructionError(RuntimeError):
    """An H2 catalogue, candidate package, or append-only publication is unsafe."""


class ExistingV2HistoricalReconstructionAuthority(Protocol):
    """Purpose-only seam; it exposes neither signing keys nor generic U1 authority."""

    def authorize_historical_reconstruction(self, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def verify_historical_reconstruction(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def read_historical_reconstruction_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_historical_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HistoricalRelationship:
    subject_ref: str
    object_ref: str
    predicate: str
    basis_type: str
    evidence_refs: tuple[str, ...]
    status: str = "candidate"
    effective_at: str | None = None
    confidence: str = "medium"
    omissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedHistoricalReconstruction:
    catalogue: dict[str, Any]
    manifest: dict[str, Any]
    package: dict[str, Any]


@dataclass(frozen=True)
class HistoricalReconstructionResult:
    status: str
    event_id: str
    receipt_id: str


class HistoricalReconstructionCoordinator:
    """Build and publish one bounded historical/candidate-only H2 packet."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ExistingV2HistoricalReconstructionAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        fail_before_event: bool = False,
    ) -> None:
        self.root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.ids = id_factory
        self.fail_before_event = fail_before_event

    def catalogue(self, parent_event: dict[str, Any], parent_manifest: dict[str, Any]) -> dict[str, Any]:
        """Create metadata-only entries from a supplied, exact H1 parent manifest."""

        self._parent(parent_event, parent_manifest)
        lane_classes = {lane["lane_id"]: lane["source_class"] for lane in parent_manifest["lanes"]}
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in parent_manifest["members"]:
            required = {
                "lane_id", "member_id", "relative_locator", "byte_count", "content_sha256", "profile",
                "disposition", "duplicate_group",
            }
            if set(item) != required or item["disposition"] != "preserved":
                raise HistoricalReconstructionError("archive parent member metadata is invalid")
            lane_id, member_id = item["lane_id"], item["member_id"]
            member_ref = f"{lane_id}:{member_id}"
            if lane_id not in lane_classes or member_ref in seen:
                raise HistoricalReconstructionError("archive parent member identity is ambiguous")
            if not isinstance(item["byte_count"], int) or item["byte_count"] < 0:
                raise HistoricalReconstructionError("archive parent member byte count is invalid")
            seen.add(member_ref)
            entries.append(
                {
                    "member_ref": member_ref,
                    "lane_id": lane_id,
                    "member_id": member_id,
                    "relative_locator": item["relative_locator"],
                    "profile": item["profile"],
                    "byte_count": item["byte_count"],
                    "content_sha256": item["content_sha256"],
                    "duplicate_group": item["duplicate_group"],
                    "source_class": lane_classes[lane_id],
                }
            )
        if not entries:
            raise HistoricalReconstructionError("archive parent has no selectable preserved members")
        if not isinstance(parent_manifest["exclusions"], list):
            raise HistoricalReconstructionError("archive parent exclusions are invalid")
        catalogue = {
            "schema_version": "1.0", "component": COMPONENT,
            "parent_event_id": parent_event["event_id"],
            "parent_manifest_digest": parent_manifest["manifest_digest"],
            "entries": sorted(entries, key=lambda item: item["member_ref"]),
            "excluded_member_count": len(parent_manifest["exclusions"]),
        }
        catalogue["catalogue_digest"] = canonical_sha256(catalogue)
        self.schemas.require("archive-reconstruction-catalogue", catalogue)
        return catalogue

    def prepare(
        self,
        *,
        catalogue: dict[str, Any],
        bundle_id: str,
        selected_member_refs: tuple[str, ...],
        relationships: tuple[HistoricalRelationship, ...],
        primary: dict[str, Any],
        supporting_artifacts: tuple[dict[str, Any], ...],
        exceptions: tuple[dict[str, Any], ...],
        expires_at: datetime,
    ) -> PreparedHistoricalReconstruction:
        self._catalogue(catalogue)
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise HistoricalReconstructionError("historical reconstruction expiry is invalid")
        if not selected_member_refs or len(selected_member_refs) != len(set(selected_member_refs)):
            raise HistoricalReconstructionError("historical reconstruction selection is invalid")
        selected = set(selected_member_refs)
        available = {entry["member_ref"] for entry in catalogue["entries"]}
        if not selected <= available:
            raise HistoricalReconstructionError("historical reconstruction selected an unavailable member")
        package_relationships = tuple(self._relationship(value, selected) for value in relationships)
        if not isinstance(primary, dict) or not primary or not supporting_artifacts:
            raise HistoricalReconstructionError("historical reconstruction primary/support package is incomplete")
        if any(not isinstance(item, dict) or not item for item in supporting_artifacts):
            raise HistoricalReconstructionError("historical reconstruction support artifact is invalid")
        if any(not isinstance(item, dict) or not item for item in exceptions):
            raise HistoricalReconstructionError("historical reconstruction exception is invalid")
        package = {
            "schema_version": "1.0", "component": COMPONENT, "family": FAMILY,
            "primary": primary, "supporting_artifacts": list(supporting_artifacts),
            "relationships": list(package_relationships), "exceptions": list(exceptions),
            "candidate_only": True, "no_activation": True, "no_knowledge_promotion": True,
            "no_current_work": True, "no_u2": True,
        }
        package["package_digest"] = canonical_sha256(package)
        self.schemas.require("historical-reconstruction-package", package)
        manifest = {
            "schema_version": "1.0", "component": COMPONENT, "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID, "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id, "family": FAMILY,
            "parent_event_id": catalogue["parent_event_id"],
            "parent_manifest_digest": catalogue["parent_manifest_digest"],
            "catalogue_digest": catalogue["catalogue_digest"],
            "selected_member_refs": list(selected_member_refs), "disclosure": "local_only",
            "candidate_only": True,
            "operations": [
                "append_candidate_relationships",
                "save_historical_primary_package",
                "build_bounded_navigation",
            ],
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        return PreparedHistoricalReconstruction(catalogue, manifest, package)

    def temporary_view(self, prepared: PreparedHistoricalReconstruction) -> dict[str, Any]:
        """Provide a U0 primary-first view without writing any state."""

        self._prepared(prepared)
        return {
            "persistence": "ephemeral", "candidate_only": True,
            "primary": prepared.package["primary"],
            "supporting_artifacts": prepared.package["supporting_artifacts"],
            "relationships": prepared.package["relationships"], "exceptions": prepared.package["exceptions"],
        }

    def authorize(self, prepared: PreparedHistoricalReconstruction) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_historical_reconstruction(prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(self, prepared: PreparedHistoricalReconstruction, *, receipt_id: str) -> HistoricalReconstructionResult:
        self._prepared(prepared)
        root = self._root()
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing["receipt_id"] != receipt_id:
                raise HistoricalReconstructionError("historical reconstruction receipt replay changed")
            self.authority.verify_archived_historical_reconstruction(
                receipt_id, prepared.manifest,
                display_root=root / "evidence" / "historical-reconstruction",
                receipt_root=root / "receipts" / "historical-reconstruction",
            )
            self._verify_package(root, prepared)
            self._rebuild(root, existing, prepared)
            return HistoricalReconstructionResult("already_complete", existing["event_id"], receipt_id)
        receipt = self.authority.verify_historical_reconstruction(receipt_id, prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_historical_reconstruction_evidence(receipt_id, prepared.manifest)
        self._initialize(root)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".historical-{prepared.manifest['admission_id']}-",
                dir=root / "staging" / "historical-reconstruction",
            )
        )
        try:
            self._immutable(stage / "manifest.json", canonical_bytes(prepared.manifest))
            self._immutable(stage / "package.json", canonical_bytes(prepared.package))
            self._immutable(stage / "display.json", display)
            self._immutable(stage / "receipt.json", signed)
            event = self._event(prepared, receipt_id)
            self.schemas.require("historical-reconstruction-event", event)
            self._immutable(stage / "event.json", canonical_bytes(event))
            if self.fail_before_event:
                raise HistoricalReconstructionError("injected interruption before historical reconstruction event")
            self._publish(
                stage / "manifest.json",
                root / "canonical" / "historical-reconstruction-manifests" / prepared.manifest["manifest_digest"],
                canonical_sha256(prepared.manifest),
            )
            self._publish(
                stage / "package.json",
                root / "canonical" / "historical-reconstruction-packages" / prepared.package["package_digest"],
                canonical_sha256(prepared.package),
            )
            self._publish(
                stage / "display.json", root / "evidence" / "historical-reconstruction" / f"{receipt_id}.json",
                sha256_hex(display),
            )
            self._publish(
                stage / "receipt.json", root / "receipts" / "historical-reconstruction" / f"{receipt_id}.json",
                sha256_hex(signed),
            )
            self._publish(
                stage / "event.json",
                root / "canonical" / "historical-reconstruction-events" / f"{event['event_id']}.json",
                canonical_sha256(event),
            )
            self._rebuild(root, event, prepared)
            return HistoricalReconstructionResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def verify_restart(
        self, prepared: PreparedHistoricalReconstruction, *, receipt_id: str
    ) -> HistoricalReconstructionResult:
        self._prepared(prepared)
        root = self._root()
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event["receipt_id"] != receipt_id:
            raise HistoricalReconstructionError("historical reconstruction event is unavailable")
        self.authority.verify_archived_historical_reconstruction(
            receipt_id, prepared.manifest,
            display_root=root / "evidence" / "historical-reconstruction",
            receipt_root=root / "receipts" / "historical-reconstruction",
        )
        self._verify_package(root, prepared)
        self._rebuild(root, event, prepared)
        return HistoricalReconstructionResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root()
        if not root.is_relative_to(Path("/private/tmp")):
            raise HistoricalReconstructionError("historical reconstruction rollback is mirror-only")
        record = {
            "schema_version": "1.0", "rollback_type": "logical_historical_reconstruction_projection",
            "target_event_id": event_id, "parent_events_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        self._immutable(
            root / "canonical" / "historical-reconstruction-rollbacks" / f"{self.ids.new('event')}.json",
            canonical_bytes(record),
        )
        return record

    def _parent(self, event: dict[str, Any], manifest: dict[str, Any]) -> None:
        if (
            event.get("publication_type") != "archive_preservation"
            or event.get("manifest_digest") != manifest.get("manifest_digest")
            or not isinstance(event.get("event_id"), str)
            or manifest.get("purpose") != "archive_preservation"
            or manifest.get("disclosure") != "local_only_no_content_index"
        ):
            raise HistoricalReconstructionError("historical reconstruction parent is not an H1 archive event")
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest["manifest_digest"] != canonical_sha256(material):
            raise HistoricalReconstructionError("historical reconstruction parent manifest changed")
        if (
            not isinstance(manifest.get("lanes"), list)
            or not isinstance(manifest.get("members"), list)
            or not isinstance(manifest.get("exclusions"), list)
        ):
            raise HistoricalReconstructionError("historical reconstruction parent metadata is incomplete")

    def _catalogue(self, catalogue: dict[str, Any]) -> None:
        self.schemas.require("archive-reconstruction-catalogue", catalogue)
        material = {key: value for key, value in catalogue.items() if key != "catalogue_digest"}
        if catalogue["catalogue_digest"] != canonical_sha256(material):
            raise HistoricalReconstructionError("historical reconstruction catalogue changed")

    def _relationship(self, value: HistoricalRelationship, selected: set[str]) -> dict[str, Any]:
        if (
            value.subject_ref not in selected
            or value.object_ref not in selected
            or value.subject_ref == value.object_ref
            or value.predicate not in _PREDICATES or value.basis_type not in _BASIS
            or not value.evidence_refs
            or set(value.evidence_refs) - selected
            or value.status not in _STATUSES
            or value.confidence not in {"high", "medium", "low", "unavailable"}
        ):
            raise HistoricalReconstructionError("historical relationship escaped the exact selection")
        if value.status == "owner_confirmed":
            raise HistoricalReconstructionError("historical reconstruction cannot owner-confirm a relationship")
        if value.status == "structurally_verified" and not (
            value.basis_type == "exact_bytes" and value.predicate == "same_bytes"
        ) and value.basis_type != "export_declared":
            raise HistoricalReconstructionError("historical structural verification is unsupported")
        record = {
            "schema_version": "1.0", "relationship_id": self.ids.new("relationship_ledger"),
            "subject_ref": value.subject_ref, "object_ref": value.object_ref, "predicate": value.predicate,
            "basis_type": value.basis_type, "evidence_refs": list(value.evidence_refs),
            "proposer": COMPONENT, "method_version": "1.0.0", "status": value.status,
            "recorded_at": timestamp(aware_utc_now()), "effective_at": value.effective_at,
            "confidence": value.confidence, "omissions": list(value.omissions),
        }
        self.schemas.require("historical-relationship-assertion", record)
        return record

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("historical-reconstruction-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest["manifest_digest"] != canonical_sha256(material):
            raise HistoricalReconstructionError("historical reconstruction manifest changed")
        if (
            manifest["purpose"] != PURPOSE or manifest["authority_id"] != AUTHORITY_ID
            or manifest["disclosure"] != "local_only" or not manifest["candidate_only"]
        ):
            raise HistoricalReconstructionError("historical reconstruction manifest is outside C1")

    def _prepared(self, prepared: PreparedHistoricalReconstruction) -> None:
        self._catalogue(prepared.catalogue)
        self._manifest(prepared.manifest)
        self.schemas.require("historical-reconstruction-package", prepared.package)
        material = {key: value for key, value in prepared.package.items() if key != "package_digest"}
        if prepared.package["package_digest"] != canonical_sha256(material):
            raise HistoricalReconstructionError("historical reconstruction package changed")
        if (
            prepared.manifest["catalogue_digest"] != prepared.catalogue["catalogue_digest"]
            or prepared.manifest["parent_event_id"] != prepared.catalogue["parent_event_id"]
            or prepared.manifest["parent_manifest_digest"] != prepared.catalogue["parent_manifest_digest"]
            or not all(
                prepared.package[key]
                for key in (
                    "candidate_only", "no_activation", "no_knowledge_promotion", "no_current_work", "no_u2"
                )
            )
        ):
            raise HistoricalReconstructionError("historical reconstruction packet binding changed")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        expected = {
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE, "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"], "manifest_digest": manifest["manifest_digest"],
        }
        if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
            raise HistoricalReconstructionError("historical reconstruction receipt binding is invalid")

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        return self.root.resolve(strict=True)

    @staticmethod
    def _initialize(root: Path) -> None:
        for relative in (
            "canonical/historical-reconstruction-manifests", "canonical/historical-reconstruction-packages",
            "canonical/historical-reconstruction-events", "canonical/historical-reconstruction-rollbacks",
            "staging/historical-reconstruction", "receipts/historical-reconstruction",
            "evidence/historical-reconstruction", "derived/historical-reconstruction-catalogue",
        ):
            path = root / relative
            if path.exists():
                if path.is_symlink() or not path.is_dir():
                    raise HistoricalReconstructionError("historical reconstruction layout is unsafe")
            else:
                path.mkdir(mode=0o700)
            if path.stat().st_mode & 0o077:
                raise HistoricalReconstructionError("historical reconstruction layout is not owner-only")

    def _event(self, prepared: PreparedHistoricalReconstruction, receipt_id: str) -> dict[str, Any]:
        manifest = prepared.manifest
        return {
            "schema_version": "1.0", "event_id": self.ids.new("event"), "publication_type": PURPOSE,
            "parent_event_id": manifest["parent_event_id"],
            "parent_manifest_digest": manifest["parent_manifest_digest"],
            "manifest_digest": manifest["manifest_digest"], "package_digest": prepared.package["package_digest"],
            "receipt_id": receipt_id, "candidate_only": True, "recorded_at": timestamp(aware_utc_now()),
        }

    def _matching(self, root: Path, digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "historical-reconstruction-events"
        if not directory.exists():
            return None
        matches: list[dict[str, Any]] = []
        for path in directory.iterdir():
            if not path.is_file() or path.is_symlink():
                continue
            record = self._json(path)
            if record.get("manifest_digest") == digest:
                matches.append(record)
        if len(matches) > 1:
            raise HistoricalReconstructionError("historical reconstruction event is duplicated")
        return matches[0] if matches else None

    def _verify_package(self, root: Path, prepared: PreparedHistoricalReconstruction) -> None:
        path = root / "canonical" / "historical-reconstruction-packages" / prepared.package["package_digest"]
        if (
            path.is_symlink()
            or not path.is_file()
            or sha256_hex(path.read_bytes()) != sha256_hex(canonical_bytes(prepared.package))
        ):
            raise HistoricalReconstructionError("historical reconstruction package object is invalid")

    def _rebuild(self, root: Path, event: dict[str, Any], prepared: PreparedHistoricalReconstruction) -> None:
        record = {
            "schema_version": "1.0", "event_id": event["event_id"],
            "parent_event_id": event["parent_event_id"],
            "package_digest": prepared.package["package_digest"], "candidate_only": True,
            "primary_first": True, "support_count": len(prepared.package["supporting_artifacts"]),
            "relationship_count": len(prepared.package["relationships"]),
            "exception_count": len(prepared.package["exceptions"]),
        }
        record["catalogue_sha256"] = canonical_sha256(record)
        target = root / "derived" / "historical-reconstruction-catalogue" / f"{event['event_id']}.json"
        target.write_bytes(canonical_bytes(record))
        os.chmod(target, 0o600)

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise HistoricalReconstructionError("historical reconstruction immutable target already exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _publish(staged: Path, target: Path, digest: str) -> None:
        if staged.is_symlink() or sha256_hex(staged.read_bytes()) != digest:
            raise HistoricalReconstructionError("historical reconstruction staged object changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(target.read_bytes()) != digest:
                raise HistoricalReconstructionError("historical reconstruction immutable target conflicts")
            staged.unlink()
        else:
            os.replace(staged, target)

    @staticmethod
    def _json(path: Path) -> dict[str, Any]:
        try:
            material = path.read_bytes()
            record = json.loads(material)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalReconstructionError("historical reconstruction record is invalid") from exc
        if not isinstance(record, dict) or canonical_bytes(record) != material:
            raise HistoricalReconstructionError("historical reconstruction record is not canonical")
        return record
