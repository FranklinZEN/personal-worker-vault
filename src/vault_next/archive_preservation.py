"""Purpose-limited S6-H1 archival preservation.

This module deliberately preserves opaque, caller-selected bytes and structural provenance only.  It
does not parse a member's meaning, create FTS rows, or expose member text as a workspace artifact.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Protocol

from hashlib import sha256

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-archive-preservation/1.0.0"
PURPOSE = "archive_preservation"
# This is intentionally a provenance-only extension.  Every lane uses the same opaque-byte,
# local-only retention and archive-preservation receipt contract; semantic parsing remains separately
# calibrated and is not enabled merely by preserving a new export class.
SOURCE_CLASSES = frozenset({"legacy_vault", "claude_export", "codex_export"})


class ArchivePreservationError(RuntimeError):
    """A preservation wave cannot safely continue."""


class ExistingV2ArchiveAuthority(Protocol):
    def authorize_archive_preservation(self, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def verify_archive_preservation(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]: ...
    def read_archive_preservation_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...
    def verify_archived_archive_preservation(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ArchiveLimits:
    """Explicit bounded-reader caps; callers must choose every nonzero limit."""

    max_members: int
    max_member_bytes: int
    max_total_bytes: int
    max_expansion_ratio: int

    def validate(self) -> None:
        if any(value <= 0 for value in (
            self.max_members, self.max_member_bytes, self.max_total_bytes, self.max_expansion_ratio
        )):
            raise ArchivePreservationError("archive resource caps must be explicit positive values")


@dataclass(frozen=True)
class ArchiveMember:
    lane_id: str
    source_class: str
    source_label: str
    source_scope_sha256: str
    member_id: str
    relative_locator: str
    content: bytes | Path
    profile: str
    observed_at: str | None = None


@dataclass(frozen=True)
class ArchiveExclusion:
    """An exact observed symlink exclusion; its target is never resolved or retained."""

    lane_id: str
    source_class: str
    source_label: str
    source_scope_sha256: str
    relative_locator: str
    unresolved_link_text_sha256: str


@dataclass(frozen=True)
class PreparedArchivePreservation:
    manifest: dict[str, Any]
    members: tuple[ArchiveMember, ...]
    staging_root: Path | None = None


@dataclass(frozen=True)
class ArchivePreservationResult:
    status: str
    event_id: str
    receipt_id: str


class DisposableArchiveStage:
    """Owner-only, `/private/tmp`-bounded staging removed on every caller exit path."""

    def __init__(self, parent: Path) -> None:
        if not parent.is_absolute() or parent.is_symlink() or not parent.is_dir():
            raise ArchivePreservationError("archive staging parent is unsafe")
        self.parent = parent.resolve(strict=True)
        if not _inside(Path("/private/tmp"), self.parent):
            raise ArchivePreservationError("archive staging is not disposable")
        self.root: Path | None = None
        self._member_index = 0

    def __enter__(self) -> DisposableArchiveStage:
        self.root = Path(tempfile.mkdtemp(prefix="vault-next-archive-stage-", dir=self.parent))
        os.chmod(self.root, 0o700)
        (self.root / "members").mkdir(mode=0o700)
        if self.root.stat().st_mode & 0o077 or (self.root / "members").stat().st_mode & 0o077:
            self.close()
            raise ArchivePreservationError("archive disposable staging is not owner-only")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def allocate_member(self) -> Path:
        if self.root is None or self.root.is_symlink() or not self.root.is_dir():
            raise ArchivePreservationError("archive disposable staging is unavailable")
        self._member_index += 1
        target = self.root / "members" / f"member-{self._member_index:08d}.bin"
        if target.exists() or target.is_symlink():
            raise ArchivePreservationError("archive disposable staging member is unsafe")
        return target

    def close(self) -> None:
        if self.root is None:
            return
        root = self.root
        self.root = None
        if root.exists():
            if root.is_symlink() or not _inside(self.parent, root):
                raise ArchivePreservationError("archive disposable staging cleanup is unsafe")
            shutil.rmtree(root)


class SafeArchiveReader:
    """Read explicit local directory/ZIP inputs without following links or expanding nested archives."""

    def __init__(
        self,
        limits: ArchiveLimits,
        *,
        excluded_basenames: frozenset[str] = frozenset(),
        expected_symlink_exclusions: dict[str, str] | None = None,
        staging: DisposableArchiveStage | None = None,
    ) -> None:
        limits.validate()
        self.limits = limits
        self.excluded_basenames = excluded_basenames
        self.expected_symlink_exclusions = dict(expected_symlink_exclusions or {})
        self.staging = staging
        if any(
            _safe_locator(locator) != locator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for locator, digest in self.expected_symlink_exclusions.items()
        ):
            raise ArchivePreservationError("archive expected symlink exclusion is invalid")
        self._members_seen = 0
        self._bytes_seen = 0
        self._exclusions: list[ArchiveExclusion] = []

    @property
    def exclusions(self) -> tuple[ArchiveExclusion, ...]:
        return tuple(self._exclusions)

    def directory_members(
        self, root: Path, *, lane_id: str, source_class: str, source_label: str
    ) -> tuple[ArchiveMember, ...]:
        self._lane(lane_id, source_class, source_label)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ArchivePreservationError("archive directory root is unsafe")
        root = root.resolve(strict=True)
        scope_digest = sha256_hex(str(root).encode("utf-8"))
        collected: list[ArchiveMember] = []
        observed_exclusions: set[str] = set()
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            if current_path.is_symlink() or not _inside(root, current_path):
                raise ArchivePreservationError("archive directory traversal escaped its root")
            directories.sort()
            files.sort()
            for name in tuple(directories):
                child = current_path / name
                if child.is_symlink():
                    self._observe_symlink_exclusion(
                        child, root, lane_id, source_class, source_label, scope_digest, observed_exclusions
                    )
                    directories.remove(name)
            for name in files:
                if name in self.excluded_basenames:
                    continue
                path = current_path / name
                if path.is_symlink():
                    self._observe_symlink_exclusion(
                        path, root, lane_id, source_class, source_label, scope_digest, observed_exclusions
                    )
                    continue
                if not path.is_file() or not _inside(root, path.resolve(strict=True)):
                    raise ArchivePreservationError("archive member is unsafe")
                try:
                    with path.open("rb") as source:
                        material = self._read_member(source)
                except OSError as exc:
                    raise ArchivePreservationError("archive member could not be read safely") from exc
                locator = path.relative_to(root).as_posix()
                collected.append(
                    ArchiveMember(
                        lane_id, source_class, source_label, scope_digest, f"file:{locator}", locator, material,
                        _profile(locator), timestamp(aware_utc_now()),
                    )
                )
        if observed_exclusions != set(self.expected_symlink_exclusions):
            raise ArchivePreservationError("archive expected symlink exclusion was not observed")
        return tuple(collected)

    def _observe_symlink_exclusion(
        self,
        path: Path,
        root: Path,
        lane_id: str,
        source_class: str,
        source_label: str,
        scope_digest: str,
        observed: set[str],
    ) -> None:
        """Allow only an exact approved locator and its exact unresolved link-text digest."""

        locator = _safe_locator(path.relative_to(root).as_posix())
        expected = self.expected_symlink_exclusions.get(locator)
        if expected is None or locator in observed:
            raise ArchivePreservationError("archive contains an unapproved symlink")
        try:
            link_text = os.readlink(path)
        except OSError as exc:
            raise ArchivePreservationError("archive symlink link text is unavailable") from exc
        digest = sha256_hex(link_text.encode("utf-8"))
        if digest != expected:
            raise ArchivePreservationError("archive symlink link text changed")
        observed.add(locator)
        self._exclusions.append(
            ArchiveExclusion(lane_id, source_class, source_label, scope_digest, locator, digest)
        )

    def zip_members(
        self, archive: Path, *, lane_id: str, source_class: str, source_label: str
    ) -> tuple[ArchiveMember, ...]:
        self._lane(lane_id, source_class, source_label)
        if not archive.is_absolute() or archive.is_symlink() or not archive.is_file():
            raise ArchivePreservationError("archive input is unsafe")
        archive = archive.resolve(strict=True)
        scope_digest = sha256_hex(str(archive).encode("utf-8"))
        collected: list[ArchiveMember] = []
        seen: set[str] = set()
        try:
            with zipfile.ZipFile(archive) as container:
                for info in sorted(container.infolist(), key=lambda item: item.filename):
                    locator = _safe_zip_locator(info.filename)
                    if locator is None:
                        raise ArchivePreservationError("archive member locator is unsafe")
                    if info.is_dir():
                        continue
                    if PurePosixPath(locator).name in self.excluded_basenames:
                        continue
                    if locator in seen or _zip_member_is_link(info) or info.flag_bits & 0x1:
                        raise ArchivePreservationError("archive member is ambiguous or unsupported")
                    if info.file_size > self.limits.max_member_bytes:
                        raise ArchivePreservationError("archive member exceeds its byte cap")
                    if info.compress_size == 0 and info.file_size:
                        raise ArchivePreservationError("archive member compression metadata is unsafe")
                    if info.compress_size and info.file_size / info.compress_size > self.limits.max_expansion_ratio:
                        raise ArchivePreservationError("archive member exceeds its expansion-ratio cap")
                    with container.open(info, "r") as source:
                        material = self._read_member(source, expected_size=info.file_size)
                    seen.add(locator)
                    collected.append(
                        ArchiveMember(
                            lane_id, source_class, source_label, scope_digest, f"zip:{locator}", locator, material,
                            _profile(locator), timestamp(aware_utc_now()),
                        )
                    )
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ArchivePreservationError("archive input is malformed or unsupported") from exc
        return tuple(collected)

    def _read_member(self, source: BinaryIO, *, expected_size: int | None = None) -> bytes | Path:
        """Bound one member while either retaining a fixture or streaming to disposable staging."""

        if self._members_seen >= self.limits.max_members:
            raise ArchivePreservationError("archive member count exceeds its cap")
        target: Path | None = self.staging.allocate_member() if self.staging is not None else None
        parts: list[bytes] = []
        byte_count = 0
        handle = None
        try:
            if target is not None:
                handle = target.open("xb")
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise ArchivePreservationError("archive member reader returned invalid bytes")
                byte_count += len(chunk)
                if (
                    byte_count > self.limits.max_member_bytes
                    or self._bytes_seen + byte_count > self.limits.max_total_bytes
                ):
                    raise ArchivePreservationError("archive byte cap exceeded")
                if handle is None:
                    parts.append(chunk)
                else:
                    handle.write(chunk)
            if expected_size is not None and byte_count != expected_size:
                raise ArchivePreservationError("archive member byte count changed during read")
            self._members_seen += 1
            self._bytes_seen += byte_count
            if handle is not None:
                handle.close()
                os.chmod(target, 0o600)
                return target
            return b"".join(parts)
        except Exception:
            if handle is not None and not handle.closed:
                handle.close()
            if target is not None and target.exists():
                target.unlink()
            raise

    @staticmethod
    def _lane(lane_id: str, source_class: str, source_label: str) -> None:
        if not lane_id or source_class not in SOURCE_CLASSES or not source_label:
            raise ArchivePreservationError("archive lane is outside the preservation contract")


class ArchivePreservationCoordinator:
    """Prepare, publish and recovery-verify one opaque archival preservation wave."""

    def __init__(
        self, bundle_root: Path, schemas: SchemaRegistry, authority: ExistingV2ArchiveAuthority,
        *, id_factory: ULIDFactory = DEFAULT_FACTORY, fail_before_event: bool = False,
    ) -> None:
        self.root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.ids = id_factory
        self.fail_before_event = fail_before_event

    def prepare(
        self,
        *,
        bundle_id: str,
        members: tuple[ArchiveMember, ...],
        expires_at: datetime,
        exclusions: tuple[ArchiveExclusion, ...] = (),
        staging_root: Path | None = None,
    ) -> PreparedArchivePreservation:
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise ArchivePreservationError("archive preservation expiry is invalid")
        if not members:
            raise ArchivePreservationError("archive preservation requires at least one selected member")
        lanes: dict[str, dict[str, str]] = {}
        items: list[dict[str, Any]] = []
        exclusion_items: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for member in members:
            if member.source_class not in SOURCE_CLASSES or not member.lane_id or not member.source_label:
                raise ArchivePreservationError("archive member source class is invalid")
            locator = _safe_locator(member.relative_locator)
            key = member.lane_id, locator
            if key in seen or not member.member_id or not member.profile:
                raise ArchivePreservationError("archive member identity is ambiguous")
            seen.add(key)
            existing = lanes.setdefault(member.lane_id, {
                "lane_id": member.lane_id, "source_class": member.source_class,
                "source_label": member.source_label, "source_scope_sha256": member.source_scope_sha256,
            })
            if (
                existing["source_class"] != member.source_class
                or existing["source_label"] != member.source_label
                or existing["source_scope_sha256"] != member.source_scope_sha256
            ):
                raise ArchivePreservationError("archive lane metadata changed within a manifest")
            digest, byte_count = _member_digest_and_size(member, staging_root)
            items.append({
                "lane_id": member.lane_id, "member_id": member.member_id,
                "relative_locator": locator, "byte_count": byte_count,
                "content_sha256": digest, "profile": member.profile, "disposition": "preserved",
                "duplicate_group": digest,
            })
        exclusion_seen: set[tuple[str, str]] = set()
        for exclusion in exclusions:
            locator = _safe_locator(exclusion.relative_locator)
            key = exclusion.lane_id, locator
            if key in seen or key in exclusion_seen or exclusion.source_class not in SOURCE_CLASSES:
                raise ArchivePreservationError("archive symlink exclusion identity is ambiguous")
            if len(exclusion.unresolved_link_text_sha256) != 64:
                raise ArchivePreservationError("archive symlink exclusion digest is invalid")
            exclusion_seen.add(key)
            existing = lanes.get(exclusion.lane_id)
            if existing is None or (
                existing["source_class"] != exclusion.source_class
                or existing["source_label"] != exclusion.source_label
                or existing["source_scope_sha256"] != exclusion.source_scope_sha256
            ):
                raise ArchivePreservationError("archive symlink exclusion lane changed within a manifest")
            exclusion_items.append({
                "lane_id": exclusion.lane_id,
                "member_id": f"symlink:{locator}",
                "relative_locator": locator,
                "disposition": "excluded_unsafe_symlink",
                "unresolved_link_text_sha256": exclusion.unresolved_link_text_sha256,
            })
        manifest = {
            "schema_version": "1.0", "component": COMPONENT, "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID, "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id, "lanes": [lanes[key] for key in sorted(lanes)],
            "members": sorted(items, key=lambda item: (item["lane_id"], item["relative_locator"])),
            "exclusions": sorted(exclusion_items, key=lambda item: (item["lane_id"], item["relative_locator"])),
            "disclosure": "local_only_no_content_index", "retention": "append_only_archive_preservation",
            "operations": ["stage_opaque_members", "append_one_archive_preservation_event", "build_metadata_catalogue"],
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        return PreparedArchivePreservation(manifest, members, staging_root)

    def authorize(self, prepared: PreparedArchivePreservation) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_archive_preservation(prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(self, prepared: PreparedArchivePreservation, *, receipt_id: str) -> ArchivePreservationResult:
        self._prepared(prepared)
        root = self._root()
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing.get("receipt_id") != receipt_id:
                raise ArchivePreservationError("archive preservation replay receipt changed")
            self.authority.verify_archived_archive_preservation(
                receipt_id, prepared.manifest,
                display_root=root / "evidence" / "archive-preservation",
                receipt_root=root / "receipts" / "archive-preservation",
            )
            self._verify_objects(root, prepared)
            self._rebuild_catalogue(root, existing, prepared)
            return ArchivePreservationResult("already_complete", existing["event_id"], receipt_id)
        receipt = self.authority.verify_archive_preservation(receipt_id, prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_archive_preservation_evidence(receipt_id, prepared.manifest)
        self._initialize_archive_layout(root)
        stage = self._stage(root, prepared.manifest["admission_id"])
        try:
            records: list[tuple[Path, Path, str]] = []
            by_key = {(member.lane_id, _safe_locator(member.relative_locator)): member for member in prepared.members}
            staged_digests: set[str] = set()
            for item in prepared.manifest["members"]:
                member = by_key[(item["lane_id"], item["relative_locator"])]
                if item["content_sha256"] in staged_digests:
                    continue
                staged_digests.add(item["content_sha256"])
                staged = stage / "members" / item["content_sha256"]
                self._immutable_member(staged, member, item["content_sha256"], prepared.staging_root)
                records.append(
                    (
                        staged,
                        root / "canonical" / "archive-member-objects" / item["content_sha256"],
                        item["content_sha256"],
                    )
                )
            self._immutable(stage / "manifest.json", canonical_bytes(prepared.manifest))
            self._immutable(stage / "display.json", display)
            self._immutable(stage / "receipt.json", signed)
            event = self._event(prepared.manifest, receipt_id)
            self._immutable(stage / "event.json", canonical_bytes(event))
            if self.fail_before_event:
                raise ArchivePreservationError("hostile interruption before archive event publication")
            for staged, target, digest in records:
                self._publish_immutable(staged, target, digest)
            self._publish_immutable(
                stage / "manifest.json",
                root / "canonical" / "archive-preservation-manifests" / prepared.manifest["manifest_digest"],
                sha256_hex(canonical_bytes(prepared.manifest)),
            )
            self._publish_immutable(
                stage / "display.json", root / "evidence" / "archive-preservation" / f"{receipt_id}.json",
                sha256_hex(display),
            )
            self._publish_immutable(
                stage / "receipt.json", root / "receipts" / "archive-preservation" / f"{receipt_id}.json",
                sha256_hex(signed),
            )
            self._publish_immutable(
                stage / "event.json", root / "canonical" / "archive-preservation-events" / f"{event['event_id']}.json",
                sha256_hex(canonical_bytes(event)),
            )
            self._rebuild_catalogue(root, event, prepared)
            return ArchivePreservationResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def verify_restart(
        self, prepared: PreparedArchivePreservation, *, receipt_id: str
    ) -> ArchivePreservationResult:
        root = self._root()
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event.get("receipt_id") != receipt_id:
            raise ArchivePreservationError("archive preservation event is unavailable after restart")
        self.authority.verify_archived_archive_preservation(
            receipt_id, prepared.manifest,
            display_root=root / "evidence" / "archive-preservation",
            receipt_root=root / "receipts" / "archive-preservation",
        )
        self._verify_objects(root, prepared)
        self._rebuild_catalogue(root, event, prepared)
        return ArchivePreservationResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root().resolve(strict=True)
        if not str(root).startswith("/private/tmp/"):
            raise ArchivePreservationError("archive rollback is limited to a disposable mirror")
        record = {
            "schema_version": "1.0", "rollback_type": "logical_archive_preservation_projection",
            "target_event_id": event_id, "parent_events_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        target = root / "canonical" / "archive-preservation-rollbacks" / f"{self.ids.new('event')}.json"
        self._immutable(target, canonical_bytes(record))
        return record

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        return self.root.resolve(strict=True)

    @staticmethod
    def _initialize_archive_layout(root: Path) -> None:
        """Create archive-only descendants after, never before, a verified U1 receipt."""

        for relative in (
            "canonical/archive-member-objects", "canonical/archive-preservation-manifests",
            "canonical/archive-preservation-events", "canonical/archive-preservation-rollbacks",
            "staging/archive-preservation", "receipts/archive-preservation",
            "evidence/archive-preservation", "derived/archive-catalogue",
        ):
            path = root / relative
            if path.exists():
                if path.is_symlink() or not path.is_dir():
                    raise ArchivePreservationError("archive preservation layout is unsafe")
            else:
                path.mkdir(mode=0o700)
            if path.stat().st_mode & 0o077:
                raise ArchivePreservationError("archive preservation layout is not owner-only")

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("archive-preservation-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest["manifest_digest"] != canonical_sha256(material):
            raise ArchivePreservationError("archive manifest digest changed")

    def _prepared(self, prepared: PreparedArchivePreservation) -> None:
        self._manifest(prepared.manifest)
        if len(prepared.members) != len(prepared.manifest["members"]):
            raise ArchivePreservationError("archive prepared members changed")
        by_key = {
            (member.lane_id, _safe_locator(member.relative_locator)): member
            for member in prepared.members
        }
        for item in prepared.manifest["members"]:
            member = by_key.get((item["lane_id"], item["relative_locator"]))
            if (
                member is None
                or _member_digest_and_size(member, prepared.staging_root)
                != (item["content_sha256"], item["byte_count"])
            ):
                raise ArchivePreservationError("archive member bytes changed after proposal")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require("archive-preservation-receipt", receipt)
        expected = {
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise ArchivePreservationError("archive preservation receipt binding is invalid")

    def _event(self, manifest: dict[str, Any], receipt_id: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0", "publication_type": PURPOSE, "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"], "receipt_id": receipt_id,
            "manifest_digest": manifest["manifest_digest"], "member_count": len(manifest["members"]),
            "excluded_member_count": len(manifest["exclusions"]),
            "disclosure": manifest["disclosure"], "semantic_adoption": False, "content_indexed": False,
            "recorded_at": timestamp(aware_utc_now()),
        }

    def _matching(self, root: Path, digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "archive-preservation-events"
        if not directory.exists():
            return None
        matches = []
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink():
                record = self._json(path)
                if record.get("manifest_digest") == digest:
                    matches.append(record)
        if len(matches) > 1:
            raise ArchivePreservationError("archive preservation event is duplicated")
        return matches[0] if matches else None

    def _verify_objects(self, root: Path, prepared: PreparedArchivePreservation) -> None:
        for item in prepared.manifest["members"]:
            path = root / "canonical" / "archive-member-objects" / item["content_sha256"]
            if (
                path.is_symlink() or not path.is_file()
                or _sha256_file(path) != item["content_sha256"]
            ):
                raise ArchivePreservationError("archive member object is invalid")

    def _rebuild_catalogue(
        self, root: Path, event: dict[str, Any], prepared: PreparedArchivePreservation
    ) -> None:
        keys = (
            "lane_id", "member_id", "relative_locator", "byte_count", "content_sha256",
            "profile", "disposition", "duplicate_group",
        )
        exclusion_keys = (
            "lane_id", "member_id", "relative_locator", "disposition", "unresolved_link_text_sha256",
        )
        catalogue = {
            "schema_version": "1.0", "event_id": event["event_id"],
            "manifest_digest": prepared.manifest["manifest_digest"], "content_indexed": False,
            "members": [{key: item[key] for key in keys} for item in prepared.manifest["members"]],
            "exclusions": [
                {key: item[key] for key in exclusion_keys} for item in prepared.manifest["exclusions"]
            ],
        }
        catalogue["catalogue_sha256"] = canonical_sha256(catalogue)
        target = root / "derived" / "archive-catalogue" / f"{event['event_id']}.json"
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(canonical_bytes(catalogue))
        os.chmod(target, 0o600)

    def _stage(self, root: Path, admission_id: str) -> Path:
        parent = root / "staging" / "archive-preservation"
        parent.mkdir(mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise ArchivePreservationError("archive staging root is unsafe")
        return Path(tempfile.mkdtemp(prefix=f".archive-{admission_id}-", dir=parent))

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise ArchivePreservationError("archive immutable target already exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _immutable_member(path: Path, member: ArchiveMember, digest: str, staging_root: Path | None) -> None:
        """Copy a checked staged member without bringing its opaque bytes back into memory."""

        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise ArchivePreservationError("archive immutable target already exists")
        if isinstance(member.content, bytes):
            ArchivePreservationCoordinator._immutable(path, member.content)
        else:
            source = _staged_member_path(member.content, staging_root)
            try:
                with source.open("rb") as incoming, path.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
            except OSError as exc:
                if path.exists():
                    path.unlink()
                raise ArchivePreservationError("archive staged member could not be copied") from exc
            os.chmod(path, 0o600)
        if _sha256_file(path) != digest:
            if path.exists():
                path.unlink()
            raise ArchivePreservationError("archive staged member digest changed")

    @staticmethod
    def _publish_immutable(staged: Path, target: Path, digest: str) -> None:
        if _sha256_file(staged) != digest:
            raise ArchivePreservationError("archive staged object digest changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or _sha256_file(target) != digest:
                raise ArchivePreservationError("archive immutable target conflicts")
            staged.unlink()
        else:
            os.replace(staged, target)

    @staticmethod
    def _json(path: Path) -> dict[str, Any]:
        try:
            material = path.read_bytes()
            value = json.loads(material)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArchivePreservationError("archive preservation canonical event is invalid") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != material:
            raise ArchivePreservationError("archive preservation event is not canonical")
        return value


def _inside(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_locator(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) in {".", ""}:
        raise ArchivePreservationError("archive member locator is unsafe")
    return path.as_posix()


def _safe_zip_locator(value: str) -> str | None:
    try:
        return _safe_locator(value.rstrip("/"))
    except ArchivePreservationError:
        return None


def _staged_member_path(path: Path, staging_root: Path | None) -> Path:
    if staging_root is None:
        raise ArchivePreservationError("archive staged member lacks a disposable root")
    if not staging_root.is_absolute() or staging_root.is_symlink() or not staging_root.is_dir():
        raise ArchivePreservationError("archive disposable staging root is unsafe")
    root = staging_root.resolve(strict=True)
    if not _inside(Path("/private/tmp"), root):
        raise ArchivePreservationError("archive staging root is not disposable")
    if root.stat().st_mode & 0o077:
        raise ArchivePreservationError("archive staging root is not owner-only")
    if path.is_symlink() or not path.is_file():
        raise ArchivePreservationError("archive staged member is unsafe")
    resolved = path.resolve(strict=True)
    if not _inside(root, resolved):
        raise ArchivePreservationError("archive staged member escaped its root")
    return resolved


def _member_digest_and_size(member: ArchiveMember, staging_root: Path | None) -> tuple[str, int]:
    if isinstance(member.content, bytes):
        return sha256_hex(member.content), len(member.content)
    return _digest_and_size_file(_staged_member_path(member.content, staging_root))


def _digest_and_size_file(path: Path) -> tuple[str, int]:
    """Read opaque stored bytes in bounded chunks without materializing them as a Python value."""

    try:
        digest = sha256()
        size = 0
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise ArchivePreservationError("archive object could not be read safely") from exc
    return digest.hexdigest(), size


def _sha256_file(path: Path) -> str:
    return _digest_and_size_file(path)[0]


def _zip_member_is_link(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _profile(locator: str) -> str:
    suffix = Path(locator).suffix.lower()
    profiles = {
        ".md": "markdown_text", ".txt": "plain_text", ".json": "json", ".zip": "opaque_archive",
    }
    return profiles.get(suffix, "opaque_binary")
