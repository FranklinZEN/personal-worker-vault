"""Append-only S6-P1 primary-artifact presentation retrofits.

The publisher adds one primary-first presentation event over exactly the already committed S6-W1,
S6-W2, and S6-W3 events.  It accepts prepared Markdown and citation companions, never opens a
source object, and treats the existing parent events as immutable preconditions.  Publication is
authorized by a new purpose under the existing v2 identity; no earlier receipt purpose is widened.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-primary-artifact-retrofit/1.0.0"
PURPOSE = "chat_first_u1_primary_artifact_retrofit"
WAVES = ("S6-W1", "S6-W2", "S6-W3")
KINDS = ("meeting_debrief", "work_continuity", "deep_dive")


class PrimaryArtifactRetrofitError(RuntimeError):
    """A three-wave append-only presentation retrofit failed closed."""


class ExistingV2PrimaryArtifactRetrofitAuthority(Protocol):
    def authorize_chat_first_u1_primary_artifact_retrofit(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def verify_chat_first_u1_primary_artifact_retrofit(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def read_chat_first_u1_primary_artifact_retrofit_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_chat_first_u1_primary_artifact_retrofit(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ParentEventBinding:
    """Digest-bound precondition for one existing parent and optional recovery event."""

    wave_id: str
    event_id: str
    event_sha256: str
    support_event_ids: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SupportReference:
    """An existing support record linked from, but not copied into, the primary package."""

    support_role: str
    ref_type: str
    ref: str
    digest: str


@dataclass(frozen=True)
class PrimaryArtifactRetrofitDraft:
    """One selected clean primary revision and its already-admitted support package."""

    wave_id: str
    artifact_id: str
    revision_id: str
    revision_number: int
    artifact_kind: str
    display_alias: str
    markdown: str
    citation_companion: dict[str, Any]
    support_refs: tuple[SupportReference, ...]


@dataclass(frozen=True)
class PreparedPrimaryArtifactRetrofit:
    manifest: dict[str, Any]
    parents: tuple[ParentEventBinding, ...]
    drafts: tuple[PrimaryArtifactRetrofitDraft, ...]
    packages: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class PrimaryArtifactRetrofitResult:
    status: str
    event_id: str
    receipt_id: str


class PrimaryArtifactRetrofitCoordinator:
    """Prepare, publish, and replay-verify one exact W1/W2/W3 retrofit batch."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ExistingV2PrimaryArtifactRetrofitAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        fail_before_event: bool = False,
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
        parents: tuple[ParentEventBinding, ...],
        drafts: tuple[PrimaryArtifactRetrofitDraft, ...],
        expires_at: datetime,
    ) -> PreparedPrimaryArtifactRetrofit:
        """Bind exactly three parent events, primary revisions, and support packages."""

        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise PrimaryArtifactRetrofitError("primary-artifact retrofit expiry is invalid")
        self._require_batch(parents, drafts)
        packages = tuple(
            self._package(parent, draft)
            for parent, draft in zip(parents, drafts, strict=True)
        )
        retrofits = []
        for parent, draft, package in zip(parents, drafts, packages, strict=True):
            retrofits.append(
                {
                    "wave_id": parent.wave_id,
                    "parent_event_id": parent.event_id,
                    "parent_event_sha256": parent.event_sha256,
                    "support_event_ids": [
                        {"event_id": event_id, "event_sha256": digest}
                        for event_id, digest in parent.support_event_ids
                    ],
                    "primary_artifact_id": draft.artifact_id,
                    "primary_revision_id": draft.revision_id,
                    "primary_revision_number": draft.revision_number,
                    "primary_artifact_kind": draft.artifact_kind,
                    "primary_display_alias": draft.display_alias,
                    "primary_markdown_sha256": sha256_hex(draft.markdown.encode("utf-8")),
                    "citation_companion_sha256": canonical_sha256(draft.citation_companion),
                    "support_package_sha256": canonical_sha256(package),
                }
            )
        manifest = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id,
            "retrofits": retrofits,
            "disclosure": "visible_hosted_reasoning_fixed_admitted_scope",
            "retention": "append_only_primary_artifact_retrofit",
            "operations": [
                "stage_three_primary_artifacts",
                "append_one_retrofit_event",
                "build_primary_first_fts5",
                "build_primary_first_workspace",
            ],
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        return PreparedPrimaryArtifactRetrofit(manifest, parents, drafts, packages)

    def authorize(self, prepared: PreparedPrimaryArtifactRetrofit) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_chat_first_u1_primary_artifact_retrofit(
            prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(
        self, prepared: PreparedPrimaryArtifactRetrofit, *, receipt_id: str
    ) -> PrimaryArtifactRetrofitResult:
        """Append one event only after exact v2 evidence and immutable parents verify."""

        self._prepared(prepared)
        root = self._root()
        self._verify_parent_files(root, prepared.parents)
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing.get("receipt_id") != receipt_id:
                raise PrimaryArtifactRetrofitError("retrofit replay receipt changed")
            self.authority.verify_archived_chat_first_u1_primary_artifact_retrofit(
                receipt_id,
                prepared.manifest,
                display_root=root / "evidence" / "u1-primary-artifact-retrofit",
                receipt_root=root / "receipts" / "chat-first-u1-primary-artifact-retrofit",
            )
            self._rebuild_derived(root, existing, prepared)
            return PrimaryArtifactRetrofitResult("already_complete", existing["event_id"], receipt_id)

        receipt = self.authority.verify_chat_first_u1_primary_artifact_retrofit(
            receipt_id, prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_chat_first_u1_primary_artifact_retrofit_evidence(
            receipt_id, prepared.manifest
        )
        stage = self._stage(root, prepared.manifest["admission_id"])
        try:
            records: list[tuple[Path, Path, str]] = []
            for draft, package, binding in zip(
                prepared.drafts,
                prepared.packages,
                prepared.manifest["retrofits"],
                strict=True,
            ):
                markdown = draft.markdown.encode("utf-8")
                companion = canonical_bytes(draft.citation_companion)
                package_bytes = canonical_bytes(package)
                for name, material, target in (
                    (
                        f"{binding['wave_id']}-primary.md",
                        markdown,
                        root / "canonical" / "primary-artifact-objects"
                        / binding["primary_markdown_sha256"],
                    ),
                    (
                        f"{binding['wave_id']}-citations.json",
                        companion,
                        root / "canonical" / "primary-artifact-citations"
                        / binding["citation_companion_sha256"],
                    ),
                    (
                        f"{binding['wave_id']}-package.json",
                        package_bytes,
                        root / "canonical" / "primary-artifact-packages"
                        / binding["support_package_sha256"],
                    ),
                ):
                    staged = stage / name
                    self._immutable(staged, material)
                    records.append((staged, target, sha256_hex(material)))
            self._immutable(stage / "manifest.json", canonical_bytes(prepared.manifest))
            self._immutable(stage / "display.json", display)
            self._immutable(stage / "receipt.json", signed)
            event = self._event(prepared.manifest, receipt_id)
            self._immutable(stage / "event.json", canonical_bytes(event))
            for staged, target, digest in records:
                self._publish_immutable(staged, target, digest)
            self._publish_immutable(
                stage / "manifest.json",
                root / "canonical" / "primary-artifact-retrofit-manifests"
                / prepared.manifest["manifest_digest"],
                sha256_hex(canonical_bytes(prepared.manifest)),
            )
            self._publish_immutable(
                stage / "display.json",
                root / "evidence" / "u1-primary-artifact-retrofit" / f"{receipt_id}.json",
                sha256_hex(display),
            )
            self._publish_immutable(
                stage / "receipt.json",
                root / "receipts" / "chat-first-u1-primary-artifact-retrofit"
                / f"{receipt_id}.json",
                sha256_hex(signed),
            )
            if self.fail_before_event:
                raise PrimaryArtifactRetrofitError("injected interruption before retrofit event")
            self._publish_immutable(
                stage / "event.json",
                root / "canonical" / "primary-artifact-retrofit-events"
                / f"{event['event_id']}.json",
                sha256_hex(canonical_bytes(event)),
            )
            self._rebuild_derived(root, event, prepared)
            return PrimaryArtifactRetrofitResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                for child in stage.iterdir():
                    child.unlink()
                stage.rmdir()

    def verify_restart(
        self, prepared: PreparedPrimaryArtifactRetrofit, *, receipt_id: str
    ) -> PrimaryArtifactRetrofitResult:
        self._prepared(prepared)
        root = self._root()
        self._verify_parent_files(root, prepared.parents)
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None:
            raise PrimaryArtifactRetrofitError("retrofit event is unavailable after restart")
        self.authority.verify_archived_chat_first_u1_primary_artifact_retrofit(
            receipt_id,
            prepared.manifest,
            display_root=root / "evidence" / "u1-primary-artifact-retrofit",
            receipt_root=root / "receipts" / "chat-first-u1-primary-artifact-retrofit",
        )
        self._verify_objects(root, prepared)
        self._rebuild_derived(root, event, prepared)
        return PrimaryArtifactRetrofitResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        """Exercise logical rollback only when this coordinator is rooted below /private/tmp."""

        root = self._root()
        private_tmp = Path("/private/tmp").resolve()
        if not root.is_relative_to(private_tmp):
            raise PrimaryArtifactRetrofitError("retrofit rollback is limited to a disposable mirror")
        event = self._json(
            root / "canonical" / "primary-artifact-retrofit-events" / f"{event_id}.json"
        )
        rollback = {
            "schema_version": "1.0",
            "record_type": "primary_artifact_retrofit_rollback/1.0",
            "rollback_event_id": self.ids.new("event"),
            "target_event_id": event_id,
            "target_manifest_digest": event["manifest_digest"],
            "effect": "deactivate_primary_first_projection_only",
            "parent_events_unchanged": True,
            "recorded_at": timestamp(aware_utc_now()),
        }
        rollback["rollback_sha256"] = canonical_sha256(rollback)
        self._immutable(
            root / "canonical" / "primary-artifact-retrofit-rollbacks"
            / f"{rollback['rollback_event_id']}.json",
            canonical_bytes(rollback),
        )
        return rollback

    def _package(
        self, parent: ParentEventBinding, draft: PrimaryArtifactRetrofitDraft
    ) -> dict[str, Any]:
        refs = [
            {
                "support_role": ref.support_role,
                "ref_type": ref.ref_type,
                "ref": ref.ref,
                "digest": ref.digest,
            }
            for ref in draft.support_refs
        ]
        if not refs or len({item["support_role"] for item in refs}) != len(refs):
            raise PrimaryArtifactRetrofitError("retrofit support package is empty or ambiguous")
        return {
            "schema_version": "1.0",
            "record_type": "primary_artifact_support_package/1.0",
            "component": COMPONENT,
            "wave_id": parent.wave_id,
            "parent_event_id": parent.event_id,
            "support_event_ids": [event_id for event_id, _ in parent.support_event_ids],
            "primary": {
                "artifact_id": draft.artifact_id,
                "revision_id": draft.revision_id,
                "revision_number": draft.revision_number,
                "artifact_kind": draft.artifact_kind,
                "display_alias": draft.display_alias,
                "markdown_sha256": sha256_hex(draft.markdown.encode("utf-8")),
                "citation_companion_sha256": canonical_sha256(draft.citation_companion),
            },
            "supporting": refs,
            "primary_first": True,
            "candidate_states_unchanged": True,
            "parent_records_unchanged": True,
        }

    def _prepared(self, prepared: PreparedPrimaryArtifactRetrofit) -> None:
        self._manifest(prepared.manifest)
        self._require_batch(prepared.parents, prepared.drafts)
        rebuilt_packages = tuple(
            self._package(parent, draft)
            for parent, draft in zip(prepared.parents, prepared.drafts, strict=True)
        )
        for actual, rebuilt in zip(prepared.packages, rebuilt_packages, strict=True):
            if actual != rebuilt:
                raise PrimaryArtifactRetrofitError("retrofit support package changed")
        for parent, draft, package, binding in zip(
            prepared.parents,
            prepared.drafts,
            rebuilt_packages,
            prepared.manifest["retrofits"],
            strict=True,
        ):
            expected = {
                "wave_id": parent.wave_id,
                "parent_event_id": parent.event_id,
                "parent_event_sha256": parent.event_sha256,
                "support_event_ids": [
                    {"event_id": event_id, "event_sha256": digest}
                    for event_id, digest in parent.support_event_ids
                ],
                "primary_artifact_id": draft.artifact_id,
                "primary_revision_id": draft.revision_id,
                "primary_revision_number": draft.revision_number,
                "primary_artifact_kind": draft.artifact_kind,
                "primary_display_alias": draft.display_alias,
                "primary_markdown_sha256": sha256_hex(draft.markdown.encode("utf-8")),
                "citation_companion_sha256": canonical_sha256(draft.citation_companion),
                "support_package_sha256": canonical_sha256(package),
            }
            if binding != expected:
                raise PrimaryArtifactRetrofitError("retrofit selected revisions changed")

    def _require_batch(
        self,
        parents: tuple[ParentEventBinding, ...],
        drafts: tuple[PrimaryArtifactRetrofitDraft, ...],
    ) -> None:
        if len(parents) != 3 or len(drafts) != 3:
            raise PrimaryArtifactRetrofitError("retrofit batch must contain exactly three waves")
        if tuple(item.wave_id for item in parents) != WAVES or tuple(
            item.wave_id for item in drafts
        ) != WAVES:
            raise PrimaryArtifactRetrofitError("retrofit wave order or identity changed")
        for index, (parent, draft) in enumerate(zip(parents, drafts, strict=True)):
            if (
                not parent.event_id.startswith("event_")
                or not _digest(parent.event_sha256)
                or draft.artifact_kind != KINDS[index]
                or not draft.artifact_id.startswith("artifact_")
                or not draft.revision_id.startswith("artifact_version_")
                or draft.revision_number < 1
                or not draft.display_alias.strip()
                or not draft.markdown.startswith("# ")
                or not draft.citation_companion
            ):
                raise PrimaryArtifactRetrofitError("retrofit parent or primary revision is invalid")
            if any(
                not event_id.startswith("event_") or not _digest(digest)
                for event_id, digest in parent.support_event_ids
            ):
                raise PrimaryArtifactRetrofitError("retrofit support event binding is invalid")
        if parents[0].support_event_ids or len(parents[1].support_event_ids) != 1 or parents[2].support_event_ids:
            raise PrimaryArtifactRetrofitError("only W2 may bind its one CR1 recovery event")

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("chat-first-u1-primary-artifact-retrofit-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest.get("manifest_digest") != canonical_sha256(material):
            raise PrimaryArtifactRetrofitError("retrofit manifest digest changed")
        if tuple(item["wave_id"] for item in manifest["retrofits"]) != WAVES:
            raise PrimaryArtifactRetrofitError("retrofit manifest wave order changed")
        if len(manifest["retrofits"][1]["support_event_ids"]) != 1 or any(
            manifest["retrofits"][index]["support_event_ids"] for index in (0, 2)
        ):
            raise PrimaryArtifactRetrofitError("retrofit manifest support event boundary changed")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require("chat-first-u1-primary-artifact-retrofit-receipt", receipt)
        if (
            receipt.get("purpose") != PURPOSE
            or any(
                receipt.get(key) != manifest.get(key)
                for key in ("admission_id", "bundle_id", "manifest_digest")
            )
        ):
            raise PrimaryArtifactRetrofitError("retrofit receipt binding changed")

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        root = self.root.resolve(strict=True)
        if root.is_symlink():
            raise PrimaryArtifactRetrofitError("retrofit root is unsafe")
        return root

    def _verify_parent_files(
        self, root: Path, parents: tuple[ParentEventBinding, ...]
    ) -> None:
        for parent in parents:
            material = self._bytes(
                root / "canonical" / "events" / f"{parent.event_id}.json",
                parent.event_sha256,
            )
            event = self._decode(material)
            if event.get("event_id") != parent.event_id:
                raise PrimaryArtifactRetrofitError("retrofit parent event identity changed")
            for event_id, digest in parent.support_event_ids:
                support = self._bytes(
                    root / "canonical" / "citation-recovery-events" / f"{event_id}.json",
                    digest,
                )
                record = self._decode(support)
                if record.get("event_id") != event_id or record.get("parent_event_id") != parent.event_id:
                    raise PrimaryArtifactRetrofitError("retrofit recovery event is not linked to W2")

    def _verify_objects(self, root: Path, prepared: PreparedPrimaryArtifactRetrofit) -> None:
        for draft, binding, package in zip(
            prepared.drafts, prepared.manifest["retrofits"], prepared.packages, strict=True
        ):
            checks = (
                (
                    root / "canonical" / "primary-artifact-objects"
                    / binding["primary_markdown_sha256"],
                    draft.markdown.encode("utf-8"),
                ),
                (
                    root / "canonical" / "primary-artifact-citations"
                    / binding["citation_companion_sha256"],
                    canonical_bytes(draft.citation_companion),
                ),
                (
                    root / "canonical" / "primary-artifact-packages"
                    / binding["support_package_sha256"],
                    canonical_bytes(package),
                ),
            )
            for path, expected in checks:
                if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                    raise PrimaryArtifactRetrofitError("retrofit canonical object changed")

    def _stage(self, root: Path, admission_id: str) -> Path:
        parent = root / "staging" / "u1-primary-artifact-retrofit"
        parent.mkdir(mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise PrimaryArtifactRetrofitError("retrofit staging root is unsafe")
        return Path(tempfile.mkdtemp(prefix=f".retrofit-{admission_id}-", dir=parent))

    def _event(self, manifest: dict[str, Any], receipt_id: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "publication_type": PURPOSE,
            "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"],
            "receipt_id": receipt_id,
            "manifest_digest": manifest["manifest_digest"],
            "parent_event_ids": [item["parent_event_id"] for item in manifest["retrofits"]],
            "retrofits": manifest["retrofits"],
            "parent_events_unchanged": True,
            "candidate_states_unchanged": True,
            "recorded_at": timestamp(aware_utc_now()),
        }

    def _matching(self, root: Path, manifest_digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "primary-artifact-retrofit-events"
        if not directory.exists():
            return None
        matches = []
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink():
                record = self._json(path)
                if record.get("manifest_digest") == manifest_digest:
                    matches.append(record)
        if len(matches) > 1:
            raise PrimaryArtifactRetrofitError("retrofit event is duplicated")
        return matches[0] if matches else None

    def _rebuild_derived(
        self, root: Path, event: dict[str, Any], prepared: PreparedPrimaryArtifactRetrofit
    ) -> None:
        database = root / "derived" / "fts5" / f"primary-{event['event_id']}.sqlite3"
        temporary = database.with_name(f".{database.name}.tmp")
        if temporary.exists():
            temporary.unlink()
        connection = sqlite3.connect(temporary)
        try:
            connection.execute(
                "CREATE VIRTUAL TABLE primary_artifacts USING fts5("
                "wave_id UNINDEXED, artifact_id UNINDEXED, title, body)"
            )
            connection.executemany(
                "INSERT INTO primary_artifacts VALUES (?, ?, ?, ?)",
                [
                    (draft.wave_id, draft.artifact_id, draft.display_alias, draft.markdown)
                    for draft in prepared.drafts
                ],
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, database)

        base = root / "workspace" / "_views" / "primary" / event["event_id"]
        for draft, package in zip(prepared.drafts, prepared.packages, strict=True):
            directory = base / draft.wave_id
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            primary = directory / "primary.md"
            citations = directory / "primary.citations.json"
            navigation = directory / "supporting-package.md"
            primary.write_text(draft.markdown, encoding="utf-8")
            citations.write_bytes(canonical_bytes(draft.citation_companion))
            lines = [
                f"# {draft.display_alias}",
                "",
                "Primary artifact: primary.md",
                "",
                "## Supporting package",
                "",
            ]
            lines.extend(
                f"- {item['support_role']}: {item['ref']}"
                for item in package["supporting"]
            )
            navigation.write_text("\n".join(lines) + "\n", encoding="utf-8")
            for path in (primary, citations, navigation):
                os.chmod(path, 0o600)

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise PrimaryArtifactRetrofitError("retrofit immutable target exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _publish_immutable(staged: Path, target: Path, digest: str) -> None:
        if sha256_hex(staged.read_bytes()) != digest:
            raise PrimaryArtifactRetrofitError("retrofit staged object digest changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(target.read_bytes()) != digest:
                raise PrimaryArtifactRetrofitError("retrofit immutable target conflicts")
            staged.unlink()
            return
        os.replace(staged, target)

    @staticmethod
    def _bytes(path: Path, digest: str) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise PrimaryArtifactRetrofitError("retrofit bounded canonical record is unavailable")
        material = path.read_bytes()
        if sha256_hex(material) != digest:
            raise PrimaryArtifactRetrofitError("retrofit bounded canonical record digest changed")
        return material

    @staticmethod
    def _decode(material: bytes) -> dict[str, Any]:
        try:
            value = json.loads(material)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrimaryArtifactRetrofitError("retrofit canonical JSON is invalid") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != material:
            raise PrimaryArtifactRetrofitError("retrofit canonical JSON is not canonical")
        return value

    def _json(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise PrimaryArtifactRetrofitError("retrofit canonical record is unavailable")
        return self._decode(path.read_bytes())


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
