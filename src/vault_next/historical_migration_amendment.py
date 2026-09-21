"""Append-only, exact-parent corrections for already-admitted historical migration views."""

from __future__ import annotations

import json
import os
import shutil
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


COMPONENT = "vault-next-historical-migration-amendment/1.0.0"
PURPOSE = "historical_migration_amendment"
DISCLOSURE = "local_private_exact_parent_append_only_amendment"
RETENTION = "append_only_historical_migration_amendment"
OPERATIONS = (
    "append_historical_migration_amendment",
    "build_amendment_fts5",
    "build_amendment_workspace",
)


class HistoricalMigrationAmendmentError(RuntimeError):
    """An amendment is incomplete, substituted, over-authoritative, or unsafe."""


class HistoricalMigrationAmendmentAuthority(Protocol):
    def authorize_historical_migration_amendment(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def verify_historical_migration_amendment(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def read_historical_migration_amendment_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_historical_migration_amendment(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PreparedHistoricalMigrationAmendment:
    manifest: dict[str, Any]
    package: dict[str, Any]
    markdown: str


@dataclass(frozen=True)
class HistoricalMigrationAmendmentResult:
    status: str
    event_id: str
    receipt_id: str


class HistoricalMigrationAmendmentCoordinator:
    """Prepare, append, verify, and project exactly three approved P2 corrections."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: HistoricalMigrationAmendmentAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
    ) -> None:
        self.root = bundle_root
        self.schemas = schemas
        self.authority = authority
        self.ids = id_factory

    def prepare(
        self,
        *,
        bundle_id: str,
        parent_binding: dict[str, str],
        owner_review: dict[str, Any],
        entries: tuple[dict[str, Any], ...],
        deferred_entries: tuple[dict[str, Any], ...],
        expires_at: datetime,
    ) -> PreparedHistoricalMigrationAmendment:
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise HistoricalMigrationAmendmentError("amendment proposal expiry is invalid")
        self._inputs(parent_binding, owner_review, entries, deferred_entries)
        material = {
            "schema_version": "1.0",
            "record_type": "historical_migration_amendment_package/1.0",
            "component": COMPONENT,
            "parent_binding": parent_binding,
            "owner_review": owner_review,
            "entries": list(entries),
            "deferred_entries": list(deferred_entries),
            "candidate_only": True,
            "no_current_work": True,
            "no_promotion": True,
            "no_activation": True,
            "parent_records_unchanged": True,
        }
        package = {**material, "package_digest": canonical_sha256(material)}
        self.schemas.require("historical-migration-amendment-package", package)
        manifest = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id,
            "parent_binding": parent_binding,
            "package_digest": package["package_digest"],
            "entry_ids": [entry["entry_id"] for entry in entries],
            "owner_review_digest": canonical_sha256(owner_review),
            "disclosure": DISCLOSURE,
            "retention": RETENTION,
            "operations": list(OPERATIONS),
            "candidate_only": True,
            "no_current_work": True,
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        markdown = self._markdown(package)
        return PreparedHistoricalMigrationAmendment(manifest, package, markdown)

    def authorize(self, prepared: PreparedHistoricalMigrationAmendment) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_historical_migration_amendment(prepared.manifest)
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(
        self, prepared: PreparedHistoricalMigrationAmendment, *, receipt_id: str
    ) -> HistoricalMigrationAmendmentResult:
        self._prepared(prepared)
        root = self._root()
        self._verify_parent(root, prepared.manifest["parent_binding"])
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing["receipt_id"] != receipt_id:
                raise HistoricalMigrationAmendmentError("amendment receipt replay changed")
            self._archived(root, receipt_id, prepared.manifest)
            self._verify_objects(root, prepared)
            self._rebuild(root, existing, prepared)
            return HistoricalMigrationAmendmentResult("already_complete", existing["event_id"], receipt_id)
        receipt = self.authority.verify_historical_migration_amendment(
            receipt_id, prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_historical_migration_amendment_evidence(
            receipt_id, prepared.manifest
        )
        stage_parent = root / "staging" / "historical-migration-amendment"
        stage_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".amendment-", dir=stage_parent))
        try:
            event = self._event(prepared.manifest, receipt_id)
            materials = {
                "package.json": canonical_bytes(prepared.package),
                "manifest.json": canonical_bytes(prepared.manifest),
                "markdown.md": prepared.markdown.encode("utf-8"),
                "display.json": display,
                "receipt.json": signed,
                "event.json": canonical_bytes(event),
            }
            for name, content in materials.items():
                self._immutable(stage / name, content)
            targets = {
                "package.json": (
                    root / "canonical" / "historical-migration-amendment-packages"
                    / prepared.package["package_digest"]
                ),
                "manifest.json": (
                    root / "canonical" / "historical-migration-amendment-manifests"
                    / prepared.manifest["manifest_digest"]
                ),
                "markdown.md": (
                    root / "canonical" / "historical-migration-amendment-artifacts"
                    / sha256_hex(materials["markdown.md"])
                ),
                "display.json": root / "evidence" / "u1-historical-migration-amendment" / f"{receipt_id}.json",
                "receipt.json": root / "receipts" / PURPOSE / f"{receipt_id}.json",
                "event.json": (
                    root / "canonical" / "historical-migration-amendment-events"
                    / f"{event['event_id']}.json"
                ),
            }
            for name, target in targets.items():
                self._publish(stage / name, target, sha256_hex(materials[name]))
            self._rebuild(root, event, prepared)
            return HistoricalMigrationAmendmentResult("complete", event["event_id"], receipt_id)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def verify_restart(
        self, prepared: PreparedHistoricalMigrationAmendment, *, receipt_id: str
    ) -> HistoricalMigrationAmendmentResult:
        self._prepared(prepared)
        root = self._root()
        self._verify_parent(root, prepared.manifest["parent_binding"])
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event["receipt_id"] != receipt_id:
            raise HistoricalMigrationAmendmentError("amendment event is unavailable after restart")
        self._archived(root, receipt_id, prepared.manifest)
        self._verify_objects(root, prepared)
        self._rebuild(root, event, prepared)
        return HistoricalMigrationAmendmentResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root()
        if not root.is_relative_to(Path("/private/tmp")):
            raise HistoricalMigrationAmendmentError("rollback is limited to a disposable mirror")
        record = {
            "schema_version": "1.0",
            "record_type": "historical_migration_amendment_rollback/1.0",
            "rollback_event_id": self.ids.new("event"),
            "target_event_id": event_id,
            "effect": "deactivate_amendment_projection_only",
            "parent_records_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        self._immutable(
            root / "canonical" / "historical-migration-amendment-rollbacks"
            / f"{record['rollback_event_id']}.json",
            canonical_bytes(record),
        )
        return record

    def _inputs(
        self,
        parent: dict[str, str],
        review: dict[str, Any],
        entries: tuple[dict[str, Any], ...],
        deferred: tuple[dict[str, Any], ...],
    ) -> None:
        required = {"event_id", "event_sha256", "package_digest", "receipt_id"}
        if set(parent) != required or not parent["event_id"].startswith("event_"):
            raise HistoricalMigrationAmendmentError("amendment parent binding is invalid")
        if any(len(parent[key]) != 64 for key in ("event_sha256", "package_digest")):
            raise HistoricalMigrationAmendmentError("amendment parent digest is invalid")
        if len(review.get("ratings", ())) != 5 or len(review.get("choices", ())) != 5:
            raise HistoricalMigrationAmendmentError("owner review is incomplete")
        if len(entries) != 3 or len({item.get("entry_id") for item in entries}) != 3:
            raise HistoricalMigrationAmendmentError("exactly three distinct amendments are required")
        if [item.get("entry_id") for item in entries] != ["A", "B", "C"]:
            raise HistoricalMigrationAmendmentError("amendment order or scope changed")
        if len(deferred) != 2 or [item.get("entry_id") for item in deferred] != ["D", "E"]:
            raise HistoricalMigrationAmendmentError("deferred M1 scope changed")

    def _prepared(self, prepared: PreparedHistoricalMigrationAmendment) -> None:
        self._manifest(prepared.manifest)
        material = {key: value for key, value in prepared.package.items() if key != "package_digest"}
        if prepared.package.get("package_digest") != canonical_sha256(material):
            raise HistoricalMigrationAmendmentError("amendment package digest changed")
        self.schemas.require("historical-migration-amendment-package", prepared.package)
        if (
            prepared.manifest["package_digest"] != prepared.package["package_digest"]
            or prepared.manifest["parent_binding"] != prepared.package["parent_binding"]
            or prepared.manifest["entry_ids"]
            != [entry["entry_id"] for entry in prepared.package["entries"]]
            or prepared.manifest["owner_review_digest"]
            != canonical_sha256(prepared.package["owner_review"])
        ):
            raise HistoricalMigrationAmendmentError("amendment presentation binding changed")

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require("historical-migration-amendment-manifest", manifest)
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest.get("manifest_digest") != canonical_sha256(material):
            raise HistoricalMigrationAmendmentError("amendment manifest digest changed")
        if (
            manifest["purpose"] != PURPOSE
            or manifest["authority_id"] != AUTHORITY_ID
            or manifest["disclosure"] != DISCLOSURE
            or manifest["retention"] != RETENTION
            or manifest["operations"] != list(OPERATIONS)
            or manifest["candidate_only"] is not True
            or manifest["no_current_work"] is not True
        ):
            raise HistoricalMigrationAmendmentError("amendment manifest exceeds its boundary")

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        return self.root.resolve(strict=True)

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise HistoricalMigrationAmendmentError("canonical amendment record is invalid")
        return value

    def _verify_parent(self, root: Path, binding: dict[str, str]) -> None:
        path = root / "canonical" / "historical-weekly-activity-events" / f"{binding['event_id']}.json"
        if not path.is_file() or sha256_hex(path.read_bytes()) != binding["event_sha256"]:
            raise HistoricalMigrationAmendmentError("amendment parent event changed")
        event = self._read(path)
        if event.get("package_digest") != binding["package_digest"] or event.get("receipt_id") != binding["receipt_id"]:
            raise HistoricalMigrationAmendmentError("amendment parent package or receipt changed")
        package = root / "canonical" / "historical-weekly-activity-packages" / binding["package_digest"]
        package_record = self._read(package) if package.is_file() else {}
        package_material = {
            key: value for key, value in package_record.items() if key != "package_digest"
        }
        if (
            not package.is_file()
            or package_record.get("package_digest") != binding["package_digest"]
            or canonical_sha256(package_material) != binding["package_digest"]
        ):
            raise HistoricalMigrationAmendmentError("amendment parent package bytes changed")

    def _matching(self, root: Path, manifest_digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "historical-migration-amendment-events"
        if not directory.exists():
            return None
        found = [self._read(path) for path in directory.glob("event_*.json")]
        matches = [item for item in found if item.get("manifest_digest") == manifest_digest]
        if len(matches) > 1:
            raise HistoricalMigrationAmendmentError("duplicate amendment events exist")
        return matches[0] if matches else None

    def _event(self, manifest: dict[str, Any], receipt_id: str) -> dict[str, Any]:
        event = {
            "schema_version": "1.0",
            "record_type": "historical_migration_amendment_published/1.0",
            "event_id": self.ids.new("event"),
            "recorded_at": timestamp(aware_utc_now()),
            "manifest_digest": manifest["manifest_digest"],
            "package_digest": manifest["package_digest"],
            "parent_event_id": manifest["parent_binding"]["event_id"],
            "receipt_id": receipt_id,
            "candidate_only": True,
            "no_current_work": True,
            "parent_records_unchanged": True,
        }
        self.schemas.require("historical-migration-amendment-event", event)
        return event

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require("historical-migration-amendment-receipt", receipt)
        for key in ("admission_id", "bundle_id", "manifest_digest"):
            if receipt.get(key) != manifest[key]:
                raise HistoricalMigrationAmendmentError("amendment receipt binding changed")

    def _archived(self, root: Path, receipt_id: str, manifest: dict[str, Any]) -> None:
        self.authority.verify_archived_historical_migration_amendment(
            receipt_id,
            manifest,
            display_root=root / "evidence" / "u1-historical-migration-amendment",
            receipt_root=root / "receipts" / PURPOSE,
        )

    def _verify_objects(self, root: Path, prepared: PreparedHistoricalMigrationAmendment) -> None:
        targets = (
            (
                root / "canonical" / "historical-migration-amendment-packages"
                / prepared.package["package_digest"],
                canonical_bytes(prepared.package),
            ),
            (
                root / "canonical" / "historical-migration-amendment-manifests"
                / prepared.manifest["manifest_digest"],
                canonical_bytes(prepared.manifest),
            ),
        )
        for path, expected in targets:
            if not path.is_file() or path.read_bytes() != expected:
                raise HistoricalMigrationAmendmentError("canonical amendment object changed")

    @staticmethod
    def _immutable(path: Path, content: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != content:
                raise HistoricalMigrationAmendmentError("immutable amendment collision")
            return
        path.write_bytes(content)
        path.chmod(0o600)

    def _publish(self, staged: Path, target: Path, digest: str) -> None:
        content = staged.read_bytes()
        if sha256_hex(content) != digest:
            raise HistoricalMigrationAmendmentError("staged amendment digest changed")
        self._immutable(target, content)

    def _rebuild(
        self,
        root: Path,
        event: dict[str, Any],
        prepared: PreparedHistoricalMigrationAmendment,
    ) -> None:
        derived = root / "derived" / "historical-migration-amendment"
        workspace = root / "workspace" / "History" / "Amendments" / event["event_id"]
        derived.mkdir(mode=0o700, parents=True, exist_ok=True)
        workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._atomic(workspace / "Migration Amendment.md", prepared.markdown.encode("utf-8"))
        projection = {
            "schema_version": "1.0",
            "event_id": event["event_id"],
            "parent_event_id": event["parent_event_id"],
            "package_digest": prepared.package["package_digest"],
            "entry_ids": prepared.manifest["entry_ids"],
            "candidate_only": True,
            "no_current_work": True,
        }
        self._atomic(derived / f"{event['event_id']}.json", canonical_bytes(projection))
        database_path = derived / f"{event['event_id']}.sqlite3"
        temp = derived / f".{event['event_id']}.sqlite3.tmp"
        if temp.exists():
            temp.unlink()
        database = sqlite3.connect(temp)
        try:
            database.execute("CREATE VIRTUAL TABLE amendments_fts USING fts5(entry_id, body)")
            for entry in prepared.package["entries"]:
                database.execute(
                    "INSERT INTO amendments_fts(entry_id, body) VALUES (?, ?)",
                    (entry["entry_id"], json.dumps(entry, sort_keys=True)),
                )
            database.commit()
        finally:
            database.close()
        os.replace(temp, database_path)
        database_path.chmod(0o600)

    @staticmethod
    def _atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = path.with_name(f".{path.name}.tmp")
        temp.write_bytes(content)
        temp.chmod(0o600)
        os.replace(temp, path)

    @staticmethod
    def _markdown(package: dict[str, Any]) -> str:
        ratings = "\n".join(
            f"- {item['dimension']}: {item['rating']}" for item in package["owner_review"]["ratings"]
        )
        entries = "\n".join(
            f"- {item['entry_id']}: {item['change_class']} — {item['target_ref']}"
            for item in package["entries"]
        )
        deferred = "\n".join(
            f"- {item['entry_id']}: {item['disposition']}" for item in package["deferred_entries"]
        )
        return (
            "# Historical migration amendment\n\n"
            f"Parent event: `{package['parent_binding']['event_id']}`.\n\n"
            "## Owner ratings\n\n"
            f"{ratings}\n\n## Advanced corrections\n\n{entries}\n\n"
            f"## Deferred M1 items\n\n{deferred}\n\n"
            "Candidate history only. Parent records are unchanged. No current work, "
            "promotion, activation, or U2 effect.\n"
        )
