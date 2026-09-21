"""Append-only owner-confirmed context over already-admitted historical weeks.

This is deliberately narrower than historical reconstruction: it accepts only an ordered set of
already-admitted event bindings and owner-authored statements.  Statements are explicitly marked
``owner_confirmed_historical_context``; they are never represented as extracted source claims and
the coordinator never opens a legacy or immutable source object.
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
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp


COMPONENT = "vault-next-historical-owner-context/1.0.0"
PURPOSE = "historical_owner_confirmed_continuity_supplement"
DISCLOSURE = "local_private_owner_confirmed_context_fixed_admitted_scope"
OPERATIONS = (
    "stage_owner_confirmed_continuity_supplement",
    "append_owner_confirmed_continuity_event",
    "build_owner_context_fts5",
    "build_owner_context_workspace",
)


class HistoricalOwnerContextError(RuntimeError):
    """An owner-context supplement is missing, substituted, or unsafe to append."""


class ExistingV2HistoricalOwnerContextAuthority(Protocol):
    def authorize_historical_owner_confirmed_continuity_supplement(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def verify_historical_owner_confirmed_continuity_supplement(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]: ...

    def read_historical_owner_confirmed_continuity_supplement_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]: ...

    def verify_archived_historical_owner_confirmed_continuity_supplement(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ParentEventBinding:
    event_id: str
    event_sha256: str
    package_digest: str
    primary_artifact_digest: str
    coverage_digest: str
    relationship_digest: str
    workspace_digest: str


@dataclass(frozen=True)
class OwnerContextStatement:
    statement_id: str
    topic: str
    text: str
    event_ids: tuple[str, ...]


@dataclass(frozen=True)
class PreparedHistoricalOwnerContext:
    manifest: dict[str, Any]
    supplement: dict[str, Any]
    markdown: str


@dataclass(frozen=True)
class HistoricalOwnerContextResult:
    status: str
    event_id: str
    receipt_id: str


class HistoricalOwnerContextCoordinator:
    """Prepare, append, and replay-verify a candidate-only owner context supplement."""

    def __init__(
        self,
        bundle_root: Path,
        schemas: SchemaRegistry,
        authority: ExistingV2HistoricalOwnerContextAuthority,
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
        statements: tuple[OwnerContextStatement, ...],
        expires_at: datetime,
    ) -> PreparedHistoricalOwnerContext:
        if expires_at.tzinfo is None or expires_at <= aware_utc_now():
            raise HistoricalOwnerContextError("owner-context proposal expiry is invalid")
        self._inputs(parents, statements)
        bindings = [self._binding(parent) for parent in parents]
        statements_payload = [self._statement(statement) for statement in statements]
        supplement_material = {
            "schema_version": "1.0",
            "record_type": "owner_confirmed_historical_continuity_supplement/1.0",
            "component": COMPONENT,
            "parent_bindings": bindings,
            "parent_set_digest": canonical_sha256(bindings),
            "statements": statements_payload,
            "statement_source": "owner_confirmed_historical_context",
            "source_extracted_claims": False,
            "candidate_only": True,
            "no_current_work_adoption": True,
            "parent_records_unchanged": True,
        }
        supplement = {
            **supplement_material,
            "supplement_sha256": canonical_sha256(supplement_material),
        }
        markdown = self._markdown(supplement)
        manifest = {
            "schema_version": "1.0",
            "component": COMPONENT,
            "purpose": PURPOSE,
            "authority_id": AUTHORITY_ID,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": bundle_id,
            "parent_bindings": bindings,
            "parent_set_digest": supplement["parent_set_digest"],
            "supplement_sha256": supplement["supplement_sha256"],
            "markdown_sha256": sha256_hex(markdown.encode("utf-8")),
            "statement_ids": [statement["statement_id"] for statement in statements_payload],
            "owner_context_statements": statements_payload,
            "disclosure": DISCLOSURE,
            "retention": "append_only_owner_confirmed_historical_context",
            "operations": list(OPERATIONS),
            "candidate_only": True,
            "no_current_work_adoption": True,
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self._manifest(manifest)
        return PreparedHistoricalOwnerContext(manifest, supplement, markdown)

    def authorize(self, prepared: PreparedHistoricalOwnerContext) -> dict[str, Any]:
        self._prepared(prepared)
        receipt = self.authority.authorize_historical_owner_confirmed_continuity_supplement(
            prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        return receipt

    def publish(
        self, prepared: PreparedHistoricalOwnerContext, *, receipt_id: str
    ) -> HistoricalOwnerContextResult:
        self._prepared(prepared)
        root = self._root()
        self._verify_parents(root, prepared.manifest["parent_bindings"])
        existing = self._matching(root, prepared.manifest["manifest_digest"])
        if existing is not None:
            if existing["receipt_id"] != receipt_id:
                raise HistoricalOwnerContextError("owner-context receipt replay changed")
            self._archived(receipt_id, prepared.manifest, root)
            self._verify_objects(root, prepared)
            self._rebuild(root, existing, prepared)
            return HistoricalOwnerContextResult("already_complete", existing["event_id"], receipt_id)
        receipt = self.authority.verify_historical_owner_confirmed_continuity_supplement(
            receipt_id, prepared.manifest
        )
        self._receipt(receipt, prepared.manifest)
        display, signed = self.authority.read_historical_owner_confirmed_continuity_supplement_evidence(
            receipt_id, prepared.manifest
        )
        stage = self._stage(root, prepared.manifest["admission_id"])
        try:
            event = self._event(prepared.manifest, receipt_id)
            materials = {
                "supplement.json": canonical_bytes(prepared.supplement),
                "manifest.json": canonical_bytes(prepared.manifest),
                "markdown.md": prepared.markdown.encode("utf-8"),
                "display.json": display,
                "receipt.json": signed,
                "event.json": canonical_bytes(event),
            }
            for name, material in materials.items():
                self._immutable(stage / name, material)
            targets = {
                "supplement.json": (
                    root / "canonical" / "historical-owner-context-supplements"
                    / prepared.supplement["supplement_sha256"]
                ),
                "manifest.json": (
                    root / "canonical" / "historical-owner-context-manifests"
                    / prepared.manifest["manifest_digest"]
                ),
                "markdown.md": (
                    root / "canonical" / "historical-owner-context-artifacts"
                    / prepared.manifest["markdown_sha256"]
                ),
                "display.json": root / "evidence" / "u1-historical-owner-context" / f"{receipt_id}.json",
                "receipt.json": root / "receipts" / PURPOSE / f"{receipt_id}.json",
                "event.json": (
                    root / "canonical" / "historical-owner-context-events"
                    / f"{event['event_id']}.json"
                ),
            }
            for name, target in targets.items():
                if name == "event.json":
                    continue
                self._publish(stage / name, target, sha256_hex(materials[name]))
            if self.fail_before_event:
                raise HistoricalOwnerContextError("injected interruption before owner-context event")
            self._publish(
                stage / "event.json", targets["event.json"], sha256_hex(materials["event.json"])
            )
            self._rebuild(root, event, prepared)
            return HistoricalOwnerContextResult("complete", event["event_id"], receipt_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def verify_restart(
        self, prepared: PreparedHistoricalOwnerContext, *, receipt_id: str
    ) -> HistoricalOwnerContextResult:
        self._prepared(prepared)
        root = self._root()
        self._verify_parents(root, prepared.manifest["parent_bindings"])
        event = self._matching(root, prepared.manifest["manifest_digest"])
        if event is None or event["receipt_id"] != receipt_id:
            raise HistoricalOwnerContextError("owner-context event is unavailable after restart")
        self._archived(receipt_id, prepared.manifest, root)
        self._verify_objects(root, prepared)
        self._rebuild(root, event, prepared)
        return HistoricalOwnerContextResult("complete", event["event_id"], receipt_id)

    def append_disposable_mirror_rollback(self, event_id: str) -> dict[str, Any]:
        root = self._root()
        if not root.is_relative_to(Path("/private/tmp")):
            raise HistoricalOwnerContextError("owner-context rollback is limited to a disposable mirror")
        record = {
            "schema_version": "1.0",
            "record_type": "owner_confirmed_historical_context_rollback/1.0",
            "rollback_event_id": self.ids.new("event"),
            "target_event_id": event_id,
            "effect": "deactivate_owner_context_projection_only",
            "parent_events_unchanged": True,
        }
        record["rollback_sha256"] = canonical_sha256(record)
        self._immutable(
            root / "canonical" / "historical-owner-context-rollbacks"
            / f"{record['rollback_event_id']}.json",
            canonical_bytes(record),
        )
        return record

    def _prepared(self, prepared: PreparedHistoricalOwnerContext) -> None:
        self._manifest(prepared.manifest)
        material = {
            key: value
            for key, value in prepared.supplement.items()
            if key != "supplement_sha256"
        }
        if prepared.supplement.get("supplement_sha256") != canonical_sha256(material):
            raise HistoricalOwnerContextError("owner-context supplement digest changed")
        if (
            prepared.manifest["supplement_sha256"] != prepared.supplement["supplement_sha256"]
            or prepared.manifest["markdown_sha256"] != sha256_hex(prepared.markdown.encode("utf-8"))
            or prepared.manifest["parent_bindings"] != prepared.supplement["parent_bindings"]
            or prepared.manifest["owner_context_statements"]
            != prepared.supplement["statements"]
        ):
            raise HistoricalOwnerContextError("owner-context presentation binding changed")

    def _manifest(self, manifest: dict[str, Any]) -> None:
        self.schemas.require(
            "historical-owner-confirmed-continuity-supplement-manifest", manifest
        )
        material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if manifest.get("manifest_digest") != canonical_sha256(material):
            raise HistoricalOwnerContextError("owner-context manifest digest changed")
        if (
            manifest["purpose"] != PURPOSE
            or manifest["authority_id"] != AUTHORITY_ID
            or manifest["disclosure"] != DISCLOSURE
            or manifest["operations"] != list(OPERATIONS)
            or manifest["candidate_only"] is not True
            or manifest["no_current_work_adoption"] is not True
            or manifest["parent_set_digest"] != canonical_sha256(manifest["parent_bindings"])
        ):
            raise HistoricalOwnerContextError("owner-context manifest is outside its purpose boundary")

    def _inputs(
        self,
        parents: tuple[ParentEventBinding, ...],
        statements: tuple[OwnerContextStatement, ...],
    ) -> None:
        if len(parents) != 4 or len({item.event_id for item in parents}) != 4:
            raise HistoricalOwnerContextError("owner-context requires exactly four distinct parent events")
        ids = {item.event_id for item in parents}
        for parent in parents:
            if not parent.event_id.startswith("event_") or not all(
                _digest(value)
                for value in (
                    parent.event_sha256,
                    parent.package_digest,
                    parent.primary_artifact_digest,
                    parent.coverage_digest,
                    parent.relationship_digest,
                    parent.workspace_digest,
                )
            ):
                raise HistoricalOwnerContextError("owner-context parent binding is invalid")
        if len(statements) != 4 or len({item.statement_id for item in statements}) != 4:
            raise HistoricalOwnerContextError("owner-context requires exactly four distinct statements")
        for statement in statements:
            if (
                not statement.statement_id
                or not statement.topic
                or not statement.text.strip()
                or not statement.event_ids
            ):
                raise HistoricalOwnerContextError("owner-context statement is incomplete")
            if set(statement.event_ids) - ids:
                raise HistoricalOwnerContextError("owner-context statement names an unbound event")

    @staticmethod
    def _binding(parent: ParentEventBinding) -> dict[str, str]:
        return {
            "event_id": parent.event_id,
            "event_sha256": parent.event_sha256,
            "package_digest": parent.package_digest,
            "primary_artifact_digest": parent.primary_artifact_digest,
            "coverage_digest": parent.coverage_digest,
            "relationship_digest": parent.relationship_digest,
            "workspace_digest": parent.workspace_digest,
        }

    @staticmethod
    def _statement(statement: OwnerContextStatement) -> dict[str, Any]:
        value = {
            "statement_id": statement.statement_id,
            "topic": statement.topic,
            "text": statement.text,
            "event_ids": list(statement.event_ids),
            "claim_class": "owner_confirmed_historical_context",
            "source_extracted": False,
        }
        return {**value, "statement_sha256": canonical_sha256(value)}

    @staticmethod
    def _markdown(supplement: dict[str, Any]) -> str:
        lines = [
            "# Owner-Confirmed Historical Continuity",
            "",
            "This record contains owner-confirmed historical context. It is not a "
            "source-extracted claim and does not change the admitted weekly records.",
            "",
        ]
        for item in supplement["statements"]:
            lines.extend(
                (
                    f"## {item['topic']}",
                    "",
                    item["text"],
                    "",
                    "**Basis:** owner-confirmed historical context; linked to admitted "
                    "weekly records: " + ", ".join(item["event_ids"]),
                    "",
                )
            )
        return "\n".join(lines)

    def _root(self) -> Path:
        PrivateBundleLayout.validate(self.root)
        root = self.root.resolve(strict=True)
        if root.is_symlink():
            raise HistoricalOwnerContextError("owner-context root is unsafe")
        return root

    def _verify_parents(self, root: Path, bindings: list[dict[str, str]]) -> None:
        """Only exact event-linked derived records are allowed; source and receipt paths are absent."""
        for binding in bindings:
            event_path = (
                root / "canonical" / "historical-weekly-activity-events"
                / f"{binding['event_id']}.json"
            )
            event = self._json_bytes(event_path, binding["event_sha256"])
            if event.get("event_id") != binding["event_id"]:
                raise HistoricalOwnerContextError("owner-context parent event identity changed")
            # The weekly package is the exact event-linked derived record.  It contains the
            # coverage, relationship and generated-workspace digests; no source object is read.
            package = (
                root / "canonical" / "historical-weekly-activity-packages"
                / binding["package_digest"]
            )
            package_record = self._json_canonical(
                package, binding["package_digest"], digest_key="package_digest"
            )
            reconciliation = package_record.get("cross_wave_reconciliation")
            views = package_record.get("weekly_wave", {}).get("views")
            primary = package_record.get("primary_artifact")
            if (
                not isinstance(reconciliation, dict)
                or not isinstance(views, dict)
                or not isinstance(primary, dict)
                or canonical_sha256(reconciliation.get("coverage_register"))
                != binding["coverage_digest"]
                or canonical_sha256(reconciliation.get("relationships"))
                != binding["relationship_digest"]
                or canonical_sha256(views) != binding["workspace_digest"]
                or primary.get("artifact_digest") != binding["primary_artifact_digest"]
            ):
                raise HistoricalOwnerContextError("owner-context event-linked package changed")

    def _receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        self.schemas.require(
            "historical-owner-confirmed-continuity-supplement-receipt", receipt
        )
        if receipt.get("purpose") != PURPOSE or any(
            receipt.get(key) != manifest.get(key)
            for key in ("admission_id", "bundle_id", "manifest_digest")
        ):
            raise HistoricalOwnerContextError("owner-context receipt binding changed")

    def _archived(self, receipt_id: str, manifest: dict[str, Any], root: Path) -> None:
        self.authority.verify_archived_historical_owner_confirmed_continuity_supplement(
            receipt_id, manifest,
            display_root=root / "evidence" / "u1-historical-owner-context",
            receipt_root=root / "receipts" / PURPOSE,
        )

    def _matching(self, root: Path, manifest_digest: str) -> dict[str, Any] | None:
        directory = root / "canonical" / "historical-owner-context-events"
        if not directory.exists():
            return None
        found = [
            self._json(path)
            for path in directory.iterdir()
            if path.is_file()
            and not path.is_symlink()
            and self._json(path).get("manifest_digest") == manifest_digest
        ]
        if len(found) > 1:
            raise HistoricalOwnerContextError("owner-context event is duplicated")
        return found[0] if found else None

    def _event(self, manifest: dict[str, Any], receipt_id: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "publication_type": PURPOSE,
            "event_id": self.ids.new("event"),
            "admission_id": manifest["admission_id"], "receipt_id": receipt_id,
            "manifest_digest": manifest["manifest_digest"],
            "parent_event_ids": [item["event_id"] for item in manifest["parent_bindings"]],
            "supplement_sha256": manifest["supplement_sha256"],
            "markdown_sha256": manifest["markdown_sha256"],
            "parent_events_unchanged": True,
            "candidate_only": True,
            "no_current_work_adoption": True,
            "recorded_at": timestamp(aware_utc_now()),
        }

    def _verify_objects(self, root: Path, prepared: PreparedHistoricalOwnerContext) -> None:
        checks = (
            (
                root / "canonical" / "historical-owner-context-supplements"
                / prepared.supplement["supplement_sha256"],
                canonical_bytes(prepared.supplement),
            ),
            (
                root / "canonical" / "historical-owner-context-manifests"
                / prepared.manifest["manifest_digest"],
                canonical_bytes(prepared.manifest),
            ),
            (
                root / "canonical" / "historical-owner-context-artifacts"
                / prepared.manifest["markdown_sha256"],
                prepared.markdown.encode("utf-8"),
            ),
        )
        for path, expected in checks:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                raise HistoricalOwnerContextError("owner-context immutable object changed")

    def _rebuild(self, root: Path, event: dict[str, Any], prepared: PreparedHistoricalOwnerContext) -> None:
        database = (
            root / "derived" / "fts5" / f"owner-context-{event['event_id']}.sqlite3"
        )
        temporary = database.with_name(f".{database.name}.tmp")
        if temporary.exists():
            temporary.unlink()
        connection = sqlite3.connect(temporary)
        try:
            connection.execute("CREATE VIRTUAL TABLE owner_context USING fts5(topic, body)")
            connection.executemany(
                "INSERT INTO owner_context VALUES (?, ?)",
                [(item["topic"], item["text"]) for item in prepared.supplement["statements"]],
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(temporary, 0o600)
        os.replace(temporary, database)
        view = (
            root / "workspace" / "History" / "Continuity Supplements"
            / f"{event['event_id']}.md"
        )
        view.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        view.write_text(prepared.markdown, encoding="utf-8")
        os.chmod(view, 0o600)

    def _stage(self, root: Path, admission_id: str) -> Path:
        parent = root / "staging" / "historical-owner-context"
        parent.mkdir(mode=0o700, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
            raise HistoricalOwnerContextError("owner-context staging root is unsafe")
        return Path(tempfile.mkdtemp(prefix=f".owner-context-{admission_id}-", dir=parent))

    @staticmethod
    def _immutable(path: Path, material: bytes) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            raise HistoricalOwnerContextError("owner-context immutable target exists")
        path.write_bytes(material)
        os.chmod(path, 0o600)

    @staticmethod
    def _publish(staged: Path, target: Path, digest: str) -> None:
        if sha256_hex(staged.read_bytes()) != digest:
            raise HistoricalOwnerContextError("owner-context staged digest changed")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(target.read_bytes()) != digest:
                raise HistoricalOwnerContextError("owner-context immutable target changed")
        else:
            os.replace(staged, target)
            os.chmod(target, 0o600)

    @staticmethod
    def _bytes(path: Path, digest: str) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise HistoricalOwnerContextError("owner-context admitted support is unavailable")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise HistoricalOwnerContextError("owner-context admitted support digest changed")
        return data

    def _json_bytes(self, path: Path, digest: str) -> dict[str, Any]:
        return self._decode(self._bytes(path, digest))

    def _json_canonical(
        self, path: Path, digest: str, *, digest_key: str | None = None
    ) -> dict[str, Any]:
        """Verify a canonical object identifier without assuming its on-disk whitespace."""

        if path.is_symlink() or not path.is_file():
            raise HistoricalOwnerContextError("owner-context admitted support is unavailable")
        value = self._decode(path.read_bytes())
        material = (
            {key: item for key, item in value.items() if key != digest_key}
            if digest_key is not None
            else value
        )
        if canonical_sha256(material) != digest:
            raise HistoricalOwnerContextError("owner-context admitted support digest changed")
        return value

    def _json(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise HistoricalOwnerContextError("owner-context record is unavailable")
        return self._decode(path.read_bytes())

    @staticmethod
    def _decode(data: bytes) -> dict[str, Any]:
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HistoricalOwnerContextError("owner-context JSON is malformed") from exc
        if not isinstance(value, dict):
            raise HistoricalOwnerContextError("owner-context JSON is not an object")
        return value


def _digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
