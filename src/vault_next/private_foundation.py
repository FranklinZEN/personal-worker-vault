"""Synthetic F1 private-admission and Meeting-workflow rehearsal boundary.

This is intentionally a sibling to the existing synthetic Chat U1 and direct-private paths.  It
models the proposed *real* contract shapes while accepting only marked disposable executions and
an injected fake v2 authority.  It has no filesystem reader, Keychain binding, host adapter, or
network/model capability.
"""

from __future__ import annotations

import hmac
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.chat_ingress import ChatIngressExecution
from vault_next.content_profiles import ContentProfileRouter
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp
from vault_next.runtime import CaseSessionRuntime


COMPONENT_ID = "vault-next-private-foundation"
COMPONENT_VERSION = "0.1.0"
AUTHORITY_ID = "vault-next-local-confirmation/v2"
_PURPOSE_CHAT = "chat_first_u1_save"
_PURPOSE_SNAPSHOT = "direct_private_snapshot_scope"
_PURPOSE_ADMISSION = "direct_private_source_admission"
_PURPOSES = frozenset({_PURPOSE_CHAT, _PURPOSE_SNAPSHOT, _PURPOSE_ADMISSION})
_RELATION_TYPES = frozenset(
    {
        "debriefs", "prepares_for", "self_reviews", "follow_up_of", "summarizes",
        "derived_from", "about_meeting", "about_initiative", "references_actor",
        "reports_decision", "reports_commitment", "supports", "contradicts", "precedes",
        "supersedes", "has_revisit_condition",
    }
)
_W1_SECTIONS = (
    "topic_chronology", "claims", "decisions", "proposals", "disagreements", "commitments",
    "dependencies", "risks", "questions", "next_meeting_proposal",
)


class PrivateFoundationError(RuntimeError):
    """An F1 synthetic admission or rehearsal cannot safely continue."""


class PrivateFoundationDeclined(PrivateFoundationError):
    """A fake exact-digest confirmation was declined, expired, or replayed."""


class ExactDigestConfirmationUI(Protocol):
    """Narrow fakeable owner-confirmation seam; production UI is deliberately absent."""

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str: ...


@dataclass(frozen=True)
class SyntheticExistingV2Authority:
    """Injected disposable stand-in for an already-existing v2 identity.

    It writes only test receipt/display evidence below a disposable runtime.  It has no Keychain
    or signing-key API, deliberately preventing accidental reuse as a durable authority.
    """

    runtime: CaseSessionRuntime
    schemas: SchemaRegistry
    confirmation_ui: ExactDigestConfirmationUI
    id_factory: ULIDFactory = field(default_factory=lambda: DEFAULT_FACTORY)
    clock: Callable[[], datetime] = aware_utc_now
    bundle_id: str | None = None

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]:
        self.schemas.require("private-foundation-manifest", manifest)
        _require_manifest_digest(manifest)
        now = _aware(self.clock())
        if _parse_time(manifest["expires_at"]) <= now:
            raise PrivateFoundationDeclined("F1 manifest is expired")
        if manifest["purpose"] not in _PURPOSES:
            raise PrivateFoundationError("F1 receipt purpose is unsupported")
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": manifest["purpose"],
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("private-foundation-receipt", receipt)
        display = {
            "component": f"{COMPONENT_ID}/{COMPONENT_VERSION}",
            "fake_existing_v2_authority": True,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        display_bytes = canonical_bytes(display)
        display_path = self._path("displays", receipt["receipt_id"])
        _write_new(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, manifest["manifest_digest"])
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise PrivateFoundationDeclined("F1 exact-digest confirmation was declined")
        if _read_bytes(display_path) != display_bytes:
            raise PrivateFoundationError("F1 confirmation display changed before issuance")
        record = {"receipt": receipt, "manifest": manifest, "display_sha256": sha256_hex(display_bytes)}
        _write_new(self._path("receipts", receipt["receipt_id"]), canonical_bytes(record))
        return receipt

    def verify(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        _require_manifest_digest(manifest)
        try:
            record_bytes = _read_bytes(self._path("receipts", receipt_id))
            record = json.loads(record_bytes)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrivateFoundationError("F1 receipt is unavailable") from exc
        if not isinstance(record, dict) or canonical_bytes(record) != record_bytes:
            raise PrivateFoundationError("F1 receipt record is not canonical")
        if set(record) != {"receipt", "manifest", "display_sha256"}:
            raise PrivateFoundationError("F1 receipt record has an unsupported shape")
        receipt = record["receipt"]
        if not isinstance(receipt, dict) or record["manifest"] != manifest:
            raise PrivateFoundationError("F1 receipt manifest replay is invalid")
        self.schemas.require("private-foundation-receipt", receipt)
        expected = {
            "receipt_id": receipt_id,
            "authority_id": AUTHORITY_ID,
            "purpose": manifest["purpose"],
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "expires_at": manifest["expires_at"],
        }
        if any(receipt[key] != value for key, value in expected.items()):
            raise PrivateFoundationError("F1 receipt binding is invalid")
        if _parse_time(receipt["expires_at"]) <= _aware(self.clock()):
            raise PrivateFoundationDeclined("F1 receipt is expired")
        return receipt

    def _path(self, kind: str, receipt_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.evidence_root / "private-foundation" / kind / f"{receipt_id}.json"
        )


@dataclass(frozen=True)
class SyntheticDirectFixture:
    """An unreadable-until-authorized invented source; it is never a path capability."""

    safe_label: str
    declared_media_type: str
    declared_extension: str
    material: bytes
    locator_sha256: str
    synthetic_only: bool = True
    reads: list[str] = field(default_factory=list, compare=False)

    def observe_after_scope_receipt(self) -> bytes:
        if not self.synthetic_only:
            raise PrivateFoundationError("F1 direct fixture must be synthetic")
        self.reads.append("observed")
        return self.material


class PrivateFoundationCoordinator:
    """One-event F1 publication/recovery coordinator over disposable runtime paths only."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        schemas: SchemaRegistry,
        router: ContentProfileRouter,
        authority: SyntheticExistingV2Authority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.schemas = schemas
        self.router = router
        self.authority = authority
        self.ids = id_factory
        self.clock = clock
        self.fault_injector = fault_injector

    def meeting_candidate_package(self, *, lifecycle: str = "inactive") -> dict[str, Any]:
        package = {
            "schema_version": "1.0",
            "candidate_id": self.ids.new("skill_candidate"),
            "family": "meeting_workflow",
            "package_version": "1.0",
            "ingress_profiles": ["plain_text", "markdown_text", "docx_wordprocessingml"],
            "required_sections": list(_W1_SECTIONS),
            "prohibitions": ["no_legacy_context_load", "no_implicit_write", "no_executor_command", "no_activation"],
            "lifecycle": lifecycle,
        }
        self.schemas.require("method-candidate-package", package)
        return package

    def prepare_chat_save(
        self,
        execution: ChatIngressExecution,
        *,
        session_id: str,
        candidate_package: dict[str, Any],
        relationships: list[dict[str, Any]],
        expires_at: datetime,
    ) -> dict[str, Any]:
        """Build the complete, one-confirmation U1 proposal from one frozen synthetic U0 run."""

        self._require_synthetic_execution(execution, session_id)
        self._validate_candidate_and_relationships(candidate_package, relationships)
        if _aware(expires_at) <= _aware(self.clock()):
            raise PrivateFoundationError("F1 proposal expiry must be in the future")
        profile_id = execution.evidence.record()["profile_id"]
        manifest = {
            "schema_version": "1.0",
            "purpose": _PURPOSE_CHAT,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": self.ids.new("private_bundle"),
            "session_id": session_id,
            "runtime_id": _runtime_id(self.runtime),
            "source_sha256": sha256_hex(execution.material_bytes),
            "source_size": len(execution.material_bytes),
            "evidence_sha256": execution.evidence.evidence_sha256,
            "result_sha256": execution.debrief["result_sha256"],
            "profile_id": profile_id,
            "candidate_package_sha256": canonical_sha256(candidate_package),
            "relationship_ledger_sha256": canonical_sha256(relationships),
            "disclosure": "visible_hosted_reasoning",
            "operations": ["stage_immutable_objects", "append_private_admission_event", "rebuild_local_fts5"],
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("private-foundation-manifest", manifest)
        return manifest

    def prepare_direct_snapshot(
        self,
        fixture: SyntheticDirectFixture,
        *,
        expires_at: datetime,
    ) -> dict[str, Any]:
        """Create a no-content scope proposal.  Calling this never reads fixture bytes."""

        self._require_fixture(fixture)
        if fixture.reads:
            raise PrivateFoundationError("F1 direct fixture was observed before scope preparation")
        return self._manifest(
            purpose=_PURPOSE_SNAPSHOT,
            source_sha256="0" * 64,
            source_size=0,
            evidence_sha256=fixture.locator_sha256,
            result_sha256=fixture.locator_sha256,
            profile_id="markdown_text",
            candidate_package={"scope": "synthetic"},
            relationships=[],
            expires_at=expires_at,
        )

    def observe_direct_snapshot(
        self,
        fixture: SyntheticDirectFixture,
        manifest: dict[str, Any],
        receipt_id: str,
    ) -> dict[str, Any]:
        self._require_manifest(manifest, _PURPOSE_SNAPSHOT)
        self.authority.verify(receipt_id, manifest)
        material = fixture.observe_after_scope_receipt()
        normalized = self.router.route(
            material, declared_media_type=fixture.declared_media_type, declared_extension=fixture.declared_extension
        )
        return {
            "snapshot_receipt_id": receipt_id,
            "source_sha256": sha256_hex(material),
            "source_size": len(material),
            "profile_id": normalized.profile_id,
            "evidence_sha256": normalized.normalized_evidence_sha256,
        }

    def prepare_direct_admission(
        self,
        snapshot: dict[str, Any],
        *,
        candidate_package: dict[str, Any],
        relationships: list[dict[str, Any]],
        expires_at: datetime,
    ) -> dict[str, Any]:
        expected = {"snapshot_receipt_id", "source_sha256", "source_size", "profile_id", "evidence_sha256"}
        if set(snapshot) != expected:
            raise PrivateFoundationError("F1 direct snapshot result is malformed")
        self._validate_candidate_and_relationships(candidate_package, relationships)
        return self._manifest(
            purpose=_PURPOSE_ADMISSION,
            source_sha256=snapshot["source_sha256"],
            source_size=snapshot["source_size"],
            evidence_sha256=snapshot["evidence_sha256"],
            result_sha256=canonical_sha256(snapshot),
            profile_id=snapshot["profile_id"],
            candidate_package=candidate_package,
            relationships=relationships,
            expires_at=expires_at,
        )

    def admit_chat(
        self,
        execution: ChatIngressExecution,
        manifest: dict[str, Any],
        receipt_id: str,
        *,
        candidate_package: dict[str, Any],
        relationships: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Publish immutable fixture-derived material only at one canonical event watermark."""

        self._require_manifest(manifest, _PURPOSE_CHAT)
        self._require_synthetic_execution(execution, self._session_id_for_manifest(manifest))
        self._validate_candidate_and_relationships(candidate_package, relationships)
        if manifest["source_sha256"] != sha256_hex(execution.material_bytes):
            raise PrivateFoundationError("F1 proposal source binding changed")
        if manifest["result_sha256"] != execution.debrief["result_sha256"]:
            raise PrivateFoundationError("F1 proposal result binding changed")
        if manifest["candidate_package_sha256"] != canonical_sha256(candidate_package):
            raise PrivateFoundationError("F1 proposal candidate package binding changed")
        if manifest["relationship_ledger_sha256"] != canonical_sha256(relationships):
            raise PrivateFoundationError("F1 proposal relationship ledger binding changed")
        prior = self._matching(manifest)
        if prior is not None:
            return {"status": "already_admitted", "event_id": prior["event_id"]}
        receipt = self.authority.verify(receipt_id, manifest)
        stage = self._stage(manifest["admission_id"])
        if stage.exists() or stage.is_symlink():
            raise PrivateFoundationError("F1 staging path already exists")
        stage.mkdir(mode=0o700, parents=True, exist_ok=False)
        committed = False
        try:
            source_path = stage / "source.bin"
            result_path = stage / "result.json"
            package_path = stage / "candidate-package.json"
            relationships_path = stage / "relationships.json"
            _write_new(source_path, execution.material_bytes)
            _write_new(result_path, canonical_bytes(execution.debrief))
            _write_new(package_path, canonical_bytes(candidate_package))
            _write_new(relationships_path, canonical_bytes(relationships))
            self._fault("after_stage")
            references = self._publish(stage, manifest, execution.ingress_envelope)
            self._fault("after_objects")
            payload = {
                "schema_version": "1.0",
                "manifest": manifest,
                "receipt": receipt,
                "source_version": references["source_version"],
                "result": references["result"],
                "candidate_package": candidate_package,
                "relationship_assertions": relationships,
            }
            self.schemas.require("private-admission-event", payload)
            session_id = self._session_id_for_manifest(manifest)
            event = self.runtime.record_reasoning_event(
                session_id,
                "private_admission.recorded",
                payload,
                subject_refs=[manifest["admission_id"], candidate_package["candidate_id"]],
                provenance=[],
            )
            committed = True
            self._fault("after_event")
            self._remove_stage(stage)
            self.rebuild()
            return {"status": "complete", "event_id": event["event_id"], "admission_id": manifest["admission_id"]}
        except Exception:
            if committed:
                raise
            raise

    def rehearse_meeting_workflow(
        self,
        candidate_package: dict[str, Any],
        selected_packet: list[dict[str, Any]],
        *,
        lifecycle: str = "needs_refinement",
    ) -> dict[str, Any]:
        """Evaluate a supplied invented W1 packet without loading/executing legacy methods."""

        self._validate_candidate_and_relationships(candidate_package, [])
        if len(selected_packet) < 1 or len(selected_packet) > 9:
            raise PrivateFoundationError("W1 selected packet must contain one to nine supplied items")
        sections: dict[str, list[dict[str, str]]] = {name: [] for name in _W1_SECTIONS}
        relations: list[dict[str, Any]] = []
        for item in selected_packet:
            required = {
                "source_version_id",
                "anchor",
                "section",
                "statement",
                "relation_type",
                "target_version_id",
                "state",
            }
            if set(item) != required:
                raise PrivateFoundationError("W1 supplied packet item has an unsupported shape")
            if item["section"] not in sections or item["relation_type"] not in _RELATION_TYPES:
                raise PrivateFoundationError("W1 supplied packet item is outside the bounded vocabulary")
            if not all(isinstance(item[key], str) and item[key] for key in item):
                raise PrivateFoundationError("W1 supplied packet item lacks exact cited fields")
            sections[item["section"]].append(
                {"statement": item["statement"], "citation": item["anchor"]}
            )
            assertion = {
                "assertion_id": self.ids.new("relationship_ledger"),
                "origin_version_id": item["source_version_id"],
                "target_version_id": item["target_version_id"],
                "type": item["relation_type"],
                "source_anchor": item["anchor"],
                "state": item["state"],
            }
            self.schemas.require("relationship-assertion", assertion)
            relations.append(assertion)
        return {
            "status": "complete",
            "candidate_lifecycle": lifecycle,
            "sections": sections,
            "relationship_assertions": relations,
            "limitations": [
                "fixture-supplied evidence only",
                "no legacy method execution",
                "U0/inactive outputs only",
                "no U2 action",
            ],
        }

    def recover(self) -> dict[str, Any]:
        root = self.runtime.paths.staging_root / "private-foundation"
        if not root.exists():
            return {"status": "complete", "recovered_stages": 0}
        if root.is_symlink() or not root.is_dir():
            raise PrivateFoundationError("F1 staging root is invalid")
        stages = list(root.iterdir())
        for stage in stages:
            if stage.is_symlink() or not stage.is_dir():
                raise PrivateFoundationError("F1 staging entry is invalid")
            self._remove_stage(stage)
        return {"status": "complete", "recovered_stages": len(stages)}

    def rebuild(self) -> dict[str, Any]:
        """Rebuild the local FTS projection only from committed immutable runtime objects."""

        rows: list[tuple[str, str, str]] = []
        for event in self._events("private_admission.recorded"):
            source = event["payload"]["source_version"]
            raw = _read_bytes(self._source_path(source["object_ref"]))
            if sha256_hex(raw) != source["content_sha256"]:
                raise PrivateFoundationError("F1 committed source object is invalid")
            normalized = self.router.route(
                raw,
                declared_media_type=source["media_type"],
                declared_extension=source["extension"],
            )
            for anchor in normalized.anchors:
                rows.append((event["event_id"], anchor.anchor, anchor.text_sha256))
        root = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "private-foundation"
        )
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        database = self.runtime.paths.ensure_runtime_write_target(root / "fts.sqlite3")
        if database.exists():
            database.unlink()
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE VIRTUAL TABLE citations USING fts5("
                "event_id UNINDEXED, anchor UNINDEXED, text_sha256 UNINDEXED)"
            )
            connection.executemany("INSERT INTO citations VALUES (?, ?, ?)", rows)
            connection.commit()
        finally:
            connection.close()
        manifest = {
            "event_count": len(self._events("private_admission.recorded")),
            "row_count": len(rows),
            "sqlite_sha256": sha256_hex(_read_bytes(database)),
        }
        _write_replace(root / "active.json", canonical_bytes(manifest))
        return {"status": "complete", **manifest}

    def verify_restart(self) -> dict[str, Any]:
        self.recover()
        for event in self._events("private_admission.recorded"):
            payload = event["payload"]
            self.schemas.require("private-admission-event", payload)
            self._require_manifest(payload["manifest"], _PURPOSE_CHAT)
            self.authority.verify(payload["receipt"]["receipt_id"], payload["manifest"])
            source = payload["source_version"]
            if (
                sha256_hex(_read_bytes(self._source_path(source["object_ref"])))
                != source["content_sha256"]
            ):
                raise PrivateFoundationError("F1 restart source verification failed")
        return self.rebuild()

    def deactivate(self, session_id: str, admission_id: str) -> dict[str, Any]:
        matching = [
            event
            for event in self._events("private_admission.recorded")
            if event["payload"]["manifest"]["admission_id"] == admission_id
        ]
        if len(matching) != 1:
            raise PrivateFoundationError("F1 deactivation target is unavailable")
        return self.runtime.record_reasoning_event(
            session_id,
            "private_admission.deactivated",
            {"admission_id": admission_id},
            subject_refs=[admission_id],
            provenance=[],
        )

    def _manifest(
        self,
        *,
        purpose: str,
        source_sha256: str,
        source_size: int,
        evidence_sha256: str,
        result_sha256: str,
        profile_id: str,
        candidate_package: dict[str, Any],
        relationships: list[dict[str, Any]],
        expires_at: datetime,
    ) -> dict[str, Any]:
        if _aware(expires_at) <= _aware(self.clock()):
            raise PrivateFoundationError("F1 proposal expiry must be in the future")
        manifest = {
            "schema_version": "1.0",
            "purpose": purpose,
            "admission_id": self.ids.new("private_admission"),
            "bundle_id": self.ids.new("private_bundle"),
            "session_id": self._only_active_session(),
            "runtime_id": _runtime_id(self.runtime),
            "source_sha256": source_sha256,
            "source_size": source_size,
            "evidence_sha256": evidence_sha256,
            "result_sha256": result_sha256,
            "profile_id": profile_id,
            "candidate_package_sha256": canonical_sha256(candidate_package),
            "relationship_ledger_sha256": canonical_sha256(relationships),
            "disclosure": "visible_hosted_reasoning",
            "operations": (
                ["observe_exact_source"]
                if purpose == _PURPOSE_SNAPSHOT
                else ["publish_exact_source"]
            ),
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("private-foundation-manifest", manifest)
        return manifest

    def _publish(
        self, stage: Path, manifest: dict[str, Any], envelope: dict[str, Any]
    ) -> dict[str, Any]:
        source = self._publish_object(
            stage / "source.bin",
            self._source_path(manifest["source_sha256"]),
            manifest["source_sha256"],
        )
        result_digest = sha256_hex(_read_bytes(stage / "result.json"))
        result = self._publish_object(
            stage / "result.json", self._artifact_path(result_digest), result_digest
        )
        package = self._publish_object(
            stage / "candidate-package.json",
            self._package_path(manifest["candidate_package_sha256"]),
            manifest["candidate_package_sha256"],
        )
        relation = self._publish_object(
            stage / "relationships.json",
            self._relationship_path(manifest["relationship_ledger_sha256"]),
            manifest["relationship_ledger_sha256"],
        )
        return {
            "source_version": {
                "source_version_id": self.ids.new("source_version"),
                "object_ref": source.name,
                "content_sha256": manifest["source_sha256"],
                "byte_count": manifest["source_size"],
                "media_type": envelope["declared_media_type"],
                "extension": envelope["declared_extension"],
            },
            "result": {
                "object_ref": result.name,
                "content_sha256": sha256_hex(_read_bytes(result)),
                "candidate_package_object_ref": package.name,
                "relationship_ledger_object_ref": relation.name,
            },
        }

    def _publish_object(self, staged: Path, target: Path, expected: str) -> Path:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        raw = _read_bytes(staged)
        if sha256_hex(raw) != expected:
            raise PrivateFoundationError("F1 staged immutable object digest changed")
        if target.exists():
            if target.is_symlink() or sha256_hex(_read_bytes(target)) != expected:
                raise PrivateFoundationError("F1 immutable object conflicts")
            staged.unlink()
            return target
        os.replace(staged, target)
        return target

    def _matching(self, manifest: dict[str, Any]) -> dict[str, Any] | None:
        matches = [
            event
            for event in self._events("private_admission.recorded")
            if event["payload"]["manifest"]["manifest_digest"] == manifest["manifest_digest"]
        ]
        if len(matches) > 1:
            raise PrivateFoundationError("F1 duplicate publication watermark")
        return matches[0] if matches else None

    def _events(self, event_type: str) -> list[dict[str, Any]]:
        return [event for event in self.runtime.semantic.read_all() if event["event_type"] == event_type]

    def _stage(self, admission_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "private-foundation" / admission_id
        )

    def _source_path(self, digest: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.source_root / "private-foundation" / "objects" / digest
        )

    def _artifact_path(self, digest: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.artifact_root / "private-foundation" / "objects" / digest
        )

    def _package_path(self, digest: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.artifact_root / "private-foundation" / "packages" / digest
        )

    def _relationship_path(self, digest: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.artifact_root / "private-foundation" / "relationships" / digest
        )

    def _session_id_for_manifest(self, manifest: dict[str, Any]) -> str:
        state = self.runtime._session(manifest["session_id"])
        if state.status != "active" or state.frozen:
            raise PrivateFoundationError("F1 manifest session is not active")
        return manifest["session_id"]

    def _only_active_session(self) -> str:
        """Direct-private synthetic proposals remain bound to one already-open fixture session."""

        # The runtime deliberately exposes one validated session lookup rather than a general source scan.
        candidates = [
            event["session_id"]
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "session.status_changed"
            and event["payload"].get("to_status") == "active"
        ]
        if len(candidates) != 1 or not isinstance(candidates[0], str):
            raise PrivateFoundationError("F1 requires exactly one active synthetic session")
        return self._session_id_for_manifest({"session_id": candidates[0]})

    def _require_synthetic_execution(self, execution: ChatIngressExecution, session_id: str) -> None:
        if (
            not isinstance(execution, ChatIngressExecution)
            or execution.ingress_envelope.get("synthetic_only") is not True
        ):
            raise PrivateFoundationError("F1 accepts only a marked hostile synthetic U0 execution")
        if execution.ingress_envelope.get("processing_surface") != "synthetic_fixture":
            raise PrivateFoundationError("F1 host/real input ingress is unavailable")
        state = self.runtime._session(session_id)
        if state.status != "active" or state.frozen:
            raise PrivateFoundationError("F1 requires an active synthetic session")

    def _require_manifest(self, manifest: dict[str, Any], purpose: str) -> None:
        self.schemas.require("private-foundation-manifest", manifest)
        _require_manifest_digest(manifest)
        if manifest["purpose"] != purpose or manifest["runtime_id"] != _runtime_id(self.runtime):
            raise PrivateFoundationError("F1 manifest purpose/runtime binding is invalid")

    def _validate_candidate_and_relationships(
        self, package: dict[str, Any], relationships: list[dict[str, Any]]
    ) -> None:
        self.schemas.require("method-candidate-package", package)
        if package["lifecycle"] not in {
            "inactive",
            "needs_refinement",
            "declined",
            "eligible_for_activation",
        }:
            raise PrivateFoundationError("F1 candidate cannot activate")
        if not isinstance(relationships, list):
            raise PrivateFoundationError("F1 relationships must be a list")
        for relation in relationships:
            self.schemas.require("relationship-assertion", relation)
            if relation["type"] not in _RELATION_TYPES or not relation["source_anchor"]:
                raise PrivateFoundationError("F1 relationship is outside the bounded ledger")

    def _require_fixture(self, fixture: SyntheticDirectFixture) -> None:
        if (
            not isinstance(fixture, SyntheticDirectFixture)
            or not fixture.synthetic_only
            or not fixture.material
        ):
            raise PrivateFoundationError("F1 direct source must be a nonempty synthetic fixture")

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    @staticmethod
    def _remove_stage(path: Path) -> None:
        shutil.rmtree(path)


def _runtime_id(runtime: CaseSessionRuntime) -> str:
    return canonical_sha256({"runtime_root": str(runtime.paths.root), "correlation_id": runtime.correlation_id})


def validate_synthetic_bundle_layout(bundle_root: Path, staging_root: Path) -> None:
    """Validate the future layout rule against disposable roots without creating a bundle.

    The check deliberately accepts only existing test directories.  Its production-root preflight
    is deferred, so this function cannot bootstrap or inspect an owner location.
    """

    for path, label in ((bundle_root, "bundle"), (staging_root, "staging")):
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise PrivateFoundationError(f"F1 synthetic {label} root is invalid")
        if path.stat().st_mode & 0o077:
            raise PrivateFoundationError(f"F1 synthetic {label} root must be owner-only")
    bundle = bundle_root.resolve(strict=True)
    staging = staging_root.resolve(strict=True)
    if bundle == staging or bundle in staging.parents or staging in bundle.parents:
        raise PrivateFoundationError("F1 synthetic bundle/staging roots overlap")
    if bundle.stat().st_dev != staging.stat().st_dev:
        raise PrivateFoundationError("F1 synthetic staging must share the bundle filesystem")


def _require_manifest_digest(manifest: dict[str, Any]) -> None:
    claimed = manifest.get("manifest_digest")
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if not isinstance(claimed, str) or claimed != canonical_sha256(material):
        raise PrivateFoundationError("F1 manifest digest is invalid")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PrivateFoundationError("F1 clock must be timezone-aware")
    return value.astimezone(UTC)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PrivateFoundationError("F1 timestamp is invalid") from exc
    return _aware(parsed)


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise PrivateFoundationError("F1 immutable path already exists")
    path.write_bytes(content)


def _write_replace(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise PrivateFoundationError("F1 derived path cannot be a symlink")
    path.write_bytes(content)


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PrivateFoundationError("F1 required immutable object is unavailable")
    return path.read_bytes()
