"""Optional one-confirmation U1 persistence for the synthetic Chat-first vertical slice."""

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
from vault_next.meeting_debrief import (
    FrozenEvidence,
    MeetingDebriefError,
    freeze_evidence,
    verify_result_bindings,
)
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp
from vault_next.runtime import CaseSessionRuntime


AUTHORITY_ID = "synthetic-chat-save-authority/0.1"
_PURPOSE = "chat_ingress_save"


class ChatSaveError(RuntimeError):
    """A synthetic U1 save cannot safely complete or replay."""


class ChatSaveDeclined(ChatSaveError):
    """The exact U1 proposal was declined, changed, or expired."""


class ChatSaveConfirmationUI(Protocol):
    """One narrow fakeable display and exact-digest confirmation boundary."""

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str: ...


class ChatSaveAuthority(Protocol):
    """A purpose-limited test authority; it has no generic signing or host access method."""

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def verify(self, receipt_id: str, *, manifest_digest: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SyntheticChatSaveAuthority:
    """Disposable exact-digest fake authority stored only in a temporary runtime evidence tree."""

    runtime: CaseSessionRuntime
    schemas: SchemaRegistry
    confirmation_ui: ChatSaveConfirmationUI
    id_factory: ULIDFactory = field(default_factory=lambda: DEFAULT_FACTORY)
    clock: Callable[[], datetime] = aware_utc_now

    def authorize(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Display and issue one fake exact-digest receipt for a complete synthetic save manifest."""

        self.schemas.require("chat-save-manifest", manifest)
        _require_manifest_digest(manifest)
        now = _aware(self.clock())
        if _parse_timestamp(manifest["expires_at"]) <= now:
            raise ChatSaveDeclined("synthetic chat save manifest is expired")
        if manifest["runtime_id"] != _runtime_id(self.runtime):
            raise ChatSaveError("synthetic chat save manifest is bound to another runtime")
        receipt_id = self.id_factory.new("receipt")
        receipt = {
            "schema_version": "1.0",
            "receipt_id": receipt_id,
            "authority_id": AUTHORITY_ID,
            "purpose": _PURPOSE,
            "save_id": manifest["save_id"],
            "manifest_digest": manifest["manifest_digest"],
            "runtime_id": manifest["runtime_id"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
            "synthetic_only": True,
        }
        self.schemas.require("chat-save-receipt", receipt)
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID,
            "synthetic_only": True,
            "purpose": _PURPOSE,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        display_bytes = canonical_bytes(display)
        display_path = self._display_path(receipt_id)
        _write_immutable(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, manifest["manifest_digest"])
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise ChatSaveDeclined("synthetic chat save confirmation did not match the exact digest")
        if _read_bytes(display_path) != display_bytes:
            raise ChatSaveError("synthetic chat save display changed before confirmation")
        record = {
            "schema_version": "1.0",
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "synthetic_only": True,
        }
        _write_immutable(self._receipt_path(receipt_id), canonical_bytes(record))
        return receipt

    def verify(self, receipt_id: str, *, manifest_digest: str) -> dict[str, Any]:
        """Load only a replay-verifiable fake receipt bound to the supplied exact manifest digest."""

        try:
            record_bytes = _read_bytes(self._receipt_path(receipt_id))
            record = json.loads(record_bytes)
            display_bytes = _read_bytes(self._display_path(receipt_id))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ChatSaveError("synthetic chat save receipt is unavailable") from exc
        if not isinstance(record, dict) or canonical_bytes(record) != record_bytes:
            raise ChatSaveError("synthetic chat save receipt is not canonical")
        required = {
            "schema_version",
            "receipt",
            "manifest",
            "manifest_digest",
            "confirmation_display_sha256",
            "synthetic_only",
        }
        if set(record) != required or record["synthetic_only"] is not True:
            raise ChatSaveError("synthetic chat save receipt has an unsupported shape")
        receipt = record["receipt"]
        manifest = record["manifest"]
        if not isinstance(receipt, dict) or not isinstance(manifest, dict):
            raise ChatSaveError("synthetic chat save receipt is malformed")
        self.schemas.require("chat-save-receipt", receipt)
        self.schemas.require("chat-save-manifest", manifest)
        if (
            receipt["receipt_id"] != receipt_id
            or receipt["purpose"] != _PURPOSE
            or receipt["authority_id"] != AUTHORITY_ID
            or receipt["manifest_digest"] != manifest_digest
            or record["manifest_digest"] != manifest_digest
            or manifest["manifest_digest"] != manifest_digest
            or record["confirmation_display_sha256"] != sha256_hex(display_bytes)
            or receipt["runtime_id"] != _runtime_id(self.runtime)
        ):
            raise ChatSaveError("synthetic chat save receipt binding is invalid")
        if _parse_timestamp(receipt["expires_at"]) <= _aware(self.clock()):
            raise ChatSaveDeclined("synthetic chat save receipt is expired")
        return receipt

    def _display_path(self, receipt_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.evidence_root / "chat-ingress" / "displays" / f"{receipt_id}.json"
        )

    def _receipt_path(self, receipt_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.evidence_root / "chat-ingress" / "receipts" / f"{receipt_id}.json"
        )


class ChatSaveCoordinator:
    """Persist a completed U0 result only after one verified fake U1 confirmation."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        schemas: SchemaRegistry,
        router: ContentProfileRouter,
        authority: ChatSaveAuthority,
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

    def prepare(
        self,
        execution: ChatIngressExecution,
        *,
        session_id: str,
        expires_at: datetime,
    ) -> dict[str, Any]:
        """Create one complete U1 proposal from an exact U0 execution and active synthetic session."""

        session = self.runtime._session(session_id)
        if session.status != "active" or session.frozen or session.manifest is None:
            raise ChatSaveError("synthetic chat save requires an active exact session")
        _validate_execution(self.schemas, execution)
        instant = _aware(self.clock())
        if _aware(expires_at) <= instant:
            raise ChatSaveError("synthetic chat save expiry must be in the future")
        manifest = {
            "schema_version": "1.0",
            "purpose": _PURPOSE,
            "save_id": self.ids.new("chat_save"),
            "case_id": session.case_id,
            "session_id": session_id,
            "ingress_envelope_sha256": canonical_sha256(execution.ingress_envelope),
            "source_sha256": sha256_hex(execution.material_bytes),
            "source_byte_count": len(execution.material_bytes),
            "evidence_sha256": execution.evidence.evidence_sha256,
            "debrief_result_sha256": execution.debrief["result_sha256"],
            "profile_id": execution.evidence.record()["profile_id"],
            "runtime_id": _runtime_id(self.runtime),
            "retention_policy_id": "synthetic_disposable",
            "candidate_lifecycle": "inactive",
            "idempotency_key": _save_key(execution),
            "operations": [
                "stage_exact_source",
                "store_immutable_source",
                "store_cited_debrief_artifact",
                "append_single_save_event",
                "rebuild_local_fts5",
                "verify_restart",
            ],
            "synthetic_only": True,
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("chat-save-manifest", manifest)
        return manifest

    def save(
        self,
        execution: ChatIngressExecution,
        manifest: dict[str, Any],
        receipt_id: str,
    ) -> dict[str, Any]:
        """Stage, verify, publish one U1 save event, and rebuild its derived local retrieval state."""

        _validate_execution(self.schemas, execution)
        self.schemas.require("chat-save-manifest", manifest)
        _require_manifest_digest(manifest)
        _require_execution_manifest_binding(self.runtime, execution, manifest)
        prior = self._matching_event(manifest)
        if prior is not None:
            return self._result_from_event(prior, "already_saved")
        receipt = self.authority.verify(receipt_id, manifest_digest=manifest["manifest_digest"])
        if receipt["save_id"] != manifest["save_id"]:
            raise ChatSaveError("synthetic chat save receipt is bound to another save")
        stage = self._stage(manifest["save_id"])
        if stage.exists() or stage.is_symlink():
            raise ChatSaveError("synthetic chat save staging already exists")
        stage.mkdir(mode=0o700, parents=True, exist_ok=False)
        event_committed = False
        try:
            _write_immutable(
                stage / "state.json",
                canonical_bytes(
                    {
                        "save_id": manifest["save_id"],
                        "manifest_digest": manifest["manifest_digest"],
                        "source_sha256": manifest["source_sha256"],
                    }
                ),
            )
            source_stage = stage / "source.bin"
            _write_immutable(source_stage, execution.material_bytes)
            self._fault("after_stage")
            normalized = self.router.route(
                execution.material_bytes,
                declared_media_type=execution.ingress_envelope["declared_media_type"],
                declared_extension=execution.ingress_envelope["declared_extension"],
            )
            rebuilt_evidence = freeze_evidence(self.schemas, execution.ingress_envelope, normalized)
            if rebuilt_evidence.evidence_sha256 != execution.evidence.evidence_sha256:
                raise ChatSaveError("synthetic chat save extraction changed before publication")
            source_version = self._source_version(manifest, execution)
            source_path = self._publish_stage_object(
                source_stage,
                self.runtime.paths.source_root / "chat-ingress" / "objects" / source_version["object_ref"],
                expected_sha256=source_version["content_sha256"],
            )
            artifact = self._debrief_artifact(manifest, execution, stage)
            self._fault("after_objects")
            inactive_method = {
                "candidate_id": self.ids.new("skill_candidate"),
                "method_package": execution.debrief["method_package"],
                "method_version": execution.debrief["method_version"],
                "lifecycle_state": "inactive",
                "evidence_sha256": execution.evidence.evidence_sha256,
                "debrief_result_sha256": execution.debrief["result_sha256"],
            }
            payload = {
                "schema_version": "1.0",
                "chat_save_manifest": manifest,
                "chat_save_manifest_sha256": manifest["manifest_digest"],
                "chat_save_receipt": receipt,
                "ingress_envelope": execution.ingress_envelope,
                "source_version": source_version,
                "source_version_sha256": canonical_sha256(source_version),
                "evidence_packet": execution.evidence.record(),
                "debrief_artifact": artifact,
                "inactive_method_evidence": inactive_method,
            }
            payload["commit_manifest_sha256"] = canonical_sha256(payload)
            self.schemas.require("chat-ingress-save-event", payload)
            event = self.runtime.record_reasoning_event(
                manifest["session_id"],
                "chat_ingress.save_committed",
                payload,
                subject_refs=[
                    manifest["save_id"],
                    source_version["source_version_id"],
                    artifact["artifact_version_id"],
                    inactive_method["candidate_id"],
                ],
                provenance=[],
            )
            event_committed = True
            self._fault("after_event")
            self._remove_stage(stage)
            self.rebuild_retrieval()
            if not source_path.is_file() or source_path.is_symlink():
                raise ChatSaveError("synthetic chat source object is unavailable after publication")
            return self._result_from_event(event, "complete")
        except Exception:
            if event_committed:
                raise
            raise

    def recover(self) -> dict[str, Any]:
        """Remove only inert, uncommitted temporary stages or completed stage residues after restart."""

        root = self.runtime.paths.staging_root / "chat-ingress"
        if not root.exists():
            return {"status": "complete", "recovered_stages": 0}
        if root.is_symlink() or not root.is_dir():
            raise ChatSaveError("synthetic chat save staging root is invalid")
        recovered = 0
        for stage in sorted(root.iterdir()):
            if stage.is_symlink() or not stage.is_dir():
                raise ChatSaveError("synthetic chat save staging entry is invalid")
            state_path = stage / "state.json"
            try:
                state = _read_canonical_json(state_path)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise ChatSaveError("synthetic chat save staging state is invalid") from exc
            if set(state) != {"save_id", "manifest_digest", "source_sha256"}:
                raise ChatSaveError("synthetic chat save staging state is unsupported")
            self._remove_stage(stage)
            recovered += 1
        return {"status": "complete", "recovered_stages": recovered}

    def verify_restart(self) -> dict[str, Any]:
        """Verify every committed U1 event from canonical objects, then rebuild local FTS without a transport."""

        self.recover()
        events = self._save_events()
        for event in events:
            self._verify_event(event)
        index = self.rebuild_retrieval()
        return {"status": "complete", "save_count": len(events), "index": index}

    def rebuild_retrieval(self) -> dict[str, Any]:
        """Rebuild a disposable FTS5 projection solely from committed U1 objects and save events."""

        material: list[tuple[dict[str, Any], Any, FrozenEvidence]] = []
        for event in self._save_events():
            payload = event["payload"]
            source = payload["source_version"]
            raw = self._read_source(source)
            normalized = self.router.route(
                raw,
                declared_media_type=source["declared_media_type"],
                declared_extension=source["declared_extension"],
            )
            evidence = freeze_evidence(self.schemas, _envelope_from_event(event), normalized)
            if evidence.record() != payload["evidence_packet"]:
                raise ChatSaveError("synthetic chat retrieval source extraction is stale")
            material.append((event, normalized, evidence))
        build_material = [
            {
                "event_id": event["event_id"],
                "event_sha256": event["integrity"]["event_sha256"],
                "source_version_id": event["payload"]["source_version"]["source_version_id"],
                "evidence_sha256": evidence.evidence_sha256,
            }
            for event, _normalized, evidence in material
        ]
        build_id = "chat_ingress_" + canonical_sha256(build_material)[:26]
        root = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "chat-ingress-retrieval"
        )
        build = self.runtime.paths.ensure_runtime_write_target(root / "builds" / build_id)
        if not build.exists():
            stage = self.runtime.paths.ensure_runtime_write_target(
                self.runtime.paths.staging_root / "chat-ingress-index" / build_id
            )
            if stage.exists() or stage.is_symlink():
                raise ChatSaveError("synthetic chat retrieval staging is unavailable")
            stage.mkdir(mode=0o700, parents=True, exist_ok=False)
            database = stage / "index.sqlite3"
            _write_retrieval_index(database, material)
            manifest = {
                "schema_version": "1.0",
                "build_id": build_id,
                "index_version": "chat-ingress-fts5/1.0",
                "material_sha256": canonical_sha256(build_material),
                "sqlite_sha256": sha256_hex(_read_bytes(database)),
                "sqlite_byte_count": database.stat().st_size,
                "source_count": len(material),
            }
            _write_immutable(stage / "manifest.json", canonical_bytes(manifest))
            build.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(stage, build)
        manifest = _read_canonical_json(build / "manifest.json")
        if manifest.get("material_sha256") != canonical_sha256(build_material):
            raise ChatSaveError("synthetic chat retrieval build is stale")
        _write_replace(
            root / "active.json",
            canonical_bytes({"build_id": build_id, "manifest_sha256": canonical_sha256(manifest)}),
        )
        return {"state": "fresh", "build_id": build_id, "source_count": len(material)}

    def retrieve(self, query: str, *, limit: int = 8) -> dict[str, Any]:
        """Return exact local citations only; source and debrief body text remain outside this API."""

        if not isinstance(query, str) or not query or len(query.encode("utf-8")) > 512:
            raise ChatSaveError("synthetic chat retrieval query is invalid")
        if not isinstance(limit, int) or not 1 <= limit <= 8:
            raise ChatSaveError("synthetic chat retrieval limit is invalid")
        root = self.runtime.paths.derived_root / "chat-ingress-retrieval"
        try:
            active = _read_canonical_json(root / "active.json")
            manifest = _read_canonical_json(root / "builds" / active["build_id"] / "manifest.json")
            database = root / "builds" / active["build_id"] / "index.sqlite3"
            if active["manifest_sha256"] != canonical_sha256(manifest):
                raise ValueError("active manifest is unbound")
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT event_id, source_version_id, source_object_sha256, anchor, text_sha256 "
                    "FROM chat_ingress_chunks WHERE chat_ingress_chunks MATCH ? LIMIT ?",
                    (query, limit),
                ).fetchall()
            finally:
                connection.close()
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            raise ChatSaveError("synthetic chat retrieval index is unavailable") from exc
        return {
            "status": "complete",
            "index": {"build_id": active["build_id"], "index_version": manifest["index_version"]},
            "citations": [
                {
                    "save_event_id": row[0],
                    "source_version_id": row[1],
                    "source_object_sha256": row[2],
                    "anchor": row[3],
                    "chunk_text_sha256": row[4],
                }
                for row in rows
            ],
            "limitations": ["local synthetic citation locators only; source body is not returned"],
        }

    def _stage(self, save_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "chat-ingress" / save_id
        )

    def _source_version(self, manifest: dict[str, Any], execution: ChatIngressExecution) -> dict[str, Any]:
        envelope = execution.ingress_envelope
        version = {
            "schema_version": "1.0",
            "source_version_id": self.ids.new("source_version"),
            "content_sha256": manifest["source_sha256"],
            "byte_count": manifest["source_byte_count"],
            "object_ref": _object_ref(manifest["source_sha256"]),
            "ingress_kind": envelope["ingress_kind"],
            "profile_id": manifest["profile_id"],
            "declared_media_type": envelope["declared_media_type"],
            "declared_extension": envelope["declared_extension"],
            "provenance_sha256": canonical_sha256(envelope["provenance"]),
            "captured_at": timestamp(_aware(self.clock())),
        }
        self.schemas.require("chat-ingress-source-version", version)
        return version

    def _debrief_artifact(
        self,
        manifest: dict[str, Any],
        execution: ChatIngressExecution,
        stage: Path,
    ) -> dict[str, Any]:
        content = canonical_bytes(execution.debrief)
        digest = sha256_hex(content)
        staged = stage / "debrief.json"
        _write_immutable(staged, content)
        object_ref = _object_ref(digest)
        self._publish_stage_object(
            staged,
            self.runtime.paths.artifact_root / "chat-ingress" / "objects" / object_ref,
            expected_sha256=digest,
        )
        return {
            "artifact_id": self.ids.new("artifact"),
            "artifact_version_id": self.ids.new("artifact_version"),
            "content_sha256": digest,
            "byte_count": len(content),
            "object_ref": object_ref,
            "media_type": "application/vnd.vault-next.meeting-debrief+json",
            "debrief_result_sha256": execution.debrief["result_sha256"],
            "save_manifest_sha256": manifest["manifest_digest"],
        }

    def _publish_stage_object(self, staged: Path, target: Path, *, expected_sha256: str) -> Path:
        target = self.runtime.paths.ensure_runtime_write_target(target)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or sha256_hex(_read_bytes(target)) != expected_sha256:
                raise ChatSaveError("synthetic immutable chat object conflicts with different bytes")
            staged.unlink()
            return target
        try:
            os.link(staged, target)
        except FileExistsError:
            if target.is_symlink() or sha256_hex(_read_bytes(target)) != expected_sha256:
                raise ChatSaveError("synthetic immutable chat object changed during publication")
        except OSError as exc:
            raise ChatSaveError("synthetic immutable chat object could not be published") from exc
        if staged.exists():
            staged.unlink()
        _fsync_file(target)
        _fsync_directory(target.parent)
        return target

    def _matching_event(self, manifest: dict[str, Any]) -> dict[str, Any] | None:
        for event in self._save_events():
            prior = event["payload"]["chat_save_manifest"]
            if prior["idempotency_key"] != manifest["idempotency_key"]:
                continue
            if _same_save_intent(prior, manifest):
                return event
            raise ChatSaveError("synthetic chat save idempotency key conflicts with another intent")
        return None

    def _save_events(self) -> list[dict[str, Any]]:
        return [
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "chat_ingress.save_committed"
        ]

    def _verify_event(self, event: dict[str, Any]) -> None:
        payload = event["payload"]
        self.schemas.require("chat-ingress-save-event", payload)
        manifest = payload["chat_save_manifest"]
        self.schemas.require("chat-save-manifest", manifest)
        _require_manifest_digest(manifest)
        if payload["chat_save_manifest_sha256"] != manifest["manifest_digest"]:
            raise ChatSaveError("synthetic chat save event manifest binding is invalid")
        source = payload["source_version"]
        self.schemas.require("chat-ingress-source-version", source)
        if payload["source_version_sha256"] != canonical_sha256(source):
            raise ChatSaveError("synthetic chat save source version binding is invalid")
        if event["case_id"] != manifest["case_id"] or event["session_id"] != manifest["session_id"]:
            raise ChatSaveError("synthetic chat save event case/session binding is invalid")
        raw = self._read_source(source)
        if sha256_hex(raw) != manifest["source_sha256"] or len(raw) != manifest["source_byte_count"]:
            raise ChatSaveError("synthetic chat save source object binding is invalid")
        envelope = _envelope_from_event(event)
        self.schemas.require("chat-ingress-envelope", envelope)
        verified_receipt = self.authority.verify(
            payload["chat_save_receipt"]["receipt_id"],
            manifest_digest=manifest["manifest_digest"],
        )
        if verified_receipt != payload["chat_save_receipt"]:
            raise ChatSaveError("synthetic chat save receipt replay differs from the event")
        normalized = self.router.route(
            raw,
            declared_media_type=source["declared_media_type"],
            declared_extension=source["declared_extension"],
        )
        evidence = freeze_evidence(self.schemas, envelope, normalized)
        if evidence.record() != payload["evidence_packet"] or evidence.evidence_sha256 != manifest["evidence_sha256"]:
            raise ChatSaveError("synthetic chat evidence binding is invalid")
        artifact = payload["debrief_artifact"]
        required_artifact = {
            "artifact_id",
            "artifact_version_id",
            "content_sha256",
            "byte_count",
            "object_ref",
            "media_type",
            "debrief_result_sha256",
            "save_manifest_sha256",
        }
        if not isinstance(artifact, dict) or set(artifact) != required_artifact:
            raise ChatSaveError("synthetic chat debrief artifact is malformed")
        artifact_path = self.runtime.paths.artifact_root / "chat-ingress" / "objects" / artifact["object_ref"]
        raw_artifact = _read_bytes(artifact_path)
        if artifact_path.is_symlink() or sha256_hex(raw_artifact) != artifact["content_sha256"]:
            raise ChatSaveError("synthetic chat debrief artifact bytes are invalid")
        try:
            debrief = json.loads(raw_artifact)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChatSaveError("synthetic chat debrief artifact is not valid JSON") from exc
        if not isinstance(debrief, dict) or canonical_bytes(debrief) != raw_artifact:
            raise ChatSaveError("synthetic chat debrief artifact is not canonical")
        self.schemas.require("meeting-debrief-result", debrief)
        try:
            verify_result_bindings(debrief, evidence)
        except MeetingDebriefError as exc:
            raise ChatSaveError("synthetic chat debrief citations are invalid") from exc
        if (
            artifact["debrief_result_sha256"] != manifest["debrief_result_sha256"]
            or debrief["result_sha256"] != manifest["debrief_result_sha256"]
            or artifact["save_manifest_sha256"] != manifest["manifest_digest"]
        ):
            raise ChatSaveError("synthetic chat debrief artifact is bound to another save")
        inactive = payload["inactive_method_evidence"]
        if (
            not isinstance(inactive, dict)
            or inactive.get("lifecycle_state") != "inactive"
            or inactive.get("debrief_result_sha256") != manifest["debrief_result_sha256"]
        ):
            raise ChatSaveError("synthetic chat method candidate is not inactive and bound")
        material = {key: value for key, value in payload.items() if key != "commit_manifest_sha256"}
        if payload["commit_manifest_sha256"] != canonical_sha256(material):
            raise ChatSaveError("synthetic chat save event commit digest is invalid")

    def _read_source(self, source: dict[str, Any]) -> bytes:
        path = self.runtime.paths.source_root / "chat-ingress" / "objects" / source["object_ref"]
        if path.is_symlink():
            raise ChatSaveError("synthetic chat source object is a symlink")
        raw = _read_bytes(path)
        if sha256_hex(raw) != source["content_sha256"] or len(raw) != source["byte_count"]:
            raise ChatSaveError("synthetic chat source object digest is invalid")
        return raw

    def _result_from_event(self, event: dict[str, Any], status: str) -> dict[str, Any]:
        payload = event["payload"]
        result = {
            "schema_version": "1.0",
            "status": status,
            "authority_level": "U1",
            "ingress_envelope": payload["ingress_envelope"],
            "evidence_packet": payload["evidence_packet"],
            "debrief": None,
            "save": {
                "save_id": payload["chat_save_manifest"]["save_id"],
                "receipt_id": payload["chat_save_receipt"]["receipt_id"],
                "event_id": event["event_id"],
                "source_version_id": payload["source_version"]["source_version_id"],
                "artifact_version_id": payload["debrief_artifact"]["artifact_version_id"],
            },
            "available_next_actions": [],
            "limitations": [
                "synthetic disposable U1 save only",
                "inactive Meeting Debrief candidate; no U2 action is available",
            ],
        }
        self.schemas.require("chat-ingress-result", result)
        return result

    def _remove_stage(self, stage: Path) -> None:
        if stage.exists():
            if stage.is_symlink() or not stage.is_dir():
                raise ChatSaveError("synthetic chat save stage is invalid")
            shutil.rmtree(stage)

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)


def _validate_execution(schemas: SchemaRegistry, execution: object) -> None:
    if not isinstance(execution, ChatIngressExecution):
        raise ChatSaveError("synthetic chat save requires a completed ChatIngressExecution")
    schemas.require("chat-ingress-result", execution.result)
    schemas.require("chat-ingress-envelope", execution.ingress_envelope)
    schemas.require("meeting-debrief-result", execution.debrief)
    execution.evidence.verify()
    if (
        execution.result["authority_level"] != "U0"
        or execution.result["status"] != "complete"
        or execution.result["ingress_envelope"] != execution.ingress_envelope
        or execution.result["evidence_packet"] != execution.evidence.record()
        or execution.result["debrief"] != execution.debrief
        or sha256_hex(execution.material_bytes) != execution.ingress_envelope["material_sha256"]
    ):
        raise ChatSaveError("synthetic chat save execution is not an exact completed U0 result")
    try:
        verify_result_bindings(execution.debrief, execution.evidence)
    except MeetingDebriefError as exc:
        raise ChatSaveError("synthetic chat save debrief is not bound to its exact evidence") from exc


def _require_execution_manifest_binding(
    runtime: CaseSessionRuntime,
    execution: ChatIngressExecution,
    manifest: dict[str, Any],
) -> None:
    expected = {
        "ingress_envelope_sha256": canonical_sha256(execution.ingress_envelope),
        "source_sha256": sha256_hex(execution.material_bytes),
        "source_byte_count": len(execution.material_bytes),
        "evidence_sha256": execution.evidence.evidence_sha256,
        "debrief_result_sha256": execution.debrief["result_sha256"],
        "profile_id": execution.evidence.record()["profile_id"],
        "runtime_id": _runtime_id(runtime),
        "idempotency_key": _save_key(execution),
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ChatSaveError("synthetic chat save manifest does not bind the exact U0 execution")
    session = runtime._session(manifest["session_id"])
    if session.case_id != manifest["case_id"] or session.status != "active" or session.frozen:
        raise ChatSaveError("synthetic chat save manifest session is unavailable")


def _save_key(execution: ChatIngressExecution) -> str:
    return canonical_sha256(
        {
            "source_sha256": sha256_hex(execution.material_bytes),
            "evidence_sha256": execution.evidence.evidence_sha256,
            "method_package": execution.debrief["method_package"],
            "method_version": execution.debrief["method_version"],
            "debrief_result_sha256": execution.debrief["result_sha256"],
        }
    )


def _same_save_intent(first: dict[str, Any], second: dict[str, Any]) -> bool:
    keys = {
        "case_id",
        "session_id",
        "ingress_envelope_sha256",
        "source_sha256",
        "source_byte_count",
        "evidence_sha256",
        "debrief_result_sha256",
        "profile_id",
        "runtime_id",
        "retention_policy_id",
        "candidate_lifecycle",
        "idempotency_key",
        "operations",
        "synthetic_only",
    }
    return all(first[key] == second[key] for key in keys)


def _envelope_from_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = event["payload"]
    manifest = payload["chat_save_manifest"]
    envelope = payload["ingress_envelope"]
    if not isinstance(envelope, dict):
        raise ChatSaveError("synthetic chat saved ingress envelope is malformed")
    source = payload["source_version"]
    if (
        manifest["ingress_envelope_sha256"] != canonical_sha256(envelope)
        or manifest["source_sha256"] != source["content_sha256"]
    ):
        raise ChatSaveError("synthetic chat saved source manifest is inconsistent")
    return envelope


def _object_ref(digest: str) -> str:
    return f"sha256/{digest[:2]}/{digest}"


def _runtime_id(runtime: CaseSessionRuntime) -> str:
    details = runtime.paths.root.stat()
    return canonical_sha256({"device": details.st_dev, "inode": details.st_ino})


def _require_manifest_digest(manifest: dict[str, Any]) -> None:
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest.get("manifest_digest") != canonical_sha256(material):
        raise ChatSaveError("synthetic chat save manifest digest is invalid")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware instant")
    return value.astimezone(UTC)


def _write_retrieval_index(
    path: Path,
    material: list[tuple[dict[str, Any], Any, FrozenEvidence]],
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE VIRTUAL TABLE chat_ingress_chunks USING fts5("
            "text, event_id UNINDEXED, source_version_id UNINDEXED, "
            "source_object_sha256 UNINDEXED, anchor UNINDEXED, text_sha256 UNINDEXED)"
        )
        for event, normalized, _evidence in material:
            source = event["payload"]["source_version"]
            for anchor in normalized.anchors:
                connection.execute(
                    "INSERT INTO chat_ingress_chunks "
                    "(text, event_id, source_version_id, source_object_sha256, anchor, text_sha256) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        anchor.text,
                        event["event_id"],
                        source["source_version_id"],
                        source["content_sha256"],
                        anchor.anchor,
                        anchor.text_sha256,
                    ),
                )
        connection.commit()
    finally:
        connection.close()


def _read_canonical_json(path: Path) -> dict[str, Any]:
    raw = _read_bytes(path)
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ValueError("JSON is not canonical")
    return value


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink():
        raise ChatSaveError("synthetic chat path cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_immutable(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _write_replace(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ChatSaveError("synthetic chat replacement temporary path is unavailable")
    _write_immutable(temporary, content)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short synthetic chat write")
        offset += written


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
