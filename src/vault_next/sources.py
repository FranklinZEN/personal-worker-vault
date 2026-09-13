"""Synthetic-only S3-B source receipts, bounded extraction, and derived lexical retrieval.

Raw source bytes are immutable objects; semantic source/extraction events are canonical receipts;
and the SQLite FTS5 database is a disposable derived candidate cache.  Nothing in this module
loads ambient files, calls a model/network service, or invokes the S2 apply boundary.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.contracts import require_request_envelope, require_result_envelope
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ledger import SemanticLedger
from vault_next.records import SchemaRegistry, build_event, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import fold_session_states

FUNCTION_SOURCE_REGISTER = "function_source_register"
FUNCTION_SOURCE_EXTRACT = "function_source_extract"
FUNCTION_SOURCE_REBUILD_INDEX = "function_source_rebuild_index"
FUNCTION_SOURCE_RETRIEVE = "function_source_retrieve"
FUNCTION_SOURCE_CITE = "function_source_cite"

_EXTRACTOR_VERSION = "utf8-structure-v1"
_INDEX_VERSION = "fts5-v1"
_MAX_SOURCES = 8
_MAX_CHUNK_BYTES = 4_096
_MAX_EXCERPT_BYTES = 8_192
_MAX_CANDIDATES = 8

_OPERATION_CONTRACTS = {
    "register": (FUNCTION_SOURCE_REGISTER, "propose"),
    "extract": (FUNCTION_SOURCE_EXTRACT, "propose"),
    "rebuild": (FUNCTION_SOURCE_REBUILD_INDEX, "propose"),
    "retrieve": (FUNCTION_SOURCE_RETRIEVE, "read"),
    "cite": (FUNCTION_SOURCE_CITE, "read"),
}


@dataclass(frozen=True)
class _SourceMaterial:
    """One verified and currently authorized source registration/extraction pair."""

    registration_event: dict[str, Any]
    version: dict[str, Any]
    extraction_event: dict[str, Any] | None
    extraction: dict[str, Any] | None
    content: bytes


@dataclass(frozen=True)
class SourceCaptureProvenance:
    """Verified receipt binding for the narrow native synthetic handoff route."""

    capture_method: str
    receipt_id: str
    capture_manifest_sha256: str


class SourceCaptureRegistrationVerifier(Protocol):
    """Verify a purpose-limited capture receipt before core source visibility."""

    def verify_for_registration(
        self,
        registration: dict[str, Any],
        *,
        source_bytes: bytes,
        case_id: str,
        session_id: str,
        source_request_id: str,
        source_idempotency_key: str,
    ) -> SourceCaptureProvenance: ...


class SourceCoordinator:
    """Coordinate only S3-B synthetic source lifecycle and bounded local retrieval."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        schemas: SchemaRegistry,
        *,
        source_capture_verifier: SourceCaptureRegistrationVerifier | None = None,
    ) -> None:
        self.runtime = runtime
        self.schemas = schemas
        self.semantic = SemanticLedger(runtime.paths, schemas)
        self.source_capture_verifier = source_capture_verifier

    def execute(self, request: dict[str, Any], *, source_bytes: bytes | None = None) -> dict[str, Any]:
        """Execute one exact structured source operation.

        ``source_bytes`` is intentionally a typed local-core argument and is never embedded in the
        request or semantic event.  It is permitted only for a synthetic ``register`` request.
        """

        self.schemas.require("s3-source-request", request)
        envelope = request["request"]
        if not isinstance(envelope, dict):
            raise _contract_error("$/request", "request must be an object")
        require_request_envelope(envelope, self.schemas)
        self._require_request_contract(request, envelope, source_bytes)
        request_sha256 = canonical_sha256(request)
        operation = request["operation"]
        if operation == "register":
            return self._register(request, envelope, request_sha256, source_bytes)
        if operation == "extract":
            return self._extract(request, envelope, request_sha256)
        if operation == "rebuild":
            return self._rebuild(request, envelope, request_sha256)
        if operation == "retrieve":
            return self._retrieve(request, envelope)
        if operation == "cite":
            return self._cite(request, envelope)
        raise AssertionError("validated source operation is unreachable")

    def _require_request_contract(
        self,
        request: dict[str, Any],
        envelope: dict[str, Any],
        source_bytes: bytes | None,
    ) -> None:
        operation = request["operation"]
        function_id, mode = _OPERATION_CONTRACTS[operation]
        if envelope["function_ids"] != [function_id] or envelope["mode"] != mode:
            raise _contract_error(
                "$/request",
                f"{operation} must request exactly {function_id} in {mode} mode",
            )
        if envelope["owner_receipt_ref"] is not None:
            raise _contract_error("$/request/owner_receipt_ref", "S3-B has no apply or receipt route")

        registration = request["registration"]
        bindings = request["source_bindings"]
        expected_refs = {request["session_id"]}
        expected_versions: list[dict[str, str]] = []
        if operation == "register":
            if registration is None or bindings or request["query"] is not None or request["citation"] is not None:
                raise _contract_error("$", "register requires only one registration input")
            expected_refs.add(registration["source_family_id"])
            parent_id = registration["prior_source_version_id"]
            parent_sha = registration["prior_content_sha256"]
            if (parent_id is None) != (parent_sha is None):
                raise _contract_error("$/registration", "source parent ID and digest must both be present or null")
            if parent_id is not None:
                expected_refs.add(parent_id)
                expected_versions.append({"ref": parent_id, "digest": parent_sha})
            if source_bytes is not None and not isinstance(source_bytes, bytes):
                raise _contract_error("$source_bytes", "source bytes must be bytes")
            capture_method = registration.get("capture_method") or "synthetic_fixture"
            capture_receipt_id = registration.get("capture_receipt_id")
            capture_manifest_sha256 = registration.get("capture_manifest_sha256")
            if capture_method == "synthetic_fixture":
                if capture_receipt_id is not None or capture_manifest_sha256 is not None:
                    raise _contract_error(
                        "$/registration",
                        "synthetic fixture registration cannot claim a capture receipt",
                    )
            elif capture_method == "native_local_synthetic_attachment_handoff":
                if capture_receipt_id is None or capture_manifest_sha256 is None:
                    raise _contract_error(
                        "$/registration",
                        "native local handoff requires its exact capture receipt and manifest digest",
                    )
                expected_refs.add(capture_receipt_id)
                expected_versions.append(
                    {"ref": capture_receipt_id, "digest": capture_manifest_sha256}
                )
            else:  # Structural schema validation makes this unreachable.
                raise AssertionError("unrecognized source capture method")
        else:
            if registration is not None:
                raise _contract_error("$/registration", "only register accepts source registration input")
            if source_bytes is not None:
                raise _contract_error("$source_bytes", "only register accepts source bytes")
            if not bindings or len(bindings) > _MAX_SOURCES:
                raise _contract_error("$/source_bindings", "S3-B requires one to eight exact source bindings")
            for binding in bindings:
                expected_refs.update((binding["registration_event_id"], binding["source_version_id"]))
                expected_versions.append(
                    {"ref": binding["source_version_id"], "digest": binding["content_sha256"]}
                )
            expected_versions.sort(key=lambda item: item["ref"])
            if operation == "extract":
                if len(bindings) != 1 or request["query"] is not None or request["citation"] is not None:
                    raise _contract_error("$", "extract requires one source and no query/citation")
            elif operation == "rebuild":
                if request["query"] is not None or request["citation"] is not None:
                    raise _contract_error("$", "rebuild requires source bindings only")
            elif operation == "retrieve":
                if request["query"] is None or request["citation"] is not None:
                    raise _contract_error("$", "retrieve requires a lexical query and no citation")
                if len(request["query"].encode("utf-8")) > 512:
                    raise _contract_error("$/query", "lexical query exceeds the 512 UTF-8 byte limit")
            elif operation == "cite":
                citation = request["citation"]
                if request["query"] is not None or len(bindings) != 1 or citation is None:
                    raise _contract_error("$", "cite requires one exact binding and citation")
                binding = bindings[0]
                if any(
                    citation[field] != binding[field]
                    for field in ("registration_event_id", "source_version_id")
                    if field in citation
                ):
                    raise _contract_error("$/citation", "citation must bind the selected source version")
                if citation["source_object_sha256"] != binding["content_sha256"]:
                    raise _contract_error("$/citation", "citation must bind the selected source digest")

        if set(envelope["target_refs"]) != expected_refs:
            raise _contract_error("$/request/target_refs", "request targets must exactly bind S3-B inputs")
        if envelope["target_versions"] != expected_versions:
            raise _contract_error(
                "$/request/target_versions",
                "request version targets must exactly bind S3-B source digests",
            )

    def _register(
        self,
        request: dict[str, Any],
        envelope: dict[str, Any],
        request_sha256: str,
        source_bytes: bytes | None,
    ) -> dict[str, Any]:
        if source_bytes is None:
            return self._result(
                request,
                envelope,
                status="needs_input",
                limits=["caller-supplied synthetic source bytes are required"],
            )
        registration = request["registration"]
        assert isinstance(registration, dict)
        if (
            sha256_hex(source_bytes) != registration["content_sha256"]
            or len(source_bytes) != registration["byte_count"]
        ):
            raise _contract_error("$source_bytes", "source bytes do not match declared digest and byte count")
        session = self._active_session(request["session_id"])
        provenance = self._capture_provenance(registration, source_bytes, session, envelope)
        existing = self._existing_event_binding(envelope, request_sha256, "source.version_registered")
        if existing is not None:
            version = existing["payload"]["version"]
            try:
                self._read_verified_source(version)
            except ValidationError:
                return self._result(
                    request,
                    envelope,
                    status="unavailable",
                    limits=["registered source object is unavailable or invalid"],
                )
            self._finalize_registration(envelope, request_sha256, existing)
            return self._result(
                request,
                envelope,
                status="complete",
                source_watermark=existing["integrity"]["event_sha256"],
                source_receipt=_source_receipt(existing),
                sources=["semantic-ledger", "synthetic-source-object"],
            )

        version_id = _derived_id("source_version", envelope["request_id"])
        object_ref = _object_ref(registration["content_sha256"])
        prepared = {
            "schema_version": "1.0",
            "request_id": envelope["request_id"],
            "idempotency_key": envelope["idempotency_key"],
            "request_sha256": request_sha256,
            "source_version_id": version_id,
            "source_object_sha256": registration["content_sha256"],
            "object_ref": object_ref,
        }
        self._prepare_registration(prepared)
        self._create_source_object(object_ref, source_bytes)
        instant = self.runtime.clock()
        version = {
            "schema_version": "1.0",
            "source_family_id": registration["source_family_id"],
            "source_version_id": version_id,
            "prior_source_version_id": registration["prior_source_version_id"],
            "prior_content_sha256": registration["prior_content_sha256"],
            "content_sha256": registration["content_sha256"],
            "byte_count": registration["byte_count"],
            "media_type": registration["media_type"],
            "object_ref": object_ref,
            "declared_label": registration["declared_label"],
            "source_class": "synthetic_fixture",
            "captured_at": timestamp(instant),
            "source_effective_at": registration["source_effective_at"],
            "sensitivity_labels": registration["sensitivity_labels"],
            "access_policy": "explicit_session_allowlist",
            "capture_method": provenance.capture_method if provenance else "synthetic_fixture",
            "capture_receipt_id": provenance.receipt_id if provenance else None,
            "capture_manifest_sha256": (
                provenance.capture_manifest_sha256 if provenance else None
            ),
            "request_id": envelope["request_id"],
            "idempotency_key": envelope["idempotency_key"],
            "request_sha256": request_sha256,
        }
        event = self._append_source_event(
            "source.version_registered",
            session,
            {"version": version, "version_sha256": canonical_sha256(version)},
            subject_refs=[version["source_family_id"], version_id],
            sensitivity=_event_sensitivity(version["sensitivity_labels"]),
        )
        self._finalize_registration(envelope, request_sha256, event)
        return self._result(
            request,
            envelope,
            status="complete",
            source_watermark=event["integrity"]["event_sha256"],
            source_receipt=_source_receipt(event),
            sources=["semantic-ledger", "synthetic-source-object"],
        )

    def _capture_provenance(
        self,
        registration: dict[str, Any],
        source_bytes: bytes,
        session: Any,
        envelope: dict[str, Any],
    ) -> SourceCaptureProvenance | None:
        """Fail closed unless the local handoff receipt verifies before source storage."""

        capture_method = registration.get("capture_method") or "synthetic_fixture"
        if capture_method == "synthetic_fixture":
            return None
        verifier = self.source_capture_verifier
        if verifier is None:
            raise _contract_error(
                "$/registration/capture_method",
                "native local attachment handoff has no selected capture receipt verifier",
            )
        provenance = verifier.verify_for_registration(
            registration,
            source_bytes=source_bytes,
            case_id=session.case_id,
            session_id=session.session_id,
            source_request_id=envelope["request_id"],
            source_idempotency_key=envelope["idempotency_key"],
        )
        if (
            provenance.capture_method != capture_method
            or provenance.receipt_id != registration["capture_receipt_id"]
            or provenance.capture_manifest_sha256 != registration["capture_manifest_sha256"]
        ):
            raise _contract_error(
                "$/registration",
                "verified capture receipt does not exactly bind the declared source registration",
            )
        return provenance

    def _extract(
        self, request: dict[str, Any], envelope: dict[str, Any], request_sha256: str
    ) -> dict[str, Any]:
        session = self._active_session(request["session_id"])
        material, limitation = self._one_authorized_source(request, session)
        if material is None:
            return self._result(request, envelope, status="unavailable", limits=[limitation])
        existing = self._existing_event_binding(envelope, request_sha256, "source.extraction_recorded")
        if existing is not None:
            extraction = existing["payload"]["extraction"]
            return self._result(
                request,
                envelope,
                status="complete",
                source_watermark=existing["integrity"]["event_sha256"],
                extraction=_extraction_ref(existing),
                sources=["semantic-ledger"],
            )
        extraction = _extract(material, envelope, request_sha256, self.runtime.clock())
        event = self._append_source_event(
            "source.extraction_recorded",
            session,
            {"extraction": extraction, "extraction_sha256": canonical_sha256(extraction)},
            subject_refs=[extraction["source_version_id"], extraction["extraction_id"]],
            sensitivity=_event_sensitivity(material.version["sensitivity_labels"]),
        )
        return self._result(
            request,
            envelope,
            status="complete",
            source_watermark=event["integrity"]["event_sha256"],
            extraction=_extraction_ref(event),
            sources=["semantic-ledger", "synthetic-source-object"],
        )

    def _rebuild(
        self, request: dict[str, Any], envelope: dict[str, Any], request_sha256: str
    ) -> dict[str, Any]:
        session = self._active_session(request["session_id"])
        materials, limitation = self._authorized_sources(request, session)
        if materials is None:
            return self._result(request, envelope, status="unavailable", limits=[limitation])
        build_id = _derived_id("source_index_build", envelope["request_id"])
        existing = self._read_sealed_build(build_id)
        if existing is not None:
            manifest, _ = existing
            if not _exact_binding(manifest, envelope, request_sha256):
                raise _contract_error("$/request", "index build ID is bound to a different request")
            self._activate_build(manifest)
            return self._result(
                request,
                envelope,
                status="complete",
                source_watermark=manifest["source_watermark"],
                index=_index_ref(manifest, "fresh"),
                sources=["derived-local-fts5"],
            )
        manifest = self._build_index(build_id, session, materials, envelope, request_sha256)
        return self._result(
            request,
            envelope,
            status="complete",
            source_watermark=manifest["source_watermark"],
            index=_index_ref(manifest, "fresh"),
            sources=["derived-local-fts5"],
        )

    def _retrieve(self, request: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        session = self._active_session(request["session_id"])
        materials, limitation = self._authorized_sources(request, session)
        if materials is None:
            return self._result(request, envelope, status="unavailable", limits=[limitation])
        loaded = self._load_active_build()
        if loaded is None:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["no verified active local retrieval index is available"],
            )
        manifest, database = loaded
        source_set_sha = _source_set_sha256(materials)
        index_state = "fresh" if manifest["source_set_sha256"] == source_set_sha else "stale"
        rows = self._search_rows(database, request["query"])
        if rows is None:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["active local retrieval index could not execute the bounded lexical query"],
            )
        candidates = _select_candidates(rows, materials)
        if candidates is None:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["active local retrieval index has an invalid source row mapping"],
            )
        selected, omissions = candidates
        if index_state == "stale":
            omissions.append({"reason": "index_not_covered", "ref": "selected-source-set"})
        for material in materials:
            if material.extraction is None or not material.extraction["chunks"]:
                omissions.append(
                    {
                        "reason": "extraction_omitted",
                        "ref": material.registration_event["event_id"],
                    }
                )
        packet = {
            "schema_version": "1.0",
            "purpose_sha256": canonical_sha256({"query": request["query"], "request_id": envelope["request_id"]}),
            "case_id": session.case_id,
            "session_id": request["session_id"],
            "manifest_sha256": session.manifest_sha256,
            "query": request["query"],
            "source_watermark": _source_watermark(materials),
            "index": _index_ref(manifest, index_state),
            "candidates": selected,
            "omissions": _dedupe_dicts(omissions),
            "limitations": (["no lexical candidates matched the bounded query"] if not selected else [])
            + (["index is stale; newer selected source state may be omitted"] if index_state == "stale" else []),
        }
        return self._result(
            request,
            envelope,
            status="complete",
            source_watermark=packet["source_watermark"],
            index=packet["index"],
            retrieval_packet=packet,
            sources=["derived-local-fts5", "semantic-ledger"],
        )

    def _cite(self, request: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        session = self._active_session(request["session_id"])
        material, limitation = self._one_authorized_source(request, session)
        if material is None:
            return self._result(request, envelope, status="unavailable", limits=[limitation])
        citation = request["citation"]
        assert isinstance(citation, dict)
        if material.extraction is None or material.extraction["extractor_version"] != citation["extractor_version"]:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["selected source has no exact verified extraction for this citation"],
            )
        chunk = next(
            (item for item in material.extraction["chunks"] if item["anchor"] == citation["anchor"]),
            None,
        )
        if chunk is None or citation["source_object_sha256"] != material.version["content_sha256"]:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["exact source citation is unavailable"],
            )
        text = _chunk_text(material.content, chunk)
        if text is None or sha256_hex(text.encode("utf-8")) != citation["chunk_text_sha256"]:
            return self._result(
                request,
                envelope,
                status="unavailable",
                limits=["exact source citation failed byte verification"],
            )
        candidate = _candidate(material, chunk, text)
        packet = {
            "schema_version": "1.0",
            "purpose_sha256": canonical_sha256(citation),
            "case_id": session.case_id,
            "session_id": request["session_id"],
            "manifest_sha256": session.manifest_sha256,
            "query": None,
            "source_watermark": _source_watermark([material]),
            "index": None,
            "candidates": [candidate],
            "omissions": [],
            "limitations": ["citation resolves source location; it does not establish inference completeness"],
        }
        return self._result(
            request,
            envelope,
            status="complete",
            source_watermark=packet["source_watermark"],
            retrieval_packet=packet,
            sources=["semantic-ledger", "synthetic-source-object"],
        )

    def _active_session(self, session_id: str):
        states, issues = fold_session_states(self.semantic.read_all())
        if issues:
            raise ValidationError(issues)
        state = states.get(session_id)
        if state is None or state.frozen or state.status != "active" or state.manifest is None:
            raise _unavailable_error("$/session_id", "selected active session is unavailable")
        return state

    def _one_authorized_source(
        self, request: dict[str, Any], session: Any
    ) -> tuple[_SourceMaterial | None, str]:
        materials, limitation = self._authorized_sources(request, session)
        if materials is None:
            return None, limitation
        return materials[0], ""

    def _authorized_sources(
        self, request: dict[str, Any], session: Any
    ) -> tuple[list[_SourceMaterial] | None, str]:
        events = self.semantic.read_all()
        event_index = {event["event_id"]: event for event in events}
        allowed = {item["ref"]: item for item in session.manifest["authorized_context"]}
        materials: list[_SourceMaterial] = []
        for binding in request["source_bindings"]:
            registration = event_index.get(binding["registration_event_id"])
            if (
                registration is None
                or registration["event_type"] != "source.version_registered"
                or registration["case_id"] != session.case_id
                or binding["registration_event_id"] not in allowed
            ):
                return None, "selected source is not authorized by the current session manifest"
            version = registration["payload"]["version"]
            if (
                version["source_version_id"] != binding["source_version_id"]
                or version["content_sha256"] != binding["content_sha256"]
            ):
                return None, "selected source version binding is unavailable or changed"
            authorization = allowed[registration["event_id"]]
            if not set(version["sensitivity_labels"]).issubset(
                set(authorization["sensitivity_labels"])
            ) or not set(version["sensitivity_labels"]).issubset(
                set(session.manifest["sensitivity_labels"])
            ):
                return None, "selected source sensitivity is not authorized by the current session"
            try:
                content = self._read_verified_source(version)
            except ValidationError:
                return None, "selected source object is unavailable or invalid"
            extraction_event = next(
                (
                    event
                    for event in reversed(events)
                    if event["event_type"] == "source.extraction_recorded"
                    and event["payload"]["extraction"].get("registration_event_id")
                    == registration["event_id"]
                    and event["payload"]["extraction"].get("source_version_id")
                    == version["source_version_id"]
                ),
                None,
            )
            extraction = extraction_event["payload"]["extraction"] if extraction_event else None
            materials.append(
                _SourceMaterial(registration, version, extraction_event, extraction, content)
            )
        return materials, ""

    def _read_verified_source(self, version: dict[str, Any]) -> bytes:
        path = self.runtime.paths.source_root / "objects" / version["object_ref"]
        if path.is_symlink():
            raise _unavailable_error("$source", "source object symlink is not permitted")
        try:
            path = self.runtime.paths.ensure_runtime_write_target(path)
            content = path.read_bytes()
        except (OSError, ValidationError) as exc:
            raise _unavailable_error("$source", "source object is unavailable") from exc
        if sha256_hex(content) != version["content_sha256"] or len(content) != version["byte_count"]:
            raise _unavailable_error("$source", "source object hash or size is invalid")
        return content

    def _existing_event_binding(
        self, envelope: dict[str, Any], request_sha256: str, event_type: str
    ) -> dict[str, Any] | None:
        matches: list[dict[str, Any]] = []
        for event in self.semantic.read_all():
            if event["event_type"] == "source.version_registered":
                record = event["payload"]["version"]
            elif event["event_type"] == "source.extraction_recorded":
                record = event["payload"]["extraction"]
            else:
                continue
            if record.get("request_id") == envelope["request_id"] or record.get(
                "idempotency_key"
            ) == envelope["idempotency_key"]:
                matches.append(event)
                if (
                    event["event_type"] != event_type
                    or not _exact_binding(record, envelope, request_sha256)
                ):
                    raise _contract_error(
                        "$/request",
                        "request ID or idempotency key is already bound to different source output",
                    )
        return matches[0] if matches else None

    def _append_source_event(
        self,
        event_type: str,
        session: Any,
        payload: dict[str, Any],
        *,
        subject_refs: list[str],
        sensitivity: str,
    ) -> dict[str, Any]:
        events = self.semantic.read_all()
        causation = next(
            (event["event_id"] for event in reversed(events) if event["session_id"] == session.session_id),
            None,
        )
        instant = self.runtime.clock()
        return self.semantic.append(
            build_event(
                event_type=event_type,
                case_id=session.case_id,
                session_id=session.session_id,
                payload=payload,
                subject_refs=subject_refs,
                correlation_id=self.runtime.correlation_id,
                causation_event_id=causation,
                sensitivity=sensitivity,
                occurred_at=instant,
                recorded_at=instant,
                id_factory=self.runtime.ids,
            )
        )

    def _prepare_registration(self, prepared: dict[str, Any]) -> None:
        path = self._registration_stage_path(prepared["request_id"], "prepared.json")
        _durable_json_if_absent(path, prepared)

    def _finalize_registration(
        self, envelope: dict[str, Any], request_sha256: str, event: dict[str, Any]) -> None:
        final = {
            "schema_version": "1.0",
            "request_id": envelope["request_id"],
            "idempotency_key": envelope["idempotency_key"],
            "request_sha256": request_sha256,
            "event_id": event["event_id"],
            "event_sha256": event["integrity"]["event_sha256"],
        }
        _durable_json_if_absent(self._registration_stage_path(envelope["request_id"], "finalized.json"), final)

    def _registration_stage_path(self, request_id: str, name: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "sources" / request_id / name
        )

    def _create_source_object(self, object_ref: str, content: bytes) -> None:
        path = self.runtime.paths.source_root / "objects" / object_ref
        if path.is_symlink():
            raise _unavailable_error("$source", "source object symlink is not permitted")
        path = self.runtime.paths.ensure_runtime_write_target(path)
        _durable_bytes_if_absent(path, content)

    def _build_index(
        self,
        build_id: str,
        session: Any,
        materials: list[_SourceMaterial],
        envelope: dict[str, Any],
        request_sha256: str,
    ) -> dict[str, Any]:
        stage = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "retrieval" / build_id
        )
        stage.mkdir(parents=True, exist_ok=False)
        database = stage / "index.sqlite3"
        chunks = _validated_chunks(materials)
        _write_index_database(database, chunks)
        database_bytes = database.read_bytes()
        manifest = {
            "schema_version": "1.0",
            "build_id": build_id,
            "request_id": envelope["request_id"],
            "idempotency_key": envelope["idempotency_key"],
            "request_sha256": request_sha256,
            "case_id": session.case_id,
            "session_id": session.session_id,
            "source_event_ids": sorted(material.registration_event["event_id"] for material in materials),
            "source_set_sha256": _source_set_sha256(materials),
            "source_watermark": _source_watermark(materials),
            "index_version": _INDEX_VERSION,
            "extractor_version": _EXTRACTOR_VERSION,
            "sqlite_sha256": sha256_hex(database_bytes),
            "sqlite_byte_count": len(database_bytes),
            "chunk_count": len(chunks),
            "validation": ["quick_check", "row_mapping", "lexical_probe"],
            "created_at": timestamp(self.runtime.clock()),
        }
        self.schemas.require("source-index-build", manifest)
        _durable_json_if_absent(stage / "manifest.json", manifest)
        _fsync_directory(stage)
        destination = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "retrieval" / "builds" / build_id
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage, destination)
        _fsync_directory(destination.parent)
        self._activate_build(manifest)
        return manifest

    def _activate_build(self, manifest: dict[str, Any]) -> None:
        pointer = {
            "schema_version": "1.0",
            "build_id": manifest["build_id"],
            "manifest_sha256": canonical_sha256(manifest),
        }
        self.schemas.require("source-index-active", pointer)
        active = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "retrieval" / "active.json"
        )
        _atomic_replace_json(active, pointer)

    def _read_sealed_build(self, build_id: str) -> tuple[dict[str, Any], Path] | None:
        directory = self.runtime.paths.derived_root / "retrieval" / "builds" / build_id
        manifest_path = directory / "manifest.json"
        database = directory / "index.sqlite3"
        if (
            manifest_path.is_symlink()
            or database.is_symlink()
            or not manifest_path.is_file()
            or not database.is_file()
        ):
            return None
        try:
            manifest = _read_canonical_json(manifest_path)
            self.schemas.require("source-index-build", manifest)
            if sha256_hex(database.read_bytes()) != manifest["sqlite_sha256"]:
                raise ValueError("database digest mismatch")
            if len(database.read_bytes()) != manifest["sqlite_byte_count"]:
                raise ValueError("database size mismatch")
            _validate_index_database(database, manifest["chunk_count"])
        except (OSError, ValueError, ValidationError, sqlite3.Error):
            return None
        return manifest, database

    def _load_active_build(self) -> tuple[dict[str, Any], Path] | None:
        active = self.runtime.paths.derived_root / "retrieval" / "active.json"
        if active.is_symlink():
            return None
        try:
            pointer = _read_canonical_json(active)
            self.schemas.require("source-index-active", pointer)
            loaded = self._read_sealed_build(pointer["build_id"])
            if loaded is None or canonical_sha256(loaded[0]) != pointer["manifest_sha256"]:
                return None
            return loaded
        except (OSError, ValueError, ValidationError):
            return None

    @staticmethod
    def _search_rows(database: Path, query: str) -> list[dict[str, str]] | None:
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT body, source_event_id, source_version_id, source_object_sha256, "
                    "extraction_id, extractor_version, anchor, text_sha256, parent_anchor "
                    "FROM source_chunks WHERE source_chunks MATCH ? LIMIT 64",
                    (query,),
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error:
            return None
        columns = (
            "body",
            "source_event_id",
            "source_version_id",
            "source_object_sha256",
            "extraction_id",
            "extractor_version",
            "anchor",
            "text_sha256",
            "parent_anchor",
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def _result(
        self,
        request: dict[str, Any],
        envelope: dict[str, Any],
        *,
        status: str,
        limits: list[str] | None = None,
        source_watermark: str | None = None,
        source_receipt: dict[str, Any] | None = None,
        extraction: dict[str, Any] | None = None,
        index: dict[str, Any] | None = None,
        retrieval_packet: dict[str, Any] | None = None,
        sources: list[str] | None = None,
    ) -> dict[str, Any]:
        function_id, _ = _OPERATION_CONTRACTS[request["operation"]]
        result = {
            "schema_version": "1.0",
            "request_id": envelope["request_id"],
            "status": status,
            "function_results": [{"function_id": function_id, "status": status}],
            "receipt_ref": None,
            "committed_watermark": None,
            "pending_refs": [],
            "sources": sources or [],
            "limits": limits or [],
            "continuation_ref": request["session_id"],
        }
        require_result_envelope(result, self.schemas)
        response = {
            "result": result,
            "operation": request["operation"],
            "source_watermark": source_watermark,
            "source_receipt": source_receipt,
            "extraction": extraction,
            "index": index,
            "retrieval_packet": retrieval_packet,
        }
        self.schemas.require("s3-source-result", response)
        return response


def _extract(
    material: _SourceMaterial,
    envelope: dict[str, Any],
    request_sha256: str,
    when: Any,
) -> dict[str, Any]:
    version = material.version
    extraction_id = _derived_id("source_extraction", envelope["request_id"])
    common = {
        "schema_version": "1.0",
        "extraction_id": extraction_id,
        "source_version_id": version["source_version_id"],
        "registration_event_id": material.registration_event["event_id"],
        "source_object_sha256": version["content_sha256"],
        "extractor_version": _EXTRACTOR_VERSION,
        "request_id": envelope["request_id"],
        "idempotency_key": envelope["idempotency_key"],
        "request_sha256": request_sha256,
        "extracted_at": timestamp(when),
    }
    if version["media_type"] == "application/octet-stream":
        return {
            **common,
            "extracted_text_sha256": None,
            "status": "preserved_unindexed",
            "chunks": [],
            "omissions": [
                {
                    "anchor": "source:whole",
                    "byte_start": 0,
                    "byte_end": len(material.content),
                    "reason": "unsupported_media_type",
                }
            ],
        }
    try:
        text = material.content.decode("utf-8")
    except UnicodeDecodeError:
        return {
            **common,
            "extracted_text_sha256": None,
            "status": "preserved_unindexed",
            "chunks": [],
            "omissions": [
                {
                    "anchor": "source:whole",
                    "byte_start": 0,
                    "byte_end": len(material.content),
                    "reason": "invalid_utf8",
                }
            ],
        }
    try:
        chunks, omissions = _structure_chunks(text, material.content, version["source_version_id"])
    except Exception:  # A parser defect must be recorded as unavailable, never guessed around.
        return {
            **common,
            "extracted_text_sha256": None,
            "status": "preserved_unindexed",
            "chunks": [],
            "omissions": [
                {
                    "anchor": "source:whole",
                    "byte_start": 0,
                    "byte_end": len(material.content),
                    "reason": "parser_failure",
                }
            ],
        }
    return {
        **common,
        "extracted_text_sha256": sha256_hex(text.encode("utf-8")),
        "status": "partial" if omissions else "complete",
        "chunks": chunks,
        "omissions": omissions,
    }


def _structure_chunks(
    text: str,
    content: bytes,
    source_version_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split only at headings/paragraphs; oversize units are disclosed, never silently split."""

    units: list[tuple[int, int, int, int, list[str], str | None]] = []
    headings: list[str] = []
    active_heading_anchor: str | None = None
    current_start: int | None = None
    current_line_start: int | None = None
    byte_offset = 0
    lines = text.splitlines(keepends=True)

    def finish_paragraph(end: int, line_end: int) -> None:
        nonlocal current_start, current_line_start
        if current_start is not None and current_line_start is not None and end > current_start:
            units.append((current_start, end, current_line_start, line_end, list(headings), active_heading_anchor))
        current_start = None
        current_line_start = None

    for line_number, line in enumerate(lines, start=1):
        encoded = line.encode("utf-8")
        end = byte_offset + len(encoded)
        stripped = line.strip()
        is_heading = stripped.startswith("#") and stripped.lstrip("#").startswith(" ")
        if is_heading:
            finish_paragraph(byte_offset, line_number - 1)
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[level:].strip()
            if title:
                headings = headings[: max(level - 1, 0)] + [title]
            anchor = _anchor(byte_offset, end, line_number, line_number)
            units.append((byte_offset, end, line_number, line_number, list(headings), None))
            active_heading_anchor = anchor
        elif not stripped:
            finish_paragraph(byte_offset, line_number - 1)
        elif current_start is None:
            current_start = byte_offset
            current_line_start = line_number
        byte_offset = end
    finish_paragraph(byte_offset, len(lines))

    chunks: list[dict[str, Any]] = []
    omissions: list[dict[str, Any]] = []
    for start, end, line_start, line_end, heading_path, parent_anchor in units:
        anchor = _anchor(start, end, line_start, line_end)
        raw = content[start:end]
        if len(raw) > _MAX_CHUNK_BYTES:
            omissions.append(
                {
                    "anchor": anchor,
                    "byte_start": start,
                    "byte_end": end,
                    "reason": "unit_exceeds_s3b_budget",
                }
            )
            continue
        text_sha = sha256_hex(raw)
        chunk_id = "source_chunk_" + canonical_sha256(
            {"source_version_id": source_version_id, "anchor": anchor, "text_sha256": text_sha}
        )[:26]
        chunks.append(
            {
                "chunk_id": chunk_id,
                "anchor": anchor,
                "byte_start": start,
                "byte_end": end,
                "line_start": line_start,
                "line_end": line_end,
                "heading_path": heading_path,
                "parent_anchor": parent_anchor,
                "text_sha256": text_sha,
            }
        )
    return chunks, omissions


def _validated_chunks(materials: list[_SourceMaterial]) -> list[tuple[_SourceMaterial, dict[str, Any], str]]:
    rows: list[tuple[_SourceMaterial, dict[str, Any], str]] = []
    for material in materials:
        if material.extraction is None:
            continue
        for chunk in material.extraction["chunks"]:
            text = _chunk_text(material.content, chunk)
            if text is None or sha256_hex(text.encode("utf-8")) != chunk["text_sha256"]:
                raise _unavailable_error("$source", "verified source extraction chunk is invalid")
            rows.append((material, chunk, text))
    return rows


def _write_index_database(path: Path, chunks: list[tuple[_SourceMaterial, dict[str, Any], str]]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(
            "CREATE VIRTUAL TABLE source_chunks USING fts5("
            "body, source_event_id UNINDEXED, source_version_id UNINDEXED, "
            "source_object_sha256 UNINDEXED, extraction_id UNINDEXED, extractor_version UNINDEXED, "
            "anchor UNINDEXED, text_sha256 UNINDEXED, parent_anchor UNINDEXED)"
        )
        connection.execute("CREATE VIRTUAL TABLE source_probe USING fts5(body)")
        connection.execute("INSERT INTO source_probe(body) VALUES (?)", ("vaultnext_s3b_probe",))
        for material, chunk, text in chunks:
            extraction = material.extraction
            assert extraction is not None
            connection.execute(
                "INSERT INTO source_chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    text,
                    material.registration_event["event_id"],
                    material.version["source_version_id"],
                    material.version["content_sha256"],
                    extraction["extraction_id"],
                    extraction["extractor_version"],
                    chunk["anchor"],
                    chunk["text_sha256"],
                    chunk["parent_anchor"] or "",
                ),
            )
        connection.commit()
        _validate_index_database(path, len(chunks), connection=connection)
    finally:
        connection.close()
    _fsync_file(path)


def _validate_index_database(path: Path, expected_count: int, *, connection: sqlite3.Connection | None = None) -> None:
    owns_connection = connection is None
    database = connection or sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        database.execute("PRAGMA query_only = ON")
        if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ValueError("SQLite quick_check failed")
        if database.execute("SELECT count(*) FROM source_chunks").fetchone() != (expected_count,):
            raise ValueError("SQLite row count mismatches sealed manifest")
        probe_count = database.execute(
            "SELECT count(*) FROM source_probe WHERE source_probe MATCH ?",
            ("vaultnext_s3b_probe",),
        ).fetchone()
        if probe_count != (1,):
            raise ValueError("SQLite FTS5 lexical probe failed")
    finally:
        if owns_connection:
            database.close()


def _select_candidates(
    rows: list[dict[str, str]], materials: list[_SourceMaterial]
) -> tuple[list[dict[str, Any]], list[dict[str, str]]] | None:
    material_by_event = {material.registration_event["event_id"]: material for material in materials}
    selected: list[dict[str, Any]] = []
    omissions: list[dict[str, str]] = []
    keys: dict[tuple[str, str, str], dict[str, Any]] = {}
    used_bytes = 0
    for row in rows:
        material = material_by_event.get(row["source_event_id"])
        if material is None or material.extraction is None:
            omissions.append({"reason": "scope_denied", "ref": row["source_event_id"]})
            continue
        chunk = next((item for item in material.extraction["chunks"] if item["anchor"] == row["anchor"]), None)
        if (
            chunk is None
            or row["source_version_id"] != material.version["source_version_id"]
            or row["source_object_sha256"] != material.version["content_sha256"]
            or row["extraction_id"] != material.extraction["extraction_id"]
            or row["extractor_version"] != material.extraction["extractor_version"]
            or row["text_sha256"] != chunk["text_sha256"]
        ):
            return None
        text = _chunk_text(material.content, chunk)
        if text is None or sha256_hex(text.encode("utf-8")) != chunk["text_sha256"]:
            return None
        key = (material.version["content_sha256"], chunk["anchor"], chunk["text_sha256"])
        if key in keys:
            keys[key]["aliases"].append(
                {
                    "registration_event_id": material.registration_event["event_id"],
                    "source_version_id": material.version["source_version_id"],
                }
            )
            omissions.append({"reason": "duplicate_collapsed", "ref": row["source_event_id"]})
            continue
        size = len(text.encode("utf-8"))
        if len(selected) >= _MAX_CANDIDATES or used_bytes + size > _MAX_EXCERPT_BYTES:
            omissions.append({"reason": "budget_exhausted", "ref": row["source_event_id"]})
            continue
        candidate = _candidate(material, chunk, text)
        keys[key] = candidate
        selected.append(candidate)
        used_bytes += size
    return selected, omissions


def _candidate(material: _SourceMaterial, chunk: dict[str, Any], text: str) -> dict[str, Any]:
    extraction = material.extraction
    assert extraction is not None
    return {
        "citation": {
            "source_version_id": material.version["source_version_id"],
            "registration_event_id": material.registration_event["event_id"],
            "source_object_sha256": material.version["content_sha256"],
            "extractor_version": extraction["extractor_version"],
            "anchor": chunk["anchor"],
            "chunk_text_sha256": chunk["text_sha256"],
        },
        "excerpt": text,
        "parent_anchor": chunk["parent_anchor"],
        "heading_path": chunk["heading_path"],
        "aliases": [
            {
                "registration_event_id": material.registration_event["event_id"],
                "source_version_id": material.version["source_version_id"],
            }
        ],
    }


def _chunk_text(content: bytes, chunk: dict[str, Any]) -> str | None:
    try:
        raw = content[chunk["byte_start"] : chunk["byte_end"]]
        if len(raw) != chunk["byte_end"] - chunk["byte_start"]:
            return None
        return raw.decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return None


def _source_set_sha256(materials: list[_SourceMaterial]) -> str:
    return canonical_sha256(
        [
            {
                "registration_event_id": material.registration_event["event_id"],
                "source_version_id": material.version["source_version_id"],
                "content_sha256": material.version["content_sha256"],
                "extraction_event_id": material.extraction_event["event_id"] if material.extraction_event else None,
                "extraction_sha256": material.extraction_event["payload"]["extraction_sha256"]
                if material.extraction_event
                else None,
            }
            for material in sorted(materials, key=lambda item: item.registration_event["event_id"])
        ]
    )


def _source_watermark(materials: list[_SourceMaterial]) -> str:
    return canonical_sha256(
        [
            {
                "registration_event_id": material.registration_event["event_id"],
                "registration_event_sha256": material.registration_event["integrity"]["event_sha256"],
                "extraction_event_id": material.extraction_event["event_id"] if material.extraction_event else None,
                "extraction_event_sha256": material.extraction_event["integrity"]["event_sha256"]
                if material.extraction_event
                else None,
            }
            for material in sorted(materials, key=lambda item: item.registration_event["event_id"])
        ]
    )


def _source_receipt(event: dict[str, Any]) -> dict[str, Any]:
    version = event["payload"]["version"]
    return {
        "registration_event_id": event["event_id"],
        "event_sha256": event["integrity"]["event_sha256"],
        "source_family_id": version["source_family_id"],
        "source_version_id": version["source_version_id"],
        "content_sha256": version["content_sha256"],
        "byte_count": version["byte_count"],
    }


def _extraction_ref(event: dict[str, Any]) -> dict[str, Any]:
    extraction = event["payload"]["extraction"]
    return {
        "extraction_event_id": event["event_id"],
        "event_sha256": event["integrity"]["event_sha256"],
        "extraction_id": extraction["extraction_id"],
        "source_version_id": extraction["source_version_id"],
        "status": extraction["status"],
        "chunk_count": len(extraction["chunks"]),
        "omissions": extraction["omissions"],
    }


def _index_ref(manifest: dict[str, Any], state: str) -> dict[str, Any]:
    return {
        "build_id": manifest["build_id"],
        "state": state,
        "source_watermark": manifest["source_watermark"],
        "source_set_sha256": manifest["source_set_sha256"],
        "index_version": manifest["index_version"],
    }


def _derived_id(prefix: str, request_id: str) -> str:
    return f"{prefix}_{request_id.removeprefix('request_')}"


def _object_ref(digest: str) -> str:
    return f"sha256/{digest[:2]}/{digest}"


def _anchor(start: int, end: int, line_start: int, line_end: int) -> str:
    return f"bytes:{start}-{end};lines:{line_start}-{line_end}"


def _event_sensitivity(labels: list[str]) -> str:
    return "none" if labels == ["none"] else sorted(labels)[0]


def _exact_binding(record: dict[str, Any], envelope: dict[str, Any], request_sha256: str) -> bool:
    return (
        record.get("request_id") == envelope["request_id"]
        and record.get("idempotency_key") == envelope["idempotency_key"]
        and record.get("request_sha256") == request_sha256
    )


def _dedupe_dicts(items: list[dict[str, str]]) -> list[dict[str, str]]:
    return list({canonical_sha256(item): item for item in items}.values())


def _durable_bytes_if_absent(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != data:
            raise _unavailable_error("$source", "content-addressed source object collision")
        return
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short durable source write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _durable_json_if_absent(path: Path, value: dict[str, Any]) -> None:
    _durable_bytes_if_absent(path, canonical_bytes(value) + b"\n")


def _atomic_replace_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise _unavailable_error("$index", "interrupted active-index temporary pointer is present")
    _durable_bytes_if_absent(temporary, canonical_bytes(value) + b"\n")
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _read_canonical_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != raw:
        raise ValueError("record is not canonical JSON")
    return value


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


def _contract_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])


def _unavailable_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.EVIDENCE_OBJECT_INVALID, path, message)])
