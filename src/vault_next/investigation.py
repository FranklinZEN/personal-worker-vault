"""Structured, adapter-independent S3-A investigation and revision coordination.

The coordinator deliberately accepts only caller-supplied synthetic text.  It does not perform
model work, source intake, retrieval, research, host calls, or S2 work-item application.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.contracts import require_request_envelope, require_result_envelope
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.interaction import InteractionRuntime
from vault_next.records import SchemaRegistry
from vault_next.review import ReviewRepository
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import fold_session_states

FUNCTION_INVESTIGATION = "function_investigation"
FUNCTION_INVESTIGATION_PAUSE = "function_investigation_pause"
FUNCTION_INVESTIGATION_RESUME = "function_investigation_resume"
FUNCTION_ARTIFACT_REVISION = "function_artifact_revision"

_MAX_CHECKPOINT_STATE_BYTES = 16_384
_MAX_CONTEXT_REFS = 8

_OPERATION_CONTRACTS = {
    "investigate": (FUNCTION_INVESTIGATION, "read"),
    "pause": (FUNCTION_INVESTIGATION_PAUSE, "propose"),
    "resume": (FUNCTION_INVESTIGATION_RESUME, "read"),
    "revise": (FUNCTION_ARTIFACT_REVISION, "propose"),
}


@dataclass(frozen=True)
class _RequestBinding:
    """One durable S3-A output already bound to an exact request."""

    event: dict[str, Any]
    record: dict[str, Any]
    kind: str


class InvestigationCoordinator:
    """Coordinate direct synthetic investigation without granting an apply capability."""

    def __init__(self, runtime: CaseSessionRuntime, schemas: SchemaRegistry) -> None:
        self.runtime = runtime
        self.schemas = schemas
        self.interaction = InteractionRuntime(runtime)

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return one bounded direct-investigation result, writing only explicit provisional output."""

        self.schemas.require("s3-investigation-request", request)
        envelope = request["request"]
        if not isinstance(envelope, dict):
            raise _contract_error("$/request", "request must be an object")
        require_request_envelope(envelope, self.schemas)
        self._require_request_contract(request, envelope)
        request_sha256 = canonical_sha256(request)
        existing = self._existing_binding(envelope, request_sha256)
        if existing is not None:
            return self._response_for_existing(request, envelope, existing)

        operation = request["operation"]
        if operation == "investigate":
            return self._investigate(request, envelope)
        if operation == "pause":
            return self._pause(request, envelope, request_sha256)
        if operation == "resume":
            return self._resume(request, envelope)
        if operation == "revise":
            return self._revise(request, envelope, request_sha256)
        raise AssertionError("validated operation is unreachable")

    def _require_request_contract(self, request: dict[str, Any], envelope: dict[str, Any]) -> None:
        operation = request["operation"]
        expected_function, expected_mode = _OPERATION_CONTRACTS[operation]
        if envelope["function_ids"] != [expected_function]:
            raise _contract_error(
                "$/request/function_ids",
                f"{operation} must request exactly {expected_function}",
            )
        if envelope["mode"] != expected_mode:
            raise _contract_error(
                "$/request/mode",
                f"{operation} must use {expected_mode} mode",
            )
        if envelope["owner_receipt_ref"] is not None:
            raise _contract_error(
                "$/request/owner_receipt_ref",
                "S3-A has no apply or receipt route",
            )

        session_id = request["session_id"]
        context_refs = request["context_refs"]
        revision = request["revision"]
        checkpoint_event_id = request["checkpoint_event_id"]
        expected_refs: set[str] = set(context_refs)
        if session_id is not None:
            expected_refs.add(session_id)
        if checkpoint_event_id is not None:
            expected_refs.add(checkpoint_event_id)
        if revision is not None:
            expected_refs.update((revision["artifact_id"], revision["version_id"]))
        if set(envelope["target_refs"]) != expected_refs:
            raise _contract_error(
                "$/request/target_refs",
                "request targets must exactly bind the selected S3-A references",
            )
        if len(context_refs) > _MAX_CONTEXT_REFS:
            raise _contract_error("$/context_refs", "S3-A context reference limit exceeded")

        target_versions = envelope["target_versions"]
        if revision is None:
            if target_versions:
                raise _contract_error(
                    "$/request/target_versions",
                    "only an exact artifact revision may name a target version",
                )
        elif target_versions != [
            {"ref": revision["version_id"], "digest": revision["prior_content_sha256"]}
        ]:
            raise _contract_error(
                "$/request/target_versions",
                "revision must bind exactly its prior artifact version and content hash",
            )

        if operation == "investigate":
            _require_none(request, "checkpoint_event_id", "checkpoint", "revision")
        elif operation == "pause":
            _require_none(request, "topic", "analysis_text", "checkpoint_event_id", "revision")
            if session_id is None:
                raise _contract_error("$/session_id", "pause requires the selected active session")
            if context_refs:
                raise _contract_error("$/context_refs", "pause may not expand context")
        elif operation == "resume":
            _require_none(request, "topic", "analysis_text", "checkpoint", "revision")
            if session_id is None or checkpoint_event_id is None:
                raise _contract_error(
                    "$/session_id",
                    "resume requires a selected session and checkpoint event",
                )
            if context_refs != [checkpoint_event_id]:
                raise _contract_error(
                    "$/context_refs",
                    "resume may expose only its exact selected checkpoint reference",
                )
        elif operation == "revise":
            _require_none(request, "topic", "analysis_text", "checkpoint_event_id", "checkpoint")
            if session_id is None or revision is None:
                raise _contract_error(
                    "$/session_id",
                    "revision requires a selected active session and exact prior version",
                )
            if context_refs:
                raise _contract_error("$/context_refs", "revision may not expand context")
            if revision["media_type"] != "text/markdown":
                raise _contract_error(
                    "$/revision/media_type",
                    "S3-A permits only caller-supplied synthetic Markdown revision text",
                )
            if sha256_hex(revision["content"].encode("utf-8")) != revision["content_sha256"]:
                raise _contract_error(
                    "$/revision/content_sha256",
                    "revision content does not match its declared digest",
                )

    def _investigate(self, request: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        if request["topic"] is None:
            return self._result(
                request,
                envelope,
                function_status="needs_input",
                status="needs_input",
                limits=["an investigation topic is required"],
            )
        if request["analysis_text"] is None:
            return self._result(
                request,
                envelope,
                function_status="needs_input",
                status="needs_input",
                limits=["caller-supplied synthetic analysis text is required"],
                topic=request["topic"],
            )
        unavailable = self._context_scope_limit(request)
        if unavailable is not None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=[unavailable],
                topic=request["topic"],
            )
        return self._result(
            request,
            envelope,
            function_status="complete",
            status="complete",
            sources=["caller-supplied-synthetic-fixture"],
            topic=request["topic"],
            analysis_text=request["analysis_text"],
            context_refs=request["context_refs"],
            continuation_ref=request["session_id"],
        )

    def _pause(
        self, request: dict[str, Any], envelope: dict[str, Any], request_sha256: str
    ) -> dict[str, Any]:
        session_id = request["session_id"]
        assert isinstance(session_id, str)
        unavailable = self._active_interaction_limit(session_id)
        if unavailable is not None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=[unavailable],
                continuation_ref=session_id,
            )
        checkpoint = request["checkpoint"]
        if checkpoint is None:
            return self._result(
                request,
                envelope,
                function_status="complete",
                status="complete",
                continuation_ref=session_id,
            )
        _require_checkpoint_budget(checkpoint["state"])
        event = self.interaction.record_checkpoint(
            session_id,
            checkpoint["summary"],
            state=checkpoint["state"],
            open_questions=checkpoint["open_questions"],
            request_id=envelope["request_id"],
            idempotency_key=envelope["idempotency_key"],
            request_sha256=request_sha256,
        )
        return self._result(
            request,
            envelope,
            function_status="complete",
            status="complete",
            sources=["semantic-ledger"],
            continuation_ref=session_id,
            durable_output_refs=[event["payload"]["checkpoint_id"]],
            checkpoint_ref=_checkpoint_ref(event),
        )

    def _resume(self, request: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        session_id = request["session_id"]
        checkpoint_event_id = request["checkpoint_event_id"]
        assert isinstance(session_id, str) and isinstance(checkpoint_event_id, str)
        session = self._session(session_id)
        if session is None or session.frozen or session.manifest is None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=["selected session is unavailable for resume"],
                continuation_ref=session_id,
            )
        allowed = {entry["ref"] for entry in session.manifest["authorized_context"]}
        if checkpoint_event_id not in allowed:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=["selected checkpoint is not authorized by the selected session manifest"],
                continuation_ref=session_id,
            )
        checkpoint_event = next(
            (
                event
                for event in self.runtime.semantic.read_all()
                if event["event_id"] == checkpoint_event_id
                and event["event_type"] == "checkpoint.recorded"
                and event["case_id"] == session.case_id
            ),
            None,
        )
        if checkpoint_event is None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=["selected checkpoint is unavailable"],
                continuation_ref=session_id,
            )
        try:
            _require_checkpoint_budget(checkpoint_event["payload"]["state"])
        except ValidationError:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=["selected checkpoint exceeds the S3-A state budget"],
                continuation_ref=session_id,
            )
        return self._result(
            request,
            envelope,
            function_status="complete",
            status="complete",
            sources=["semantic-ledger"],
            continuation_ref=session_id,
            context_refs=[checkpoint_event_id],
            checkpoint_ref=_checkpoint_ref(checkpoint_event),
        )

    def _revise(
        self, request: dict[str, Any], envelope: dict[str, Any], request_sha256: str
    ) -> dict[str, Any]:
        session_id = request["session_id"]
        revision = request["revision"]
        assert isinstance(session_id, str) and isinstance(revision, dict)
        unavailable = self._active_interaction_limit(session_id)
        if unavailable is not None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=[unavailable],
                continuation_ref=session_id,
            )
        version = self._exact_current_version(session_id, revision)
        if version is None:
            return self._result(
                request,
                envelope,
                function_status="unavailable",
                status="unavailable",
                limits=["selected artifact version is unavailable, changed, or outside the session case"],
                continuation_ref=session_id,
            )
        registration = self.interaction.create_artifact_version(
            session_id,
            revision["content"].encode("utf-8"),
            artifact_id=revision["artifact_id"],
            prior_version_id=revision["version_id"],
            purpose=revision["purpose"],
            change_summary=revision["change_summary"],
            media_type=revision["media_type"],
            request_id=envelope["request_id"],
            idempotency_key=envelope["idempotency_key"],
            request_sha256=request_sha256,
        )
        return self._result(
            request,
            envelope,
            function_status="complete",
            status="complete",
            sources=["semantic-ledger", "caller-supplied-synthetic-fixture"],
            continuation_ref=session_id,
            durable_output_refs=[registration.version["version_id"]],
            artifact_version_ref=_artifact_ref(registration.event, registration.version),
        )

    def _existing_binding(
        self, envelope: dict[str, Any], request_sha256: str
    ) -> _RequestBinding | None:
        matches: list[_RequestBinding] = []
        for event in self.runtime.semantic.read_all():
            if event["event_type"] == "checkpoint.recorded":
                record = event["payload"]
                kind = "checkpoint"
            elif event["event_type"] == "artifact.version_created":
                record = event["payload"]["version"]
                kind = "artifact"
            else:
                continue
            same_request = record.get("request_id") == envelope["request_id"]
            same_key = record.get("idempotency_key") == envelope["idempotency_key"]
            if not same_request and not same_key:
                continue
            if (
                not same_request
                or not same_key
                or record.get("request_sha256") != request_sha256
            ):
                raise _contract_error(
                    "$/request/idempotency_key",
                    "request ID or idempotency key is already bound to different S3-A output",
                )
            matches.append(_RequestBinding(event, record, kind))
        if len(matches) > 1:
            raise _contract_error(
                "$/request/idempotency_key",
                "request binding resolves to multiple durable outputs",
            )
        return matches[0] if matches else None

    def _response_for_existing(
        self, request: dict[str, Any], envelope: dict[str, Any], binding: _RequestBinding
    ) -> dict[str, Any]:
        if request["operation"] == "pause" and binding.kind == "checkpoint":
            return self._result(
                request,
                envelope,
                function_status="complete",
                status="complete",
                sources=["semantic-ledger"],
                continuation_ref=request["session_id"],
                durable_output_refs=[binding.record["checkpoint_id"]],
                checkpoint_ref=_checkpoint_ref(binding.event),
            )
        if request["operation"] == "revise" and binding.kind == "artifact":
            session_id = request["session_id"]
            assert isinstance(session_id, str)
            self._ensure_artifact_output(session_id, binding.record)
            ReviewRepository(self.runtime.paths, self.schemas).read_verified_artifact(binding.record)
            return self._result(
                request,
                envelope,
                function_status="complete",
                status="complete",
                sources=["semantic-ledger", "caller-supplied-synthetic-fixture"],
                continuation_ref=session_id,
                durable_output_refs=[binding.record["version_id"]],
                artifact_version_ref=_artifact_ref(binding.event, binding.record),
            )
        raise _contract_error(
            "$/request",
            "existing durable request binding has a different S3-A operation",
        )

    def _context_scope_limit(self, request: dict[str, Any]) -> str | None:
        session_id = request["session_id"]
        context_refs = request["context_refs"]
        if session_id is None:
            return None if not context_refs else "context requires a selected session"
        session = self._session(session_id)
        if session is None or session.frozen or session.manifest is None:
            return "selected session is unavailable"
        allowed = {entry["ref"] for entry in session.manifest["authorized_context"]}
        if not set(context_refs).issubset(allowed):
            return "one or more context references are not authorized by the selected session"
        return None

    def _active_interaction_limit(self, session_id: str) -> str | None:
        session = self._session(session_id)
        if session is None or session.frozen or session.manifest is None:
            return "selected session is unavailable"
        try:
            self.interaction._require_interaction(session_id)
        except ValidationError:
            return "selected session has no active compatible interaction"
        return None

    def _exact_current_version(
        self, session_id: str, revision: dict[str, Any]
    ) -> dict[str, Any] | None:
        session = self._session(session_id)
        if session is None:
            return None
        from vault_next.state import fold_artifact_state

        artifact = fold_artifact_state(
            self.runtime.semantic.read_all(), case_id=session.case_id
        ).get(revision["artifact_id"])
        if artifact is None or artifact["current_version_id"] != revision["version_id"]:
            return None
        version = artifact["versions"][revision["version_id"]]
        if version["content_sha256"] != revision["prior_content_sha256"]:
            return None
        return version

    def _ensure_artifact_output(self, session_id: str, version: dict[str, Any]) -> None:
        session = self._session(session_id)
        if session is None or session.frozen or session.manifest is None:
            raise _contract_error("$/session_id", "session vanished before artifact retry recovery")
        if version["version_id"] in session.manifest["output_refs"]:
            return
        self.runtime.amend_scope(
            session_id,
            changes={
                "output_refs": [
                    *session.manifest["output_refs"],
                    version["version_id"],
                ]
            },
            reason="recover exact S3-A artifact output reference",
        )

    def _session(self, session_id: str) -> Any | None:
        states, _ = fold_session_states(self.runtime.semantic.read_all())
        return states.get(session_id)

    def _result(
        self,
        request: dict[str, Any],
        envelope: dict[str, Any],
        *,
        function_status: str,
        status: str,
        limits: list[str] | None = None,
        sources: list[str] | None = None,
        topic: str | None = None,
        analysis_text: str | None = None,
        context_refs: list[str] | None = None,
        continuation_ref: str | None = None,
        durable_output_refs: list[str] | None = None,
        checkpoint_ref: dict[str, Any] | None = None,
        artifact_version_ref: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {
            "schema_version": "1.0",
            "request_id": envelope["request_id"],
            "status": status,
            "function_results": [
                {"function_id": envelope["function_ids"][0], "status": function_status}
            ],
            "receipt_ref": None,
            "committed_watermark": None,
            "pending_refs": [],
            "sources": sorted(set(sources or [])),
            "limits": sorted(set(limits or [])),
            "continuation_ref": continuation_ref,
        }
        require_result_envelope(result, self.schemas, request=envelope)
        response = {
            "schema_version": "1.0",
            "result": result,
            "operation": request["operation"],
            "topic": topic,
            "analysis_text": analysis_text,
            "context_refs": sorted(set(context_refs or [])),
            "source_watermark": _watermark(self.runtime.semantic.read_all()),
            "durable_output_refs": sorted(set(durable_output_refs or [])),
            "checkpoint_ref": checkpoint_ref,
            "artifact_version_ref": artifact_version_ref,
        }
        self.schemas.require("s3-investigation-result", response)
        return response


def _require_none(request: dict[str, Any], *names: str) -> None:
    present = [name for name in names if request[name] is not None]
    if present:
        raise _contract_error(
            "$",
            f"operation does not allow: {', '.join(present)}",
        )


def _require_checkpoint_budget(state: dict[str, Any]) -> None:
    if len(canonical_bytes(state)) > _MAX_CHECKPOINT_STATE_BYTES:
        raise _contract_error(
            "$/checkpoint/state",
            "checkpoint state exceeds the S3-A bounded state budget",
        )


def _checkpoint_ref(event: dict[str, Any]) -> dict[str, Any]:
    payload = event["payload"]
    return {
        "checkpoint_id": payload["checkpoint_id"],
        "event_id": event["event_id"],
        "summary": payload["summary"],
        "state": payload["state"],
        "open_questions": payload["open_questions"],
        "source_watermark": payload["source_watermark"],
    }


def _artifact_ref(event: dict[str, Any], version: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": version["artifact_id"],
        "version_id": version["version_id"],
        "content_sha256": version["content_sha256"],
        "event_id": event["event_id"],
    }


def _watermark(events: list[dict[str, Any]]) -> str:
    return events[-1]["integrity"]["event_sha256"] if events else "GENESIS"


def _contract_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
