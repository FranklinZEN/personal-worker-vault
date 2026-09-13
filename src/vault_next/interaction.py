"""P3A interaction checkpoints, immutable artifacts, and work-item operations."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from vault_next import __version__
from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import fold_artifact_state, fold_interaction_state, fold_work_items

WORK_ITEM_TRANSITIONS = {
    "proposed": frozenset({"open", "cancelled"}),
    "open": frozenset({"in_progress", "waiting", "done", "cancelled"}),
    "in_progress": frozenset({"open", "waiting", "done", "cancelled"}),
    "waiting": frozenset({"open", "in_progress", "done", "cancelled"}),
    "done": frozenset(),
    "cancelled": frozenset(),
}

FORBIDDEN_CHECKPOINT_KEYS = frozenset(
    {"chain_of_thought", "hidden_reasoning", "messages", "raw_transcript", "transcript"}
)


@dataclass(frozen=True)
class ArtifactRegistration:
    """One immutable artifact-version registration and its canonical event."""

    version: dict[str, Any]
    event: dict[str, Any]
    object_path: Path


class InteractionRuntime:
    """Append governed interaction state without granting owner authority to the model."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.runtime = runtime
        self.paths: RuntimePaths = runtime.paths
        self.schemas: SchemaRegistry = runtime.schemas
        self.ids = id_factory
        self.clock = clock

    def record_owner_input(
        self,
        session_id: str,
        statement: str,
        *,
        role: str,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Record material owner knowledge without attributing it to the runtime."""

        self._require_interaction(session_id)
        input_id = self.ids.new("owner_input")
        return self.runtime.record_reasoning_event(
            session_id,
            "owner_input.recorded",
            {
                "input_id": input_id,
                "statement": statement,
                "role": role,
                "explicit_confirmation": True,
            },
            subject_refs=[input_id],
            actor={"type": "owner", "id": owner_id},
        )

    def record_checkpoint(
        self,
        session_id: str,
        summary: str,
        *,
        state: dict[str, Any],
        open_questions: list[str] | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        request_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Capture concise resumable state while rejecting transcript-like storage."""

        interaction = self._require_interaction(session_id)
        forbidden = sorted(_forbidden_checkpoint_keys(state))
        if forbidden:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.CHECKPOINT_CONTENT_FORBIDDEN,
                        "$state",
                        f"checkpoint contains forbidden fields: {', '.join(forbidden)}",
                    )
                ]
            )
        prior = self._session_events(session_id)
        checkpoint_id = self.ids.new("checkpoint")
        payload = {
            "checkpoint_id": checkpoint_id,
            "summary": summary,
            "state": state,
            "open_questions": list(dict.fromkeys(open_questions or [])),
            "contract_sha256": interaction["contract_sha256"],
            "source_event_ids": [event["event_id"] for event in prior],
            "source_watermark": prior[-1]["integrity"]["event_sha256"],
        }
        _add_request_binding(
            payload,
            request_id=request_id,
            idempotency_key=idempotency_key,
            request_sha256=request_sha256,
        )
        return self.runtime.record_reasoning_event(
            session_id,
            "checkpoint.recorded",
            payload,
            subject_refs=[checkpoint_id],
        )

    def create_artifact_version(
        self,
        session_id: str,
        content: bytes,
        *,
        purpose: str,
        change_summary: str,
        media_type: str = "text/markdown",
        artifact_id: str | None = None,
        prior_version_id: str | None = None,
        addressed_feedback_ids: list[str] | None = None,
        review_pending: bool = False,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        request_sha256: str | None = None,
    ) -> ArtifactRegistration:
        """Create immutable bytes and append their exact lineage to semantic history."""

        interaction = self._require_interaction(session_id)
        if interaction["contract"]["artifact_policy"] == "none":
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        "$interaction/artifact_policy",
                        "current interaction contract does not allow an artifact",
                    )
                ]
            )
        session = self.runtime._session(session_id)
        events = self.runtime.semantic.read_all()
        artifacts = fold_artifact_state(events, case_id=session.case_id)
        feedback_ids = list(dict.fromkeys(addressed_feedback_ids or []))
        if artifact_id is None:
            if prior_version_id is not None or feedback_ids:
                raise self._artifact_error("new artifact cannot name prior version or feedback")
            artifact_id = self.ids.new("artifact")
            version_number = 1
        else:
            artifact = artifacts.get(artifact_id)
            if artifact is None or prior_version_id != artifact["current_version_id"]:
                raise self._artifact_error("revision must reference the current existing version")
            missing_feedback = sorted(set(feedback_ids) - set(artifact["feedback"]))
            if missing_feedback:
                raise self._artifact_error("revision references unknown feedback")
            version_number = artifact["versions"][prior_version_id]["version_number"] + 1
        digest = sha256_hex(content)
        object_ref = f"sha256/{digest[:2]}/{digest}"
        object_path = self.paths.ensure_runtime_write_target(
            self.paths.artifact_root / "objects" / object_ref
        )
        created = _durable_create_if_absent(object_path, content)
        event_committed = False
        try:
            prior_events = self._session_events(session_id)
            when = self.clock()
            version = {
                "schema_version": "1.0",
                "artifact_id": artifact_id,
                "version_id": self.ids.new("artifact_version"),
                "version_number": version_number,
                "purpose": purpose,
                "media_type": media_type,
                "content_sha256": digest,
                "byte_count": len(content),
                "object_ref": object_ref,
                "created_at": timestamp(when),
                "producer": {
                    "type": "runtime",
                    "id": f"vault-next-runtime/{__version__}",
                },
                "source_event_ids": [event["event_id"] for event in prior_events],
                "source_watermark": prior_events[-1]["integrity"]["event_sha256"],
                "prior_version_id": prior_version_id,
                "addressed_feedback_ids": feedback_ids,
                "change_summary": change_summary,
                "status": "review_pending" if review_pending else "working",
            }
            _add_request_binding(
                version,
                request_id=request_id,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
            self.schemas.require("artifact-version", version)
            event = self.runtime.record_reasoning_event(
                session_id,
                "artifact.version_created",
                {"version": version, "version_sha256": canonical_sha256(version)},
                subject_refs=[artifact_id, version["version_id"]],
            )
            event_committed = True
            current_manifest = self.runtime._session(session_id).manifest
            if current_manifest is not None:
                output_refs = list(
                    dict.fromkeys([*current_manifest["output_refs"], version["version_id"]])
                )
                self.runtime.amend_scope(
                    session_id,
                    changes={"output_refs": output_refs},
                    reason="register immutable working-artifact version",
                )
            return ArtifactRegistration(version, event, object_path)
        except Exception:
            if created and not event_committed and object_path.exists():
                object_path.unlink()
            raise

    def record_artifact_feedback(
        self,
        session_id: str,
        artifact_id: str,
        version_id: str,
        *,
        feedback: str,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Bind explicit owner feedback to one exact artifact version."""

        version = self._artifact_version(session_id, artifact_id, version_id)
        feedback_id = self.ids.new("feedback")
        return self.runtime.record_reasoning_event(
            session_id,
            "artifact.feedback_recorded",
            {
                "feedback_id": feedback_id,
                "artifact_id": artifact_id,
                "version_id": version_id,
                "content_sha256": version["content_sha256"],
                "feedback": feedback,
                "disposition": "open",
                "explicit_confirmation": True,
            },
            subject_refs=[artifact_id, version_id, feedback_id],
            actor={"type": "owner", "id": owner_id},
        )

    def accept_artifact(
        self,
        session_id: str,
        artifact_id: str,
        version_id: str,
        *,
        purpose: str,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Accept one exact version without creating any other authority event."""

        version = self._artifact_version(session_id, artifact_id, version_id)
        return self.runtime.record_reasoning_event(
            session_id,
            "artifact.accepted",
            {
                "artifact_id": artifact_id,
                "version_id": version_id,
                "content_sha256": version["content_sha256"],
                "purpose": purpose,
                "explicit_confirmation": True,
            },
            subject_refs=[artifact_id, version_id],
            actor={"type": "owner", "id": owner_id},
        )

    def withdraw_artifact(
        self,
        session_id: str,
        artifact_id: str,
        version_id: str,
        *,
        reason: str,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Withdraw one exact version without deleting its bytes or history."""

        version = self._artifact_version(session_id, artifact_id, version_id)
        return self.runtime.record_reasoning_event(
            session_id,
            "artifact.withdrawn",
            {
                "artifact_id": artifact_id,
                "version_id": version_id,
                "content_sha256": version["content_sha256"],
                "reason": reason,
                "explicit_confirmation": True,
            },
            subject_refs=[artifact_id, version_id],
            actor={"type": "owner", "id": owner_id},
        )

    def propose_work_item(
        self,
        session_id: str,
        statement: str,
        *,
        priority: str | None = None,
        due_on: str | None = None,
        next_review_on: str | None = None,
        blocker: str | None = None,
    ) -> dict[str, Any]:
        """Create a visibly uncommitted system suggestion."""

        return self._record_work_item(
            session_id,
            statement,
            status="proposed",
            source_kind="system_suggestion",
            priority=priority,
            due_on=due_on,
            next_review_on=next_review_on,
            blocker=blocker,
            actor={"type": "runtime", "id": f"vault-next-runtime/{__version__}"},
            explicit_confirmation=False,
        )

    def record_owner_work_item(
        self,
        session_id: str,
        statement: str,
        *,
        priority: str | None = None,
        due_on: str | None = None,
        next_review_on: str | None = None,
        blocker: str | None = None,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Create an owner-confirmed open work item."""

        return self._record_work_item(
            session_id,
            statement,
            status="open",
            source_kind="owner_instruction",
            priority=priority,
            due_on=due_on,
            next_review_on=next_review_on,
            blocker=blocker,
            actor={"type": "owner", "id": owner_id},
            explicit_confirmation=True,
        )

    def change_work_item_status(
        self,
        session_id: str,
        work_item_id: str,
        to_status: str,
        *,
        reason: str,
        priority: str | None = None,
        due_on: str | None = None,
        next_review_on: str | None = None,
        blocker: str | None = None,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Apply one explicit owner work-item transition and full next state."""

        session = self._require_interaction(session_id)
        items = fold_work_items(self.runtime.semantic.read_all(), case_id=session["case_id"])
        current = items.get(work_item_id)
        if current is None or to_status not in WORK_ITEM_TRANSITIONS[current["status"]]:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.WORK_ITEM_TRANSITION_INVALID,
                        "$to_status",
                        f"invalid work-item transition: {current['status'] if current else None} -> {to_status}",
                    )
                ]
            )
        payload = {
            "work_item_id": work_item_id,
            "from_status": current["status"],
            "to_status": to_status,
            "reason": reason,
            "priority": priority if priority is not None else current["priority"],
            "due_on": due_on if due_on is not None else current["due_on"],
            "next_review_on": (
                next_review_on if next_review_on is not None else current["next_review_on"]
            ),
            "blocker": blocker if blocker is not None else current["blocker"],
            "explicit_confirmation": True,
        }
        return self.runtime.record_reasoning_event(
            session_id,
            "work_item.status_changed",
            payload,
            subject_refs=[work_item_id],
            actor={"type": "owner", "id": owner_id},
        )

    def _record_work_item(
        self,
        session_id: str,
        statement: str,
        *,
        status: str,
        source_kind: str,
        priority: str | None,
        due_on: str | None,
        next_review_on: str | None,
        blocker: str | None,
        actor: dict[str, str],
        explicit_confirmation: bool,
    ) -> dict[str, Any]:
        self._require_interaction(session_id)
        work_item_id = self.ids.new("work_item")
        return self.runtime.record_reasoning_event(
            session_id,
            "work_item.recorded",
            {
                "work_item_id": work_item_id,
                "statement": statement,
                "status": status,
                "source_kind": source_kind,
                "priority": priority,
                "due_on": due_on,
                "next_review_on": next_review_on,
                "blocker": blocker,
                "explicit_confirmation": explicit_confirmation,
            },
            subject_refs=[work_item_id],
            actor=actor,
        )

    def _require_interaction(self, session_id: str) -> dict[str, Any]:
        session = self.runtime._session(session_id)
        if session.frozen or session.manifest is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$session_id",
                        "interaction requires a nonterminal full session",
                    )
                ]
            )
        interaction = fold_interaction_state(self.runtime.semantic.read_all(), session_id)
        if interaction["contract"] is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$interaction",
                        "session has no canonical interaction contract",
                    )
                ]
            )
        return {**interaction, "case_id": session.case_id}

    def _artifact_version(
        self, session_id: str, artifact_id: str, version_id: str
    ) -> dict[str, Any]:
        session = self._require_interaction(session_id)
        artifacts = fold_artifact_state(
            self.runtime.semantic.read_all(), case_id=session["case_id"]
        )
        artifact = artifacts.get(artifact_id)
        if artifact is None or version_id not in artifact["versions"]:
            raise self._artifact_error("artifact version does not exist in this case")
        return artifact["versions"][version_id]

    def _session_events(self, session_id: str) -> list[dict[str, Any]]:
        events = [
            event
            for event in self.runtime.semantic.read_all()
            if event.get("session_id") == session_id
        ]
        if not events:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        "$session_id",
                        "session has no canonical events",
                    )
                ]
            )
        return events

    @staticmethod
    def _artifact_error(message: str) -> ValidationError:
        return ValidationError(
            [Issue(ErrorCode.ARTIFACT_REFERENCE_INVALID, "$artifact", message)]
        )


def _forbidden_checkpoint_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in FORBIDDEN_CHECKPOINT_KEYS:
                found.add(key)
            found.update(_forbidden_checkpoint_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_forbidden_checkpoint_keys(item))
    return found


def _add_request_binding(
    record: dict[str, Any],
    *,
    request_id: str | None,
    idempotency_key: str | None,
    request_sha256: str | None,
) -> None:
    """Attach an all-or-nothing S3 request binding without changing legacy records."""

    values = (request_id, idempotency_key, request_sha256)
    if all(value is None for value in values):
        return
    if any(value is None for value in values):
        raise ValueError("request binding requires request ID, idempotency key, and digest")
    record.update(
        {
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "request_sha256": request_sha256,
        }
    )


def _durable_create_if_absent(path: Path, data: bytes) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError("content-addressed artifact collision")
        return False
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short artifact object write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True
