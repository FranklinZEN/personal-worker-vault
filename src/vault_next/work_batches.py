"""Single-ledger commitment of exact owner-authorized work batches.

This module is deliberately core-only: it knows no connector or external authority.  Callers
must supply an approval plus a receipt that the configured policy verifier accepts.  The
semantic ledger is the sole durable commit point and returns the watermark used by readers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from vault_next.contracts import (
    OwnerReceipt,
    finalize_work_change_proposal,
    require_work_change_proposal,
    require_work_change_receipt,
)
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.policy import Approval, PolicyEngine, Proposal
from vault_next.records import RUNTIME_ACTOR, SchemaRegistry
from vault_next.runtime import CaseSessionRuntime


class WorkBatchCoordinator:
    """Commit a complete work proposal only after exact policy receipt verification."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        policy: PolicyEngine,
        schemas: SchemaRegistry,
    ) -> None:
        self.runtime = runtime
        self.policy = policy
        self.schemas = schemas

    def commit(
        self,
        proposal: dict[str, Any],
        *,
        approval: Approval,
        owner_receipt: OwnerReceipt,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Append one validated v2 event or return its exact prior idempotent receipt."""

        require_work_change_proposal(proposal, self.schemas)
        instant = now or self.runtime.clock()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        if _parse_timestamp(proposal["expires_at"]) <= instant.astimezone(UTC):
            raise _batch_error("$/expires_at", "work proposal is expired")

        if any(
            event["event_type"] == "work_transaction.committed"
            for event in self.runtime.semantic.read_all()
        ):
            raise _batch_error(
                "$/proposal",
                "legacy per-case work batches are fenced after a v3 global transaction",
            )

        existing = self._existing(proposal)
        if existing is not None:
            existing_payload = existing["payload"]
            if (
                existing_payload["proposal"]["proposal_digest"]
                == proposal["proposal_digest"]
                and existing_payload["request_id"] == proposal["request_id"]
                and existing_payload["idempotency_key"] == proposal["idempotency_key"]
                and existing_payload["owner_receipt"]["receipt_id"] == owner_receipt.receipt_id
            ):
                return self._receipt_from_event(existing)
            code = (
                ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT
                if existing_payload["idempotency_key"] == proposal["idempotency_key"]
                else ErrorCode.WORK_BATCH_CONFLICT
            )
            raise _batch_error(
                "$/proposal/batch_id",
                "batch ID or idempotency key is already bound to a different commitment",
                code=code,
            )

        targets = tuple(sorted(operation["work_item_id"] for operation in proposal["operations"]))
        policy_proposal = Proposal(
            operation_class="commit",
            targets=targets,
            consequence_class="owner_decision",
            actor_id=RUNTIME_ACTOR["id"],
            source_refs=(f"work_batch:{proposal['proposal_digest']}",),
            approval_ref=owner_receipt.approval_id,
        ).finalized()
        result = self.policy.evaluate(
            policy_proposal,
            approvals={approval.approval_id: approval},
            receipts={owner_receipt.approval_id: owner_receipt},
            now=instant,
        )
        if result.result != "allow":
            raise _batch_error(
                "$/owner_receipt",
                f"owner authority did not allow this exact work batch: {result.reason_code}",
            )

        work_receipt_id = self.runtime.ids.new("receipt")
        payload = {
            "proposal": proposal,
            "owner_receipt": owner_receipt.to_record(),
            "work_receipt_id": work_receipt_id,
            "request_id": proposal["request_id"],
            "idempotency_key": proposal["idempotency_key"],
            "compatibility": {
                "minimum_semantic_schema_version": "2.0",
                "minimum_reader_version": RUNTIME_ACTOR["id"].rsplit("/", maxsplit=1)[1],
            },
        }
        event = self.runtime._append(
            "work_batch.committed",
            proposal["case_id"],
            self._session_id(proposal["case_id"]),
            payload,
            subject_refs=list(targets),
            when=instant,
            actor=dict(RUNTIME_ACTOR),
            approval_ref=owner_receipt.approval_id,
            schema_version="2.0",
        )
        return self._receipt_from_event(event)

    def _existing(self, proposal: dict[str, Any]) -> dict[str, Any] | None:
        for event in self.runtime.semantic.read_all():
            if event["event_type"] != "work_batch.committed":
                continue
            existing = event["payload"]
            if (
                existing["proposal"]["batch_id"] == proposal["batch_id"]
                or existing["idempotency_key"] == proposal["idempotency_key"]
            ):
                return event
        return None

    def _session_id(self, case_id: str) -> str:
        sessions = [
            event["session_id"]
            for event in self.runtime.semantic.read_all()
            if event["case_id"] == case_id
            and event["event_type"] in {"session.created", "session.started"}
        ]
        if not sessions:
            raise _batch_error("$/case_id", "work batch requires an existing session")
        return sessions[-1]

    def _receipt_from_event(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = event["payload"]
        receipt = {
            "schema_version": "1.0",
            "receipt_id": payload["work_receipt_id"],
            "batch_id": payload["proposal"]["batch_id"],
            "proposal_digest": payload["proposal"]["proposal_digest"],
            "status": "committed",
            "committed_watermark": event["integrity"]["event_sha256"],
            "owner_receipt_ref": payload["owner_receipt"]["receipt_id"],
        }
        require_work_change_receipt(receipt, self.schemas)
        return receipt


def finalize_work_batch_proposal(record: dict[str, Any]) -> dict[str, Any]:
    """Public explicit finalizer for callers constructing disposable or production proposals."""

    return finalize_work_change_proposal(record)


def policy_proposal_for_work_batch(
    proposal: dict[str, Any], *, actor_id: str = RUNTIME_ACTOR["id"]
) -> Proposal:
    """Return the exact protected policy proposal a matching owner receipt must bind."""

    targets = tuple(sorted(operation["work_item_id"] for operation in proposal["operations"]))
    return Proposal(
        operation_class="commit",
        targets=targets,
        consequence_class="owner_decision",
        actor_id=actor_id,
        source_refs=(f"work_batch:{proposal['proposal_digest']}",),
    ).finalized()


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _batch_error(
    path: str, message: str, *, code: ErrorCode = ErrorCode.WORK_BATCH_CONFLICT
) -> ValidationError:
    return ValidationError([Issue(code, path, message)])
