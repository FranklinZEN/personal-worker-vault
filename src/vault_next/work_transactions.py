"""One-event, all-or-nothing v3 work transaction coordinator.

Prepared manifests are noncanonical crash evidence.  Exactly one global v3 semantic event is the
only visibility point; its embedded immutable manifest is sufficient for replay if ancillary
prepared files disappear after a successful append.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from vault_next.canonical import canonical_bytes
from vault_next.contracts import (
    OwnerReceipt,
    require_work_transaction_manifest,
    require_work_transaction_receipt,
    work_transaction_targets,
)
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.policy import Approval, PolicyEngine, Proposal
from vault_next.records import RUNTIME_ACTOR, SchemaRegistry, build_event
from vault_next.runtime import CaseSessionRuntime
from vault_next.work_transaction_policy import policy_proposal_for_transaction


class WorkTransactionCoordinator:
    """Prepare and append exact v3 transactions through the one semantic writer lock."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        policy: PolicyEngine,
        schemas: SchemaRegistry,
    ) -> None:
        self.runtime = runtime
        self.policy = policy
        self.schemas = schemas

    def prepare(self, manifest: dict[str, Any]) -> Path:
        """Durably preserve a noncanonical exact manifest before confirmation."""

        require_work_transaction_manifest(manifest, self.schemas)
        prepared = {
            "schema_version": "3.0",
            "state": "prepared",
            "transaction_id": manifest["transaction_id"],
            "transaction_manifest": manifest,
            "transaction_manifest_digest": manifest["manifest_digest"],
        }
        path = self.prepared_path(manifest["transaction_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        _durable_immutable_create(path, canonical_bytes(prepared))
        return path

    def commit(
        self,
        manifest: dict[str, Any],
        *,
        approval: Approval,
        owner_receipt: OwnerReceipt,
        now: datetime | None = None,
        after_append: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Return the exact prior receipt or append one globally visible v3 transaction."""

        require_work_transaction_manifest(manifest, self.schemas)
        prior = self._matching(manifest, self.runtime.semantic.read_all(), owner_receipt)
        if prior is not None:
            receipt = self._receipt_from_event(prior)
            self._finalize(manifest, receipt)
            return receipt

        instant = now or self.runtime.clock()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        if _parse_timestamp(manifest["expires_at"]) <= instant.astimezone(UTC):
            raise _transaction_error("$/expires_at", "transaction manifest is expired")
        self._require_prepared(manifest)
        self._require_policy(manifest, approval, owner_receipt, instant)

        transaction_receipt_id = self.runtime.ids.new("receipt")
        payload = {
            "transaction_id": manifest["transaction_id"],
            "transaction_manifest": manifest,
            "transaction_manifest_digest": manifest["manifest_digest"],
            "affected_case_ids": manifest["affected_case_ids"],
            "owner_receipt": owner_receipt.to_record(),
            "transaction_receipt_id": transaction_receipt_id,
            "request_id": manifest["request_id"],
            "idempotency_key": manifest["idempotency_key"],
            "compatibility": manifest["compatibility"],
        }
        candidate = build_event(
            event_type="work_transaction.committed",
            case_id=None,
            session_id=None,
            payload=payload,
            actor=dict(RUNTIME_ACTOR),
            subject_refs=list(work_transaction_targets(manifest)),
            correlation_id=self.runtime.correlation_id,
            occurred_at=instant,
            recorded_at=instant,
            approval_ref=owner_receipt.approval_id,
            schema_version="3.0",
            id_factory=self.runtime.ids,
        )

        def revalidate(previous_records: list[dict[str, Any]]) -> dict[str, Any] | None:
            self._require_prepared(manifest)
            existing = self._matching(manifest, previous_records, owner_receipt)
            if existing is not None:
                return existing
            self._require_policy(manifest, approval, owner_receipt, instant)
            return None

        event = self.runtime.semantic.append_with_locked_revalidation(candidate, revalidate)
        receipt = self._receipt_from_event(event)
        if after_append is not None:
            after_append(event)
        self._finalize(manifest, receipt)
        return receipt

    def prepared_path(self, transaction_id: str) -> Path:
        """Return the sole noncanonical preparation path for one canonical transaction ID."""

        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "transactions" / transaction_id / "prepared.json"
        )

    def finalized_path(self, transaction_id: str) -> Path:
        """Return the immutable completion marker, separate from the prepared bytes."""

        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "transactions" / transaction_id / "finalized.json"
        )

    def _require_prepared(self, manifest: dict[str, Any]) -> None:
        path = self.prepared_path(manifest["transaction_id"])
        try:
            raw = _read_bytes(path)
            prepared = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise _transaction_error("$/transaction_id", "prepared transaction manifest is unavailable") from exc
        if not isinstance(prepared, dict) or canonical_bytes(prepared) != raw:
            raise _transaction_error("$/transaction_id", "prepared transaction manifest is not canonical")
        expected = {
            "schema_version": "3.0",
            "state": "prepared",
            "transaction_id": manifest["transaction_id"],
            "transaction_manifest": manifest,
            "transaction_manifest_digest": manifest["manifest_digest"],
        }
        if prepared != expected:
            raise _transaction_error(
                "$/transaction_manifest", "prepared transaction does not match the exact manifest"
            )

    def _require_policy(
        self,
        manifest: dict[str, Any],
        approval: Approval,
        owner_receipt: OwnerReceipt,
        instant: datetime,
    ) -> None:
        policy_proposal = _bound_policy_proposal(manifest, owner_receipt)
        result = self.policy.evaluate(
            policy_proposal,
            approvals={approval.approval_id: approval},
            receipts={owner_receipt.approval_id: owner_receipt},
            now=instant,
        )
        if result.result != "allow":
            raise _transaction_error(
                "$/owner_receipt",
                f"owner authority did not allow this exact work transaction: {result.reason_code}",
            )

    def _matching(
        self,
        manifest: dict[str, Any],
        events: list[dict[str, Any]],
        owner_receipt: OwnerReceipt,
    ) -> dict[str, Any] | None:
        """Return only an exact previous v3 commit; reject every overlapping identity."""

        for event in events:
            if event["event_type"] not in {
                "work_batch.committed",
                "work_transaction.committed",
            }:
                continue
            payload = event["payload"]
            matching_idempotency = payload.get("idempotency_key") == manifest["idempotency_key"]
            matching_request = payload.get("request_id") == manifest["request_id"]
            matching_transaction = (
                event["event_type"] == "work_transaction.committed"
                and payload.get("transaction_id") == manifest["transaction_id"]
            )
            if not (matching_idempotency or matching_request or matching_transaction):
                continue
            if (
                event["event_type"] == "work_transaction.committed"
                and payload.get("transaction_manifest") == manifest
                and payload.get("transaction_manifest_digest") == manifest["manifest_digest"]
                and payload.get("request_id") == manifest["request_id"]
                and payload.get("idempotency_key") == manifest["idempotency_key"]
                and payload.get("owner_receipt") == owner_receipt.to_record()
            ):
                return event
            code = (
                ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT
                if matching_idempotency or matching_request
                else ErrorCode.WORK_BATCH_CONFLICT
            )
            raise _transaction_error(
                "$/transaction_id",
                "transaction, request, or idempotency key is already bound to a different commitment",
                code=code,
            )
        return None

    def _finalize(self, manifest: dict[str, Any], receipt: dict[str, Any]) -> None:
        marker = {
            "schema_version": "3.0",
            "state": "finalized",
            "transaction_id": manifest["transaction_id"],
            "transaction_manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        path = self.finalized_path(manifest["transaction_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        _durable_immutable_create(path, canonical_bytes(marker))

    def _receipt_from_event(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = event["payload"]
        receipt = {
            "schema_version": "3.0",
            "receipt_id": payload["transaction_receipt_id"],
            "transaction_id": payload["transaction_id"],
            "manifest_digest": payload["transaction_manifest_digest"],
            "status": "committed",
            "committed_watermark": event["integrity"]["event_sha256"],
            "owner_receipt_ref": payload["owner_receipt"]["receipt_id"],
        }
        require_work_transaction_receipt(receipt, self.schemas)
        return receipt


def _bound_policy_proposal(manifest: dict[str, Any], owner_receipt: OwnerReceipt) -> Proposal:
    """Attach the supplied exact receipt reference without changing protected proposal material."""

    return policy_proposal_for_transaction(manifest, approval_ref=owner_receipt.approval_id)


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _transaction_error(
    path: str, message: str, *, code: ErrorCode = ErrorCode.WORK_BATCH_CONFLICT
) -> ValidationError:
    return ValidationError([Issue(code, path, message)])


def _read_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        while data := os.read(descriptor, 65536):
            chunks.append(data)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _durable_immutable_create(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if _read_bytes(path) != data:
            raise _transaction_error("$/transaction_id", "immutable transaction record differs")
        return
    try:
        written = os.write(descriptor, data)
        if written != len(data):
            raise OSError("short durable transaction write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
