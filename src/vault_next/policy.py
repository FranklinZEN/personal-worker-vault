"""Typed proposal, exact-scope approval, and default-deny policy engine."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.contracts import (
    OwnerReceipt,
    OwnerReceiptVerifier,
    ReceiptVerificationStatus,
    UnavailableReceiptVerifier,
)
from vault_next.paths import RuntimePaths
from vault_next.records import SCHEMA_VERSION, SchemaRegistry, timestamp

PROTECTED_CONSEQUENCE_CLASSES = frozenset(
    {
        "consequential_action",
        "canonical_recovery",
        "durable_knowledge_promotion",
        "governance_change",
        "identity_change",
        "owner_decision",
        "package_activation",
        "permission_change",
    }
)


class PolicyReason(StrEnum):
    APPROVAL_DIGEST_MISMATCH = "APPROVAL_DIGEST_MISMATCH"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_REVOKED = "APPROVAL_REVOKED"
    APPROVAL_RECEIPT_EXPIRED = "APPROVAL_RECEIPT_EXPIRED"
    APPROVAL_RECEIPT_AUTHORITY_MISMATCH = "APPROVAL_RECEIPT_AUTHORITY_MISMATCH"
    APPROVAL_RECEIPT_MISMATCH = "APPROVAL_RECEIPT_MISMATCH"
    APPROVAL_RECEIPT_REJECTED = "APPROVAL_RECEIPT_REJECTED"
    APPROVAL_RECEIPT_REQUIRED = "APPROVAL_RECEIPT_REQUIRED"
    APPROVAL_RECEIPT_UNAVAILABLE = "APPROVAL_RECEIPT_UNAVAILABLE"
    APPROVAL_SCOPE_MISMATCH = "APPROVAL_SCOPE_MISMATCH"
    APPROVAL_TARGET_MISMATCH = "APPROVAL_TARGET_MISMATCH"
    EXACT_APPROVAL_MATCH = "EXACT_APPROVAL_MATCH"
    EXTERNAL_ACTION_DEFAULT_DENY = "EXTERNAL_ACTION_DEFAULT_DENY"
    LOCAL_UNPROTECTED_OPERATION = "LOCAL_UNPROTECTED_OPERATION"
    PATH_OUTSIDE_RUNTIME_ROOT = "PATH_OUTSIDE_RUNTIME_ROOT"
    PROTECTED_PATH_WRITE_DENIED = "PROTECTED_PATH_WRITE_DENIED"


@dataclass(frozen=True)
class Proposal:
    operation_class: str
    targets: tuple[str, ...]
    consequence_class: str
    actor_id: str
    sensitivity: str = "none"
    source_refs: tuple[str, ...] = ()
    approval_ref: str | None = None
    proposal_digest: str = ""

    def finalized(self) -> "Proposal":
        normalized = replace(
            self,
            targets=tuple(sorted(set(self.targets))),
            source_refs=tuple(sorted(set(self.source_refs))),
            proposal_digest="",
        )
        digest = canonical_sha256(normalized.digest_material())
        return replace(normalized, proposal_digest=digest)

    def digest_material(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "consequence_class": self.consequence_class,
            "operation_class": self.operation_class,
            "sensitivity": self.sensitivity,
            "source_refs": list(self.source_refs),
            "targets": list(self.targets),
        }

    def to_record(self) -> dict[str, Any]:
        proposal = self if self.proposal_digest else self.finalized()
        return {
            "schema_version": SCHEMA_VERSION,
            "operation_class": proposal.operation_class,
            "targets": list(proposal.targets),
            "consequence_class": proposal.consequence_class,
            "actor_id": proposal.actor_id,
            "sensitivity": proposal.sensitivity,
            "source_refs": list(proposal.source_refs),
            "approval_ref": proposal.approval_ref,
            "proposal_digest": proposal.proposal_digest,
        }


@dataclass(frozen=True)
class Approval:
    approval_id: str
    proposal_digest: str
    targets: tuple[str, ...]
    consequence_class: str
    granted_at: datetime
    expires_at: datetime | None
    owner_actor_id: str
    revoked: bool = False

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "approval_id": self.approval_id,
            "proposal_digest": self.proposal_digest,
            "targets": list(self.targets),
            "consequence_class": self.consequence_class,
            "granted_at": timestamp(self.granted_at),
            "expires_at": timestamp(self.expires_at) if self.expires_at else None,
            "revoked": self.revoked,
            "owner_actor_id": self.owner_actor_id,
        }


@dataclass(frozen=True)
class PolicyResult:
    result: str
    reason_code: PolicyReason
    approval_ref: str | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "result": self.result,
            "reason_code": self.reason_code,
            "approval_ref": self.approval_ref,
        }


class PolicyEngine:
    """Deterministic local policy evaluation with exact approval binding."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        external_mode: str = "deny",
        receipt_verifier: OwnerReceiptVerifier | None = None,
    ):
        if external_mode not in {"deny", "requires_owner_approval"}:
            raise ValueError("external_mode must be deny or requires_owner_approval")
        self.paths = paths
        self.schemas = schemas
        self.external_mode = external_mode
        self.receipt_verifier = receipt_verifier or UnavailableReceiptVerifier()

    def evaluate(
        self,
        proposal: Proposal,
        *,
        approvals: dict[str, Approval] | None = None,
        receipts: dict[str, OwnerReceipt] | None = None,
        now: datetime,
    ) -> PolicyResult:
        proposal = proposal if proposal.proposal_digest else proposal.finalized()
        self.schemas.require("policy-proposal", proposal.to_record())
        approvals = approvals or {}
        receipts = receipts or {}

        if proposal.operation_class in {"write", "promote", "delete", "execute"}:
            path_result = self._evaluate_local_targets(proposal.targets)
            if path_result is not None:
                return self._validated(path_result)

        if proposal.operation_class == "transmit" and self.external_mode == "deny":
            return self._validated(
                PolicyResult("deny", PolicyReason.EXTERNAL_ACTION_DEFAULT_DENY)
            )

        needs_approval = (
            proposal.operation_class in {"delete", "promote", "transmit"}
            or proposal.consequence_class in PROTECTED_CONSEQUENCE_CLASSES
        )
        if not needs_approval:
            return self._validated(
                PolicyResult("allow", PolicyReason.LOCAL_UNPROTECTED_OPERATION)
            )

        if proposal.approval_ref is None or proposal.approval_ref not in approvals:
            return self._validated(
                PolicyResult("requires_owner_approval", PolicyReason.APPROVAL_REQUIRED)
            )
        approval = approvals[proposal.approval_ref]
        self.schemas.require("approval", approval.to_record())
        reason = self._approval_mismatch(proposal, approval, now)
        if reason is not None:
            return self._validated(
                PolicyResult("requires_owner_approval", reason, approval.approval_id)
            )
        receipt_reason = self._receipt_mismatch(
            approval, proposal, receipts.get(approval.approval_id), now
        )
        if receipt_reason is not None:
            return self._validated(
                PolicyResult("requires_owner_approval", receipt_reason, approval.approval_id)
            )
        return self._validated(
            PolicyResult("allow", PolicyReason.EXACT_APPROVAL_MATCH, approval.approval_id)
        )

    def _evaluate_local_targets(self, targets: tuple[str, ...]) -> PolicyResult | None:
        for raw in targets:
            if not raw.startswith("/"):
                return PolicyResult("deny", PolicyReason.PATH_OUTSIDE_RUNTIME_ROOT)
            target = Path(raw).resolve()
            for protected in self.paths.protected_roots:
                try:
                    target.relative_to(protected)
                except ValueError:
                    continue
                return PolicyResult("deny", PolicyReason.PROTECTED_PATH_WRITE_DENIED)
            try:
                target.relative_to(self.paths.root)
            except ValueError:
                return PolicyResult("deny", PolicyReason.PATH_OUTSIDE_RUNTIME_ROOT)
        return None

    @staticmethod
    def _approval_mismatch(
        proposal: Proposal,
        approval: Approval,
        now: datetime,
    ) -> PolicyReason | None:
        if approval.revoked:
            return PolicyReason.APPROVAL_REVOKED
        if approval.expires_at is not None and now >= approval.expires_at:
            return PolicyReason.APPROVAL_EXPIRED
        if approval.proposal_digest != proposal.proposal_digest:
            return PolicyReason.APPROVAL_DIGEST_MISMATCH
        if tuple(approval.targets) != tuple(proposal.targets):
            return PolicyReason.APPROVAL_TARGET_MISMATCH
        if approval.consequence_class != proposal.consequence_class:
            return PolicyReason.APPROVAL_SCOPE_MISMATCH
        return None

    def _receipt_mismatch(
        self,
        approval: Approval,
        proposal: Proposal,
        receipt: OwnerReceipt | None,
        now: datetime,
    ) -> PolicyReason | None:
        if receipt is None:
            return PolicyReason.APPROVAL_RECEIPT_REQUIRED
        self.schemas.require("owner-receipt", receipt.to_record())
        if receipt.issued_at > now or receipt.issued_at < approval.granted_at:
            return PolicyReason.APPROVAL_RECEIPT_MISMATCH
        if receipt.expires_at is not None and now >= receipt.expires_at:
            return PolicyReason.APPROVAL_RECEIPT_EXPIRED
        if (
            receipt.approval_id != approval.approval_id
            or receipt.proposal_digest != proposal.proposal_digest
            or tuple(receipt.targets) != tuple(proposal.targets)
            or receipt.consequence_class != proposal.consequence_class
        ):
            return PolicyReason.APPROVAL_RECEIPT_MISMATCH
        verification = self.receipt_verifier.verify(receipt)
        if verification.status == ReceiptVerificationStatus.VERIFIED:
            if verification.authority_id != receipt.authority_id:
                return PolicyReason.APPROVAL_RECEIPT_AUTHORITY_MISMATCH
            return None
        if verification.status == ReceiptVerificationStatus.UNAVAILABLE:
            return PolicyReason.APPROVAL_RECEIPT_UNAVAILABLE
        return PolicyReason.APPROVAL_RECEIPT_REJECTED

    def _validated(self, result: PolicyResult) -> PolicyResult:
        self.schemas.require("policy-result", result.to_record())
        return result
