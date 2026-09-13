"""Bounded S1-C request, function, receipt, and work-change contracts.

These value objects deliberately do not append canonical events. A real host verifier and the
versioned canonical batch event are separate, explicitly gated work.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.records import SchemaRegistry, timestamp


class ReceiptVerificationStatus(StrEnum):
    """The only results a host-facing receipt verifier may report."""

    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"
    VERIFIED = "verified"


@dataclass(frozen=True)
class ReceiptVerification:
    """A verifier's bounded response, separate from owner attribution."""

    status: ReceiptVerificationStatus
    authority_id: str


@dataclass(frozen=True)
class OwnerReceipt:
    """An exact receipt envelope that still needs an external verifier to be trusted."""

    receipt_id: str
    authority_id: str
    approval_id: str
    proposal_digest: str
    targets: tuple[str, ...]
    consequence_class: str
    issued_at: datetime
    expires_at: datetime | None

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "receipt_id": self.receipt_id,
            "authority_id": self.authority_id,
            "approval_id": self.approval_id,
            "proposal_digest": self.proposal_digest,
            "targets": list(self.targets),
            "consequence_class": self.consequence_class,
            "issued_at": timestamp(self.issued_at),
            "expires_at": timestamp(self.expires_at) if self.expires_at else None,
        }


class OwnerReceiptVerifier(Protocol):
    """A selected host authority verifies a receipt; an actor label never does."""

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification: ...


class UnavailableReceiptVerifier:
    """Fail closed until S1-D establishes a real, owner-approved host verifier."""

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        return ReceiptVerification(ReceiptVerificationStatus.UNAVAILABLE, "unavailable")


def function_contract_from_profile(
    profile: dict[str, Any], schemas: SchemaRegistry
) -> dict[str, Any] | None:
    """Return the governed function metadata embedded in a profile, if it is declared."""

    schemas.require("profile-package", profile)
    declared = profile["config"].get("function_contract")
    if declared is None:
        return None
    contract = {
        "schema_version": "1.0",
        "profile_package_id": profile["package_id"],
        "profile_version": profile["version"],
        **declared,
    }
    schemas.require("function-contract", contract)
    return contract


def require_adapter_capabilities(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate an adapter declaration without claiming an adapter is configured."""

    schemas.require("adapter-capabilities", record)
    if record["owner_receipt_verification"] == "verified" and "commit" not in record[
        "allowed_effects"
    ]:
        raise _contract_error(
            "$/allowed_effects",
            "verified owner receipts require an explicitly declared commit effect",
        )


def require_request_envelope(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate one bounded request before it reaches a host or core adapter."""

    schemas.require("request-envelope", record)
    target_refs = set(record["target_refs"])
    version_refs = [item["ref"] for item in record["target_versions"]]
    if len(version_refs) != len(set(version_refs)):
        raise _contract_error("$/target_versions", "target versions must name each ref once")
    if not set(version_refs).issubset(target_refs):
        raise _contract_error(
            "$/target_versions", "every target version must bind a declared target reference"
        )
    if record["mode"] == "apply" and record["owner_receipt_ref"] is None:
        raise _contract_error(
            "$/owner_receipt_ref", "an apply request requires an exact owner receipt reference"
        )
    if record["mode"] != "apply" and record["owner_receipt_ref"] is not None:
        raise _contract_error(
            "$/owner_receipt_ref", "only an apply request may carry an owner receipt reference"
        )


def require_result_envelope(
    record: dict[str, Any],
    schemas: SchemaRegistry,
    *,
    request: dict[str, Any] | None = None,
) -> None:
    """Validate truthful result visibility, optionally against its exact request."""

    schemas.require("result-envelope", record)
    if request is not None:
        require_request_envelope(request, schemas)
        if record["request_id"] != request["request_id"]:
            raise _contract_error("$/request_id", "result must bind the supplied request")
        actual = {item["function_id"] for item in record["function_results"]}
        expected = set(request["function_ids"])
        if actual != expected:
            raise _contract_error(
                "$/function_results", "result must report exactly the requested functions"
            )
    status = record["status"]
    has_commit = record["receipt_ref"] is not None or record["committed_watermark"] is not None
    if status == "committed":
        if record["receipt_ref"] is None or record["committed_watermark"] in {None, "GENESIS"}:
            raise _contract_error(
                "$/committed_watermark", "a committed result requires a non-genesis receipt watermark"
            )
        if record["pending_refs"]:
            raise _contract_error("$/pending_refs", "a committed result cannot retain pending refs")
    elif has_commit:
        raise _contract_error(
            "$/receipt_ref", "only a committed result may claim a receipt or watermark"
        )
    if status == "pending" and not record["pending_refs"]:
        raise _contract_error("$/pending_refs", "a pending result requires pending references")
    if status != "pending" and record["pending_refs"]:
        raise _contract_error("$/pending_refs", "only a pending result may contain pending references")


def require_work_change_proposal(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate proposal-time revision and target binding without committing it."""

    schemas.require("work-change-proposal", record)
    work_item_ids = [item["work_item_id"] for item in record["operations"]]
    if len(work_item_ids) != len(set(work_item_ids)):
        raise _contract_error("$/operations", "a batch may name a work item only once")
    invalid_revisions = [
        item
        for item in record["operations"]
        if (item["operation"] == "record" and item["expected_revision"] != 0)
        or (item["operation"] == "status_change" and item["expected_revision"] < 1)
    ]
    if invalid_revisions:
        raise _contract_error(
            "$/operations", "record operations require revision zero; status changes require positive revisions"
        )
    expected_digest = canonical_sha256({**record, "proposal_digest": ""})
    if record["proposal_digest"] != expected_digest:
        raise _contract_error(
            "$/proposal_digest", "proposal digest must bind the complete operation state"
        )


def finalize_work_change_proposal(record: dict[str, Any]) -> dict[str, Any]:
    """Return a complete immutable proposal whose digest binds every intended work state."""

    finalized = {**record, "proposal_digest": ""}
    return {**finalized, "proposal_digest": canonical_sha256(finalized)}


def require_work_change_receipt(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate transaction visibility without asserting that a transaction was implemented."""

    schemas.require("work-change-receipt", record)
    committed = record["status"] == "committed"
    watermark = record["committed_watermark"]
    if committed and (watermark in {None, "GENESIS"} or record["owner_receipt_ref"] is None):
        raise _contract_error(
            "$/committed_watermark", "a committed work receipt requires an owner receipt and non-genesis watermark"
        )
    if not committed and (watermark is not None or record["owner_receipt_ref"] is not None):
        raise _contract_error(
            "$/committed_watermark", "only a committed work receipt may carry owner authority or a watermark"
        )


def require_work_transaction_manifest(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate one immutable v3 manifest before confirmation or canonical commit."""

    schemas.require("work-transaction-manifest", record, schema_version="3.0")
    operations = record["operations"]
    if len(operations) > 100 or len(record["affected_case_ids"]) > 50:
        raise _contract_error(
            "$/operations", "transaction exceeds the bounded operation or affected-case limit"
        )
    operation_keys = [(item["case_id"], item["work_item_id"]) for item in operations]
    work_item_ids = [item["work_item_id"] for item in operations]
    expected_cases = sorted({item["case_id"] for item in operations})
    expected_operations = sorted(
        operations, key=lambda item: (item["case_id"], item["work_item_id"])
    )
    if len(operation_keys) != len(set(operation_keys)) or len(work_item_ids) != len(
        set(work_item_ids)
    ):
        raise _contract_error("$/operations", "a transaction may name a work item only once")
    if operations != expected_operations:
        raise _contract_error(
            "$/operations", "transaction operations must use canonical case and work-item order"
        )
    if record["affected_case_ids"] != expected_cases:
        raise _contract_error(
            "$/affected_case_ids",
            "affected cases must exactly match the sorted operation case IDs",
        )
    invalid_revisions = [
        item
        for item in operations
        if (item["operation"] == "record" and item["expected_revision"] != 0)
        or (item["operation"] == "status_change" and item["expected_revision"] < 1)
    ]
    if invalid_revisions:
        raise _contract_error(
            "$/operations",
            "record operations require revision zero; status changes require positive revisions",
        )
    expected_digest = canonical_sha256({**record, "manifest_digest": ""})
    if record["manifest_digest"] != expected_digest:
        raise _contract_error(
            "$/manifest_digest", "manifest digest must bind every case, session, operation, and selection"
        )


def finalize_work_transaction_manifest(record: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize and bind a v3 global transaction before local confirmation."""

    operations = sorted(
        (dict(operation) for operation in record["operations"]),
        key=lambda item: (item["case_id"], item["work_item_id"]),
    )
    finalized = {
        **record,
        "operations": operations,
        "affected_case_ids": sorted({item["case_id"] for item in operations}),
        "manifest_digest": "",
    }
    return {**finalized, "manifest_digest": canonical_sha256(finalized)}


def work_transaction_targets(record: dict[str, Any]) -> tuple[str, ...]:
    """Return the one exact policy target set for a valid global transaction."""

    return tuple(sorted(item["work_item_id"] for item in record["operations"]))


def work_transaction_source_ref(record: dict[str, Any]) -> str:
    """Return the immutable manifest reference that a receipt must authorize."""

    return f"work_transaction:{record['manifest_digest']}"


def require_work_transaction_receipt(record: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate a v3 receipt that represents one visible global event."""

    schemas.require("work-transaction-receipt", record, schema_version="3.0")


def _contract_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
