"""S1-C synthetic-only contract and owner-receipt boundary tests."""

from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from tests.helpers import Harness
from vault_next.catalog import install_synthetic_catalog
from vault_next.contracts import (
    OwnerReceipt,
    ReceiptVerification,
    ReceiptVerificationStatus,
    function_contract_from_profile,
    finalize_work_change_proposal,
    require_adapter_capabilities,
    require_request_envelope,
    require_result_envelope,
    require_work_change_proposal,
    require_work_change_receipt,
)
from vault_next.errors import ErrorCode, ValidationError
from vault_next.packages import PackageRegistry
from vault_next.policy import Approval, PolicyEngine, Proposal
from vault_next.records import timestamp


class _FixtureReceiptVerifier:
    """A disposable test verifier; it is never an application authority or host proof."""

    def __init__(self, receipt_ids: set[str]) -> None:
        self.receipt_ids = receipt_ids

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        status = (
            ReceiptVerificationStatus.VERIFIED
            if receipt.receipt_id in self.receipt_ids
            else ReceiptVerificationStatus.REJECTED
        )
        return ReceiptVerification(status, "synthetic-fixture-verifier")


class _WrongAuthorityFixtureVerifier:
    """Hostile test double that must not substitute a different verifier identity."""

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        return ReceiptVerification(ReceiptVerificationStatus.VERIFIED, "wrong-fixture-authority")


class SharedContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()

    def _protected_proposal(self) -> Proposal:
        return Proposal(
            operation_class="promote",
            targets=(str(self.harness.runtime_root / "invented" / "item.md"),),
            consequence_class="durable_knowledge_promotion",
            actor_id="runtime",
        ).finalized()

    def _approval_and_receipt(self) -> tuple[Proposal, Approval, OwnerReceipt]:
        proposal = self._protected_proposal()
        approval_id = self.harness.ids.new("approval")
        approval = Approval(
            approval_id,
            proposal.proposal_digest,
            proposal.targets,
            proposal.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(hours=1),
            "forged-owner-label-is-not-proof",
        )
        receipt = OwnerReceipt(
            self.harness.ids.new("receipt"),
            "synthetic-fixture-verifier",
            approval_id,
            proposal.proposal_digest,
            proposal.targets,
            proposal.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(hours=1),
        )
        return Proposal(**{**proposal.__dict__, "approval_ref": approval_id}), approval, receipt

    def test_c_t01_t05_actor_labels_forgery_stale_and_unavailable_receipts_fail_closed(self) -> None:
        proposal, approval, receipt = self._approval_and_receipt()
        approvals = {approval.approval_id: approval}
        engine = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            external_mode="requires_owner_approval",
        )
        no_receipt = engine.evaluate(proposal, approvals=approvals, now=self.harness.current)
        self.assertEqual(no_receipt.reason_code, "APPROVAL_RECEIPT_REQUIRED")
        unavailable = engine.evaluate(
            proposal,
            approvals=approvals,
            receipts={approval.approval_id: receipt},
            now=self.harness.current,
        )
        self.assertEqual(unavailable.reason_code, "APPROVAL_RECEIPT_UNAVAILABLE")
        fixture_engine = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            external_mode="requires_owner_approval",
            receipt_verifier=_FixtureReceiptVerifier({receipt.receipt_id}),
        )
        forged = OwnerReceipt(
            self.harness.ids.new("receipt"),
            receipt.authority_id,
            receipt.approval_id,
            receipt.proposal_digest,
            receipt.targets,
            receipt.consequence_class,
            receipt.issued_at,
            receipt.expires_at,
        )
        self.assertEqual(
            fixture_engine.evaluate(
                proposal,
                approvals=approvals,
                receipts={approval.approval_id: forged},
                now=self.harness.current,
            ).reason_code,
            "APPROVAL_RECEIPT_REJECTED",
        )
        stale = OwnerReceipt(
            receipt.receipt_id,
            receipt.authority_id,
            receipt.approval_id,
            receipt.proposal_digest,
            receipt.targets,
            receipt.consequence_class,
            receipt.issued_at,
            self.harness.current,
        )
        self.assertEqual(
            fixture_engine.evaluate(
                proposal,
                approvals=approvals,
                receipts={approval.approval_id: stale},
                now=self.harness.current,
            ).reason_code,
            "APPROVAL_RECEIPT_EXPIRED",
        )
        self.assertEqual(
            fixture_engine.evaluate(
                proposal,
                approvals=approvals,
                receipts={approval.approval_id: receipt},
                now=self.harness.current,
            ).result,
            "allow",
        )
        wrong_authority = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            external_mode="requires_owner_approval",
            receipt_verifier=_WrongAuthorityFixtureVerifier(),
        )
        self.assertEqual(
            wrong_authority.evaluate(
                proposal,
                approvals=approvals,
                receipts={approval.approval_id: receipt},
                now=self.harness.current,
            ).reason_code,
            "APPROVAL_RECEIPT_AUTHORITY_MISMATCH",
        )

    def test_c_t02_exact_digest_and_target_binding_survives_receipt_verification(self) -> None:
        proposal, approval, receipt = self._approval_and_receipt()
        changed = Proposal(
            operation_class="promote",
            targets=(str(self.harness.runtime_root / "invented" / "other.md"),),
            consequence_class="durable_knowledge_promotion",
            actor_id="runtime",
            approval_ref=approval.approval_id,
        ).finalized()
        engine = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            receipt_verifier=_FixtureReceiptVerifier({receipt.receipt_id}),
        )
        result = engine.evaluate(
            changed,
            approvals={approval.approval_id: approval},
            receipts={approval.approval_id: receipt},
            now=self.harness.current,
        )
        self.assertEqual(result.reason_code, "APPROVAL_DIGEST_MISMATCH")
        self.assertNotEqual(changed.proposal_digest, proposal.proposal_digest)

    def test_c_t06_t09_profile_embeds_one_direct_entry_function_contract(self) -> None:
        registry = PackageRegistry(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
        )
        install_synthetic_catalog(registry)
        profile, _ = registry.resolve_version("profile", "profile_deep_dive", "1.0.0")
        self.assertIsNone(function_contract_from_profile(profile, self.harness.schemas))
        declared = copy.deepcopy(profile)
        declared["config"]["function_contract"] = {
            "function_id": "function_deep_dive",
            "direct_entry": True,
            "required_inputs": ["topic"],
            "defaults": {"depth": "standard"},
            "allowed_effects": ["read", "propose"],
            "completion_outcomes": ["answered", "paused", "unavailable"],
            "dependencies": [],
            "readiness_capabilities": ["scoped_context"],
            "acceptance_ids": ["MF-01", "MF-12"],
        }
        contract = function_contract_from_profile(declared, self.harness.schemas)
        assert contract is not None
        self.assertEqual(contract["profile_package_id"], "profile_deep_dive")
        self.assertTrue(contract["direct_entry"])
        invalid = copy.deepcopy(declared)
        invalid["config"]["function_contract"]["direct_entry"] = False
        with self.assertRaises(ValidationError):
            function_contract_from_profile(invalid, self.harness.schemas)

    def test_c_t10_t14_request_result_and_adapter_contracts_are_bounded_and_truthful(self) -> None:
        request = {
            "schema_version": "1.0",
            "request_id": self.harness.ids.new("request"),
            "idempotency_key": "invented-request-1",
            "intent": "Inspect only invented current work",
            "function_ids": ["function_status"],
            "mode": "read",
            "owner_receipt_ref": None,
            "target_refs": [self.harness.case_id],
            "target_versions": [{"ref": self.harness.case_id, "digest": "a" * 64}],
            "policy_version": "1.0",
            "capability_version": "1.0",
        }
        require_request_envelope(request, self.harness.schemas)
        unapproved_apply = copy.deepcopy(request)
        unapproved_apply["mode"] = "apply"
        with self.assertRaises(ValidationError):
            require_request_envelope(unapproved_apply, self.harness.schemas)
        complete = {
            "schema_version": "1.0",
            "request_id": request["request_id"],
            "status": "complete",
            "function_results": [{"function_id": "function_status", "status": "complete"}],
            "receipt_ref": None,
            "committed_watermark": None,
            "pending_refs": [],
            "sources": ["synthetic-current-work"],
            "limits": [],
            "continuation_ref": None,
        }
        require_result_envelope(complete, self.harness.schemas, request=request)
        committed = copy.deepcopy(complete)
        committed.update(
            {
                "status": "committed",
                "receipt_ref": self.harness.ids.new("receipt"),
                "committed_watermark": "b" * 64,
            }
        )
        require_result_envelope(committed, self.harness.schemas, request=request)
        false_commit = copy.deepcopy(committed)
        false_commit["committed_watermark"] = None
        with self.assertRaises(ValidationError) as caught:
            require_result_envelope(false_commit, self.harness.schemas, request=request)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.CONTRACT_SEMANTICS_INVALID)
        escaped_version = copy.deepcopy(request)
        escaped_version["target_versions"][0]["ref"] = "unbound-invented-target"
        with self.assertRaises(ValidationError):
            require_request_envelope(escaped_version, self.harness.schemas)
        unavailable_adapter = {
            "schema_version": "1.0",
            "adapter_id": "synthetic-unconfigured-adapter",
            "capability_version": "1.0",
            "direct_entry": True,
            "supported_function_ids": ["function_status"],
            "allowed_effects": ["read", "propose"],
            "owner_receipt_verification": "unavailable",
        }
        require_adapter_capabilities(unavailable_adapter, self.harness.schemas)
        inconsistent_adapter = copy.deepcopy(unavailable_adapter)
        inconsistent_adapter["owner_receipt_verification"] = "verified"
        with self.assertRaises(ValidationError):
            require_adapter_capabilities(inconsistent_adapter, self.harness.schemas)

    def test_c_t15_t19_work_proposals_and_receipts_never_overstate_commit_visibility(self) -> None:
        work_item_id = self.harness.ids.new("work_item")
        proposal = {
            "schema_version": "1.0",
            "batch_id": self.harness.ids.new("work_batch"),
            "request_id": self.harness.ids.new("request"),
            "idempotency_key": "synthetic-contract-idempotency-key",
            "case_id": self.harness.case_id,
            "operations": [
                {
                    "work_item_id": work_item_id,
                    "expected_revision": 1,
                    "operation": "status_change",
                    "next_state": {
                        "statement": "Invented work item",
                        "status": "open",
                        "source_kind": "owner_instruction",
                        "priority": "normal",
                        "due_on": None,
                        "next_review_on": None,
                        "blocker": None,
                    },
                }
            ],
            "proposal_digest": "",
            "expires_at": timestamp(self.harness.current + timedelta(minutes=5)),
        }
        proposal = finalize_work_change_proposal(proposal)
        require_work_change_proposal(proposal, self.harness.schemas)
        duplicate = copy.deepcopy(proposal)
        duplicate["operations"].append(
            {
                "work_item_id": work_item_id,
                "expected_revision": 2,
                "operation": "status_change",
                "next_state": {
                    "statement": "Invented work item",
                    "status": "in_progress",
                    "source_kind": "owner_instruction",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                },
            }
        )
        with self.assertRaises(ValidationError):
            require_work_change_proposal(duplicate, self.harness.schemas)
        stale = copy.deepcopy(proposal)
        stale["operations"][0]["expected_revision"] = 0
        with self.assertRaises(ValidationError):
            require_work_change_proposal(stale, self.harness.schemas)
        record = copy.deepcopy(proposal)
        record["operations"] = [
            {
                "work_item_id": work_item_id,
                "expected_revision": 0,
                "operation": "record",
                "next_state": {
                    "statement": "Invented work item",
                    "status": "open",
                    "source_kind": "owner_instruction",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                },
            }
        ]
        record = finalize_work_change_proposal(record)
        require_work_change_proposal(record, self.harness.schemas)
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "batch_id": proposal["batch_id"],
            "proposal_digest": proposal["proposal_digest"],
            "status": "committed",
            "committed_watermark": "d" * 64,
            "owner_receipt_ref": self.harness.ids.new("receipt"),
        }
        require_work_change_receipt(receipt, self.harness.schemas)
        pending = copy.deepcopy(receipt)
        pending["status"] = "pending"
        with self.assertRaises(ValidationError):
            require_work_change_receipt(pending, self.harness.schemas)


if __name__ == "__main__":
    unittest.main()
