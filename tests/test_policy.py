"""Unit tests for exact-scope approvals and path policy."""

from __future__ import annotations

import unittest
from datetime import timedelta

from vault_next.ids import validate_id
from vault_next.policy import Approval, PolicyEngine, Proposal
from tests.helpers import Harness


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_matching_approval_allows_protected_proposal(self) -> None:
        proposal = Proposal(
            operation_class="promote",
            targets=(str(self.harness.runtime_root / "knowledge" / "item.md"),),
            consequence_class="durable_knowledge_promotion",
            actor_id="runtime",
        ).finalized()
        approval_id = self.harness.ids.new("approval")
        validate_id(approval_id, "approval")
        approval = Approval(
            approval_id,
            proposal.proposal_digest,
            proposal.targets,
            proposal.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(hours=1),
            "owner",
        )
        with_ref = Proposal(**{**proposal.__dict__, "approval_ref": approval_id})
        result = self.harness.policy.evaluate(
            with_ref,
            approvals={approval_id: approval},
            now=self.harness.current,
        )
        self.assertEqual(result.result, "allow")
        self.harness.schemas.require("approval", approval.to_record())

    def test_protected_path_is_denied_even_when_local_operation(self) -> None:
        proposal = Proposal(
            operation_class="write",
            targets=(str(self.harness.legacy_root / "do-not-write"),),
            consequence_class="ordinary",
            actor_id="runtime",
        ).finalized()
        result = self.harness.policy.evaluate(proposal, now=self.harness.current)
        self.assertEqual(result.result, "deny")
        self.assertEqual(result.reason_code, "PROTECTED_PATH_WRITE_DENIED")

    def test_approval_mismatch_revocation_and_expiry_all_fail_closed(self) -> None:
        engine = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            external_mode="requires_owner_approval",
        )
        proposal = Proposal(
            operation_class="transmit",
            targets=("https://synthetic.invalid/x",),
            consequence_class="consequential_action",
            actor_id="runtime",
        ).finalized()
        approval_id = self.harness.ids.new("approval")
        base = Approval(
            approval_id,
            proposal.proposal_digest,
            proposal.targets,
            proposal.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(hours=1),
            "owner",
        )
        with_ref = Proposal(**{**proposal.__dict__, "approval_ref": approval_id})
        variants = [
            Approval(**{**base.__dict__, "proposal_digest": "b" * 64}),
            Approval(**{**base.__dict__, "targets": ("https://synthetic.invalid/y",)}),
            Approval(**{**base.__dict__, "consequence_class": "different"}),
            Approval(**{**base.__dict__, "revoked": True}),
            Approval(**{**base.__dict__, "expires_at": self.harness.current}),
        ]
        expected = {
            "APPROVAL_DIGEST_MISMATCH",
            "APPROVAL_TARGET_MISMATCH",
            "APPROVAL_SCOPE_MISMATCH",
            "APPROVAL_REVOKED",
            "APPROVAL_EXPIRED",
        }
        actual = {
            engine.evaluate(
                with_ref,
                approvals={approval_id: variant},
                now=self.harness.current,
            ).reason_code
            for variant in variants
        }
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
