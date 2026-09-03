"""Positive and negative authority checks for protected semantic event types."""

from __future__ import annotations

import unittest

from vault_next.errors import ValidationError
from vault_next.projection import build_session_trace
from tests.helpers import Harness


class ActorAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.harness.start()

    def tearDown(self) -> None:
        self.harness.close()

    def test_explicit_owner_decision_can_support_decided_closure(self) -> None:
        decision_id = self.harness.ids.new("decision")
        decision = self.harness.append(
            self.harness.candidate(
                "owner_decision.recorded",
                {"decision": "Choose invented option A", "explicit_confirmation": True},
                session_id=self.harness.session_id,
                actor={"type": "owner", "id": "synthetic-owner"},
                subject_refs=[decision_id],
            )
        )
        self.harness.append(
            self.harness.candidate(
                "session.closed",
                {"disposition": "decided"},
                session_id=self.harness.session_id,
                subject_refs=[self.harness.session_id],
            )
        )
        projection = build_session_trace(
            self.harness.semantic.read_all(),
            self.harness.session_id,
            self.harness.schemas,
        )
        self.assertEqual(projection["owner_decision_refs"], [decision_id])
        self.assertEqual(projection["disposition"], "decided")
        self.assertEqual(decision["actor"]["type"], "owner")

    def test_runtime_cannot_grant_approval_but_owner_can(self) -> None:
        approval_id = self.harness.ids.new("approval")
        payload = {"approval_id": approval_id, "proposal_digest": "a" * 64}
        invalid = self.harness.candidate(
            "approval.granted",
            payload,
            session_id=self.harness.session_id,
            actor={"type": "runtime", "id": "runtime"},
            subject_refs=[approval_id],
        )
        with self.assertRaises(ValidationError):
            self.harness.semantic.append(invalid)
        valid = self.harness.candidate(
            "approval.granted",
            payload,
            session_id=self.harness.session_id,
            actor={"type": "owner", "id": "synthetic-owner"},
            subject_refs=[approval_id],
        )
        self.harness.append(valid)


if __name__ == "__main__":
    unittest.main()

