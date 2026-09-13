"""Synthetic hostile tests for the S1-C D2 versioned embedded work-batch commit."""

from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from tests.helpers import Harness
from vault_next.contracts import OwnerReceipt
from vault_next.errors import ErrorCode, ValidationError
from vault_next.policy import Approval
from vault_next.records import RUNTIME_ACTOR, build_event, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import build_current_work_view, fold_work_items
from vault_next.work_batches import (
    WorkBatchCoordinator,
    finalize_work_batch_proposal,
    policy_proposal_for_work_batch,
)


class WorkBatchTests(unittest.TestCase):
    """Every fixture is disposable and has invented identities only."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.harness.start()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id=self.harness.correlation_id,
        )
        self.coordinator = WorkBatchCoordinator(
            self.runtime, self.harness.policy, self.harness.schemas
        )

    def tearDown(self) -> None:
        self.harness.close()

    def _proposal(
        self,
        work_item_id: str,
        *,
        operation: str = "record",
        expected_revision: int = 0,
        idempotency_key: str = "synthetic-d2-idempotency",
        statement: str = "Invented D2 fixture work",
    ) -> dict:
        next_state = {
            "statement": statement,
            "status": "open" if operation == "record" else "in_progress",
            "source_kind": "owner_instruction",
            "priority": "normal",
            "due_on": None,
            "next_review_on": None,
            "blocker": None,
        }
        return finalize_work_batch_proposal(
            {
                "schema_version": "1.0",
                "batch_id": self.harness.ids.new("work_batch"),
                "request_id": self.harness.ids.new("request"),
                "idempotency_key": idempotency_key,
                "case_id": self.harness.case_id,
                "operations": [
                    {
                        "work_item_id": work_item_id,
                        "expected_revision": expected_revision,
                        "operation": operation,
                        "next_state": next_state,
                    }
                ],
                "proposal_digest": "",
                "expires_at": timestamp(self.harness.current + timedelta(minutes=5)),
            }
        )

    def _authority(self, proposal: dict) -> tuple[Approval, OwnerReceipt]:
        policy_proposal = policy_proposal_for_work_batch(proposal)
        approval = Approval(
            approval_id=self.harness.ids.new("approval"),
            proposal_digest=policy_proposal.proposal_digest,
            targets=policy_proposal.targets,
            consequence_class=policy_proposal.consequence_class,
            granted_at=self.harness.current,
            expires_at=self.harness.current + timedelta(minutes=5),
            owner_actor_id="synthetic-owner",
        )
        return approval, self.harness.issue_fixture_receipt(approval)

    def _record_legacy_work_item(self, work_item_id: str) -> None:
        self.harness.append(
            self.harness.candidate(
                "work_item.recorded",
                {
                    "work_item_id": work_item_id,
                    "statement": "Invented legacy work",
                    "status": "open",
                    "source_kind": "owner_instruction",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                    "explicit_confirmation": True,
                },
                session_id=self.harness.session_id,
                actor={"type": "owner", "id": "synthetic-owner"},
                subject_refs=[work_item_id],
            )
        )

    def test_commits_one_v2_event_and_upcasts_legacy_work_state(self) -> None:
        work_item_id = self.harness.ids.new("work_item")
        self._record_legacy_work_item(work_item_id)
        legacy = fold_work_items(self.runtime.semantic.read_all())
        self.assertEqual(legacy[work_item_id]["revision"], 1)

        proposal = self._proposal(
            work_item_id,
            operation="status_change",
            expected_revision=1,
            statement="Invented legacy work",
        )
        approval, owner_receipt = self._authority(proposal)
        receipt = self.coordinator.commit(
            proposal, approval=approval, owner_receipt=owner_receipt
        )

        events = self.runtime.semantic.read_all()
        event = events[-1]
        self.assertEqual(event["schema_version"], "2.0")
        self.assertEqual(event["event_type"], "work_batch.committed")
        self.assertEqual(event["payload"]["proposal"], proposal)
        self.assertEqual(receipt["committed_watermark"], event["integrity"]["event_sha256"])
        items = fold_work_items(events)
        self.assertEqual(items[work_item_id]["status"], "in_progress")
        self.assertEqual(items[work_item_id]["revision"], 2)

        current = build_current_work_view(
            events,
            as_of_date="2026-09-01",
            time_zone="UTC",
            minimum_watermark=receipt["committed_watermark"],
        )
        self.assertEqual(current["state"]["active_work_items"][0]["work_item_id"], work_item_id)
        with self.assertRaises(ValidationError) as caught:
            build_current_work_view(
                events,
                as_of_date="2026-09-01",
                time_zone="UTC",
                minimum_watermark="a" * 64,
            )
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.WORK_BATCH_WATERMARK_STALE)

        replay = self.coordinator.commit(proposal, approval=approval, owner_receipt=owner_receipt)
        self.assertEqual(replay, receipt)
        self.assertEqual(len(self.runtime.semantic.read_all()), len(events))

    def test_rejects_stale_revision_before_any_batch_event_is_visible(self) -> None:
        work_item_id = self.harness.ids.new("work_item")
        self._record_legacy_work_item(work_item_id)
        proposal = self._proposal(work_item_id, operation="status_change", expected_revision=7)
        approval, owner_receipt = self._authority(proposal)
        event_count = len(self.runtime.semantic.read_all())

        with self.assertRaises(ValidationError) as caught:
            self.coordinator.commit(proposal, approval=approval, owner_receipt=owner_receipt)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.WORK_ITEM_TRANSITION_INVALID)
        self.assertEqual(len(self.runtime.semantic.read_all()), event_count)

    def test_conflicting_idempotency_and_future_versions_fail_closed(self) -> None:
        first_work_item_id = self.harness.ids.new("work_item")
        proposal = self._proposal(first_work_item_id)
        approval, owner_receipt = self._authority(proposal)
        self.coordinator.commit(proposal, approval=approval, owner_receipt=owner_receipt)

        conflicting = self._proposal(
            self.harness.ids.new("work_item"), idempotency_key=proposal["idempotency_key"]
        )
        conflict_approval, conflict_receipt = self._authority(conflicting)
        with self.assertRaises(ValidationError) as caught:
            self.coordinator.commit(
                conflicting,
                approval=conflict_approval,
                owner_receipt=conflict_receipt,
            )
        self.assertEqual(
            caught.exception.issues[0].code, ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT
        )

        future = self.harness.candidate(
            "work_batch.committed",
            {},
            session_id=self.harness.session_id,
        )
        future["schema_version"] = "4.0"
        before = len(self.runtime.semantic.read_all())
        with self.assertRaises(ValidationError) as caught:
            self.harness.semantic.append(future)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.SCHEMA_VERSION_UNSUPPORTED)
        self.assertEqual(len(self.runtime.semantic.read_all()), before)

        incompatible = self._proposal(
            self.harness.ids.new("work_item"), idempotency_key="synthetic-too-new-reader"
        )
        incompatible_approval, incompatible_receipt = self._authority(incompatible)
        incompatible_candidate = build_event(
            event_type="work_batch.committed",
            case_id=self.harness.case_id,
            session_id=self.harness.session_id,
            payload={
                "proposal": incompatible,
                "owner_receipt": incompatible_receipt.to_record(),
                "work_receipt_id": self.harness.ids.new("receipt"),
                "request_id": incompatible["request_id"],
                "idempotency_key": incompatible["idempotency_key"],
                "compatibility": {
                    "minimum_semantic_schema_version": "2.0",
                    "minimum_reader_version": "0.5.0",
                },
            },
            actor=dict(RUNTIME_ACTOR),
            subject_refs=[incompatible["operations"][0]["work_item_id"]],
            correlation_id=self.harness.correlation_id,
            approval_ref=incompatible_approval.approval_id,
            schema_version="2.0",
            occurred_at=self.harness.tick(),
            recorded_at=self.harness.current,
            id_factory=self.harness.ids,
        )
        with self.assertRaises(ValidationError) as caught:
            self.harness.semantic.append(incompatible_candidate)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.WORK_BATCH_CONFLICT)
        self.assertEqual(len(self.runtime.semantic.read_all()), before)

    def test_receipt_must_bind_the_exact_work_batch_policy_proposal(self) -> None:
        proposal = self._proposal(self.harness.ids.new("work_item"))
        approval, owner_receipt = self._authority(proposal)
        forged = copy.copy(owner_receipt)
        forged = forged.__class__(
            forged.receipt_id,
            forged.authority_id,
            forged.approval_id,
            "f" * 64,
            forged.targets,
            forged.consequence_class,
            forged.issued_at,
            forged.expires_at,
        )
        self.harness.receipt_verifier.register(forged)
        with self.assertRaises(ValidationError) as caught:
            self.coordinator.commit(proposal, approval=approval, owner_receipt=forged)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.WORK_BATCH_CONFLICT)
        self.assertFalse(
            any(
                event["event_type"] == "work_batch.committed"
                for event in self.runtime.semantic.read_all()
            )
        )


if __name__ == "__main__":
    unittest.main()
