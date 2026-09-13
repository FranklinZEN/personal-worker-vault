"""S2-A hostile synthetic tests for independent read/propose work functions."""

from __future__ import annotations

import copy
import unittest
from datetime import timedelta
from unittest.mock import patch

from tests.helpers import Harness
from vault_next.contracts import OwnerReceipt
from vault_next.errors import ValidationError
from vault_next.interaction import InteractionRuntime
from vault_next.policy import Approval
from vault_next.records import timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.status_updates import (
    FUNCTION_HISTORICAL_DIFF,
    FUNCTION_STATUS,
    FUNCTION_UPDATE,
    StatusUpdateCoordinator,
)
from vault_next.work_batches import (
    WorkBatchCoordinator,
    finalize_work_batch_proposal,
    policy_proposal_for_work_batch,
)


class StatusUpdateCoordinatorTests(unittest.TestCase):
    """All events, times, identities, and work statements are invented and disposable."""

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
        self.coordinator = StatusUpdateCoordinator(self.runtime, self.harness.schemas)

    def tearDown(self) -> None:
        self.harness.close()

    def _record_item(self, *, statement: str = "Invented S2 work", status: str = "open") -> str:
        work_item_id = self.harness.ids.new("work_item")
        self.harness.append(
            self.harness.candidate(
                "work_item.recorded",
                {
                    "work_item_id": work_item_id,
                    "statement": statement,
                    "status": status,
                    "source_kind": "owner_instruction",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                    "explicit_confirmation": True,
                },
                session_id=self.harness.session_id,
                actor={"type": "owner", "id": "invented-owner"},
                subject_refs=[work_item_id],
            )
        )
        return work_item_id

    def _query(self) -> dict:
        return {
            "schema_version": "1.0",
            "case_scope": [self.harness.case_id],
            "as_of_date": "2026-09-01",
            "time_zone": "UTC",
        }

    def _envelope(self, function_ids: list[str], mode: str, *, idempotency_key: str = "s2-test") -> dict:
        return {
            "schema_version": "1.0",
            "request_id": self.harness.ids.new("request"),
            "idempotency_key": idempotency_key,
            "intent": "Structured invented S2 request",
            "function_ids": function_ids,
            "mode": mode,
            "owner_receipt_ref": None,
            "target_refs": [self.harness.case_id],
            "target_versions": [],
            "policy_version": "1.0",
            "capability_version": "1.0",
        }

    def _status_request(self) -> dict:
        return {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_STATUS], "read"),
            "status_query": self._query(),
            "historical_diff_query": None,
            "pending_update": None,
        }

    def _pending_update(self, work_item_id: str, *, expected_revision: int = 1) -> dict:
        return {
            "schema_version": "1.0",
            "case_id": self.harness.case_id,
            "selection": {"kind": "direct_work_item", "work_item_id": work_item_id},
            "expected_revision": expected_revision,
            "next_state": {
                "statement": "Invented S2 work",
                "status": "in_progress",
                "source_kind": "owner_instruction",
                "priority": "normal",
                "due_on": None,
                "next_review_on": None,
                "blocker": None,
            },
            "expires_at": timestamp(self.harness.current + timedelta(minutes=5)),
        }

    def test_s2a_t01_fresh_status_is_read_only_and_has_an_exact_displayed_view(self) -> None:
        work_item_id = self._record_item()
        before = self.runtime.semantic.read_all()
        fresh_runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id="fresh-s2-status",
        )
        response = StatusUpdateCoordinator(fresh_runtime, self.harness.schemas).execute(
            self._status_request()
        )

        self.assertEqual(response["result"]["status"], "complete")
        self.assertEqual(response["result"]["committed_watermark"], None)
        assert response["status_view"] is not None
        self.assertEqual(response["status_view"]["active_items"][0]["work_item_id"], work_item_id)
        self.assertEqual(response["status_view"]["displayed_view"]["items"][0]["ordinal"], 1)
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s2a_t02_combined_status_and_pending_update_are_separate_and_idempotent(self) -> None:
        work_item_id = self._record_item()
        envelope = self._envelope([FUNCTION_STATUS, FUNCTION_UPDATE], "propose", idempotency_key="s2-pending")
        request = {
            "schema_version": "1.0",
            "request": envelope,
            "status_query": self._query(),
            "historical_diff_query": None,
            "pending_update": self._pending_update(work_item_id),
        }
        before = self.runtime.semantic.read_all()
        with patch.object(InteractionRuntime, "record_owner_work_item", side_effect=AssertionError), patch.object(
            InteractionRuntime, "change_work_item_status", side_effect=AssertionError
        ):
            first = self.coordinator.execute(request)
            second = self.coordinator.execute(request)

        self.assertEqual(first, second)
        self.assertEqual(first["result"]["status"], "pending")
        self.assertEqual(first["result"]["receipt_ref"], None)
        self.assertEqual(first["result"]["committed_watermark"], None)
        assert first["status_view"] is not None
        self.assertEqual(first["status_view"]["active_items"][0]["status"], "open")
        assert first["pending_work_proposal"] is not None
        proposal = first["pending_work_proposal"]["work_change_proposal"]
        self.assertEqual(proposal["operations"][0]["work_item_id"], work_item_id)
        self.assertEqual(proposal["operations"][0]["expected_revision"], 1)
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s2a_t03_historical_diff_uses_committed_baseline_not_pending_proposal(self) -> None:
        work_item_id = self._record_item()
        baseline = self.runtime.semantic.read_all()[-1]["integrity"]["event_sha256"]
        self.harness.append(
            self.harness.candidate(
                "work_item.status_changed",
                {
                    "work_item_id": work_item_id,
                    "from_status": "open",
                    "to_status": "done",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                    "reason": "Invented completion",
                    "explicit_confirmation": True,
                },
                session_id=self.harness.session_id,
                actor={"type": "owner", "id": "invented-owner"},
                subject_refs=[work_item_id],
            )
        )
        request = {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_HISTORICAL_DIFF], "read"),
            "status_query": None,
            "historical_diff_query": {
                **self._query(),
                "baseline": {"kind": "watermark", "watermark": baseline},
            },
            "pending_update": None,
        }
        response = self.coordinator.execute(request)

        self.assertEqual(response["result"]["status"], "complete")
        assert response["historical_diff"] is not None
        change = response["historical_diff"]["changes"][0]
        self.assertEqual(change["kind"], "changed")
        self.assertEqual(change["before"]["status"], "open")
        self.assertEqual(change["after"]["status"], "done")

    def test_s2a_t04_missing_scope_or_baseline_is_unavailable_without_a_write(self) -> None:
        self._record_item()
        before = self.runtime.semantic.read_all()
        missing_scope = self._status_request()
        missing_scope["status_query"]["case_scope"] = []
        missing_scope["request"]["target_refs"] = []
        status_response = self.coordinator.execute(missing_scope)
        self.assertEqual(status_response["result"]["status"], "unavailable")
        self.assertIsNone(status_response["status_view"])

        missing_baseline = {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_HISTORICAL_DIFF], "read"),
            "status_query": None,
            "historical_diff_query": {**self._query(), "baseline": None},
            "pending_update": None,
        }
        diff_response = self.coordinator.execute(missing_baseline)
        self.assertEqual(diff_response["result"]["status"], "unavailable")
        self.assertIsNone(diff_response["historical_diff"])
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s2a_t05_ordinal_binding_and_stale_revision_fail_before_pending_proposal(self) -> None:
        self._record_item(statement="Invented first work")
        second = self._record_item(statement="Invented second work")
        display = self.coordinator.execute(self._status_request())["status_view"]["displayed_view"]
        request = {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_UPDATE], "propose"),
            "status_query": None,
            "historical_diff_query": None,
            "pending_update": self._pending_update(second),
        }
        request["pending_update"]["selection"] = {
            "kind": "displayed_ordinal",
            "ordinal": 2,
            "displayed_view": display,
        }
        self.assertEqual(
            self.coordinator.execute(request)["pending_work_proposal"]["selection_binding"]["ordinal"], 2
        )
        before = self.runtime.semantic.read_all()
        malformed = copy.deepcopy(request)
        malformed["pending_update"]["selection"]["displayed_view"]["items"][1]["revision"] = 9
        with self.assertRaises(ValidationError):
            self.coordinator.execute(malformed)
        stale = copy.deepcopy(request)
        stale["pending_update"]["expected_revision"] = 2
        with self.assertRaises(ValidationError):
            self.coordinator.execute(stale)
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s2a_t06_apply_and_committed_idempotency_key_are_refused(self) -> None:
        work_item_id = self._record_item()
        apply = {
            "schema_version": "1.0",
            "request": {
                **self._envelope([FUNCTION_UPDATE], "apply"),
                "owner_receipt_ref": self.harness.ids.new("receipt"),
            },
            "status_query": None,
            "historical_diff_query": None,
            "pending_update": self._pending_update(work_item_id),
        }
        before = self.runtime.semantic.read_all()
        with self.assertRaises(ValidationError):
            self.coordinator.execute(apply)
        self.assertEqual(self.runtime.semantic.read_all(), before)

        committed_key = "already-committed-synthetic-key"
        self._commit_existing_update(work_item_id, committed_key)
        duplicate = {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_UPDATE], "propose", idempotency_key=committed_key),
            "status_query": None,
            "historical_diff_query": None,
            "pending_update": self._pending_update(work_item_id, expected_revision=2),
        }
        after_commit = self.runtime.semantic.read_all()
        with self.assertRaises(ValidationError):
            self.coordinator.execute(duplicate)
        self.assertEqual(self.runtime.semantic.read_all(), after_commit)

    def test_s2a_t07_scope_escape_unknown_target_and_invalid_timezone_fail_closed(self) -> None:
        self._record_item()
        before = self.runtime.semantic.read_all()
        escaped = self._status_request()
        escaped["request"]["target_refs"] = []
        with self.assertRaises(ValidationError):
            self.coordinator.execute(escaped)

        unknown = self._status_request()
        unknown_case = self.harness.ids.new("case")
        unknown["request"]["target_refs"] = [unknown_case]
        unknown["status_query"]["case_scope"] = [unknown_case]
        unknown_response = self.coordinator.execute(unknown)
        self.assertEqual(unknown_response["result"]["status"], "unavailable")

        invalid_timezone = self._status_request()
        invalid_timezone["status_query"]["time_zone"] = "Not/A_Time_Zone"
        with self.assertRaises(ValidationError):
            self.coordinator.execute(invalid_timezone)
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s2a_t08_date_baseline_resolves_to_committed_genesis_without_pending_confusion(self) -> None:
        work_item_id = self._record_item()
        request = {
            "schema_version": "1.0",
            "request": self._envelope([FUNCTION_HISTORICAL_DIFF], "read"),
            "status_query": None,
            "historical_diff_query": {
                **self._query(),
                "baseline": {"kind": "end_of_local_date", "as_of_date": "2026-08-31"},
            },
            "pending_update": None,
        }
        response = self.coordinator.execute(request)
        assert response["historical_diff"] is not None
        self.assertEqual(response["historical_diff"]["baseline_watermark"], "GENESIS")
        self.assertEqual(response["historical_diff"]["changes"][0]["kind"], "added")
        self.assertEqual(response["historical_diff"]["changes"][0]["work_item_id"], work_item_id)

    def _commit_existing_update(self, work_item_id: str, idempotency_key: str) -> None:
        proposal = finalize_work_batch_proposal(
            {
                "schema_version": "1.0",
                "batch_id": self.harness.ids.new("work_batch"),
                "request_id": self.harness.ids.new("request"),
                "idempotency_key": idempotency_key,
                "case_id": self.harness.case_id,
                "operations": [
                    {
                        "work_item_id": work_item_id,
                        "expected_revision": 1,
                        "operation": "status_change",
                        "next_state": {
                            "statement": "Invented S2 work",
                            "status": "in_progress",
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
        )
        policy_proposal = policy_proposal_for_work_batch(proposal)
        approval = Approval(
            self.harness.ids.new("approval"),
            policy_proposal.proposal_digest,
            policy_proposal.targets,
            policy_proposal.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(minutes=5),
            "invented-fixture-owner",
        )
        receipt: OwnerReceipt = self.harness.issue_fixture_receipt(approval)
        WorkBatchCoordinator(self.runtime, self.harness.policy, self.harness.schemas).commit(
            proposal, approval=approval, owner_receipt=receipt, now=self.harness.current
        )


if __name__ == "__main__":
    unittest.main()
