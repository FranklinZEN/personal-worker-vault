"""Executable Phase 1 acceptance scenarios from AT-007 through AT-021 subsets."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import timedelta
from pathlib import Path

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.contracts import OwnerReceipt
from vault_next.dry_run import SyntheticSnapshotItem, plan_synthetic_dry_run
from vault_next.errors import ErrorCode, LedgerCorruptionError, ValidationError
from vault_next.fixtures import run_synthetic_session
from vault_next.policy import Approval, PolicyEngine, Proposal
from vault_next.projection import build_session_trace, write_session_trace
from vault_next.records import build_audit_record
from tests.helpers import Harness, SCHEMA_ROOT


def audit_policy(result: object) -> dict[str, object]:
    record = result.to_record()
    record.pop("schema_version")
    return record


def recovery_authorization(
    harness: Harness,
    partition: Path,
) -> tuple[Proposal, dict[str, Approval], dict[str, OwnerReceipt]]:
    base = harness.semantic.recovery_proposal(partition)
    approval_id = harness.ids.new("approval")
    approval = Approval(
        approval_id,
        base.proposal_digest,
        base.targets,
        base.consequence_class,
        harness.current,
        harness.current + timedelta(hours=1),
        "synthetic-owner",
    )
    proposal = Proposal(**{**base.__dict__, "approval_ref": approval_id})
    receipt = harness.issue_fixture_receipt(approval)
    return proposal, {approval_id: approval}, {approval_id: receipt}


class Phase1AcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_at_007_ambiguous_agreement_does_not_create_owner_decision(self) -> None:
        self.harness.start()
        recommendation_id = self.harness.ids.new("recommendation")
        self.harness.append(
            self.harness.candidate(
                "recommendation.issued",
                {"summary": "Synthetic recommendation"},
                session_id=self.harness.session_id,
                subject_refs=[recommendation_id],
            )
        )
        invalid_decision = self.harness.candidate(
            "owner_decision.recorded",
            {"language": "looks reasonable", "explicit_confirmation": False},
            session_id=self.harness.session_id,
            actor={"type": "runtime", "id": "runtime"},
            subject_refs=[self.harness.ids.new("decision")],
        )
        with self.assertRaises(ValidationError):
            self.harness.semantic.append(invalid_decision)
        invalid_closure = self.harness.candidate(
            "session.closed",
            {"disposition": "decided"},
            session_id=self.harness.session_id,
            subject_refs=[self.harness.session_id],
        )
        with self.assertRaises(ValidationError):
            self.harness.semantic.append(invalid_closure)
        self.harness.append(
            self.harness.candidate(
                "session.closed",
                {"disposition": "no_decision"},
                session_id=self.harness.session_id,
                subject_refs=[self.harness.session_id],
            )
        )
        projection = build_session_trace(
            self.harness.semantic.read_all(),
            self.harness.session_id,
            self.harness.schemas,
        )
        self.assertEqual(projection["owner_decision_refs"], [])
        self.assertEqual(projection["disposition"], "no_decision")

    def test_at_010_correction_appends_without_rewriting_original(self) -> None:
        self.harness.start()
        original = self.harness.append(
            self.harness.candidate(
                "question.recorded",
                {"observed_date": "2026-08-31", "question": "Invented?"},
                session_id=self.harness.session_id,
            )
        )
        partition = self.harness.semantic.partition_path(original["recorded_at"])
        original_line = partition.read_bytes().splitlines(keepends=True)[-1]
        correction = self.harness.candidate(
            "event.correction_recorded",
            {
                "corrected_values": {"payload.observed_date": "2026-09-01"},
                "corrects_event_id": original["event_id"],
            },
            session_id=self.harness.session_id,
            provenance=[{"ref": original["event_id"], "relation": "corrects"}],
        )
        self.harness.append(correction)
        self.assertIn(original_line, partition.read_bytes().splitlines(keepends=True))
        projection = build_session_trace(
            self.harness.semantic.read_all(),
            self.harness.session_id,
            self.harness.schemas,
        )
        trace = {item["event_id"]: item for item in projection["event_trace"]}
        self.assertEqual(
            trace[original["event_id"]]["effective_values"]["payload.observed_date"],
            "2026-09-01",
        )

    def test_at_012_denied_transmission_is_not_attempted_and_is_audited(self) -> None:
        proposal = Proposal(
            operation_class="transmit",
            targets=("https://synthetic.invalid/receiver",),
            consequence_class="consequential_action",
            actor_id="runtime",
            sensitivity="personal",
        ).finalized()
        result = self.harness.policy.evaluate(proposal, now=self.harness.current)
        self.assertEqual((result.result, result.reason_code), ("deny", "EXTERNAL_ACTION_DEFAULT_DENY"))
        audit = build_audit_record(
            operation_class="transmit",
            target_summary="synthetic external receiver",
            input_digest=proposal.proposal_digest,
            policy=audit_policy(result),
            attempt_status="not_attempted",
            result="denied",
            error_code=result.reason_code,
            attempted_at=self.harness.tick(),
            id_factory=self.harness.ids,
        )
        committed = self.harness.operational.append(audit)
        self.assertEqual(committed["attempt_status"], "not_attempted")
        self.assertEqual(committed["output_refs"], [])

    def test_at_013_approval_cannot_be_reused_for_changed_target_or_digest(self) -> None:
        policy = PolicyEngine(
            self.harness.paths,
            self.harness.schemas,
            external_mode="requires_owner_approval",
            receipt_verifier=self.harness.receipt_verifier,
        )
        proposal_a = Proposal(
            operation_class="transmit",
            targets=("https://synthetic.invalid/x",),
            consequence_class="consequential_action",
            actor_id="runtime",
        ).finalized()
        approval_id = self.harness.ids.new("approval")
        approval = Approval(
            approval_id,
            proposal_a.proposal_digest,
            proposal_a.targets,
            proposal_a.consequence_class,
            self.harness.current,
            self.harness.current + timedelta(hours=1),
            "owner",
        )
        approved_a = Proposal(**{**proposal_a.__dict__, "approval_ref": approval_id})
        receipt = self.harness.issue_fixture_receipt(approval)
        self.assertEqual(
            policy.evaluate(
                approved_a,
                approvals={approval_id: approval},
                receipts={approval_id: receipt},
                now=self.harness.current,
            ).result,
            "allow",
        )
        proposal_b = Proposal(
            operation_class="transmit",
            targets=("https://synthetic.invalid/y",),
            consequence_class="consequential_action",
            actor_id="runtime",
            approval_ref=approval_id,
        ).finalized()
        changed = policy.evaluate(
            proposal_b,
            approvals={approval_id: approval},
            now=self.harness.current,
        )
        self.assertEqual(changed.result, "requires_owner_approval")
        self.assertEqual(changed.reason_code, "APPROVAL_DIGEST_MISMATCH")

    def test_at_014_malformed_event_does_not_change_ledger_tail(self) -> None:
        self.harness.start()
        partition = next(self.harness.paths.semantic_root.glob("*.jsonl"))
        before = partition.read_bytes()
        malformed = self.harness.candidate(
            "question.recorded",
            {"question": "Malformed synthetic event"},
            session_id=self.harness.session_id,
            actor={"type": "alien", "id": "untrusted"},
            provenance=[{"ref": "event_00000000000000000000000000", "relation": "supports"}],
        )
        malformed.pop("approval_ref")
        with self.assertRaises(ValidationError) as caught:
            self.harness.semantic.append(malformed)
        codes = {issue.code for issue in caught.exception.issues}
        self.assertIn(ErrorCode.SCHEMA_ENUM, codes)
        self.assertIn(ErrorCode.SCHEMA_REQUIRED, codes)
        self.assertIn(ErrorCode.EVENT_REFERENCE_MISSING, codes)
        self.assertEqual(partition.read_bytes(), before)
        self.harness.append(
            self.harness.candidate(
                "question.recorded",
                {"question": "Valid synthetic event"},
                session_id=self.harness.session_id,
            )
        )
        self.assertGreater(len(partition.read_bytes()), len(before))

    def test_at_015_partial_tail_is_quarantined_and_valid_prefix_survives(self) -> None:
        self.harness.start()
        partition = next(self.harness.paths.semantic_root.glob("*.jsonl"))
        valid_prefix = partition.read_bytes()
        with partition.open("ab") as stream:
            stream.write(b'{"partial":')
            stream.flush()
        scan = self.harness.semantic.scan(partition)
        self.assertFalse(scan.is_valid)
        with self.assertRaises(LedgerCorruptionError):
            self.harness.semantic.read_all()
        proposal, approvals, receipts = recovery_authorization(self.harness, partition)
        recovery = self.harness.semantic.recover(
            partition,
            proposal=proposal,
            policy=self.harness.policy,
            approvals=approvals,
            receipts=receipts,
            now=self.harness.current,
        )
        self.assertTrue(recovery.recovered)
        self.assertEqual(partition.read_bytes(), valid_prefix)
        self.assertEqual(recovery.quarantine_path.read_bytes(), b'{"partial":')
        self.harness.append(
            self.harness.candidate(
                "question.recorded",
                {"question": "Append after recovery"},
                session_id=self.harness.session_id,
            )
        )

    def test_at_015_wrong_chain_hash_is_quarantined_from_last_valid_record(self) -> None:
        first, second = self.harness.start()
        partition = next(self.harness.paths.semantic_root.glob("*.jsonl"))
        lines = partition.read_bytes().splitlines(keepends=True)
        first_line = lines[0]
        tampered = copy.deepcopy(second)
        tampered["integrity"]["previous_event_sha256"] = "f" * 64
        tampered["integrity"]["event_sha256"] = "e" * 64
        partition.write_bytes(first_line + canonical_bytes(tampered) + b"\n")
        scan = self.harness.semantic.scan(partition)
        self.assertFalse(scan.is_valid)
        self.assertEqual(scan.valid_byte_count, len(first_line))
        proposal, approvals, receipts = recovery_authorization(self.harness, partition)
        recovery = self.harness.semantic.recover(
            partition,
            proposal=proposal,
            policy=self.harness.policy,
            approvals=approvals,
            receipts=receipts,
            now=self.harness.current,
        )
        self.assertTrue(recovery.recovered)
        self.assertEqual(partition.read_bytes(), first_line)
        self.assertEqual(recovery.quarantine_path.read_bytes(), canonical_bytes(tampered) + b"\n")

    def test_at_015_recovery_approval_is_invalid_after_tail_changes(self) -> None:
        self.harness.start()
        partition = next(self.harness.paths.semantic_root.glob("*.jsonl"))
        with partition.open("ab") as stream:
            stream.write(b'{"partial":')
            stream.flush()
        proposal, approvals, receipts = recovery_authorization(self.harness, partition)
        with partition.open("ab") as stream:
            stream.write(b"changed")
            stream.flush()
        with self.assertRaises(ValidationError) as caught:
            self.harness.semantic.recover(
                partition,
                proposal=proposal,
                policy=self.harness.policy,
                approvals=approvals,
                receipts=receipts,
                now=self.harness.current,
            )
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.APPROVAL_DIGEST_MISMATCH)

    def test_at_018_projection_rebuild_is_equal_and_tamper_is_quarantined(self) -> None:
        result = run_synthetic_session(self.harness.runtime_root, SCHEMA_ROOT)
        events = self.harness.semantic.read_all()
        projection_a = build_session_trace(events, result.session_id, self.harness.schemas)
        projection_b = build_session_trace(events, result.session_id, self.harness.schemas)
        self.assertEqual(canonical_bytes(projection_a), canonical_bytes(projection_b))
        semantic_hashes = {
            path: sha256_hex(path.read_bytes())
            for path in self.harness.paths.semantic_root.glob("*.jsonl")
        }
        result.projection_path.write_bytes(b'{"tampered":true}\n')
        write_result = write_session_trace(projection_b, self.harness.paths)
        self.assertEqual(write_result.findings[0].code, ErrorCode.PROJECTION_TAMPERED)
        self.assertEqual(json.loads(result.projection_path.read_text()), projection_b)
        self.assertEqual(
            semantic_hashes,
            {
                path: sha256_hex(path.read_bytes())
                for path in self.harness.paths.semantic_root.glob("*.jsonl")
            },
        )

    def test_at_019_operational_attempts_remain_out_of_semantic_projection(self) -> None:
        self.harness.start()
        action_id = self.harness.ids.new("action")
        action_event = self.harness.append(
            self.harness.candidate(
                "action.proposed",
                {"summary": "Invented local action"},
                session_id=self.harness.session_id,
                subject_refs=[action_id],
            )
        )
        local_proposal = Proposal(
            operation_class="write",
            targets=(str(self.harness.runtime_root / "synthetic-output"),),
            consequence_class="ordinary",
            actor_id="runtime",
        ).finalized()
        allow = self.harness.policy.evaluate(local_proposal, now=self.harness.current)
        deny = self.harness.policy.evaluate(
            Proposal(
                operation_class="transmit",
                targets=("https://synthetic.invalid",),
                consequence_class="consequential_action",
                actor_id="runtime",
            ).finalized(),
            now=self.harness.current,
        )
        states = [
            (deny, "not_attempted", "denied", "EXTERNAL_ACTION_DEFAULT_DENY"),
            (allow, "attempted", "failed", "SYNTHETIC_TOOL_FAILURE"),
            (allow, "attempted", "succeeded", None),
        ]
        for policy_result, attempted, result, error in states:
            candidate = build_audit_record(
                operation_class="write" if policy_result.result == "allow" else "transmit",
                target_summary="invented operation target",
                input_digest=canonical_sha256({"state": result}),
                policy=audit_policy(policy_result),
                attempt_status=attempted,
                result=result,
                case_id=self.harness.case_id,
                session_id=self.harness.session_id,
                action_id=action_id,
                semantic_event_refs=[action_event["event_id"]],
                error_code=error,
                attempted_at=self.harness.tick(),
                id_factory=self.harness.ids,
            )
            self.harness.operational.append(candidate)
        projection = build_session_trace(
            self.harness.semantic.read_all(),
            self.harness.session_id,
            self.harness.schemas,
        )
        self.assertEqual(projection["action_refs"], [action_id])
        self.assertNotIn("operation", json.dumps(projection))
        self.assertEqual(len(self.harness.operational.read_all()), 3)

    def test_at_020_synthetic_protected_trees_and_symlink_cannot_be_write_targets(self) -> None:
        source = self.harness.legacy_root / "source.txt"
        backup = self.harness.backup_root / "backup.txt"
        source.write_text("synthetic source", encoding="utf-8")
        backup.write_text("synthetic backup", encoding="utf-8")
        before = {path: (path.stat().st_size, sha256_hex(path.read_bytes())) for path in (source, backup)}
        for target in (source, backup):
            with self.assertRaises(ValidationError):
                self.harness.paths.ensure_runtime_write_target(target)
        link = self.harness.runtime_root / "synthetic-link"
        link.symlink_to(source)
        with self.assertRaises(ValidationError):
            self.harness.paths.ensure_runtime_write_target(link)
        after = {path: (path.stat().st_size, sha256_hex(path.read_bytes())) for path in (source, backup)}
        self.assertEqual(before, after)

    def test_at_021_synthetic_dry_run_is_stable_and_has_no_runtime_writes(self) -> None:
        items = [
            SyntheticSnapshotItem("b.txt", "b" * 64, 20),
            SyntheticSnapshotItem("a.txt", "a" * 64, 10),
        ]
        before = sorted(str(path) for path in self.harness.runtime_root.rglob("*"))
        first = plan_synthetic_dry_run(items)
        second = plan_synthetic_dry_run(copy.deepcopy(items))
        after = sorted(str(path) for path in self.harness.runtime_root.rglob("*"))
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertEqual([item["source"]["relative_path"] for item in first], ["a.txt", "b.txt"])


if __name__ == "__main__":
    unittest.main()
