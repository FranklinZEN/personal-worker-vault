"""Synthetic-only Phase 5 semantic-review and degraded-mode acceptance checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import SCHEMA_ROOT
from vault_next.errors import ErrorCode, ValidationError
from vault_next.evaluation import EvaluationRegistry
from vault_next.fixtures import run_synthetic_phase5
from vault_next.ids import ULIDFactory
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry
from vault_next.review import (
    ReviewRepository,
    ReviewerUnavailable,
    SemanticReviewCoordinator,
    SemanticReviewWorkflow,
)
from vault_next.runtime import CaseSessionRuntime
from vault_next.validator import KernelValidator


class _Clock:
    def __init__(self) -> None:
        self.current = datetime(2026, 9, 3, 16, 0, tzinfo=UTC)

    def next(self) -> datetime:
        value = self.current
        self.current += timedelta(seconds=1)
        return value


class _HighFindingReviewer:
    reviewer_id = "synthetic-high-finding-reviewer"
    reviewer_version = "1.0"

    def review(self, packet: dict):
        return (
            "findings",
            "synthetic coherence failure",
            [
                {
                    "finding_id": "finding_synthetic_contradiction",
                    "severity": "high",
                    "source_event_ids": [packet["source_event_ids"][-1]],
                    "explanation": "Invented recommendation contradicts its declared support.",
                    "proposed_remediation": "Revise the synthetic recommendation and request a new review.",
                }
            ],
        )


class _UnavailableReviewer:
    reviewer_id = "synthetic-unavailable-reviewer"
    reviewer_version = "1.0"

    def review(self, packet: dict):
        raise ReviewerUnavailable()


class _PassingReviewer:
    reviewer_id = "synthetic-passing-reviewer"
    reviewer_version = "1.0"

    def review(self, packet: dict):
        return "pass", "synthetic rubric finds no blocking defect", []


class Phase5SemanticReviewAcceptanceTests(unittest.TestCase):
    """Exercise AT-016/017 without a model, tools, private data, or reviewer write authority."""

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-phase5-")
        self.root = Path(self.temporary.name)
        self.paths = RuntimePaths(self.root)
        self.paths.initialize()
        self.schemas = SchemaRegistry(SCHEMA_ROOT)
        self.clock = _Clock()
        self.ids = ULIDFactory(
            now_ms=lambda: int(self.clock.current.timestamp() * 1000),
            random_source=lambda length: bytes(range(length)),
        )
        self.runtime = CaseSessionRuntime(
            self.paths,
            self.schemas,
            id_factory=self.ids,
            clock=self.clock.next,
            correlation_id="synthetic-phase5-review",
        )
        coordinator = SemanticReviewCoordinator(
            ReviewRepository(self.paths, self.schemas),
            self.schemas,
            id_factory=self.ids,
            clock=self.clock.next,
        )
        self.workflow = SemanticReviewWorkflow(coordinator, self.runtime)
        case = self.runtime.create_case("Synthetic Phase 5 review proof")
        session = self.runtime.create_session(
            case["case_id"], "Which invented recommendation is internally coherent?"
        )
        self.session_id = session["session_id"]
        for status in ("routed", "authorized", "active"):
            self.runtime.transition_session(self.session_id, status, reason=f"synthetic {status}")
        recommendation = self.ids.new("recommendation")
        self.runtime.record_reasoning_event(
            self.session_id,
            "recommendation.issued",
            {
                "recommendation_id": recommendation,
                "revision": 1,
                "summary": "Use the invented option with contradictory support.",
            },
            subject_refs=[recommendation],
        )
        self.recommendation_id = recommendation

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_at_016_high_finding_blocks_finalization_without_reviewer_mutation(self) -> None:
        packet, packet_sha256 = self.workflow.request(
            self.session_id, target_type="recommendation", target_ref=self.recommendation_id
        )
        self.assertEqual(packet["policy"], {
            "tools_available": False,
            "write_authority": False,
            "approval_authority": False,
            "decision_authority": False,
        })
        review = self.workflow.run(
            self.session_id, packet, packet_sha256, _HighFindingReviewer(), attempt=1
        )
        self.assertEqual(review.result["status"], "findings")
        self.assertEqual(review.result["findings"][0]["severity"], "high")
        with self.assertRaises(ValidationError) as caught:
            self.runtime.record_owner_decision(self.session_id, "Choose invented option")
        self.assertTrue(any(issue.code == ErrorCode.REVIEW_REQUIRED_UNRESOLVED for issue in caught.exception.issues))
        self.assertEqual(self.runtime._session(self.session_id).status, "blocked")
        self.assertTrue(KernelValidator(self.paths, self.schemas).validate().passed)

    def test_at_017_unavailability_records_nonpass_then_retry_can_clear_same_hash(self) -> None:
        packet, packet_sha256 = self.workflow.request(
            self.session_id, target_type="recommendation", target_ref=self.recommendation_id
        )
        unavailable = self.workflow.run(
            self.session_id, packet, packet_sha256, _UnavailableReviewer(), attempt=1
        )
        self.assertEqual(unavailable.result["status"], "unavailable")
        self.assertEqual(unavailable.result["target_sha256"], packet["subject"]["target_sha256"])
        self.runtime.transition_session(self.session_id, "active", reason="reviewer retry available")
        self.runtime.transition_session(self.session_id, "review_pending", reason="retry existing exact review")
        retry = self.workflow.run(
            self.session_id, packet, packet_sha256, _PassingReviewer(), attempt=2
        )
        self.assertEqual(retry.result["status"], "pass")
        self.assertEqual(retry.result["target_sha256"], unavailable.result["target_sha256"])
        self.runtime.record_owner_decision(self.session_id, "Choose the synthetic reviewed option")
        self.runtime.close_session(self.session_id, disposition="decided", reason="review passed")
        self.assertTrue(KernelValidator(self.paths, self.schemas).validate().passed)

    def test_explicit_owner_waiver_clears_only_the_exact_finding_result(self) -> None:
        packet, packet_sha256 = self.workflow.request(
            self.session_id, target_type="recommendation", target_ref=self.recommendation_id
        )
        review = self.workflow.run(
            self.session_id, packet, packet_sha256, _HighFindingReviewer(), attempt=1
        )
        waiver, _ = self.workflow.coordinator.waive(
            review_id=packet["packet_id"],
            target_sha256=packet["subject"]["target_sha256"],
            result_sha256=review.result_sha256,
            finding_ids=["finding_synthetic_contradiction"],
            reason="Synthetic waiver exercises exact owner control.",
        )
        self.runtime.waive_semantic_review(
            self.session_id,
            waiver_id=waiver["waiver_id"],
            review_id=packet["packet_id"],
            target_sha256=packet["subject"]["target_sha256"],
            result_sha256=review.result_sha256,
            finding_ids=waiver["finding_ids"],
        )
        self.runtime.close_session(self.session_id, disposition="no_decision", reason="owner waived finding")
        self.assertTrue(KernelValidator(self.paths, self.schemas).validate().passed)

    def test_regression_run_and_baseline_change_require_reviewed_owner_record(self) -> None:
        registry = EvaluationRegistry(
            self.paths, self.schemas, id_factory=self.ids, clock=self.clock.next
        )
        run = registry.run(
            {"suite_id": "synthetic-p5-core", "suite_version": "1.0"},
            {
                "event-invariants": lambda: {"passed": True, "event_count": 6},
                "projections": lambda: {"passed": True, "projection_count": 0},
                "reviewer-rubric": lambda: {"passed": True, "rubric": "synthetic"},
                "routing": lambda: {"passed": True, "route": "dynamic"},
            },
        )
        with self.assertRaises(ValidationError) as caught:
            registry.establish_or_change_baseline(run, reviewed_change_record_sha256=None)
        self.assertTrue(
            any(
                issue.code == ErrorCode.REVIEW_BASELINE_CHANGE_UNREVIEWED
                for issue in caught.exception.issues
            )
        )
        baseline = registry.establish_or_change_baseline(
            run,
            reviewed_change_record_sha256="a" * 64,
            explicit_confirmation=True,
        )
        self.assertEqual(baseline["run_sha256"], run.sha256)

    def test_phase5_fixture_replays_question_to_outcome_and_review_deterministically(self) -> None:
        first = run_synthetic_phase5(self.root / "first", SCHEMA_ROOT)
        second = run_synthetic_phase5(self.root / "second", SCHEMA_ROOT)
        self.assertEqual(first.to_record(), second.to_record())
        self.assertTrue(first.review_result_sha256)


if __name__ == "__main__":
    unittest.main()
