"""Synthetic-only Phase 4 decision, case, artifact, and current-work projections."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness, SCHEMA_ROOT
from vault_next.canonical import canonical_bytes
from vault_next.errors import ErrorCode, ValidationError
from vault_next.fixtures import run_synthetic_phase4
from vault_next.readable_projections import (
    build_case_journal,
    build_current_work_view,
    build_decision_memo,
    write_markdown_projection,
)
from vault_next.validator import KernelValidator
from vault_next.records import build_event


class Phase4ProjectionAcceptanceTests(unittest.TestCase):
    """Verify P4 views remain derived, source-labelled, and non-authoritative."""

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-phase4-")
        self.root = Path(self.temporary.name)
        self.result = run_synthetic_phase4(self.root, SCHEMA_ROOT)
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()
        self.temporary.cleanup()

    def _path(self, *parts: str) -> Path:
        return self.root / "data" / "projections" / Path(*parts)

    def test_at_006_008_025_decision_memo_preserves_history_and_outcome_separation(self) -> None:
        memo = self._path("decision-memos", f"{self.result.case_id}.md").read_text()
        self.assertIn("## Original question", memo)
        self.assertIn("## Owner decision history and current disposition", memo)
        self.assertIn("Historical owner decision", memo)
        self.assertIn("revision 2, current", memo)
        self.assertIn("## Current outcome assessment", memo)
        self.assertIn("result quality mixed; process quality strong", memo)
        self.assertIn("competing explanation", memo)
        self.assertIn("Source watermark", memo)
        self.assertIn("source: event_", memo)
        self.assertTrue(KernelValidator(self._paths, self._schemas).validate().passed)

    def test_at_032_033_artifact_and_today_views_are_exact_and_non_mutating(self) -> None:
        artifact = self._path("artifacts", f"{self.result.artifact_id}.md").read_text()
        today = self._path("work", "today-2026-09-02-America-New_York.md").read_text()
        self.assertIn("## Version lineage", artifact)
        self.assertIn("## Feedback and review state", artifact)
        self.assertIn("## Exact acceptance", artifact)
        self.assertIn("Accepted version", artifact)
        self.assertIn("## Proposed work — not committed", today)
        self.assertIn("## Owner-committed work", today)
        self.assertIn("## Accepted artifacts awaiting an explicit next step", today)
        events_before = b"".join(
            path.read_bytes() for path in sorted(self._paths.semantic_root.glob("*.jsonl"))
        )
        build_current_work_view(
            self._semantic.read_all(),
            as_of_date="2026-09-02",
            time_zone="America/New_York",
            schemas=self._schemas,
        )
        events_after = b"".join(
            path.read_bytes() for path in sorted(self._paths.semantic_root.glob("*.jsonl"))
        )
        self.assertEqual(events_before, events_after)

    def test_at_018_tampered_markdown_is_quarantined_and_clean_rebuild_restores_it(self) -> None:
        path = self._path("decision-memos", f"{self.result.case_id}.md")
        original = path.read_text()
        path.write_text(original + "\nmanual edit")
        report = KernelValidator(self._paths, self._schemas).validate()
        self.assertFalse(report.passed)
        self.assertTrue(any(Path(issue.path).resolve() == path.resolve() for issue in report.issues))
        write_result = write_markdown_projection(
            build_decision_memo(self._semantic.read_all(), self.result.case_id, self._schemas),
            self._paths,
        )
        self.assertTrue(write_result.findings)
        self.assertIsNotNone(write_result.quarantined_path)
        self.assertEqual(path.read_text(), original)
        self.assertTrue(KernelValidator(self._paths, self._schemas).validate().passed)

    def test_at_010_case_journal_marks_a_correction_without_rewriting_the_original(self) -> None:
        self.harness.start()
        original = self.harness.append(
            self.harness.candidate(
                "question.recorded",
                {"observed_date": "2026-08-31", "question": "Invented correction target?"},
                session_id=self.harness.session_id,
            )
        )
        original_bytes = canonical_bytes(original)
        correction = self.harness.append(
            self.harness.candidate(
                "event.correction_recorded",
                {
                    "corrected_values": {"payload.observed_date": "2026-09-01"},
                    "corrects_event_id": original["event_id"],
                },
                session_id=self.harness.session_id,
                provenance=[{"ref": original["event_id"], "relation": "corrects"}],
            )
        )
        journal = build_case_journal(
            self.harness.semantic.read_all(), self.harness.case_id, self.harness.schemas
        )
        self.assertIn("Correction for " + original["event_id"], journal.content)
        self.assertIn(correction["event_id"], journal.content)
        self.assertEqual(canonical_bytes(original), original_bytes)

    def test_p4_fixture_replays_with_equivalent_semantics(self) -> None:
        with TemporaryDirectory(prefix="vault-next-phase4-replay-") as other:
            replay = run_synthetic_phase4(Path(other), SCHEMA_ROOT)
        self.assertEqual(self.result.to_record(), replay.to_record())

    def test_outcome_assessment_requires_owner_authority_even_when_appended_directly(self) -> None:
        events = self._semantic.read_all()
        outcome = next(event for event in events if event["event_type"] == "outcome.assessed")
        candidate = build_event(
            event_type="outcome.assessed",
            case_id=self.result.case_id,
            session_id=self.result.session_id,
            payload=outcome["payload"],
            actor={"type": "runtime", "id": "synthetic-runtime"},
            subject_refs=outcome["subject_refs"],
            provenance=outcome["provenance"],
            correlation_id="synthetic-phase4-authority-test",
        )
        with self.assertRaises(ValidationError) as caught:
            self._semantic.append(candidate)
        self.assertTrue(
            any(issue.code == ErrorCode.ACTOR_AUTHORITY_INVALID for issue in caught.exception.issues)
        )

    @property
    def _paths(self):
        from vault_next.paths import RuntimePaths

        return RuntimePaths(self.root)

    @property
    def _schemas(self):
        from vault_next.records import SchemaRegistry

        return SchemaRegistry(SCHEMA_ROOT)

    @property
    def _semantic(self):
        from vault_next.ledger import SemanticLedger

        return SemanticLedger(self._paths, self._schemas)


if __name__ == "__main__":
    unittest.main()
