"""Hostile synthetic S4-C committee-evaluation tests.

The fixtures below are supplied text only.  No role is an agent, model, or decision maker.
"""

from __future__ import annotations

import copy
import unittest

from tests import test_knowledge_library as _knowledge_library
from vault_next.canonical import canonical_sha256
from vault_next.committee_evaluation import SyntheticCommitteeEvaluationCoordinator
from vault_next.errors import ValidationError


class SyntheticCommitteeEvaluationTests(unittest.TestCase):
    """Exercise only the S4-C fixture-supplied sequential coordinator."""

    def setUp(self) -> None:
        self.fixtures = _knowledge_library.SyntheticKnowledgeLibraryTests("runTest")
        self.fixtures.setUp()
        self.runtime = self.fixtures.runtime
        self.session_id = self.fixtures.session_id
        self.library = self.fixtures.library
        self.coordinator = SyntheticCommitteeEvaluationCoordinator(self.runtime)
        self.source = self.fixtures._source(b"# Invented Atlas\nA reversible blue constraint.")
        self.candidate = self.library.record_candidate(
            self.session_id, self.fixtures._proposal(self.source)
        )["candidate"]
        self.candidate_id = self.candidate["candidate_id"]

    def tearDown(self) -> None:
        self.fixtures.tearDown()

    def _packet(self) -> dict:
        marks = self.library.watermarks([self.candidate_id])
        return {
            "question": "What should the invented Atlas exercise examine?",
            "purpose": "Compare bounded synthetic perspectives without deciding anything.",
            "execution_mode": "fixture_supplied_sequential",
            "role_cards": [
                {
                    "role_id": "evidence_reader",
                    "lens": "Trace stated fixture evidence.",
                    "allowed_claim_categories": ["evidence"],
                    "non_purpose": ["No authority or approval."],
                },
                {
                    "role_id": "counter_reader",
                    "lens": "Locate stated fixture limitations.",
                    "allowed_claim_categories": ["counterevidence"],
                    "non_purpose": ["No authority or approval."],
                },
            ],
            "s4a_baseline": {
                "package_id": "skill_evidence_mapping",
                "version": "0.1.0",
                "digest": "a" * 64,
                "baseline_digest": "b" * 64,
                "candidate_ids": [self.candidate_id],
            },
            "s4b_scope": {
                "candidate_ids": [self.candidate_id],
                "candidate_watermark": marks["candidate_watermark"],
                "source_watermark": marks["source_watermark"],
                "search_result_digest": canonical_sha256({"invented": "no-results-used"}),
                "confidentiality_space": "synthetic-atlas",
            },
            "first_pass_budget_bytes": 512,
            "challenge_budget_bytes": 512,
            "synthesis_budget_bytes": 512,
        }

    def _finding(self, role_id: str, *, conclusion: str = "supports", claim: str = "claim-blue") -> dict:
        return {
            "role_id": role_id,
            "claim_id": claim,
            "conclusion": conclusion,
            "statement": f"Invented {role_id} fixture finding: {conclusion}.",
            "evidence_candidate_ids": [] if conclusion == "unavailable" else [self.candidate_id],
            "limitations": ["Invented fixture text only."],
        }

    def _run(self) -> str:
        return self.coordinator.create_run(self.session_id, self._packet())["committee_run_id"]

    def _two_findings(self, *, second: str = "challenges") -> tuple[str, dict, dict]:
        run_id = self._run()
        first = self.coordinator.record_first_pass(
            self.session_id, run_id, self._finding("evidence_reader")
        )
        second_result = self.coordinator.record_first_pass(
            self.session_id,
            run_id,
            self._finding("counter_reader", conclusion=second),
        )
        return run_id, first, second_result

    @staticmethod
    def _synthesis(deltas: list[dict] | None = None) -> dict:
        return {
            "recommendation": "Keep the invented question open for later owner review.",
            "unaddressed_gaps": ["No real-world evidence is present."],
            "change_of_mind_condition": "New owner-supplied evidence would be required.",
            "deltas": deltas or [],
        }

    def test_s4c_t01_sequential_fixture_run_is_attributable(self) -> None:
        run_id, first, second = self._two_findings()
        events = [
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"].startswith("committee.")
        ]
        self.assertEqual(run_id, events[0]["payload"]["packet"]["committee_run_id"])
        self.assertEqual("fixture_supplied_sequential", events[0]["payload"]["packet"]["execution_mode"])
        self.assertEqual([first["finding_id"], second["finding_id"]], [
            events[1]["payload"]["finding"]["finding_id"],
            events[2]["payload"]["finding"]["finding_id"],
        ])

    def test_s4c_t02_packet_and_role_limits_fail_closed(self) -> None:
        before = list(self.runtime.semantic.read_all())
        invalid_packets: list[dict] = []

        authority_role = self._packet()
        authority_role["role_cards"][0]["allowed_claim_categories"] = ["approval"]
        invalid_packets.append(authority_role)

        duplicate_role = self._packet()
        duplicate_role["role_cards"][1]["role_id"] = "evidence_reader"
        invalid_packets.append(duplicate_role)

        excess_roles = self._packet()
        excess_roles["role_cards"] *= 3
        invalid_packets.append(excess_roles)

        altered_baseline = self._packet()
        altered_baseline["s4a_baseline"]["package_id"] = "unknown-package"
        invalid_packets.append(altered_baseline)

        stale_watermark = self._packet()
        stale_watermark["s4b_scope"]["candidate_watermark"] = "c" * 64
        invalid_packets.append(stale_watermark)

        for packet in invalid_packets:
            with self.assertRaises(ValidationError):
                self.coordinator.create_run(self.session_id, packet)
            self.assertEqual(before, self.runtime.semantic.read_all())

    def test_s4c_t03_challenge_requires_complete_first_pass_and_scope(self) -> None:
        run_id = self._run()
        with self.assertRaises(ValidationError):
            self.coordinator.record_challenge(
                self.session_id,
                run_id,
                {
                    "role_id": "evidence_reader",
                    "target_finding_id": "committee_finding_missing",
                    "statement": "Invented challenge.",
                    "evidence_candidate_ids": [self.candidate_id],
                },
            )
        first = self.coordinator.record_first_pass(
            self.session_id, run_id, self._finding("evidence_reader")
        )
        self.coordinator.record_first_pass(
            self.session_id, run_id, self._finding("counter_reader", conclusion="gap")
        )
        with self.assertRaises(ValidationError):
            self.coordinator.record_challenge(
                self.session_id,
                run_id,
                {
                    "role_id": "counter_reader",
                    "target_finding_id": first["finding_id"],
                    "statement": "Invented out-of-scope challenge.",
                    "evidence_candidate_ids": ["knowledge_candidate_outside"],
                },
            )

    def test_s4c_t04_dissent_is_preserved_in_synthesis(self) -> None:
        run_id, first, second = self._two_findings()
        self.assertIsNotNone(second["dissent_event_id"])
        result = self.coordinator.synthesize(
            self.session_id,
            run_id,
            self._synthesis([{"kind": "conflict_retained", "finding_id": first["finding_id"]}]),
        )
        self.assertEqual("attributable_delta", result["comparison"]["result"])
        synthesis = self.runtime.semantic.read_all()[-2]["payload"]["synthesis"]
        self.assertTrue(synthesis["open_dissent_ids"])
        self.assertEqual(
            "New owner-supplied evidence would be required.",
            synthesis["change_of_mind_condition"],
        )

    def test_s4c_t05_unavailable_role_yields_explicit_partial_outcome(self) -> None:
        run_id = self._run()
        self.coordinator.record_first_pass(
            self.session_id, run_id, self._finding("evidence_reader")
        )
        self.coordinator.record_first_pass(
            self.session_id,
            run_id,
            self._finding("counter_reader", conclusion="unavailable"),
        )
        result = self.coordinator.synthesize(self.session_id, run_id, self._synthesis())
        self.assertEqual("partial", result["status"])
        self.assertEqual("no_demonstrated_increment", result["comparison"]["result"])

    def test_s4c_t06_comparison_deltas_are_deterministic_and_bounded(self) -> None:
        run_id, first, _ = self._two_findings(second="gap")
        with self.assertRaises(ValidationError):
            self.coordinator.synthesize(
                self.session_id,
                run_id,
                self._synthesis([{"kind": "gap_surfaced", "finding_id": first["finding_id"]}]),
            )
        result = self.coordinator.synthesize(self.session_id, run_id, self._synthesis())
        self.assertEqual("no_demonstrated_increment", result["comparison"]["result"])

    def test_s4c_t07_restart_cross_case_and_stale_scope_fail_closed(self) -> None:
        run_id = self._run()
        self.coordinator.record_first_pass(
            self.session_id, run_id, self._finding("evidence_reader")
        )
        restarted = SyntheticCommitteeEvaluationCoordinator(self.runtime)
        with self.assertRaises(ValidationError):
            restarted.record_first_pass(
                self.session_id, run_id, self._finding("evidence_reader")
            )
        self.library.withdraw_candidate(
            self.session_id, self.candidate_id, reason="invented stale-scope probe"
        )
        with self.assertRaises(ValidationError):
            restarted.record_first_pass(
                self.session_id, run_id, self._finding("counter_reader")
            )
        other_case, other_session = self.fixtures._active_case("Other invented S4-C case")
        self.assertNotEqual(other_case, self.fixtures.case_id)
        with self.assertRaises(ValidationError):
            restarted.record_first_pass(
                other_session, run_id, self._finding("counter_reader")
            )

    def test_s4c_t08_no_external_executor_or_authority_is_exposed(self) -> None:
        run_id, _, _ = self._two_findings()
        result = self.coordinator.synthesize(self.session_id, run_id, self._synthesis())
        events = self.runtime.semantic.read_all()
        committee_events = [event for event in events if event["event_type"].startswith("committee.")]
        self.assertEqual(
            [
                "committee.run_recorded",
                "committee.finding_recorded",
                "committee.finding_recorded",
                "committee.dissent_recorded",
                "committee.synthesis_recorded",
                "committee.comparison_recorded",
            ],
            [event["event_type"] for event in committee_events],
        )
        self.assertEqual("unavailable: committee output is non-authoritative", result["promotion"])

    def test_s4c_t09_packet_digest_and_receiptless_state_are_deterministic(self) -> None:
        packet = self._packet()
        first = self.coordinator.create_run(self.session_id, packet)
        stored = self.runtime.semantic.read_all()[-1]["payload"]["packet"]
        self.assertEqual(first["packet_sha256"], stored["packet_sha256"])
        altered = copy.deepcopy(packet)
        altered["purpose"] = "Different invented purpose."
        second = self.coordinator.create_run(self.session_id, altered)
        self.assertNotEqual(first["packet_sha256"], second["packet_sha256"])
