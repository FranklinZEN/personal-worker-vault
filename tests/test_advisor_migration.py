"""P1 compatibility, retrieval-fixture, and amendment-preview tests."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from tests.helpers import Harness, PROJECT_ROOT
from vault_next.advisor_migration import (
    ActorAttribution,
    AdvisorMigrationCoordinator,
    AdvisorMigrationError,
    RationaleAttribution,
)
from vault_next.canonical import canonical_sha256
from vault_next.errors import ValidationError


class AdvisorMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.coordinator = AdvisorMigrationCoordinator(self.harness.schemas)
        self.citation = "fixture:executive-meeting:line-000020"
        material = {
            "schema_version": "1.0",
            "component": "invented-legacy-week/1.0.0",
            "candidate_only": True,
            "no_current_work": True,
            "weekly_wave": {
                "decisions": [
                    {
                        "label": "Invented executive approved three lantern roles",
                        "status": "source_reported_candidate",
                    }
                ]
            },
            "item_observations": [
                {
                    "observation_id": "artifact-invented",
                    "citation_refs": [self.citation],
                }
            ],
            "conversation_observations": [],
        }
        self.package = {**material, "package_digest": canonical_sha256(material)}
        self.event = {
            "schema_version": "1.0",
            "event_id": "event_invented_week",
            "package_digest": self.package["package_digest"],
            "receipt_id": "receipt_invented_record_approval",
            "recorded_at": "2026-09-20T12:00:00Z",
        }

    def tearDown(self) -> None:
        self.harness.close()

    def _supplement(self, *, rationale: RationaleAttribution | None = None) -> dict:
        return self.coordinator.prepare_attribution_supplement(
            supplement_id="supplement-invented-1",
            event=self.event,
            package=self.package,
            decision_index=0,
            decision_makers=(
                ActorAttribution(
                    "business_decision_maker",
                    "known",
                    "person-executive-invented",
                    "contemporary_source",
                    (self.citation,),
                ),
            ),
            owner_roles=(
                ActorAttribution(
                    "proposal_contributor",
                    "known",
                    "person-owner-invented",
                    "contemporary_source",
                    (self.citation,),
                ),
            ),
            reporters=(
                ActorAttribution(
                    "source_reporter",
                    "known",
                    "record-invented-meeting",
                    "contemporary_source",
                    (self.citation,),
                ),
            ),
            record_approvers=(
                ActorAttribution(
                    "repository_record_approver",
                    "known",
                    "person-owner-invented",
                    "contemporary_source",
                    (self.citation,),
                ),
            ),
            rationale=rationale
            or RationaleAttribution(
                "stated",
                "The invented roles replace three departing roles.",
                ("person-executive-invented",),
                "contemporary_source",
                (self.citation,),
            ),
            evidence_anchors=(self.citation,),
            event_time="2026-07-29T16:48:00-04:00",
            effective_time="2026-07-29T16:48:00-04:00",
            recorded_at="2026-09-20T12:00:00Z",
        )

    def test_p1_a1_legacy_decision_remains_readable_and_unknowns_are_not_guessed(self) -> None:
        original = deepcopy(self.package)
        view = self.coordinator.read_legacy_decisions(
            event=self.event, package=self.package
        )[0]
        self.assertEqual(view.decision_statement, self.package["weekly_wave"]["decisions"][0]["label"])
        self.assertEqual(view.decision_makers[0]["identity_state"], "unknown")
        self.assertEqual(view.record_approvers[0]["identity_state"], "unknown")
        self.assertFalse(view.current_authority)
        self.assertTrue(view.candidate_only)
        self.assertEqual(self.package, original)
        receiptless_event = deepcopy(self.event)
        receiptless_event.pop("receipt_id")
        receiptless = self.coordinator.read_legacy_decisions(
            event=receiptless_event, package=self.package
        )[0]
        self.assertIsNone(receiptless.publication_receipt_ref)

    def test_p1_a1_roles_stay_distinct_and_record_approval_never_becomes_decision_authority(self) -> None:
        supplement = self._supplement()
        view = self.coordinator.read_legacy_decisions(
            event=self.event, package=self.package, supplements=(supplement,)
        )[0]
        self.assertEqual(view.decision_makers[0]["party_ref"], "person-executive-invented")
        self.assertEqual(view.owner_roles[0]["role"], "proposal_contributor")
        self.assertEqual(view.record_approvers[0]["role"], "repository_record_approver")
        self.assertNotEqual(
            view.decision_makers[0]["party_ref"], view.record_approvers[0]["party_ref"]
        )
        self.assertEqual(view.publication_receipt_ref, "receipt_invented_record_approval")
        self.assertFalse(view.current_authority)

    def test_p1_a1_unknown_rationale_and_later_recollection_are_separate(self) -> None:
        unknown = RationaleAttribution("not_stated", None, (), "not_stated", ())
        supplement = self.coordinator.prepare_attribution_supplement(
            supplement_id="supplement-invented-unknown",
            event=self.event,
            package=self.package,
            decision_index=0,
            decision_makers=(ActorAttribution("business_decision_maker", "unknown", None, "not_stated"),),
            owner_roles=(ActorAttribution("owner_role", "unknown", None, "not_stated"),),
            reporters=(ActorAttribution("source_reporter", "unknown", None, "not_stated"),),
            record_approvers=(
                ActorAttribution("repository_record_approver", "unknown", None, "not_stated"),
            ),
            rationale=unknown,
            evidence_anchors=(self.citation,),
            event_time=None,
            effective_time=None,
            recorded_at="2026-09-20T12:00:00Z",
            retrospective_recollections=(
                {
                    "claim_basis": "later_owner_recollection",
                    "recorded_at": "2026-09-20T11:00:00Z",
                    "text": "Invented later recollection, not contemporary rationale.",
                    "evidence_refs": [],
                },
            ),
        )
        view = self.coordinator.read_legacy_decisions(
            event=self.event, package=self.package, supplements=(supplement,)
        )[0]
        self.assertEqual(view.rationale["state"], "not_stated")
        self.assertEqual(
            supplement["retrospective_recollections"][0]["claim_basis"],
            "later_owner_recollection",
        )

    def test_p1_a1_parent_or_supplement_mutation_fails_closed(self) -> None:
        supplement = self._supplement()
        supplement["decision_statement"] = "substituted"
        with self.assertRaises(AdvisorMigrationError):
            self.coordinator.read_legacy_decisions(
                event=self.event, package=self.package, supplements=(supplement,)
            )
        package = deepcopy(self.package)
        package["weekly_wave"]["decisions"][0]["label"] = "mutated"
        with self.assertRaises(AdvisorMigrationError):
            self.coordinator.read_legacy_decisions(event=self.event, package=package)
        supplement = self._supplement()
        event = deepcopy(self.event)
        event["recorded_at"] = "2026-09-20T12:00:01Z"
        with self.assertRaises(AdvisorMigrationError):
            self.coordinator.read_legacy_decisions(
                event=event, package=self.package, supplements=(supplement,)
            )

    def test_p1_a1_supplement_evidence_must_resolve_to_parent_or_receipt(self) -> None:
        with self.assertRaises(AdvisorMigrationError):
            self.coordinator.prepare_attribution_supplement(
                supplement_id="supplement-invented-external-evidence",
                event=self.event,
                package=self.package,
                decision_index=0,
                decision_makers=(
                    ActorAttribution(
                        "business_decision_maker",
                        "known",
                        "person-executive-invented",
                        "contemporary_source",
                        ("file:outside-parent#line-1",),
                    ),
                ),
                owner_roles=(ActorAttribution("owner_role", "unknown", None, "not_stated"),),
                reporters=(ActorAttribution("source_reporter", "unknown", None, "not_stated"),),
                record_approvers=(
                    ActorAttribution(
                        "repository_record_approver",
                        "known",
                        "person-owner-invented",
                        "contemporary_source",
                        ("receipt:receipt_invented_record_approval",),
                    ),
                ),
                rationale=RationaleAttribution("not_stated", None, (), "not_stated", ()),
                evidence_anchors=(self.citation,),
                event_time=None,
                effective_time=None,
                recorded_at="2026-09-20T12:00:00Z",
            )

    def test_p1_a2_frozen_retrieval_cases_cover_required_intents_and_distinctions(self) -> None:
        fixture = PROJECT_ROOT / "fixtures" / "synthetic" / "advisor-retrieval-evaluation-v1.json"
        cases = self.coordinator.load_retrieval_cases(fixture)
        self.assertEqual(len(cases), 6)
        self.assertEqual(
            {case["intent"] for case in cases},
            {
                "next_meeting",
                "direction_change",
                "analogous_case",
                "leadership_evidence",
                "public_practice_comparison",
            },
        )
        self.assertTrue(next(case for case in cases if case["case_id"] == "A2-03-analogy-renamed")["different_wording"])

    def test_p1_a2_result_evaluation_rejects_hindsight_and_authority_effects(self) -> None:
        fixture = PROJECT_ROOT / "fixtures" / "synthetic" / "advisor-retrieval-evaluation-v1.json"
        case = next(
            item
            for item in self.coordinator.load_retrieval_cases(fixture)
            if item["case_id"] == "A2-02-direction-as-of"
        )
        result = {
            "schema_version": "1.0",
            "case_id": case["case_id"],
            "status": "complete",
            "selected_record_ids": list(case["expected_record_ids"]),
            "citations": ["fixture:cobalt:line-1"],
            "coverage_boundary": "Invented records through 2026-05-01 only.",
            "labels": list(case["required_labels"]),
            "public_sources": [],
            "source_recommended_questions": [],
            "advisor_derived_questions": [],
            "unavailable_claims": list(case["expected_unknowns"]),
            "no_persistence": True,
            "no_authority_effect": True,
            "current_work_adopted": False,
            "knowledge_promoted": False,
        }
        self.assertTrue(self.coordinator.evaluate_retrieval_result(case, result).passed)
        hostile = deepcopy(result)
        hostile["selected_record_ids"].append("record-cobalt-later-outcome")
        self.assertFalse(self.coordinator.evaluate_retrieval_result(case, hostile).passed)
        hostile = deepcopy(result)
        hostile["current_work_adopted"] = True
        with self.assertRaises(ValidationError):
            self.coordinator.evaluate_retrieval_result(case, hostile)

    def test_p1_a3_preview_is_exhaustive_and_has_no_write_path(self) -> None:
        roles = (
            "executive_owned_decision_with_owner_input",
            "redirected_or_discontinuous_initiative",
            "career_relevant_artifact",
        )
        entries = tuple(
            {
                "entry_id": f"pilot-{index}",
                "pilot_role": role,
                "parent_event_ids": [f"event-invented-{index}"],
                "source_record_refs": [f"record-invented-{index}"],
                "evidence_refs": [f"fixture:pilot:{index}"],
                "disposition": "missing_attribution" if index == 0 else "retained_as_is",
                "reason": "Invented bounded pilot finding.",
                "proposed_change_class": "interpretation_amendment" if index == 0 else "none",
                "affected_views": ["decision_lineage"] if index == 0 else [],
                "limitations": ["Synthetic fixture does not establish real-history accuracy."],
            }
            for index, role in enumerate(roles)
        )
        preview = self.coordinator.build_amendment_preview(entries)
        self.assertEqual(preview["coverage_denominator"], 3)
        self.assertEqual(preview["coverage_dispositioned"], 3)
        self.assertTrue(preview["no_write"])
        self.assertTrue(preview["parent_records_unchanged"])


if __name__ == "__main__":
    unittest.main()
