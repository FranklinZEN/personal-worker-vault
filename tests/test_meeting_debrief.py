"""S5CF-T05/T06/T11 tests for the bounded synthetic Meeting Debrief evaluator."""

from __future__ import annotations

import unittest
from typing import Any

from tests.chat_fixtures import (
    FixtureMeetingDebriefAnalyzer,
    MutatingFixtureAnalyzer,
    ingress_coordinator,
    synthetic_text,
    transport,
)
from tests.helpers import Harness
from vault_next.meeting_debrief import MeetingDebriefError


class _UnboundCitationAnalyzer(FixtureMeetingDebriefAnalyzer):
    def analyze(self, evidence: Any, request: dict[str, Any]) -> dict[str, Any]:
        result = super().analyze(evidence, request)
        result["findings"][0]["citations"] = [{"anchor": "missing-anchor"}]
        return result


class _AllClaimClassesAnalyzer(FixtureMeetingDebriefAnalyzer):
    def analyze(self, evidence: Any, request: dict[str, Any]) -> dict[str, Any]:
        plain_anchor = evidence.anchors[1].anchor
        owner_anchor = evidence.anchors[-1].anchor
        findings = []
        for claim_class in (
            "reported_fact",
            "reported_decision",
            "proposal",
            "commitment",
            "risk",
            "conflict",
            "unknown",
            "unavailable",
        ):
            finding = {
                "claim_class": claim_class,
                "statement": f"Invented {claim_class} fixture statement.",
                "citations": [{"anchor": plain_anchor}],
                "owner": None,
                "owner_citation": None,
                "due": None,
                "due_citation": None,
            }
            if claim_class == "commitment":
                finding["citations"] = [{"anchor": owner_anchor}]
                finding["owner"] = "Invented Ada"
                finding["owner_citation"] = owner_anchor
                finding["due"] = "2099-01-01"
                finding["due_citation"] = owner_anchor
            findings.append(finding)
        return {
            "findings": findings,
            "summary": {
                "statement": "Invented summary distinguishes evidence from suggestions.",
                "citations": [{"anchor": plain_anchor}],
            },
            "open_questions": ["Invented ambiguity remains open."],
            "suggested_followups": ["Invented next step is non-executable advice."],
            "omissions": ["No real-world inference is asserted."],
            "limitations": ["Synthetic fixture only."],
        }


class _UnsupportedOwnerAnalyzer(FixtureMeetingDebriefAnalyzer):
    def analyze(self, evidence: Any, request: dict[str, Any]) -> dict[str, Any]:
        result = super().analyze(evidence, request)
        finding = result["findings"][0]
        finding["owner"] = "Uncited Owner"
        finding["owner_citation"] = evidence.anchors[0].anchor
        return result


class MeetingDebriefTests(unittest.TestCase):
    """No test analyzer is a model, tool caller, agent, or host integration."""

    def setUp(self) -> None:
        self.harness = Harness()

    def tearDown(self) -> None:
        self.harness.close()

    def test_s5cf_t05_only_frozen_evidence_reaches_analyzer_and_mutation_or_bad_citation_fails(self) -> None:
        coordinator, _router, analyzer = ingress_coordinator(self.harness)
        execution = coordinator.run(transport("paste"))
        self.assertEqual(analyzer.calls[0].evidence_sha256, execution.evidence.evidence_sha256)
        mutated, _router, _analyzer = ingress_coordinator(
            self.harness, MutatingFixtureAnalyzer()
        )
        with self.assertRaises(MeetingDebriefError):
            mutated.run(transport("attachment"))
        unbound, _router, _analyzer = ingress_coordinator(
            self.harness, _UnboundCitationAnalyzer()
        )
        with self.assertRaises(MeetingDebriefError):
            unbound.run(transport("local_file"))

    def test_s5cf_t06_claim_classes_citations_and_supported_owner_due_fields_are_exact(self) -> None:
        coordinator, _router, _analyzer = ingress_coordinator(
            self.harness, _AllClaimClassesAnalyzer()
        )
        execution = coordinator.run(
            transport("attachment", synthetic_text(include_owner_due=True))
        )
        classes = {finding["claim_class"] for finding in execution.debrief["findings"]}
        self.assertEqual(
            classes,
            {
                "reported_fact",
                "reported_decision",
                "proposal",
                "commitment",
                "risk",
                "conflict",
                "unknown",
                "unavailable",
            },
        )
        unsupported, _router, _analyzer = ingress_coordinator(
            self.harness, _UnsupportedOwnerAnalyzer()
        )
        with self.assertRaises(MeetingDebriefError):
            unsupported.run(transport("paste"))

    def test_s5cf_t11_u2_isolation_and_disclosure_labels_hold_against_embedded_instructions(self) -> None:
        coordinator, _router, _analyzer = ingress_coordinator(self.harness)
        execution = coordinator.run(transport("acquired_link", synthetic_text()))
        result = execution.result
        self.assertEqual(result["debrief"]["execution_surface"], "synthetic_fixture")
        self.assertEqual(result["debrief"]["analytical_usefulness"], "synthetic_mechanics_only")
        self.assertEqual(result["available_next_actions"], ["save_to_vault_next"])
        for forbidden in ("apply", "send", "schedule", "browse", "activate", "promote"):
            self.assertFalse(hasattr(coordinator, forbidden))
