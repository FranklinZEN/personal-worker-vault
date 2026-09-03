"""Synthetic-only Phase 2 acceptance and lifecycle gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import Harness
from vault_next.context import ExplicitContextLoader
from vault_next.errors import ErrorCode, ValidationError
from vault_next.evidence import SyntheticEvidenceStore
from vault_next.lifecycle import fold_decisions, fold_session_states
from vault_next.projection import build_session_trace
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import fold_reasoning_state
from vault_next.validator import KernelValidator

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Phase2AcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
            correlation_id="synthetic-phase2-test",
        )
        self.case_event = self.runtime.create_case("Invented continuity case")
        self.case_id = self.case_event["case_id"]

    def tearDown(self) -> None:
        self.harness.close()

    def _active_session(self) -> str:
        created = self.runtime.create_session(self.case_id, "Which invented option should we test?")
        session_id = created["session_id"]
        self.runtime.transition_session(session_id, "routed", reason="synthetic route")
        self.runtime.transition_session(session_id, "authorized", reason="local-only scope")
        self.runtime.transition_session(session_id, "active", reason="begin synthetic analysis")
        return session_id

    def _canonical_bytes(self) -> bytes:
        return b"".join(path.read_bytes() for path in sorted(self.harness.paths.semantic_root.glob("*.jsonl")))

    def test_full_manifests_and_invalid_transition_do_not_mutate_canonical_ledger(self) -> None:
        created = self.runtime.create_session(self.case_id, "Draft synthetic question")
        manifest = created["payload"]["manifest"]
        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(manifest["status"], "draft")
        before = self._canonical_bytes()
        with self.assertRaises(ValidationError) as raised:
            self.runtime.transition_session(created["session_id"], "active", reason="skip gates")
        self.assertEqual(raised.exception.issues[0].code, ErrorCode.LIFECYCLE_TRANSITION_INVALID)
        self.assertEqual(self._canonical_bytes(), before)

        routed = self.runtime.transition_session(created["session_id"], "routed", reason="valid")
        self.assertEqual(routed["payload"]["manifest"]["manifest_version"], 2)
        self.assertEqual(
            routed["payload"]["previous_manifest_sha256"],
            created["payload"]["manifest_sha256"],
        )

    def test_scope_block_no_decision_close_abandon_and_resume_are_explicit(self) -> None:
        session_id = self._active_session()
        blocked = self.runtime.transition_session(session_id, "blocked", reason="invented dependency")
        self.assertEqual(blocked["payload"]["manifest"]["status"], "blocked")
        self.runtime.transition_session(session_id, "active", reason="dependency resolved")
        scoped = self.runtime.amend_scope(
            session_id,
            changes={"primary_question": "Which reversible invented option should we test first?"},
            reason="clarify scope",
        )
        self.assertEqual(scoped["event_type"], "session.scope_changed")
        closed = self.runtime.close_session(session_id, disposition="no_decision", reason="more evidence needed")
        self.assertEqual(closed["payload"]["frozen_manifest"]["closure_disposition"], "no_decision")
        before = self._canonical_bytes()
        with self.assertRaises(ValidationError):
            self.runtime.transition_session(session_id, "active", reason="illegal reopen")
        self.assertEqual(self._canonical_bytes(), before)
        with self.assertRaises(ValidationError):
            self.runtime.record_reasoning_event(
                session_id,
                "assumption.recorded",
                {
                    "assumption_id": "assumption_too_late",
                    "statement": "Must not enter frozen session",
                    "status": "open",
                },
                subject_refs=["assumption_too_late"],
            )
        self.assertEqual(self._canonical_bytes(), before)

        resumed = self.runtime.resume_as_new_session(session_id)
        self.assertNotEqual(resumed["session_id"], session_id)
        self.assertEqual(resumed["payload"]["manifest"]["continues_session_id"], session_id)
        states, issues = fold_session_states(self.runtime.semantic.read_all())
        self.assertFalse(issues)
        self.assertEqual(states[session_id].status, "closed")
        self.assertEqual(states[resumed["session_id"]].status, "draft")

        abandoned = self.runtime.create_session(self.case_id, "Unused invented branch")
        event = self.runtime.transition_session(abandoned["session_id"], "abandoned", reason="not needed")
        self.assertEqual(event["payload"]["disposition"], "abandoned")

    def test_synthetic_evidence_is_content_addressed_and_context_is_allowlisted(self) -> None:
        session_id = self._active_session()
        store = SyntheticEvidenceStore(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
            correlation_id="synthetic-phase2-test",
        )
        registered = store.register(
            case_id=self.case_id,
            session_id=session_id,
            content=b"Invented observation: option blue is reversible.",
            display_name="invented-observation.txt",
            sensitivity_labels=["personal"],
        )
        evidence_id = registered.metadata["evidence_id"]
        self.assertTrue(registered.object_path.is_file())
        self.assertEqual(
            store.read_verified(registered.metadata),
            b"Invented observation: option blue is reversible.",
        )
        self.runtime.amend_scope(
            session_id,
            changes={
                "authorized_context": [
                    {
                        "ref": evidence_id,
                        "purpose": "compare invented options",
                        "sensitivity_labels": ["personal"],
                    }
                ],
                "sensitivity_labels": ["personal"],
                "evidence_refs": [evidence_id],
            },
            reason="authorize synthetic observation",
        )
        fresh_loader = ExplicitContextLoader(self.harness.paths, self.harness.schemas)
        loaded = fresh_loader.load(
            session_id=session_id,
            requested_refs=[evidence_id],
            events=self.runtime.semantic.read_all(),
        )
        self.assertEqual(loaded.report["loaded_refs"], [evidence_id])
        manifest_refs = {
            item["ref"]
            for item in self.runtime._session(session_id).manifest["authorized_context"]
        }
        self.assertIn(evidence_id, manifest_refs)
        self.assertEqual(loaded.items[0]["kind"], "evidence")
        self.assertTrue(
            KernelValidator(self.harness.paths, self.harness.schemas).validate().passed
        )

        with self.assertRaises(ValidationError) as raised:
            fresh_loader.load(
                session_id=session_id,
                requested_refs=[self.case_event["event_id"]],
                events=self.runtime.semantic.read_all(),
            )
        self.assertEqual(
            raised.exception.issues[0].code,
            ErrorCode.CONTEXT_AUTHORIZATION_DENIED,
        )

    def test_sensitivity_and_cross_case_guards_fail_closed(self) -> None:
        session_id = self._active_session()
        other = self.runtime.create_case("Unrelated invented case")
        with self.assertRaises(ValidationError) as raised:
            self.runtime.amend_scope(
                session_id=session_id,
                changes={
                    "authorized_context": [
                        {
                            "ref": other["event_id"],
                            "purpose": "must be denied",
                            "sensitivity_labels": ["none"],
                        }
                    ]
                },
                reason="exercise cross-case guard",
            )
        self.assertEqual(
            raised.exception.issues[0].code,
            ErrorCode.CONTEXT_AUTHORIZATION_DENIED,
        )

        store = SyntheticEvidenceStore(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
        )
        sensitive = store.register(
            case_id=self.case_id,
            session_id=session_id,
            content=b"Invented HR fixture",
            display_name="invented-hr.txt",
            sensitivity_labels=["hr"],
        )
        self.runtime.amend_scope(
            session_id,
            changes={"sensitivity_labels": ["none"]},
            reason="retain low sensitivity before negative test",
        )
        before = self._canonical_bytes()
        with self.assertRaises(ValidationError) as raised:
            self.runtime.amend_scope(
                session_id,
                changes={
                    "authorized_context": [
                        {
                            "ref": sensitive.metadata["evidence_id"],
                            "purpose": "test labels",
                            "sensitivity_labels": ["hr"],
                        }
                    ]
                },
                reason="must not exceed session sensitivity",
            )
        self.assertEqual(
            raised.exception.issues[0].code,
            ErrorCode.CONTEXT_SENSITIVITY_EXCEEDED,
        )
        self.assertEqual(self._canonical_bytes(), before)
        self.runtime.amend_scope(
            session_id,
            changes={
                "authorized_context": [
                    {
                        "ref": sensitive.metadata["evidence_id"],
                        "purpose": "test labels",
                        "sensitivity_labels": ["hr"],
                    }
                ],
                "sensitivity_labels": ["hr"],
            },
            reason="propagate source sensitivity",
        )
        loader = ExplicitContextLoader(self.harness.paths, self.harness.schemas)
        loaded = loader.load_from_repository(
            session_id=session_id,
            requested_refs=[sensitive.metadata["evidence_id"]],
        )
        self.assertEqual(loaded.report["sensitivity_labels"], ["hr"])

    def test_reasoning_objects_preserve_revisions_and_current_state(self) -> None:
        session_id = self._active_session()
        self.runtime.record_reasoning_event(
            session_id,
            "assumption.recorded",
            {
                "assumption_id": "assumption_blue",
                "statement": "Blue is cheapest",
                "status": "open",
            },
            subject_refs=["assumption_blue"],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "assumption.revised",
            {
                "assumption_id": "assumption_blue",
                "statement": "Blue may be cheapest",
                "status": "validated",
            },
            subject_refs=["assumption_blue"],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "alternative.recorded",
            {
                "alternative_id": "alternative_green",
                "description": "Try green",
                "disposition": "open",
            },
            subject_refs=["alternative_green"],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "alternative.disposition_changed",
            {
                "alternative_id": "alternative_green",
                "disposition": "deferred",
                "reason": "invented constraint",
            },
            subject_refs=["alternative_green"],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "disagreement.recorded",
            {
                "disagreement_id": "disagreement_cost",
                "statement": "Cost estimate differs",
                "status": "open",
            },
            subject_refs=["disagreement_cost"],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "disagreement.resolved",
            {
                "disagreement_id": "disagreement_cost",
                "resolution": "Use synthetic median",
            },
            subject_refs=["disagreement_cost"],
        )
        recommendation_id = self.harness.ids.new("recommendation")
        self.runtime.record_reasoning_event(
            session_id,
            "recommendation.issued",
            {"recommendation_id": recommendation_id, "revision": 1, "summary": "Try blue"},
            subject_refs=[recommendation_id],
        )
        self.runtime.record_reasoning_event(
            session_id,
            "recommendation.revised",
            {
                "recommendation_id": recommendation_id,
                "revision": 2,
                "summary": "Try green first",
            },
            subject_refs=[recommendation_id],
        )
        current = fold_reasoning_state(self.runtime.semantic.read_all(), session_id)
        self.assertEqual(current["assumptions"]["assumption_blue"]["status"], "validated")
        self.assertEqual(current["alternatives"]["alternative_green"]["disposition"], "deferred")
        self.assertEqual(current["disagreements"]["disagreement_cost"]["status"], "resolved")
        self.assertEqual(current["recommendations"][recommendation_id]["revision"], 2)
        recommendation_events = [
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"].startswith("recommendation.")
        ]
        self.assertEqual(len(recommendation_events), 2)

    def test_at_007_recommendation_never_implies_owner_decision(self) -> None:
        session_id = self._active_session()
        recommendation_id = self.harness.ids.new("recommendation")
        self.runtime.record_reasoning_event(
            session_id,
            "recommendation.issued",
            {
                "recommendation_id": recommendation_id,
                "revision": 1,
                "summary": "Invented recommendation",
            },
            subject_refs=[recommendation_id],
        )
        self.runtime.close_session(
            session_id,
            disposition="no_decision",
            reason="looks reasonable is not confirmation",
        )
        events = self.runtime.semantic.read_all()
        self.assertFalse(
            any(event["event_type"].startswith("owner_decision.") for event in events)
        )

    def test_at_008_explicit_supersession_keeps_original_and_rejects_cycles(self) -> None:
        first_session = self._active_session()
        original = self.runtime.record_owner_decision(
            first_session, "Choose invented option blue"
        )
        original_line = next(
            line
            for line in self._canonical_bytes().splitlines(keepends=True)
            if original["event_id"].encode() in line
        )
        self.runtime.close_session(
            first_session,
            disposition="decided",
            reason="explicit synthetic decision",
        )
        second_created = self.runtime.resume_as_new_session(first_session)
        second_session = second_created["session_id"]
        self.runtime.transition_session(second_session, "routed", reason="synthetic route")
        self.runtime.transition_session(second_session, "authorized", reason="local scope")
        self.runtime.transition_session(second_session, "active", reason="reconsider")
        replacement = self.runtime.record_owner_decision(
            second_session, "Choose invented option green"
        )
        self.runtime.supersede_owner_decision(
            second_session,
            original["payload"]["decision_id"],
            replacement["payload"]["decision_id"],
            reason="new synthetic constraint",
        )
        states, issues = fold_decisions(self.runtime.semantic.read_all())
        self.assertFalse(issues)
        self.assertFalse(states[original["payload"]["decision_id"]].current)
        self.assertTrue(states[replacement["payload"]["decision_id"]].current)
        projection = build_session_trace(
            self.runtime.semantic.read_all(), second_session, self.harness.schemas
        )
        self.assertFalse(
            projection["decision_state"][original["payload"]["decision_id"]]["current"]
        )
        self.assertTrue(
            projection["decision_state"][replacement["payload"]["decision_id"]]["current"]
        )
        self.assertIn(
            original_line, self._canonical_bytes().splitlines(keepends=True)
        )
        before = self._canonical_bytes()
        with self.assertRaises(ValidationError) as raised:
            self.runtime.supersede_owner_decision(
                second_session,
                replacement["payload"]["decision_id"],
                original["payload"]["decision_id"],
                reason="would cycle",
            )
        self.assertTrue(
            any(
                issue.code == ErrorCode.DECISION_SUPERSESSION_CYCLE
                for issue in raised.exception.issues
            )
        )
        self.assertEqual(self._canonical_bytes(), before)

    def test_at_009_fresh_loader_restores_only_manifest_authorized_case_context(self) -> None:
        first_session = self._active_session()
        assumption = self.runtime.record_reasoning_event(
            first_session,
            "assumption.recorded",
            {
                "assumption_id": "assumption_open",
                "statement": "Invented dependency remains",
                "status": "open",
            },
            subject_refs=["assumption_open"],
        )
        alternative = self.runtime.record_reasoning_event(
            first_session,
            "alternative.recorded",
            {
                "alternative_id": "alternative_open",
                "description": "Invented fallback",
                "disposition": "open",
            },
            subject_refs=["alternative_open"],
        )
        decision = self.runtime.record_owner_decision(
            first_session, "Continue after invented review trigger"
        )
        self.runtime.amend_scope(
            first_session,
            changes={"review_refs": ["review_trigger_2030"]},
            reason="record synthetic next review trigger",
        )
        self.runtime.close_session(
            first_session,
            disposition="decided",
            reason="explicit synthetic decision",
        )
        refs = [assumption["event_id"], alternative["event_id"], decision["event_id"]]
        authorizations = [
            {
                "ref": ref,
                "purpose": "resume unresolved synthetic state",
                "sensitivity_labels": ["none"],
            }
            for ref in refs
        ]
        new_session = self.runtime.resume_as_new_session(
            first_session, authorized_context=authorizations
        )

        unrelated = self.runtime.create_case("Unrelated invented case")
        script = """
import json, sys
from pathlib import Path
from vault_next.context import ExplicitContextLoader
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry
paths = RuntimePaths(Path(sys.argv[1]))
loaded = ExplicitContextLoader(paths, SchemaRegistry(Path(sys.argv[2]))).load_from_repository(
    session_id=sys.argv[3], requested_refs=sys.argv[4:]
)
print(json.dumps({
    "report": loaded.report,
    "types": [item["value"]["event_type"] for item in loaded.items]
}, sort_keys=True))
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
        output = subprocess.check_output(
            [
                sys.executable,
                "-c",
                script,
                str(self.harness.runtime_root),
                str(PROJECT_ROOT / "schemas" / "v1"),
                new_session["session_id"],
                *refs,
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
        )
        fresh = json.loads(output)
        self.assertEqual(set(fresh["report"]["loaded_refs"]), set(refs))
        self.assertNotIn(unrelated["event_id"], fresh["report"]["source_event_ids"])
        loaded_types = set(fresh["types"])
        self.assertEqual(
            loaded_types,
            {
                "assumption.recorded",
                "alternative.recorded",
                "owner_decision.recorded",
            },
        )
        manifest_refs = {
            item["ref"]
            for item in new_session["payload"]["manifest"]["authorized_context"]
        }
        self.assertEqual(set(fresh["report"]["loaded_refs"]), manifest_refs)


if __name__ == "__main__":
    unittest.main()
