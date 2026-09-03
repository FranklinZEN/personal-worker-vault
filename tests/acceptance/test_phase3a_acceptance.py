"""Synthetic-only P3A interaction-first acceptance scenarios."""

from __future__ import annotations

import copy
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes
from vault_next.catalog import install_synthetic_catalog
from vault_next.context import ExplicitContextLoader
from vault_next.errors import ErrorCode, ValidationError
from vault_next.interaction import InteractionRuntime
from vault_next.packages import PackageRegistry
from vault_next.routing import RoutingRuntime
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import (
    build_current_work_state,
    fold_artifact_state,
    fold_interaction_state,
    fold_work_items,
)
from vault_next.triage import TriageRequest, UniversalTriage
from vault_next.validator import KernelValidator


class Phase3AInteractionAcceptanceTests(unittest.TestCase):
    """Exercise the P3A contract without personal data, models, or adapters."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.registry = PackageRegistry(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
        )
        install_synthetic_catalog(self.registry)
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
            correlation_id="synthetic-phase3a-acceptance",
        )
        self.triage = UniversalTriage(
            self.registry,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
        )
        self.router = RoutingRuntime(self.runtime, self.registry)
        self.interaction = InteractionRuntime(
            self.runtime,
            id_factory=self.harness.ids,
            clock=self.harness.tick,
        )

    def tearDown(self) -> None:
        self.harness.close()

    def _active_session(
        self,
        question: str,
        *,
        mode: str,
        work_units: tuple[str, ...],
        framework_id: str = "framework_specialist",
    ) -> tuple[str, str, dict]:
        case = self.runtime.create_case("Invented P3A case")
        case_id = case["case_id"]
        session = self.runtime.create_session(case_id, question)
        session_id = session["session_id"]
        plan = self.triage.plan(
            TriageRequest(
                question,
                required_work_units=work_units,
                preferred_framework_id=framework_id,
                preferred_interaction_mode=mode,
            )
        )
        self.router.apply(session_id, plan)
        self.runtime.transition_session(session_id, "authorized", reason="synthetic local scope")
        self.runtime.transition_session(session_id, "active", reason="begin synthetic interaction")
        return case_id, session_id, plan

    def _canonical_bytes(self) -> bytes:
        return b"".join(
            path.read_bytes()
            for path in sorted(self.harness.paths.semantic_root.glob("*.jsonl"))
        )

    def test_at_030_exploration_can_pause_without_forcing_an_artifact(self) -> None:
        case_id, session_id, _ = self._active_session(
            "Deep dive into an invented reversible topic",
            mode="explore",
            work_units=("source_comprehension",),
        )
        owner_input = self.interaction.record_owner_input(
            session_id,
            "The invented constraint is reversible rather than permanent.",
            role="correction",
        )
        checkpoint = self.interaction.record_checkpoint(
            session_id,
            "We clarified the constraint and retained two open explanations.",
            state={
                "working_question": "Which explanation best fits the invented evidence?",
                "assumptions": ["The fixture remains reversible"],
                "alternatives": ["blue explanation", "green explanation"],
                "uncertainty": "No synthetic observation distinguishes them yet",
            },
            open_questions=["Which observation would distinguish the explanations?"],
        )
        before = self._canonical_bytes()
        with self.assertRaises(ValidationError) as caught:
            self.interaction.record_checkpoint(
                session_id,
                "Forbidden transcript-shaped checkpoint",
                state={"messages": ["invented transcript"]},
            )
        self.assertEqual(
            caught.exception.issues[0].code, ErrorCode.CHECKPOINT_CONTENT_FORBIDDEN
        )
        self.assertEqual(self._canonical_bytes(), before)
        self.runtime.close_session(
            session_id,
            disposition="no_decision",
            reason="owner paused after reaching sufficient understanding",
        )
        events = self.runtime.semantic.read_all()
        types = [event["event_type"] for event in events]
        self.assertNotIn("artifact.version_created", types)
        self.assertNotIn("recommendation.issued", types)
        self.assertNotIn("owner_decision.recorded", types)
        self.assertNotIn("work_item.recorded", types)
        self.assertEqual(owner_input["actor"]["type"], "owner")

        resumed = self.runtime.resume_as_new_session(
            session_id,
            authorized_context=[
                {
                    "ref": checkpoint["event_id"],
                    "purpose": "resume the explicit interaction checkpoint",
                    "sensitivity_labels": ["none"],
                }
            ],
        )
        fresh_loader = ExplicitContextLoader(self.harness.paths, self.harness.schemas)
        loaded = fresh_loader.load_from_repository(
            session_id=resumed["session_id"],
            requested_refs=[checkpoint["event_id"]],
        )
        self.assertEqual(loaded.report["loaded_refs"], [checkpoint["event_id"]])
        self.assertEqual(resumed["case_id"], case_id)
        self.assertTrue(KernelValidator(self.harness.paths, self.harness.schemas).validate().passed)

    def test_at_031_mode_change_recomposes_and_cannot_bypass_manifest_history(self) -> None:
        _, session_id, plan = self._active_session(
            "Explore an invented source",
            mode="explore",
            work_units=("source_comprehension",),
        )
        original_route = next(
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "routing.proposed"
        )
        original_bytes = canonical_bytes(original_route)
        before_manifest = copy.deepcopy(self.runtime._session(session_id).manifest)
        changed = self.router.change_interaction_mode(
            session_id,
            plan,
            new_mode="artifact_iterate",
            reason="turn the exploration into a reviewed synthetic brief",
            required_work_units=["source_comprehension", "synthesis"],
            framework_id="framework_synthesis",
            skill_ids=["skill_comprehension", "skill_synthesis"],
        )
        current = self.runtime._session(session_id).manifest
        self.assertEqual(current["interaction"]["mode"], "artifact_iterate")
        self.assertEqual(current["manifest_version"], before_manifest["manifest_version"] + 1)
        self.assertEqual(current["authorized_context"], before_manifest["authorized_context"])
        self.assertEqual(current["granted_permissions"], before_manifest["granted_permissions"])
        self.assertEqual(changed["event"]["payload"]["added_skill_ids"], ["skill_synthesis"])
        self.assertEqual(canonical_bytes(original_route), original_bytes)

        before_invalid = self._canonical_bytes()
        with self.assertRaises(ValidationError):
            self.runtime.amend_scope(
                session_id,
                changes={"interaction": before_manifest["interaction"]},
                reason="attempt to bypass the canonical mode-change event",
            )
        self.assertEqual(self._canonical_bytes(), before_invalid)
        state = fold_interaction_state(self.runtime.semantic.read_all(), session_id)
        self.assertEqual(len(state["mode_changes"]), 1)
        self.assertTrue(KernelValidator(self.harness.paths, self.harness.schemas).validate().passed)

    def test_at_032_artifact_revision_and_acceptance_bind_exact_versions(self) -> None:
        case_id, session_id, _ = self._active_session(
            "Draft an invented brief",
            mode="artifact_iterate",
            work_units=("synthesis",),
        )
        version_1 = self.interaction.create_artifact_version(
            session_id,
            b"# Invented brief\n\nVersion one.\n",
            purpose="synthetic briefing",
            change_summary="initial synthetic draft",
        )
        version_1_bytes = version_1.object_path.read_bytes()
        feedback = self.interaction.record_artifact_feedback(
            session_id,
            version_1.version["artifact_id"],
            version_1.version["version_id"],
            feedback="Explain the reversible assumption.",
        )
        version_2 = self.interaction.create_artifact_version(
            session_id,
            b"# Invented brief\n\nVersion two explains the reversible assumption.\n",
            artifact_id=version_1.version["artifact_id"],
            prior_version_id=version_1.version["version_id"],
            addressed_feedback_ids=[feedback["payload"]["feedback_id"]],
            purpose="synthetic briefing",
            change_summary="address owner feedback about reversibility",
        )
        accepted = self.interaction.accept_artifact(
            session_id,
            version_2.version["artifact_id"],
            version_2.version["version_id"],
            purpose="use as the accepted synthetic briefing",
        )
        self.assertEqual(version_1.object_path.read_bytes(), version_1_bytes)
        artifacts = fold_artifact_state(self.runtime.semantic.read_all(), case_id=case_id)
        artifact = artifacts[version_1.version["artifact_id"]]
        self.assertEqual(len(artifact["versions"]), 2)
        self.assertEqual(artifact["accepted_version_id"], version_2.version["version_id"])
        self.assertEqual(
            artifact["feedback"][feedback["payload"]["feedback_id"]]["disposition"],
            "addressed",
        )
        self.assertEqual(accepted["actor"]["type"], "owner")

        version_3 = self.interaction.create_artifact_version(
            session_id,
            b"# Invented brief\n\nAn unaccepted third version.\n",
            artifact_id=version_2.version["artifact_id"],
            prior_version_id=version_2.version["version_id"],
            purpose="synthetic briefing",
            change_summary="prove acceptance does not float to later bytes",
        )
        after_version_3 = fold_artifact_state(
            self.runtime.semantic.read_all(), case_id=case_id
        )[version_1.version["artifact_id"]]
        self.assertEqual(
            after_version_3["accepted_version_id"], version_2.version["version_id"]
        )
        self.assertEqual(
            after_version_3["versions"][version_3.version["version_id"]]["status"],
            "working",
        )

        before_model_acceptance = self._canonical_bytes()
        with self.assertRaises(ValidationError) as caught:
            self.runtime.record_reasoning_event(
                session_id,
                "artifact.accepted",
                {
                    "artifact_id": version_3.version["artifact_id"],
                    "version_id": version_3.version["version_id"],
                    "content_sha256": version_3.version["content_sha256"],
                    "purpose": "model must not accept for the owner",
                    "explicit_confirmation": True,
                },
                subject_refs=[
                    version_3.version["artifact_id"],
                    version_3.version["version_id"],
                ],
            )
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.ACTOR_AUTHORITY_INVALID)
        self.assertEqual(self._canonical_bytes(), before_model_acceptance)

        before_invalid = self._canonical_bytes()
        with self.assertRaises(ValidationError) as caught:
            self.runtime.record_reasoning_event(
                session_id,
                "artifact.accepted",
                {
                    "artifact_id": version_3.version["artifact_id"],
                    "version_id": version_3.version["version_id"],
                    "content_sha256": "0" * 64,
                    "purpose": "must not float to changed bytes",
                    "explicit_confirmation": True,
                },
                subject_refs=[
                    version_3.version["artifact_id"],
                    version_3.version["version_id"],
                ],
                actor={"type": "owner", "id": "owner"},
            )
        self.assertEqual(
            caught.exception.issues[0].code, ErrorCode.ARTIFACT_REFERENCE_INVALID
        )
        self.assertEqual(self._canonical_bytes(), before_invalid)
        event_types = [event["event_type"] for event in self.runtime.semantic.read_all()]
        self.assertNotIn("owner_decision.recorded", event_types)
        self.assertNotIn("promotion.approved", event_types)
        self.assertNotIn("action.proposed", event_types)
        self.assertTrue(KernelValidator(self.harness.paths, self.harness.schemas).validate().passed)

    def test_at_033_current_work_is_derived_and_owner_transitions_are_explicit(self) -> None:
        _, session_id, _ = self._active_session(
            "What do I have today in this invented case?",
            mode="status_review",
            work_units=("context_assessment",),
        )
        proposed = self.interaction.propose_work_item(
            session_id,
            "Consider an invented follow-up",
            due_on="2026-09-02",
        )
        waiting = self.interaction.record_owner_work_item(
            session_id,
            "Request the invented dependency",
            next_review_on="2026-09-02",
        )
        self.interaction.change_work_item_status(
            session_id,
            waiting["payload"]["work_item_id"],
            "waiting",
            reason="waiting on an invented party",
            blocker="invented party",
        )
        finished = self.interaction.record_owner_work_item(
            session_id,
            "Complete the invented preparation",
        )
        self.interaction.change_work_item_status(
            session_id,
            finished["payload"]["work_item_id"],
            "done",
            reason="owner explicitly completed it",
        )
        initial_view = build_current_work_state(
            self.runtime.semantic.read_all(),
            as_of_date="2026-09-02",
            time_zone="America/New_York",
        )
        self.assertEqual(
            [item["work_item_id"] for item in initial_view["proposed_work_items"]],
            [proposed["payload"]["work_item_id"]],
        )
        self.interaction.change_work_item_status(
            session_id,
            proposed["payload"]["work_item_id"],
            "open",
            reason="owner accepts this proposed follow-up",
        )
        bytes_before_read = self._canonical_bytes()
        first = build_current_work_state(
            self.runtime.semantic.read_all(),
            as_of_date="2026-09-02",
            time_zone="America/New_York",
        )
        second = build_current_work_state(
            self.runtime.semantic.read_all(),
            as_of_date="2026-09-02",
            time_zone="America/New_York",
        )
        self.assertEqual(first, second)
        self.assertEqual(self._canonical_bytes(), bytes_before_read)
        items = fold_work_items(self.runtime.semantic.read_all())
        self.assertEqual(items[proposed["payload"]["work_item_id"]]["status"], "open")
        self.assertEqual(items[waiting["payload"]["work_item_id"]]["status"], "waiting")
        self.assertEqual(items[finished["payload"]["work_item_id"]]["status"], "done")
        self.assertIn(proposed["payload"]["work_item_id"], first["due_or_overdue_ids"])
        self.assertIn(waiting["payload"]["work_item_id"], first["review_due_ids"])

        before_bad_date = self._canonical_bytes()
        with self.assertRaises(ValidationError) as caught:
            self.interaction.propose_work_item(
                session_id,
                "Invalid invented calendar item",
                due_on="2026-99-99",
            )
        self.assertEqual(
            caught.exception.issues[0].code, ErrorCode.EVENT_TYPE_SEMANTICS_INVALID
        )
        self.assertEqual(self._canonical_bytes(), before_bad_date)

        before_invalid = self._canonical_bytes()
        with self.assertRaises(ValidationError) as caught:
            self.runtime.record_reasoning_event(
                session_id,
                "work_item.status_changed",
                {
                    "work_item_id": waiting["payload"]["work_item_id"],
                    "from_status": "waiting",
                    "to_status": "done",
                    "reason": "model must not mark owner work done",
                    "priority": None,
                    "due_on": None,
                    "next_review_on": "2026-09-02",
                    "blocker": "invented party",
                    "explicit_confirmation": True,
                },
                subject_refs=[waiting["payload"]["work_item_id"]],
            )
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.ACTOR_AUTHORITY_INVALID)
        self.assertEqual(self._canonical_bytes(), before_invalid)

    def test_at_034_normalized_journey_is_adapter_independent(self) -> None:
        codex = self._run_normalized_adapter_journey("codex")
        chatgpt_work = self._run_normalized_adapter_journey("chatgpt_work")
        self.assertEqual(codex, chatgpt_work)

    @staticmethod
    def _run_normalized_adapter_journey(adapter_name: str) -> dict:
        harness = Harness()
        try:
            registry = PackageRegistry(
                harness.paths,
                harness.schemas,
                id_factory=harness.ids,
                clock=harness.tick,
            )
            install_synthetic_catalog(registry)
            runtime = CaseSessionRuntime(
                harness.paths,
                harness.schemas,
                id_factory=harness.ids,
                clock=harness.tick,
                correlation_id="normalized-interaction-packet",
            )
            triage = UniversalTriage(
                registry,
                harness.schemas,
                id_factory=harness.ids,
                clock=harness.tick,
            )
            router = RoutingRuntime(runtime, registry)
            interaction = InteractionRuntime(
                runtime,
                id_factory=harness.ids,
                clock=harness.tick,
            )
            case = runtime.create_case("Adapter-neutral invented journey")
            session = runtime.create_session(case["case_id"], "Explore an invented brief")
            session_id = session["session_id"]
            plan = triage.plan(
                TriageRequest(
                    "Explore an invented brief",
                    required_work_units=("source_comprehension",),
                    preferred_framework_id="framework_specialist",
                    preferred_interaction_mode="explore",
                )
            )
            router.apply(session_id, plan)
            runtime.transition_session(session_id, "authorized", reason="normalized local scope")
            runtime.transition_session(session_id, "active", reason="begin normalized journey")
            changed = router.change_interaction_mode(
                session_id,
                plan,
                new_mode="artifact_iterate",
                reason="produce a reviewed invented brief",
                required_work_units=["source_comprehension", "synthesis"],
                framework_id="framework_synthesis",
                skill_ids=["skill_comprehension", "skill_synthesis"],
            )
            version_1 = interaction.create_artifact_version(
                session_id,
                b"adapter-neutral version one",
                purpose="adapter-neutral proof",
                change_summary="initial version",
            )
            feedback = interaction.record_artifact_feedback(
                session_id,
                version_1.version["artifact_id"],
                version_1.version["version_id"],
                feedback="add the invented qualification",
            )
            version_2 = interaction.create_artifact_version(
                session_id,
                b"adapter-neutral version two with the invented qualification",
                artifact_id=version_1.version["artifact_id"],
                prior_version_id=version_1.version["version_id"],
                addressed_feedback_ids=[feedback["payload"]["feedback_id"]],
                purpose="adapter-neutral proof",
                change_summary="address qualification feedback",
            )
            interaction.accept_artifact(
                session_id,
                version_2.version["artifact_id"],
                version_2.version["version_id"],
                purpose="accepted adapter-neutral proof",
            )
            runtime.close_session(
                session_id,
                disposition="no_decision",
                reason="artifact acceptance is not an owner decision",
            )

            fresh_runtime = CaseSessionRuntime(
                harness.paths,
                harness.schemas,
                id_factory=harness.ids,
                clock=harness.tick,
                correlation_id="normalized-interaction-packet",
            )
            status_session = fresh_runtime.create_session(
                case["case_id"], "What do I have today?"
            )
            status_plan = triage.plan(
                TriageRequest(
                    "What do I have today?",
                    required_work_units=("context_assessment",),
                    preferred_framework_id="framework_specialist",
                    preferred_interaction_mode="status_review",
                )
            )
            RoutingRuntime(fresh_runtime, registry).apply(
                status_session["session_id"], status_plan
            )
            fresh_runtime.transition_session(
                status_session["session_id"], "authorized", reason="normalized local scope"
            )
            fresh_runtime.transition_session(
                status_session["session_id"], "active", reason="open normalized status review"
            )
            fresh_interaction = InteractionRuntime(
                fresh_runtime,
                id_factory=harness.ids,
                clock=harness.tick,
            )
            work_item = fresh_interaction.propose_work_item(
                status_session["session_id"], "Consider the accepted invented brief"
            )
            events = fresh_runtime.semantic.read_all()
            artifacts = fold_artifact_state(events, case_id=case["case_id"])
            artifact = artifacts[version_1.version["artifact_id"]]
            current_work = build_current_work_state(
                events,
                as_of_date="2026-09-02",
                time_zone="America/New_York",
            )
            validation = KernelValidator(harness.paths, harness.schemas).validate()
            if not validation.passed:
                raise AssertionError(
                    f"{adapter_name} normalized journey failed: {validation.issues}"
                )
            return {
                "initial_mode": "explore",
                "changed_mode": changed["plan"]["interaction"]["mode"],
                "version_hashes": [
                    artifact["versions"][version_id]["content_sha256"]
                    for version_id in sorted(artifact["versions"])
                ],
                "accepted_version": artifact["accepted_version_id"],
                "status_mode": fold_interaction_state(
                    events, status_session["session_id"]
                )["contract"]["mode"],
                "work_status": fold_work_items(events)[
                    work_item["payload"]["work_item_id"]
                ]["status"],
                "accepted_artifact_count": len(current_work["accepted_artifacts"]),
                "owner_decision_count": sum(
                    event["event_type"] == "owner_decision.recorded" for event in events
                ),
            }
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()
