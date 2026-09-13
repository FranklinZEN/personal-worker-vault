"""Hostile synthetic S3-A tests for direct investigation, pause/resume, and revision."""

from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from tests.helpers import Harness
from vault_next.catalog import install_synthetic_catalog
from vault_next.errors import ValidationError
from vault_next.interaction import InteractionRuntime
from vault_next.investigation import InvestigationCoordinator
from vault_next.packages import PackageRegistry
from vault_next.routing import RoutingRuntime
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import fold_artifact_state, fold_interaction_state
from vault_next.status_updates import FUNCTION_STATUS, StatusUpdateCoordinator
from vault_next.triage import TriageRequest
from vault_next.triage import UniversalTriage
from vault_next.validator import KernelValidator


class InvestigationCoordinatorTests(unittest.TestCase):
    """Every case, artifact, analysis, and identity in this module is invented."""

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
            correlation_id="synthetic-s3a",
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
        self.coordinator = InvestigationCoordinator(self.runtime, self.harness.schemas)

    def tearDown(self) -> None:
        self.harness.close()

    def _active_session(
        self, question: str, *, mode: str = "explore", work_units: tuple[str, ...] = ("source_comprehension",)
    ) -> tuple[str, str]:
        case = self.runtime.create_case("Invented S3-A case")
        session = self.runtime.create_session(case["case_id"], question)
        plan = self.triage.plan(
            TriageRequest(
                question,
                required_work_units=work_units,
                preferred_interaction_mode=mode,
            )
        )
        self.router.apply(session["session_id"], plan)
        self.runtime.transition_session(
            session["session_id"], "authorized", reason="invented S3-A setup"
        )
        self.runtime.transition_session(
            session["session_id"], "active", reason="invented S3-A setup"
        )
        return case["case_id"], session["session_id"]

    def _request(
        self,
        operation: str,
        *,
        session_id: str | None = None,
        topic: str | None = None,
        analysis_text: str | None = None,
        context_refs: list[str] | None = None,
        checkpoint_event_id: str | None = None,
        checkpoint: dict | None = None,
        revision: dict | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        function_id, mode = {
            "investigate": ("function_investigation", "read"),
            "pause": ("function_investigation_pause", "propose"),
            "resume": ("function_investigation_resume", "read"),
            "revise": ("function_artifact_revision", "propose"),
        }[operation]
        refs = set(context_refs or [])
        if session_id is not None:
            refs.add(session_id)
        if checkpoint_event_id is not None:
            refs.add(checkpoint_event_id)
        if revision is not None:
            refs.update((revision["artifact_id"], revision["version_id"]))
        return {
            "schema_version": "1.0",
            "request": {
                "schema_version": "1.0",
                "request_id": request_id or self.harness.ids.new("request"),
                "idempotency_key": idempotency_key or f"s3a-{operation}-{self.harness.ids.new('request')}",
                "intent": f"Invented S3-A {operation} request",
                "function_ids": [function_id],
                "mode": mode,
                "target_refs": sorted(refs),
                "target_versions": (
                    [
                        {
                            "ref": revision["version_id"],
                            "digest": revision["prior_content_sha256"],
                        }
                    ]
                    if revision is not None
                    else []
                ),
                "policy_version": "1.0",
                "capability_version": "1.0",
                "owner_receipt_ref": None,
            },
            "operation": operation,
            "topic": topic,
            "analysis_text": analysis_text,
            "session_id": session_id,
            "context_refs": context_refs or [],
            "checkpoint_event_id": checkpoint_event_id,
            "checkpoint": checkpoint,
            "revision": revision,
        }

    def _checkpoint(self) -> dict:
        return {
            "summary": "Invented pause retains the reversible constraint and an open question.",
            "state": {
                "working_question": "Which invented option handles the reversible constraint?",
                "assumptions": ["The invented source is reversible"],
            },
            "open_questions": ["Which invented observation distinguishes the options?"],
        }

    def _revision(self, initial: dict, content: str = "# Invented revision\n\nRevised fixture.\n") -> dict:
        from vault_next.canonical import sha256_hex

        return {
            "artifact_id": initial["artifact_id"],
            "version_id": initial["version_id"],
            "prior_content_sha256": initial["content_sha256"],
            "content": content,
            "content_sha256": sha256_hex(content.encode("utf-8")),
            "purpose": "invented S3-A revision",
            "change_summary": "address an invented hostile review comment",
            "media_type": "text/markdown",
        }

    def test_s3a_t01_fresh_direct_investigation_needs_no_status_or_durable_write(self) -> None:
        before = self.runtime.semantic.read_all()
        fresh = InvestigationCoordinator(
            CaseSessionRuntime(
                self.harness.paths,
                self.harness.schemas,
                id_factory=self.harness.ids,
                clock=self.harness.tick,
                correlation_id="fresh-s3a-investigation",
            ),
            self.harness.schemas,
        )
        response = fresh.execute(
            self._request(
                "investigate",
                topic="Invented deep-dive topic",
                analysis_text="Caller-supplied invented analysis; no model generated this text.",
            )
        )
        self.assertEqual(response["result"]["status"], "complete")
        self.assertEqual(response["analysis_text"], "Caller-supplied invented analysis; no model generated this text.")
        self.assertEqual(response["durable_output_refs"], [])
        self.assertEqual(self.runtime.semantic.read_all(), before)

        missing = fresh.execute(self._request("investigate", analysis_text="Invented text"))
        self.assertEqual(missing["result"]["status"], "needs_input")
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s3a_t02_pause_without_capture_is_read_only_and_requested_checkpoint_is_bounded(self) -> None:
        _, session_id = self._active_session("Invented direct pause")
        before = self.runtime.semantic.read_all()
        paused = self.coordinator.execute(self._request("pause", session_id=session_id))
        self.assertEqual(paused["result"]["status"], "complete")
        self.assertEqual(self.runtime.semantic.read_all(), before)

        captured = self.coordinator.execute(
            self._request("pause", session_id=session_id, checkpoint=self._checkpoint())
        )
        self.assertEqual(captured["checkpoint_ref"]["summary"], self._checkpoint()["summary"])
        before_invalid = self.runtime.semantic.read_all()
        invalid = self._request(
            "pause",
            session_id=session_id,
            checkpoint={
                **self._checkpoint(),
                "state": {"messages": ["hostile transcript-shaped fixture"]},
            },
        )
        with self.assertRaises(ValidationError):
            self.coordinator.execute(invalid)
        self.assertEqual(self.runtime.semantic.read_all(), before_invalid)

    def test_s3a_t03_fresh_resume_requires_one_manifest_authorized_checkpoint(self) -> None:
        case_id, original_session = self._active_session("Invented resumable question")
        captured = self.coordinator.execute(
            self._request("pause", session_id=original_session, checkpoint=self._checkpoint())
        )
        checkpoint_event_id = captured["checkpoint_ref"]["event_id"]
        self.runtime.close_session(
            original_session, disposition="no_decision", reason="invented pause"
        )
        resumed = self.runtime.resume_as_new_session(
            original_session,
            authorized_context=[
                {
                    "ref": checkpoint_event_id,
                    "purpose": "resume the exact invented checkpoint",
                    "sensitivity_labels": ["none"],
                }
            ],
        )
        response = InvestigationCoordinator(
            CaseSessionRuntime(
                self.harness.paths,
                self.harness.schemas,
                id_factory=self.harness.ids,
                clock=self.harness.tick,
                correlation_id="fresh-s3a-resume",
            ),
            self.harness.schemas,
        ).execute(
            self._request(
                "resume",
                session_id=resumed["session_id"],
                checkpoint_event_id=checkpoint_event_id,
                context_refs=[checkpoint_event_id],
            )
        )
        self.assertEqual(response["result"]["status"], "complete")
        assert response["checkpoint_ref"] is not None
        self.assertEqual(response["checkpoint_ref"]["state"], self._checkpoint()["state"])
        self.assertEqual(resumed["case_id"], case_id)

        unbound = self.runtime.create_session(case_id, "Invented unbound resume")
        before = self.runtime.semantic.read_all()
        unavailable = self.coordinator.execute(
            self._request(
                "resume",
                session_id=unbound["session_id"],
                checkpoint_event_id=checkpoint_event_id,
                context_refs=[checkpoint_event_id],
            )
        )
        self.assertEqual(unavailable["result"]["status"], "unavailable")
        self.assertEqual(self.runtime.semantic.read_all(), before)

    def test_s3a_t04_exact_revision_creates_one_working_version_without_acceptance_or_work_change(self) -> None:
        case_id, session_id = self._active_session(
            "Invented artifact revision", mode="artifact_iterate", work_units=("synthesis",)
        )
        initial = self.interaction.create_artifact_version(
            session_id,
            b"# Invented draft\n\nVersion one.\n",
            purpose="invented draft",
            change_summary="initial invented version",
        ).version
        initial_bytes = (
            self.harness.paths.artifact_root / "objects" / initial["object_ref"]
        ).read_bytes()
        response = self.coordinator.execute(
            self._request("revise", session_id=session_id, revision=self._revision(initial))
        )
        self.assertEqual(response["result"]["status"], "complete")
        artifacts = fold_artifact_state(self.runtime.semantic.read_all(), case_id=case_id)
        artifact = artifacts[initial["artifact_id"]]
        self.assertEqual(len(artifact["versions"]), 2)
        self.assertEqual(
            (self.harness.paths.artifact_root / "objects" / initial["object_ref"]).read_bytes(),
            initial_bytes,
        )
        types = [event["event_type"] for event in self.runtime.semantic.read_all()]
        self.assertNotIn("artifact.accepted", types)
        self.assertNotIn("work_item.recorded", types)
        self.assertNotIn("work_item.status_changed", types)

    def test_s3a_t05_invalid_changed_cross_case_and_unauthorized_targets_fail_closed(self) -> None:
        first_case, first_session = self._active_session(
            "Invented first revision", mode="artifact_iterate", work_units=("synthesis",)
        )
        initial = self.interaction.create_artifact_version(
            first_session,
            b"# Invented original\n",
            purpose="invented original",
            change_summary="initial",
        ).version
        before = self.runtime.semantic.read_all()

        changed = self._revision(initial)
        changed["prior_content_sha256"] = "f" * 64
        unavailable = self.coordinator.execute(
            self._request("revise", session_id=first_session, revision=changed)
        )
        self.assertEqual(unavailable["result"]["status"], "unavailable")

        hostile = self._revision(initial)
        hostile["content_sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            self.coordinator.execute(
                self._request("revise", session_id=first_session, revision=hostile)
            )

        _, second_session = self._active_session(
            "Invented second revision", mode="artifact_iterate", work_units=("synthesis",)
        )
        cross_case = self.coordinator.execute(
            self._request("revise", session_id=second_session, revision=self._revision(initial))
        )
        self.assertEqual(cross_case["result"]["status"], "unavailable")

        unauthorized = self.coordinator.execute(
            self._request(
                "investigate",
                session_id=first_session,
                topic="Invented bounded context",
                analysis_text="Invented analysis.",
                context_refs=["event_01M2B6JF02123MS2WMP85JW2D5"],
            )
        )
        self.assertEqual(unauthorized["result"]["status"], "unavailable")
        self.assertEqual(
            [event for event in self.runtime.semantic.read_all() if event["case_id"] == first_case],
            [event for event in before if event["case_id"] == first_case],
        )

    def test_s3a_t06_switch_to_unrelated_s2_status_preserves_investigation_checkpoint(self) -> None:
        case_id, session_id = self._active_session("Invented investigation X")
        checkpoint = self.coordinator.execute(
            self._request("pause", session_id=session_id, checkpoint=self._checkpoint())
        )
        item = self.interaction.record_owner_work_item(
            session_id, "Invented unrelated status item"
        )
        status_request = {
            "schema_version": "1.0",
            "request": {
                "schema_version": "1.0",
                "request_id": self.harness.ids.new("request"),
                "idempotency_key": "invented-unrelated-status",
                "intent": "Invented status Y",
                "function_ids": [FUNCTION_STATUS],
                "mode": "read",
                "target_refs": [case_id],
                "target_versions": [],
                "policy_version": "1.0",
                "capability_version": "1.0",
                "owner_receipt_ref": None,
            },
            "status_query": {
                "schema_version": "1.0",
                "case_scope": [case_id],
                "as_of_date": "2026-09-01",
                "time_zone": "UTC",
            },
            "historical_diff_query": None,
            "pending_update": None,
        }
        status = StatusUpdateCoordinator(self.runtime, self.harness.schemas).execute(status_request)
        self.assertEqual(status["result"]["status"], "complete")
        self.assertEqual(
            fold_interaction_state(self.runtime.semantic.read_all(), session_id)["checkpoints"][0]["checkpoint_id"],
            checkpoint["checkpoint_ref"]["checkpoint_id"],
        )
        self.assertEqual(
            status["status_view"]["active_items"][0]["work_item_id"], item["payload"]["work_item_id"]
        )
        self.assertNotIn(
            "work_transaction.committed",
            [event["event_type"] for event in self.runtime.semantic.read_all()],
        )

    def test_s3a_t07_exact_retries_conflicts_and_post_append_recovery_are_truthful(self) -> None:
        _, pause_session = self._active_session("Invented idempotent pause")
        pause_request = self._request(
            "pause",
            session_id=pause_session,
            checkpoint=self._checkpoint(),
            idempotency_key="invented-pause-retry",
        )
        first = self.coordinator.execute(pause_request)
        second = self.coordinator.execute(copy.deepcopy(pause_request))
        self.assertEqual(first, second)
        self.assertEqual(
            len(fold_interaction_state(self.runtime.semantic.read_all(), pause_session)["checkpoints"]),
            1,
        )
        conflict = copy.deepcopy(pause_request)
        conflict["request"]["request_id"] = self.harness.ids.new("request")
        conflict["checkpoint"]["summary"] = "Different invented checkpoint under the same key."
        with self.assertRaises(ValidationError):
            self.coordinator.execute(conflict)

        _, revision_session = self._active_session(
            "Invented crash-safe revision", mode="artifact_iterate", work_units=("synthesis",)
        )
        initial = self.interaction.create_artifact_version(
            revision_session,
            b"# Invented crash fixture\n",
            purpose="invented crash fixture",
            change_summary="initial",
        ).version
        request = self._request(
            "revise",
            session_id=revision_session,
            revision=self._revision(initial, "# Invented recovered revision\n"),
            idempotency_key="invented-revision-recovery",
        )
        with patch.object(self.runtime, "amend_scope", side_effect=RuntimeError("invented crash")):
            with self.assertRaises(RuntimeError):
                self.coordinator.execute(request)
        after_crash = fold_artifact_state(self.runtime.semantic.read_all())
        self.assertEqual(len(after_crash[initial["artifact_id"]]["versions"]), 2)

        recovered = self.coordinator.execute(copy.deepcopy(request))
        self.assertEqual(recovered["result"]["status"], "complete")
        final = fold_artifact_state(self.runtime.semantic.read_all())
        self.assertEqual(len(final[initial["artifact_id"]]["versions"]), 2)
        self.assertIn(
            recovered["artifact_version_ref"]["version_id"],
            self.runtime._session(revision_session).manifest["output_refs"],
        )

    def test_s3a_t08_s2_boundaries_and_ledger_replay_remain_intact(self) -> None:
        response = self.coordinator.execute(
            self._request(
                "investigate",
                topic="Invented compatibility topic",
                analysis_text="Invented analysis with no work update.",
            )
        )
        self.assertEqual(response["result"]["receipt_ref"], None)
        self.assertEqual(response["result"]["committed_watermark"], None)
        self.assertEqual(response["durable_output_refs"], [])
        self.assertTrue(KernelValidator(self.harness.paths, self.harness.schemas).validate().passed)
