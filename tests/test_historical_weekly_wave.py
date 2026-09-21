"""Hostile source-free tests for weekly operating reconstruction and cross-wave continuity."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.historical_activity import (
    HistoricalActivityCaps,
    HistoricalActivityCoordinator,
    SafeLogicalParser,
)
from vault_next.historical_weekly_wave import (
    HistoricalWeeklyWaveCoordinator,
    HistoricalWeeklyWaveError,
)


class HistoricalWeeklyWaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-weekly-", dir="/private/tmp")
        self.root = Path(self.temporary.name)
        self.activity = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, None, id_factory=self.harness.ids
        )
        self.weekly = HistoricalWeeklyWaveCoordinator(self.harness.schemas)
        self.parent = {
            "parent_event_id": "event_h1_synthetic",
            "parent_manifest_digest": "a" * 64,
            "catalogue_digest": "b" * 64,
        }
        self.first_record = self._record(
            "vault:file:first.md", b"Meeting 2026-08-04\nProject Alpha advanced.\n"
        )
        self.second_record = self._record(
            "vault:file:second.md", b"Meeting 2026-08-11\nProject Alpha was explicitly stalled.\n"
        )
        self.first = self._item(self.first_record, "2026-08-04T10:00:00Z", "artifact_first")
        self.second = self._item(self.second_record, "2026-08-11T10:00:00Z", "artifact_second")
        self.conversation = self._conversation()

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    @staticmethod
    def _member(member_ref: str, source_class: str, profile: str, material: bytes) -> dict:
        return {
            "member_ref": member_ref,
            "source_class": source_class,
            "profile": profile,
            "content_sha256": sha256_hex(material),
            "byte_count": len(material),
        }

    def _record(self, member_ref: str, material: bytes):
        return SafeLogicalParser(HistoricalActivityCaps()).parse(
            self._member(member_ref, "legacy_vault", "markdown_text", material), material
        )[0]

    @staticmethod
    def _semantic(label: str, citation: str, **extra) -> dict:
        return {"label": label, "citation_refs": [citation], **extra}

    @staticmethod
    def _time(citation: str, value: str, *, field: str = "event_started_at") -> dict:
        return {
            "field": field,
            "value": value,
            "earliest": None,
            "latest": None,
            "precision": "instant",
            "basis": "explicit_content" if field == "event_started_at" else "export_structured",
            "confidence": "high",
            "citation_refs": [citation],
            "conflicts": [],
            "timezone_assumption": None,
        }

    def _item(self, record, when: str, identifier: str) -> dict:
        first, second = (anchor["anchor_id"] for anchor in record.anchors[:2])
        observation = self.activity.build_item_observation(
            record,
            self.parent,
            {
                "item_class": "meeting_debrief",
                "temporal_assertions": [self._time(first, when)],
                "people": [self._semantic("Invented Person", first, role="participant")],
                "meeting_types": [self._semantic("staff_meeting", first)],
                "strands": [self._semantic("operations", first, merge_authorized=False)],
                "inputs": [self._semantic("invented input", first)],
                "generated_artifacts": [self._semantic("invented debrief", second)],
                "skill_triggers": [],
                "statements": [self._semantic("invented status", second, kind="proposal")],
                "owner_dispositions": [
                    self._semantic("historical only", second, state="source_reported")
                ],
                "conflicts": [],
                "omissions": [],
                "child_event_occurrences": [],
            },
        )
        observation["observation_id"] = identifier
        observation["observation_digest"] = canonical_sha256(
            {key: value for key, value in observation.items() if key != "observation_digest"}
        )
        return observation

    def _conversation(self) -> dict:
        material = canonical_bytes(
            [
                {
                    "uuid": "conversation-invented",
                    "chat_messages": [
                        {"uuid": "owner-1", "sender": "human", "text": "Review Alpha."},
                        {"uuid": "assistant-1", "sender": "assistant", "text": "Draft."},
                    ],
                }
            ]
        )
        record = SafeLogicalParser(HistoricalActivityCaps()).parse(
            self._member("claude:conversations.json", "claude_export", "json", material),
            material,
        )[0]
        owner, assistant = (anchor["anchor_id"] for anchor in record.anchors[:2])
        observation = self.activity.build_conversation_observation(
            record,
            self.parent,
            {
                "temporal_assertions": [
                    self._time(owner, "2026-08-05T10:00:00Z", field="conversation_started_at")
                ],
                "owner_intents": [self._semantic("review project", owner)],
                "inputs": [self._semantic("owner prompt", owner)],
                "skill_triggers": [],
                "outputs": [self._semantic("assistant draft", assistant)],
                "revisions": [self._semantic("first revision", assistant, revision=1)],
                "owner_dispositions": [
                    self._semantic("not accepted", owner, state="unavailable")
                ],
                "effects": [self._semantic("no save", owner, state="none")],
                "conflicts": [],
                "omissions": [],
            },
        )
        observation["observation_id"] = "conversation_first"
        observation["observation_digest"] = canonical_sha256(
            {key: value for key, value in observation.items() if key != "observation_digest"}
        )
        return observation

    def _strand(self, observations, projects=("project-alpha",)) -> dict:
        return {
            "strand_id": "strand-operations",
            "label": "Operations",
            "observation_ids": [item["observation_id"] for item in observations],
            "project_ids": list(projects),
            "citation_refs": [item["citation_refs"][0] for item in observations],
            "confidence": "high",
            "aliases": [],
            "conflicts": [],
            "omissions": [],
        }

    def _project(
        self,
        observation: dict,
        *,
        movement: str = "advanced",
        basis: str = "source_reported",
        start: str = "reported_planning",
        end: str = "reported_active",
        movement_refs: list[str] | None = None,
    ) -> dict:
        citation = observation["citation_refs"][0]
        return {
            "project_id": "project-alpha",
            "label": "Project Alpha",
            "strand_ids": ["strand-operations"],
            "observation_ids": [observation["observation_id"]],
            "start_status": start,
            "end_status": end,
            "movement": movement,
            "movement_basis": basis,
            "membership_citation_refs": [citation],
            "movement_citation_refs": [citation] if movement_refs is None else movement_refs,
            "confidence": "high",
            "aliases": [],
            "conflicts": [],
            "omissions": [],
        }

    def _decision(self, observation: dict) -> dict:
        return {
            "decision_id": "decision-alpha",
            "label": "Proceed with Alpha",
            "state": "source_reported_decision",
            "project_ids": ["project-alpha"],
            "observation_ids": [observation["observation_id"]],
            "citation_refs": [observation["citation_refs"][0]],
            "confidence": "high",
            "conflicts": [],
            "omissions": [],
        }

    def _wave_one(self, *, observations=None, projects=None):
        observations = observations or (self.first, self.conversation)
        projects = projects or (self._project(self.first),)
        return self.weekly.build_wave(
            wave_id="week-2026-08-03",
            week_start="2026-08-03T00:00:00Z",
            week_end="2026-08-10T00:00:00Z",
            catalogue_digest="b" * 64,
            observations=tuple(observations),
            strands=(self._strand(observations),),
            projects=tuple(projects),
            decisions=(self._decision(self.first),),
        )

    def _wave_two(self, *, project=None):
        project = project or self._project(
            self.second,
            movement="stalled_reported",
            basis="source_reported",
            start="reported_active",
            end="reported_blocked",
        )
        return self.weekly.build_wave(
            wave_id="week-2026-08-10",
            week_start="2026-08-10T00:00:00Z",
            week_end="2026-08-17T00:00:00Z",
            catalogue_digest="b" * 64,
            observations=(self.second,),
            strands=(self._strand((self.second,)),),
            projects=(project,),
            completeness="complete",
        )

    def test_weekly_01_requires_exact_monday_calendar_week(self) -> None:
        wave = self._wave_one()
        self.assertEqual(wave.package["week_start"], "2026-08-03T00:00:00Z")
        with self.assertRaises(HistoricalWeeklyWaveError):
            self.weekly.build_wave(
                wave_id="not-a-week",
                week_start="2026-08-04T00:00:00Z",
                week_end="2026-08-11T00:00:00Z",
                catalogue_digest="b" * 64,
                observations=(self.first,),
                strands=(self._strand((self.first,)),),
                projects=(self._project(self.first),),
            )

    def test_weekly_02_chronology_does_not_manufacture_semantic_relationship(self) -> None:
        wave = self._wave_one()
        self.assertFalse(wave.package["chronology_creates_relationships"])
        self.assertEqual(
            wave.package["views"]["weekly_overview"]["unassigned_observation_count"], 1
        )
        self.assertNotIn("relationships", wave.package)

    def test_weekly_03_multistrand_project_requires_cited_membership(self) -> None:
        extra = deepcopy(self._strand((self.first,), projects=("project-alpha",)))
        extra["strand_id"] = "strand-governance"
        extra["label"] = "Governance"
        project = self._project(self.first)
        project["strand_ids"].append("strand-governance")
        wave = self.weekly.build_wave(
            wave_id="week-2026-08-03",
            week_start="2026-08-03T00:00:00Z",
            week_end="2026-08-10T00:00:00Z",
            catalogue_digest="b" * 64,
            observations=(self.first,),
            strands=(self._strand((self.first,)), extra),
            projects=(project,),
        )
        self.assertEqual(len(wave.package["projects"][0]["strand_ids"]), 2)
        hostile = deepcopy(project)
        hostile["membership_citation_refs"] = []
        with self.assertRaises(HistoricalWeeklyWaveError):
            self.weekly.build_wave(
                wave_id="week-2026-08-03",
                week_start="2026-08-03T00:00:00Z",
                week_end="2026-08-10T00:00:00Z",
                catalogue_digest="b" * 64,
                observations=(self.first,),
                strands=(self._strand((self.first,)), extra),
                projects=(hostile,),
            )

    def test_weekly_04_absence_is_not_a_reported_stall(self) -> None:
        no_movement = self._project(
            self.first,
            movement="no_observed_movement",
            basis="absence_only",
            start="reported_planning",
            end="reported_planning",
            movement_refs=[],
        )
        wave = self._wave_one(observations=(self.first,), projects=(no_movement,))
        self.assertTrue(wave.package["no_observed_movement_is_not_stalled"])
        hostile = deepcopy(no_movement)
        hostile["movement"] = "stalled_reported"
        with self.assertRaises(HistoricalWeeklyWaveError):
            self._wave_one(observations=(self.first,), projects=(hostile,))

    def test_weekly_05_inventory_counts_meetings_conversations_inputs_and_artifacts(self) -> None:
        inventory = self._wave_one().package["inventory"]
        self.assertEqual(inventory["observation_count"], 2)
        self.assertEqual(inventory["meeting_count"], 1)
        self.assertEqual(inventory["conversation_count"], 1)
        self.assertEqual(inventory["input_count"], 2)
        self.assertEqual(inventory["generated_artifact_count"], 2)

    def test_weekly_06_cross_wave_status_transition_requires_exact_evidence(self) -> None:
        first, second = self._wave_one(), self._wave_two()
        citation = second.package["projects"][0]["movement_citation_refs"][0]
        reconciled = self.weekly.reconcile(
            waves=(first, second),
            transitions=(
                {
                    "project_id": "project-alpha",
                    "from_wave_id": "week-2026-08-03",
                    "to_wave_id": "week-2026-08-10",
                    "transition": "stalled_reported",
                    "evidence_refs": [citation],
                    "confidence": "high",
                    "conflicts": [],
                    "omissions": [],
                },
            ),
        )
        history = reconciled.package["global_views"]["project_history"]["project-alpha"]
        self.assertEqual(len(history["weekly_states"]), 2)
        self.assertEqual(
            reconciled.package["global_views"]["transition_network"][0]["transition"],
            "stalled_reported",
        )

    def test_weekly_07_alias_and_status_merge_cannot_be_inferred_from_time(self) -> None:
        first, second = self._wave_one(), self._wave_two()
        with self.assertRaises(HistoricalWeeklyWaveError):
            self.weekly.reconcile(
                waves=(first, second),
                project_aliases=(
                    {
                        "canonical_id": "project-alpha",
                        "alias_id": "project-alpha",
                        "evidence_refs": [],
                        "confidence": "low",
                        "conflicts": [],
                    },
                ),
            )

    def test_weekly_08_views_rebuild_byte_identically_without_authority(self) -> None:
        first, second = self._wave_one(), self._wave_two()
        reconciliation = self.weekly.reconcile(waves=(first, second))
        derived = self.root / "derived"
        first_digest = self.weekly.rebuild_views(derived, (first, second), reconciliation)
        stored = (derived / "weekly-operating-views.json").read_bytes()
        second_digest = self.weekly.rebuild_views(derived, (first, second), reconciliation)
        self.assertEqual(first_digest, second_digest)
        self.assertEqual(stored, (derived / "weekly-operating-views.json").read_bytes())
        self.assertTrue(reconciliation.package["candidate_only"])
        self.assertTrue(reconciliation.package["no_current_work"])


if __name__ == "__main__":
    unittest.main()
