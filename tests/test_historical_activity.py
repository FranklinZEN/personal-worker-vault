"""Hostile-synthetic S6-H2-C historical activity reconstruction tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.historical_activity import (
    CODEX_MANIFEST_PROFILE,
    CODEX_MARKDOWN_PROFILE,
    CONVERSATION_METHOD,
    CUTOFF,
    ITEM_METHOD,
    PURPOSE,
    RELATIONSHIP_METHOD,
    HistoricalActivityCaps,
    HistoricalActivityCoordinator,
    HistoricalActivityError,
    PreparedHistoricalActivity,
    SafeLogicalParser,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeHistoricalActivityAuthority:
    """Purpose-limited existing-v2 double with no Keychain or persistent authority access."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_historical_activity_reconstruction(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-16T00:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = canonical_bytes({"fixture": "historical-activity-display", "receipt": receipt})
        signed = canonical_bytes({"fixture": "historical-activity-signed", "receipt": receipt})
        self.records[receipt["receipt_id"]] = receipt, display, signed
        return receipt

    def verify_historical_activity_reconstruction(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("hostile manifest substitution")
        return receipt

    def read_historical_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        self.verify_historical_activity_reconstruction(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_historical_activity_reconstruction(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("hostile archived evidence substitution")
        return self.verify_historical_activity_reconstruction(receipt_id, manifest)


class HistoricalActivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-h2c-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeHistoricalActivityAuthority(self.harness)
        self.coordinator = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )
        self.parent = {
            "parent_event_id": "event_synthetic_h1",
            "parent_manifest_digest": "a" * 64,
            "catalogue_digest": "b" * 64,
        }
        self.item_record, self.conversation_record = self._records()

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

    def _records(self):
        parser = SafeLogicalParser(HistoricalActivityCaps())
        item = b"Meeting 2026-09-11\nOwner asked for a cited draft.\nDecision remained proposed.\n"
        item_record = parser.parse(
            self._member("vault:file:meeting.md", "legacy_vault", "markdown_text", item), item
        )[0]
        conversation = canonical_bytes(
            [
                {
                    "uuid": "conversation-invented",
                    "chat_messages": [
                        {"uuid": "owner-1", "sender": "human", "text": "Create a debrief."},
                        {"uuid": "assistant-1", "sender": "assistant", "text": "Draft created."},
                    ],
                }
            ]
        )
        conversation_record = parser.parse(
            self._member(
                "claude:zip:conversations.json", "claude_export", "json", conversation
            ),
            conversation,
        )[0]
        return item_record, conversation_record

    @staticmethod
    def _time(anchor: str, value: str | None = "2026-09-11T14:00:00Z") -> dict:
        unknown = value is None
        return {
            "field": "event_started_at",
            "value": value,
            "earliest": None,
            "latest": None,
            "precision": "unknown" if unknown else "instant",
            "basis": "unknown" if unknown else "explicit_content",
            "confidence": "unavailable" if unknown else "high",
            "citation_refs": [] if unknown else [anchor],
            "conflicts": [],
            "timezone_assumption": None,
        }

    @staticmethod
    def _semantic(label: str, anchor: str, **extra) -> dict:
        return {"label": label, "citation_refs": [anchor], **extra}

    def _item_payload(self, *, unknown_time: bool = False) -> dict:
        anchor = self.item_record.anchors[0]["anchor_id"]
        second = self.item_record.anchors[1]["anchor_id"]
        return {
            "item_class": "meeting_debrief",
            "temporal_assertions": [self._time(anchor, None if unknown_time else "2026-09-11T14:00:00Z")],
            "people": [self._semantic("Invented Person", anchor, role="participant")],
            "meeting_types": [self._semantic("staff_meeting", anchor)],
            "strands": [self._semantic("invented-workstream", anchor, merge_authorized=False)],
            "inputs": [self._semantic("meeting transcript", anchor)],
            "generated_artifacts": [self._semantic("meeting debrief", second)],
            "skill_triggers": [
                self._semantic(
                    "meeting-debrief", second, basis="source_reported",
                    evidence_type="artifact_declared_method",
                )
            ],
            "statements": [self._semantic("A proposal was recorded.", second, kind="proposal")],
            "owner_dispositions": [self._semantic("revision requested", second, state="revise")],
            "conflicts": [],
            "omissions": [{"label": "owner unavailable", "citation_refs": [], "citation_unavailable": True}],
            "child_event_occurrences": [],
        }

    def _conversation_payload(self) -> dict:
        owner = self.conversation_record.anchors[0]["anchor_id"]
        assistant = self.conversation_record.anchors[1]["anchor_id"]
        return {
            "temporal_assertions": [
                {
                    **self._time(owner, "2026-09-12T10:00:00Z"),
                    "field": "conversation_started_at",
                    "basis": "export_structured",
                }
            ],
            "owner_intents": [self._semantic("create a debrief", owner)],
            "inputs": [self._semantic("owner prompt", owner)],
            "skill_triggers": [
                self._semantic(
                    "meeting-debrief", owner, basis="explicitly_invoked",
                    evidence_type="owner_explicit_request",
                )
            ],
            "outputs": [self._semantic("assistant draft", assistant)],
            "revisions": [self._semantic("first revision", assistant, revision=1)],
            "owner_dispositions": [self._semantic("not yet accepted", owner, state="unavailable")],
            "effects": [self._semantic("no save and no action", owner, state="none")],
            "conflicts": [],
            "omissions": [],
        }

    def _observations(self):
        item = self.coordinator.build_item_observation(
            self.item_record, self.parent, self._item_payload()
        )
        conversation = self.coordinator.build_conversation_observation(
            self.conversation_record, self.parent, self._conversation_payload()
        )
        return item, conversation

    def _reconstruction(self, observations):
        item, conversation = observations
        item_ref = item["citation_refs"][0]
        conversation_ref = conversation["citation_refs"][0]
        relation = {
            "relationship_id": "candidate-relation-1",
            "subject_ref": conversation["observation_id"],
            "object_ref": item["observation_id"],
            "predicate": "candidate_generated",
            "status": "candidate",
            "basis_type": "content_evidence",
            "evidence_refs": [conversation_ref, item_ref],
            "method_version": RELATIONSHIP_METHOD,
            "confidence": "medium",
            "effective_at": None,
            "conflicts": [],
            "omissions": [],
        }
        view = lambda label: [{"label": label, "citation_refs": [item_ref]}]
        return self.coordinator.build_reconstruction(
            observations,
            {
                "relationships": [relation],
                "clusters": [
                    {
                        "cluster_id": "candidate-cluster-1",
                        "member_observation_ids": [
                            item["observation_id"], conversation["observation_id"]
                        ],
                        "candidate_only": True,
                    }
                ],
                "exceptions": [
                    {"label": "missing attachment", "citation_refs": [], "citation_unavailable": True}
                ],
                "primary": {
                    "title": "Historical Activity and Artifact Map — 2026-08-01 onward",
                    "markdown": "# Historical Activity and Artifact Map\n\nInvented cited history.\n",
                    "citation_refs": [item_ref, conversation_ref],
                },
                "views": {
                    "daily_timeline": view("2026-09-11"),
                    "strands": view("invented-workstream"),
                    "people": view("Invented Person as participant"),
                    "meeting_types": view("staff_meeting"),
                    "artifact_lineage": view("conversation to debrief candidate"),
                    "missing_evidence": view("missing attachment"),
                },
            },
        )

    def _prepared(self) -> PreparedHistoricalActivity:
        observations = self._observations()
        records = (self.item_record, self.conversation_record)
        return self.coordinator.prepare(
            bundle_id="private_bundle_synthetic",
            parent=self.parent,
            selected_member_refs=tuple(dict.fromkeys(record.member_ref for record in records)),
            records=records,
            item_observations=(observations[0],),
            conversation_observations=(observations[1],),
            reconstruction=self._reconstruction(observations),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_h2c_t01_parent_and_order_reject_substitution(self) -> None:
        prepared = self._prepared()
        self.assertEqual(prepared.manifest["parent_event_id"], self.parent["parent_event_id"])
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.prepare(
                bundle_id="private_bundle_synthetic", parent=self.parent,
                selected_member_refs=tuple(reversed(prepared.manifest["selected_member_refs"])),
                records=(self.item_record, self.conversation_record),
                item_observations=(prepared.package["item_observations"][0],),
                conversation_observations=(prepared.package["conversation_observations"][0],),
                reconstruction=prepared.package["reconstruction"],
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )

    def test_h2c_t02_temporal_policy_and_unresolved_dates(self) -> None:
        anchor = self.item_record.anchors[0]["anchor_id"]
        self.assertEqual(
            self.coordinator.cutoff_disposition([self._time(anchor, "2026-08-01T00:00:00Z")]),
            "eligible",
        )
        self.assertEqual(
            self.coordinator.cutoff_disposition([self._time(anchor, "2026-07-31T23:59:59Z")]),
            "excluded_before_cutoff",
        )
        unknown = self.coordinator.build_item_observation(
            self.item_record, self.parent, self._item_payload(unknown_time=True)
        )
        self.assertEqual(
            self.coordinator.cutoff_disposition(unknown["temporal_assertions"]), "date_unavailable"
        )
        self.assertEqual(CUTOFF, "2026-08-01T00:00:00Z")

    def test_h2c_t03_item_observation_requires_exact_citations(self) -> None:
        observation = self._observations()[0]
        self.assertEqual(observation["method_version"], ITEM_METHOD)
        self.assertEqual(observation["item_class"], "meeting_debrief")
        payload = self._item_payload()
        payload["statements"][0]["citation_refs"] = ["invented:missing-anchor"]
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_item_observation(self.item_record, self.parent, payload)

    def test_h2c_t04_conversation_keeps_execution_stages_distinct(self) -> None:
        observation = self._observations()[1]
        self.assertEqual(observation["method_version"], CONVERSATION_METHOD)
        self.assertNotEqual(observation["owner_intents"], observation["outputs"])
        self.assertEqual(observation["effects"][0]["state"], "none")
        jsonl = b'{"type":"user","uuid":"line-1","message":{"content":"invented"}}\n'
        session = SafeLogicalParser(HistoricalActivityCaps()).parse(
            self._member(
                "claude_sessions:zip:invented-session.jsonl",
                "claude_export",
                "opaque_binary",
                jsonl,
            ),
            jsonl,
        )[0]
        self.assertEqual(session.logical_record_id, "invented-session")
        self.assertEqual(session.anchors[0]["kind"], "jsonl_record")

    def test_h2c_t04a_jsonl_finite_float_is_stably_anchored_and_nonfinite_rejected(self) -> None:
        parser = SafeLogicalParser(HistoricalActivityCaps())
        finite = b'{"type":"tool","uuid":"line-1","durationSeconds":1.25}\n'
        member = self._member(
            "claude_sessions:zip:invented-float.jsonl", "claude_export", "opaque_binary", finite
        )
        first = parser.parse(member, finite)[0]
        second = parser.parse(member, finite)[0]
        self.assertEqual(first.logical_record_digest, second.logical_record_digest)
        self.assertIn("$vault_next_json_float_hex", first.content)
        hostile = b'{"type":"tool","uuid":"line-1","durationSeconds":NaN}\n'
        with self.assertRaises(HistoricalActivityError):
            parser.parse(
                self._member(
                    "claude_sessions:zip:invented-nan.jsonl", "claude_export", "opaque_binary", hostile
                ),
                hostile,
            )

    def test_h2c_t04b_jsonl_literal_newline_is_repaired_with_line_span(self) -> None:
        parser = SafeLogicalParser(HistoricalActivityCaps())
        material = (
            b'{"type":"user","uuid":"line-1","text":"first\nsecond"}\n'
            b'{"type":"assistant","uuid":"line-2","text":"third"}\n'
        )
        record = parser.parse(
            self._member(
                "claude_sessions:zip:invented-multiline.jsonl",
                "claude_export",
                "opaque_binary",
                material,
            ),
            material,
        )[0]
        self.assertEqual(len(record.anchors), 2)
        self.assertEqual(record.anchors[0]["locator"], "lines:1-2")
        self.assertEqual(record.anchors[1]["locator"], "line:3")

    def test_h2c_t05_people_roles_cannot_substitute(self) -> None:
        payload = self._item_payload()
        payload["people"][0]["role"] = "participant_and_audience"
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_item_observation(self.item_record, self.parent, payload)

    def test_h2c_t06_relationship_and_skill_bases_remain_distinct(self) -> None:
        item, conversation = self._observations()
        self.assertEqual(item["skill_triggers"][0]["basis"], "source_reported")
        self.assertEqual(conversation["skill_triggers"][0]["basis"], "explicitly_invoked")
        reconstruction = self._reconstruction((item, conversation))
        self.assertEqual(reconstruction["relationships"][0]["status"], "candidate")
        altered = self._conversation_payload()
        altered["skill_triggers"][0]["basis"] = "owner_confirmed"
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_conversation_observation(
                self.conversation_record, self.parent, altered
            )

    def test_h2c_t07_same_bytes_retain_distinct_provenance(self) -> None:
        material = b"Invented duplicate meeting bytes.\n"
        parser = SafeLogicalParser(HistoricalActivityCaps())
        first = parser.parse(
            self._member("vault:file:a.md", "legacy_vault", "markdown_text", material), material
        )[0]
        second = parser.parse(
            self._member("vault:file:b.md", "legacy_vault", "markdown_text", material), material
        )[0]
        self.assertEqual(first.object_digest, second.object_digest)
        self.assertNotEqual(first.logical_record_digest, second.logical_record_digest)
        self.assertEqual(len(self.coordinator.build_packs((first, second))[0].records), 2)

    def test_h2c_t08_reconstruction_cannot_add_an_unknown_endpoint(self) -> None:
        observations = self._observations()
        reconstruction = self._reconstruction(observations)
        payload = {
            key: deepcopy(reconstruction[key])
            for key in ("relationships", "clusters", "exceptions", "primary", "views")
        }
        payload["relationships"][0]["object_ref"] = "unknown-source-record"
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_reconstruction(observations, payload)

    def test_h2c_t09_taxonomy_drift_and_unsupported_records_fail_closed(self) -> None:
        payload = self._item_payload()
        payload["meeting_types"][0]["label"] = "invented_meeting_type"
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_item_observation(self.item_record, self.parent, payload)
        binary = b"not-a-supported-profile"
        parser = SafeLogicalParser(HistoricalActivityCaps())
        with self.assertRaises(HistoricalActivityError):
            parser.parse(
                self._member("vault:file:data.bin", "legacy_vault", "opaque_binary", binary), binary
            )

    def test_h2c_t10_batches_are_bounded_deterministic_and_digest_verified(self) -> None:
        packs = self.coordinator.build_packs((self.item_record, self.conversation_record))
        again = self.coordinator.build_packs((self.item_record, self.conversation_record))
        self.assertEqual([pack.pack_digest for pack in packs], [pack.pack_digest for pack in again])
        small = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, self.authority,
            caps=HistoricalActivityCaps(max_pack_records=1, max_pack_chars=250_000),
            id_factory=self.harness.ids,
        )
        self.assertEqual(len(small.build_packs((self.item_record, self.conversation_record))), 2)
        changed = replace(self.item_record, content=self.item_record.content + "mutation")
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_packs((changed,))

    def test_h2c_t11_candidate_barriers_reject_recomputed_mutation(self) -> None:
        prepared = self._prepared()
        package = deepcopy(prepared.package)
        package["no_current_work"] = False
        package["package_digest"] = canonical_sha256(
            {key: value for key, value in package.items() if key != "package_digest"}
        )
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.authorize(PreparedHistoricalActivity(prepared.manifest, package))

    def test_h2c_t12_views_are_cited_primary_first_and_rebuildable(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        workspace = self.root / "workspace" / "History"
        self.assertTrue((workspace / "Historical Activity and Artifact Map.md").is_file())
        for name in (
            "Daily Timeline.md", "Strands.md", "People.md", "Meeting Types.md",
            "Artifact Lineage.md", "Missing Evidence.md",
        ):
            self.assertTrue((workspace / name).is_file())
        database = sqlite3.connect(self.root / "derived" / "historical-activity" / "views.sqlite3")
        try:
            self.assertEqual(database.execute("SELECT COUNT(*) FROM views").fetchone()[0], 7)
        finally:
            database.close()
        (workspace / "Daily Timeline.md").unlink()
        self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"])
        self.assertTrue((workspace / "Daily Timeline.md").is_file())
        self.assertTrue(result.event_id)

    def test_h2c_t13_interruption_and_decline_expose_no_event(self) -> None:
        prepared = self._prepared()
        event_root = self.root / "canonical" / "historical-activity-events"
        self.assertFalse(event_root.exists())
        receipt = self.coordinator.authorize(prepared)
        interrupted = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, self.authority,
            id_factory=self.harness.ids, fail_before_event=True,
        )
        with self.assertRaises(HistoricalActivityError):
            interrupted.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(list(event_root.iterdir()) if event_root.exists() else [], [])

    def test_h2c_t14_restart_idempotence_and_mirror_rollback_preserve_parents(self) -> None:
        h1 = self.root / "canonical" / "archive-preservation-events" / "h1.json"
        w1 = self.root / "canonical" / "events" / "w1.json"
        h1.parent.mkdir(exist_ok=True)
        h1.write_bytes(b"h1-sentinel")
        w1.write_bytes(b"w1-sentinel")
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        first = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        second = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(second.status, "already_complete")
        self.assertEqual(first.event_id, second.event_id)
        self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"])
        rollback = self.coordinator.append_disposable_mirror_rollback(first.event_id)
        self.assertTrue(rollback["parent_events_unchanged"])
        self.assertEqual(h1.read_bytes(), b"h1-sentinel")
        self.assertEqual(w1.read_bytes(), b"w1-sentinel")

    def test_h2c_r01_large_jsonl_uses_stable_cited_overlap_chunks(self) -> None:
        entries = []
        for index in range(12):
            entries.append(
                canonical_bytes(
                    {
                        "type": "user" if index % 2 == 0 else "assistant",
                        "uuid": f"message-{index:02d}",
                        "message": {"content": "hostile invented " + (str(index) * 60)},
                    }
                ).decode("utf-8")
            )
        material = ("\n".join(entries) + "\n").encode("utf-8")
        parser = SafeLogicalParser(HistoricalActivityCaps(max_pack_chars=500))
        record = parser.parse(
            self._member(
                "claude_sessions:zip:large-invented.jsonl", "claude_export",
                "opaque_binary", material,
            ),
            material,
        )[0]
        coordinator = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, self.authority,
            caps=HistoricalActivityCaps(max_pack_chars=500), id_factory=self.harness.ids,
        )
        first = coordinator.build_packs((record,))
        second = coordinator.build_packs((record,))
        self.assertGreater(len(first), 1)
        self.assertEqual([pack.pack_digest for pack in first], [pack.pack_digest for pack in second])
        chunks = [entry for pack in first for entry in pack.records]
        self.assertTrue(all(len(entry["content"]) <= 500 for entry in chunks))
        self.assertEqual(chunks[0]["chunk"]["overlap_anchor_ids"], [])
        for previous, current in zip(chunks, chunks[1:]):
            self.assertEqual(
                current["chunk"]["overlap_anchor_ids"],
                [previous["chunk"]["anchor_ids"][-1]],
            )
            self.assertEqual(
                current["chunk"]["anchor_ids"][0], previous["chunk"]["anchor_ids"][-1]
            )
        covered = {anchor for entry in chunks for anchor in entry["chunk"]["anchor_ids"]}
        self.assertEqual(covered, {anchor["anchor_id"] for anchor in record.anchors})

    def test_h2c_r02_multi_meeting_children_are_cited_and_typed(self) -> None:
        payload = self._item_payload()
        first = self.item_record.anchors[0]["anchor_id"]
        second = self.item_record.anchors[1]["anchor_id"]
        payload["item_class"] = "multi_meeting_bundle"
        payload["meeting_types"] = [self._semantic("mixed", first)]
        payload["child_event_occurrences"] = [
            {
                "occurrence_id": "meeting-1", "label": "First invented meeting",
                "temporal_assertions": [self._time(first, "2026-09-11T14:00:00Z")],
                "people": [self._semantic("First Person", first, role="participant")],
                "meeting_types": [self._semantic("staff_meeting", first)],
                "strands": [self._semantic("first-strand", first, merge_authorized=False)],
                "citation_refs": [first], "confidence": "high", "conflicts": [], "omissions": [],
            },
            {
                "occurrence_id": "meeting-2", "label": "Second invented meeting",
                "temporal_assertions": [self._time(second, "2026-09-11T15:00:00Z")],
                "people": [self._semantic("Second Person", second, role="participant")],
                "meeting_types": [self._semantic("project_alignment", second)],
                "strands": [self._semantic("second-strand", second, merge_authorized=False)],
                "citation_refs": [second], "confidence": "high", "conflicts": [], "omissions": [],
            },
        ]
        observation = self.coordinator.build_item_observation(
            self.item_record, self.parent, payload
        )
        self.assertEqual(observation["item_class"], "multi_meeting_bundle")
        self.assertEqual(len(observation["child_event_occurrences"]), 2)
        self.assertIn(second, observation["citation_refs"])
        payload["child_event_occurrences"][1]["citation_refs"] = ["hostile:substitution"]
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_item_observation(self.item_record, self.parent, payload)

    def test_h2c_r03_company_all_hands_and_skill_evidence_guard(self) -> None:
        payload = self._item_payload()
        anchor = self.item_record.anchors[0]["anchor_id"]
        payload["meeting_types"] = [self._semantic("company_all_hands", anchor)]
        observation = self.coordinator.build_item_observation(
            self.item_record, self.parent, payload
        )
        self.assertEqual(observation["meeting_types"][0]["label"], "company_all_hands")
        conversation = self._conversation_payload()
        conversation["skill_triggers"][0]["evidence_type"] = "available_tool_metadata"
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_conversation_observation(
                self.conversation_record, self.parent, conversation
            )
        del conversation["skill_triggers"][0]["evidence_type"]
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.build_conversation_observation(
                self.conversation_record, self.parent, conversation
            )

    def test_h2c_g01_codex_markdown_has_stable_line_anchors_and_strict_counts(self) -> None:
        material = """---
source: codex-app task reader
kind: conversation-export
project: vault
project_id: local-invented
thread_id: 01a00000-acde-7abc-8def-0123456789ab
title: \"Hostile invented conversation\"
status_at_export: idle
completeness: complete_for_exposed_history
created_at: 2026-09-01T10:00:00Z
updated_at: 2026-09-01T10:10:00Z
exported_at: 2026-09-18T10:00:00Z
turns: 1
messages: 2
truncated_message_items: 0
---

# Codex conversation — Hostile invented conversation

## Turn 1 — 09/01/2026, 06:00:00 EDT

### User

Available skills: meeting-debrief. Do not infer invocation.

### Assistant — final answer

No action or save occurred.
""".encode("utf-8")
        parser = SafeLogicalParser(HistoricalActivityCaps(max_pack_chars=120))
        record = parser.parse(
            self._member("codex:zip:invented.md", "codex_export", "markdown_text", material),
            material,
        )[0]
        self.assertEqual(record.logical_record_id, "01a00000-acde-7abc-8def-0123456789ab")
        self.assertEqual(record.profile, CODEX_MARKDOWN_PROFILE)
        self.assertTrue(all(anchor["kind"] == "codex_line" for anchor in record.anchors))
        coordinator = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, self.authority,
            caps=HistoricalActivityCaps(max_pack_chars=120), id_factory=self.harness.ids,
        )
        packs = coordinator.build_packs((record,))
        self.assertGreater(len(packs), 1)
        covered = {
            anchor for pack in packs for entry in pack.records
            for anchor in entry["chunk"]["anchor_ids"]
        }
        self.assertEqual(covered, {anchor["anchor_id"] for anchor in record.anchors})

        changed = material.replace(b"messages: 2", b"messages: 3")
        with self.assertRaises(HistoricalActivityError):
            parser.parse(
                self._member(
                    "codex:zip:invented.md", "codex_export", "markdown_text", changed
                ),
                changed,
            )

    def test_h2c_g02_codex_manifest_uses_json_pointer_anchors_and_rejects_opaque(self) -> None:
        material = canonical_bytes(
            {
                "schema_version": 1,
                "export_name": "invented-export",
                "exported_at": "2026-09-18T10:00:00Z",
                "project": {"id": "local-invented", "label": "vault", "path": "/invented"},
                "inclusion_policy": {"included": ["text"], "excluded": ["tools"]},
                "coverage": {"visible_project_threads": 1},
                "totals": {"threads": 1},
                "threads": [
                    {
                        "id": "01a00000-invented", "title": "Invented", "status": "idle",
                        "created_at": "2026-09-01T10:00:00Z",
                        "updated_at": "2026-09-01T10:10:00Z", "turn_count": 1,
                        "message_count": 2, "file": "conversations/invented.md",
                        "completeness": "complete_for_exposed_history",
                        "truncated_message_items": 0, "non_text_references": 0,
                    }
                ],
            }
        )
        parser = SafeLogicalParser(HistoricalActivityCaps())
        record = parser.parse(
            self._member("codex:zip:manifest.json", "codex_export", "json", material), material
        )[0]
        self.assertEqual(record.profile, CODEX_MANIFEST_PROFILE)
        self.assertIn("/threads/0", {anchor["locator"] for anchor in record.anchors})
        opaque = b"{\"hostile\":true}\n"
        with self.assertRaises(HistoricalActivityError):
            parser.parse(
                self._member(
                    "codex:zip:normalized/conversations.jsonl", "codex_export",
                    "opaque_binary", opaque,
                ),
                opaque,
            )
    def test_h2c_r04_observation_revision_retains_identity(self) -> None:
        item, conversation = self._observations()
        revised_item = self.coordinator.revise_item_observation(
            item, self.item_record, self.parent, self._item_payload()
        )
        revised_conversation = self.coordinator.revise_conversation_observation(
            conversation, self.conversation_record, self.parent, self._conversation_payload()
        )
        self.assertEqual(revised_item["observation_id"], item["observation_id"])
        self.assertEqual(revised_conversation["observation_id"], conversation["observation_id"])
        self.assertEqual(revised_item["observation_version"], 2)
        self.assertEqual(revised_conversation["observation_version"], 2)
        substituted = deepcopy(item)
        substituted["object_digest"] = "0" * 64
        with self.assertRaises(HistoricalActivityError):
            self.coordinator.revise_item_observation(
                substituted, self.item_record, self.parent, self._item_payload()
            )

    def test_h2c_r05_legacy_observations_remain_valid_and_revisable(self) -> None:
        item, conversation = self._observations()
        legacy_item = deepcopy(item)
        legacy_item.pop("child_event_occurrences")
        legacy_item["parser_version"] = "safe_logical_parser/1.0.0"
        legacy_item["method_version"] = "historical_item_observer/1.0.0"
        legacy_item["prompt_version"] = "historical_item_observer/1.0.0"
        for trigger in legacy_item["skill_triggers"]:
            trigger.pop("evidence_type")
        legacy_item["observation_digest"] = canonical_sha256(
            {key: value for key, value in legacy_item.items() if key != "observation_digest"}
        )
        legacy_conversation = deepcopy(conversation)
        legacy_conversation["parser_version"] = "safe_logical_parser/1.0.0"
        legacy_conversation["method_version"] = "historical_conversation_observer/1.0.0"
        legacy_conversation["prompt_version"] = "historical_conversation_observer/1.0.0"
        for trigger in legacy_conversation["skill_triggers"]:
            trigger.pop("evidence_type")
        legacy_conversation["observation_digest"] = canonical_sha256(
            {
                key: value for key, value in legacy_conversation.items()
                if key != "observation_digest"
            }
        )
        revised_item = self.coordinator.revise_item_observation(
            legacy_item, self.item_record, self.parent, self._item_payload()
        )
        revised_conversation = self.coordinator.revise_conversation_observation(
            legacy_conversation, self.conversation_record, self.parent,
            self._conversation_payload(),
        )
        self.assertEqual(revised_item["observation_id"], legacy_item["observation_id"])
        self.assertEqual(
            revised_conversation["observation_id"], legacy_conversation["observation_id"]
        )


if __name__ == "__main__":
    unittest.main()
