"""Hostile-synthetic additive multi-parent weekly publication tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ValidationError
from vault_next.historical_activity import HistoricalActivityCaps, SafeLogicalParser
from vault_next.historical_weekly_activity import (
    COMPONENT,
    PURPOSE,
    HistoricalWeeklyActivityCoordinator,
    HistoricalWeeklyActivityError,
    PreparedHistoricalWeeklyActivity,
    VIEW_NAMES,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout
from vault_next.records import aware_utc_now


class FakeHistoricalWeeklyAuthority:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_historical_weekly_activity_reconstruction(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-19T12:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = canonical_bytes({"fixture": "historical-weekly-display", "receipt": receipt})
        signed = canonical_bytes({"fixture": "historical-weekly-signed", "receipt": receipt})
        self.records[receipt["receipt_id"]] = receipt, display, signed
        return receipt

    def verify_historical_weekly_activity_reconstruction(
        self, receipt_id: str, manifest: dict
    ) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("hostile manifest substitution")
        return receipt

    def read_historical_weekly_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        self.verify_historical_weekly_activity_reconstruction(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_historical_weekly_activity_reconstruction(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("hostile archived evidence substitution")
        return self.verify_historical_weekly_activity_reconstruction(receipt_id, manifest)


class HistoricalWeeklyActivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-h2-mp1-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeHistoricalWeeklyAuthority(self.harness)
        self.coordinator = HistoricalWeeklyActivityCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )
        self.parents = (
            {
                "parent_event_id": "event_synthetic_vault",
                "parent_manifest_digest": "a" * 64,
                "catalogue_digest": "b" * 64,
                "source_lane": "legacy_vault",
            },
            {
                "parent_event_id": "event_synthetic_codex",
                "parent_manifest_digest": "c" * 64,
                "catalogue_digest": "d" * 64,
                "source_lane": "codex_export",
            },
        )
        self.records = self._records()

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    @staticmethod
    def _member(member_ref: str, source_class: str, material: bytes) -> dict:
        return {
            "member_ref": member_ref,
            "source_class": source_class,
            "profile": "markdown_text",
            "content_sha256": sha256_hex(material),
            "byte_count": len(material),
        }

    def _records(self):
        parser = SafeLogicalParser(HistoricalActivityCaps())
        first = b"Meeting 2026-09-01\nProject Alpha advanced after review.\n"
        second = b"Conversation 2026-09-03\nProject Beta remained proposed.\n"
        return (
            parser.parse(self._member("vault:alpha.md", "legacy_vault", first), first)[0],
            parser.parse(self._member("codex:beta.md", "legacy_vault", second), second)[0],
        )

    @staticmethod
    def _semantic(label: str, anchor: str, **extra) -> dict:
        return {"label": label, "citation_refs": [anchor], **extra}

    def _payload(self, record, label: str) -> dict:
        anchor = record.anchors[0]["anchor_id"]
        detail = record.anchors[1]["anchor_id"]
        return {
            "item_class": "meeting_debrief",
            "temporal_assertions": [
                {
                    "field": "event_started_at",
                    "value": "2026-09-01T14:00:00Z",
                    "earliest": None,
                    "latest": None,
                    "precision": "instant",
                    "basis": "explicit_content",
                    "confidence": "high",
                    "citation_refs": [anchor],
                    "conflicts": [],
                    "timezone_assumption": None,
                }
            ],
            "people": [self._semantic("Invented Person", anchor, role="participant")],
            "meeting_types": [self._semantic("project_alignment", anchor)],
            "strands": [self._semantic(label, detail, merge_authorized=False)],
            "inputs": [self._semantic("invented input", anchor)],
            "generated_artifacts": [self._semantic("invented result", detail)],
            "skill_triggers": [],
            "statements": [self._semantic("Invented statement", detail, kind="proposal")],
            "owner_dispositions": [],
            "conflicts": [],
            "omissions": [],
            "child_event_occurrences": [],
        }

    @staticmethod
    def _source(parent: dict, record) -> dict:
        return {
            "parent_event_id": parent["parent_event_id"],
            "parent_manifest_digest": parent["parent_manifest_digest"],
            "catalogue_digest": parent["catalogue_digest"],
            "member_ref": record.member_ref,
            "logical_record_id": record.logical_record_id,
            "object_digest": record.object_digest,
            "parser_identity": "safe_logical_parser/1.1.0",
        }

    @staticmethod
    def _presentation(title: str, anchor: str, *, field: str) -> dict:
        record = {
            "title": title,
            "markdown": f"# {title}\n\nInvented evidence-backed result.\n",
            "citation_refs": [anchor],
        }
        record[field] = canonical_sha256(record)
        return record

    def _prepared(self) -> PreparedHistoricalWeeklyActivity:
        observations = tuple(
            self.coordinator.build_item_observation(
                record,
                {key: parent[key] for key in (
                    "parent_event_id", "parent_manifest_digest", "catalogue_digest"
                )},
                self._payload(record, label),
            )
            for record, parent, label in zip(
                self.records, self.parents, ("alpha", "beta"), strict=True
            )
        )
        parent_set = canonical_sha256(list(self.parents))
        catalogue_set = canonical_sha256([parent["catalogue_digest"] for parent in self.parents])
        observation_digests = [item["observation_digest"] for item in observations]
        fences = {
            "candidate_only": True,
            "no_current_work": True,
            "no_promotion": True,
            "no_activation": True,
            "no_u2": True,
        }
        wave = {
            "schema_version": "1.0",
            "component": "vault-next-historical-weekly-multi-parent-wave/1.0.0",
            "wave_id": "week-2026-08-31",
            "week_start": "2026-08-31T00:00:00Z",
            "week_end": "2026-09-07T00:00:00Z",
            "parent_set_digest": parent_set,
            "catalogue_set_digest": catalogue_set,
            "completeness": "partial",
            "observation_digests": observation_digests,
            "strands": [],
            "projects": [],
            "decisions": [],
            "inventory": {"observation_count": 2},
            "views": {"fixture": True},
            "chronology_creates_relationships": False,
            "no_observed_movement_is_not_stalled": True,
            **fences,
        }
        wave["wave_digest"] = canonical_sha256(wave)
        reconciliation = {
            "schema_version": "1.0",
            "component": "vault-next-historical-weekly-multi-parent-reconciliation/1.0.0",
            "reconciliation_kind": "incremental",
            "cohort_id": "week-2026-08-31",
            "parent_set_digest": parent_set,
            "catalogue_set_digest": catalogue_set,
            "prior_cohort_digests": [],
            "new_observation_digests": observation_digests,
            "prior_endpoint_digests": [],
            "lineages": [],
            "relationships": [],
            "temporal_reconciliation": {"conflicts": []},
            "coverage_register": {"fixture": True},
            "global_views": {"fixture": True},
            **fences,
        }
        reconciliation["reconciliation_digest"] = canonical_sha256(reconciliation)
        anchor = observations[0]["citation_refs"][0]
        primary = self._presentation("Weekly Operating Reconstruction", anchor, field="artifact_digest")
        views = {
            name: self._presentation(name.replace("_", " ").title(), anchor, field="view_digest")
            for name in VIEW_NAMES
        }
        return self.coordinator.prepare(
            bundle_id="private_bundle_synthetic",
            week_start="2026-08-31T00:00:00Z",
            week_end="2026-09-07T00:00:00Z",
            parent_bindings=self.parents,
            selected_sources=tuple(
                self._source(parent, record)
                for parent, record in zip(self.parents, self.records, strict=True)
            ),
            records=self.records,
            item_observations=observations,
            conversation_observations=(),
            weekly_wave=wave,
            cross_wave_reconciliation=reconciliation,
            primary_artifact=primary,
            support_views=views,
            expires_at=aware_utc_now() + timedelta(minutes=10),
        )

    def test_publish_restart_idempotence_fts_and_workspace(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        restarted = self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(restarted.event_id, result.event_id)
        repeated = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(repeated.status, "already_complete")
        database = sqlite3.connect(
            self.root / "derived" / "historical-weekly-activity" / f"{result.event_id}.sqlite3"
        )
        try:
            count = database.execute("SELECT count(*) FROM views").fetchone()[0]
        finally:
            database.close()
        self.assertEqual(count, 1 + len(VIEW_NAMES))
        workspace = self.root / "workspace" / "History" / "Weeks" / result.event_id
        self.assertEqual(len(tuple(workspace.glob("*.md"))), 1 + len(VIEW_NAMES))

    def test_parent_order_substitution_and_omission_rejected(self) -> None:
        prepared = self._prepared()
        for replacement in (
            list(reversed(prepared.manifest["parent_bindings"])),
            prepared.manifest["parent_bindings"][:1],
            [
                prepared.manifest["parent_bindings"][0],
                {
                    **prepared.manifest["parent_bindings"][1],
                    "parent_event_id": "event_substituted",
                },
            ],
        ):
            hostile = deepcopy(prepared.manifest)
            hostile["parent_bindings"] = replacement
            hostile["parent_set_digest"] = canonical_sha256(replacement)
            hostile["catalogue_set_digest"] = canonical_sha256(
                [item["catalogue_digest"] for item in replacement]
            )
            hostile["manifest_digest"] = canonical_sha256(
                {key: value for key, value in hostile.items() if key != "manifest_digest"}
            )
            with self.assertRaises((HistoricalWeeklyActivityError, ValidationError)):
                self.coordinator.authorize(PreparedHistoricalWeeklyActivity(hostile, prepared.package))

    def test_mixed_parent_observation_substitution_rejected(self) -> None:
        prepared = self._prepared()
        hostile_package = deepcopy(prepared.package)
        observation = hostile_package["item_observations"][0]
        observation["parent_event_id"] = self.parents[1]["parent_event_id"]
        observation["parent_manifest_digest"] = self.parents[1]["parent_manifest_digest"]
        observation["catalogue_digest"] = self.parents[1]["catalogue_digest"]
        observation["observation_digest"] = canonical_sha256(
            {key: value for key, value in observation.items() if key != "observation_digest"}
        )
        hostile_package["package_digest"] = canonical_sha256(
            {key: value for key, value in hostile_package.items() if key != "package_digest"}
        )
        with self.assertRaises(HistoricalWeeklyActivityError):
            self.coordinator.authorize(
                PreparedHistoricalWeeklyActivity(prepared.manifest, hostile_package)
            )

    def test_receipt_replay_and_evidence_mutation_rejected(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        (self.root / "evidence" / "historical-weekly-activity" / f"{receipt['receipt_id']}.json").write_bytes(
            b"{}"
        )
        with self.assertRaises(RuntimeError):
            self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"])

    def test_interruption_is_recoverable_with_same_receipt(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        failing = HistoricalWeeklyActivityCoordinator(
            self.root,
            self.harness.schemas,
            self.authority,
            id_factory=self.harness.ids,
            fail_before_event=True,
        )
        with self.assertRaises(HistoricalWeeklyActivityError):
            failing.publish(prepared, receipt_id=receipt["receipt_id"])
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")

    def test_restart_rebuilds_missing_derived_views(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        derived = self.root / "derived" / "historical-weekly-activity" / f"{result.event_id}.json"
        derived.unlink()
        self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"])
        self.assertTrue(derived.is_file())

    def test_disposable_mirror_rollback_preserves_parent_events(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        rollback = self.coordinator.append_disposable_mirror_rollback(result.event_id)
        self.assertTrue(rollback["parent_events_unchanged"])

    def test_duplicate_rerun_with_another_receipt_is_rejected(self) -> None:
        prepared = self._prepared()
        first = self.coordinator.authorize(prepared)
        self.coordinator.publish(prepared, receipt_id=first["receipt_id"])
        second = self.coordinator.authorize(prepared)
        with self.assertRaises(HistoricalWeeklyActivityError):
            self.coordinator.publish(prepared, receipt_id=second["receipt_id"])


if __name__ == "__main__":
    unittest.main()
