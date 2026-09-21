"""Hostile fixture tests for the exact-scope cross-week real-U0 adapter."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vault_next.canonical import canonical_sha256
from vault_next.cross_week_operating_view_real_u0 import (
    RealCrossWeekOperatingViewError,
    RealCrossWeekOperatingViewReader,
    WeeklyEventScope,
)


class RealCrossWeekOperatingViewReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-cross-week-u0-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        self.events = (
            "event_01M2X8WB6YZXWERZ8JV6FY27KW",
            "event_01M2XA9DZDMFKH194H5KFZCSQT",
        )
        self.scopes = tuple(self._write(event, index) for index, event in enumerate(self.events))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, event_id: str, index: int) -> WeeklyEventScope:
        anchor = f"fixture:week:{index}:anchor"
        primary = self._presentation("Primary", anchor, "artifact_digest")
        views = {
            name: self._presentation(name, anchor, "view_digest")
            for name in (
                "timeline", "strands", "project_status_transitions",
                "meeting_conversation_artifact_inventory", "decision_lineage", "people", "missing_evidence",
            )
        }
        observation = {
            "observation_id": f"artifact-week-{index}", "citation_refs": [anchor],
            "item_class": "meeting_debrief",
            "generated_artifacts": [
                {"label": "coverage=primary artifact; relationship=standalone", "citation_refs": [anchor]}
            ],
        }
        conversation = {
            "observation_id": f"conversation-week-{index}", "citation_refs": [anchor],
            "outputs": [{"label": "coverage=supporting evidence; relationship=linked", "citation_refs": [anchor]}],
        }
        package = {
            "schema_version": "1.0", "component": "vault-next-historical-weekly-activity-reconstruction/1.0.0",
            "week_start": f"2026-09-{7 + index * 7:02d}T00:00:00Z",
            "week_end": f"2026-09-{14 + index * 7:02d}T00:00:00Z",
            "candidate_only": True, "no_current_work": True, "no_promotion": True, "no_activation": True,
            "no_u2": True, "primary_artifact": primary, "support_views": views,
            "item_observations": [observation], "conversation_observations": [conversation],
            "weekly_wave": {
                "strands": [{"label": "Operations", "status": "open"}],
                "projects": [{"label": "Project Alpha", "movement": "advanced"}],
            },
        }
        package["package_digest"] = canonical_sha256(package)
        package_path = self.root / "canonical" / "historical-weekly-activity-packages" / package["package_digest"]
        package_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        package_path.write_text(json.dumps(package, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        event = {
            "schema_version": "1.0", "event_id": event_id,
            "publication_type": "historical_weekly_activity_reconstruction", "parent_bindings": [],
            "parent_set_digest": "a" * 64, "catalogue_set_digest": "b" * 64,
            "manifest_digest": "c" * 64, "package_digest": package["package_digest"],
            "receipt_id": "receipt_fixture", "candidate_only": True, "recorded_at": "2026-09-19T00:00:00Z",
            "week_start": package["week_start"], "week_end": package["week_end"],
        }
        event_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{event_id}.json"
        event_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        event_path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return WeeklyEventScope(event_id, package["package_digest"])

    @staticmethod
    def _presentation(title: str, anchor: str, digest: str) -> dict:
        record = {"title": title, "markdown": f"# {title}\n", "citation_refs": [anchor]}
        record[digest] = canonical_sha256(record)
        return record

    def test_xwu0_01_reads_only_two_fixed_package_snapshots(self) -> None:
        before = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        reader = RealCrossWeekOperatingViewReader(self.root, scopes=self.scopes)
        snapshots = reader.snapshots()
        artifacts = reader.primary_artifacts()
        after = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual([item.event_id for item in snapshots], list(self.events))
        self.assertEqual(len(artifacts), 2)
        self.assertTrue(all(item.status == "standalone" for item in artifacts))

    def test_xwu0_02_rejects_event_package_substitution(self) -> None:
        hostile = (self.scopes[0], WeeklyEventScope(self.scopes[1].event_id, self.scopes[0].package_digest))
        with self.assertRaises(RealCrossWeekOperatingViewError):
            RealCrossWeekOperatingViewReader(self.root, scopes=hostile).snapshots()

    def test_xwu0_03_rejects_tampered_package_digest(self) -> None:
        path = self.root / "canonical" / "historical-weekly-activity-packages" / self.scopes[0].package_digest
        package = json.loads(path.read_text())
        package["weekly_wave"]["projects"][0]["label"] = "Changed"
        path.write_text(json.dumps(package), encoding="utf-8")
        with self.assertRaises(RealCrossWeekOperatingViewError):
            RealCrossWeekOperatingViewReader(self.root, scopes=self.scopes).snapshots()

    def test_xwu0_04_rejects_presentation_or_citation_substitution(self) -> None:
        path = self.root / "canonical" / "historical-weekly-activity-packages" / self.scopes[0].package_digest
        package = json.loads(path.read_text())
        package["support_views"]["strands"] = deepcopy(package["support_views"]["strands"])
        package["support_views"]["strands"]["citation_refs"] = ["fixture:substituted"]
        package["support_views"]["strands"]["view_digest"] = canonical_sha256(
            {key: value for key, value in package["support_views"]["strands"].items() if key != "view_digest"}
        )
        package["package_digest"] = canonical_sha256(
            {key: value for key, value in package.items() if key != "package_digest"}
        )
        new_path = self.root / "canonical" / "historical-weekly-activity-packages" / package["package_digest"]
        new_path.write_text(json.dumps(package), encoding="utf-8")
        event_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{self.scopes[0].event_id}.json"
        event = json.loads(event_path.read_text())
        event["package_digest"] = package["package_digest"]
        event_path.write_text(json.dumps(event), encoding="utf-8")
        scopes = (WeeklyEventScope(self.scopes[0].event_id, package["package_digest"]), self.scopes[1])
        with self.assertRaises(RealCrossWeekOperatingViewError):
            RealCrossWeekOperatingViewReader(self.root, scopes=scopes).snapshots()

    def test_xwu0_05_rejects_root_escape_or_extra_scope(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir(mode=0o700)
        with self.assertRaises(RealCrossWeekOperatingViewError):
            RealCrossWeekOperatingViewReader(outside, scopes=self.scopes).snapshots()
        with self.assertRaises(RealCrossWeekOperatingViewError):
            RealCrossWeekOperatingViewReader(self.root, scopes=(self.scopes[0],))

    def test_xwu0_06_accepts_equivalent_utc_and_offset_week_boundaries(self) -> None:
        event_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{self.scopes[0].event_id}.json"
        event = json.loads(event_path.read_text())
        event["week_start"] = "2026-09-07T04:00:00Z"
        event["week_end"] = "2026-09-14T00:00:00Z"
        package_path = (
            self.root / "canonical" / "historical-weekly-activity-packages" / self.scopes[0].package_digest
        )
        package = json.loads(package_path.read_text())
        package["week_start"] = "2026-09-07T00:00:00-04:00"
        package["week_end"] = "2026-09-13T20:00:00-04:00"
        package["package_digest"] = canonical_sha256(
            {key: value for key, value in package.items() if key != "package_digest"}
        )
        new_package = self.root / "canonical" / "historical-weekly-activity-packages" / package["package_digest"]
        new_package.write_text(json.dumps(package), encoding="utf-8")
        event["package_digest"] = package["package_digest"]
        event_path.write_text(json.dumps(event), encoding="utf-8")
        scopes = (WeeklyEventScope(self.scopes[0].event_id, package["package_digest"]), self.scopes[1])
        snapshot = RealCrossWeekOperatingViewReader(self.root, scopes=scopes).snapshots()[0]
        self.assertEqual(snapshot.event_id, self.scopes[0].event_id)

    def test_xwu0_07_allows_only_supplemental_unclassified_exact_anchor(self) -> None:
        path = self.root / "canonical" / "historical-weekly-activity-packages" / self.scopes[0].package_digest
        package = json.loads(path.read_text())
        package["conversation_observations"][0]["outputs"].append(
            {"label": "bounded reviewed evidence anchor", "citation_refs": ["fixture:week:0:anchor"]}
        )
        package["package_digest"] = canonical_sha256(
            {key: value for key, value in package.items() if key != "package_digest"}
        )
        new_path = self.root / "canonical" / "historical-weekly-activity-packages" / package["package_digest"]
        new_path.write_text(json.dumps(package), encoding="utf-8")
        event_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{self.scopes[0].event_id}.json"
        event = json.loads(event_path.read_text())
        event["package_digest"] = package["package_digest"]
        event_path.write_text(json.dumps(event), encoding="utf-8")
        scopes = (WeeklyEventScope(self.scopes[0].event_id, package["package_digest"]), self.scopes[1])
        snapshot = RealCrossWeekOperatingViewReader(self.root, scopes=scopes).snapshots()[0]
        self.assertEqual(snapshot.coverage.selected_count, 2)


if __name__ == "__main__":
    unittest.main()
