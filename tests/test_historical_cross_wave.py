"""Hostile-synthetic H2C-X01-X08 cross-wave reconciliation tests."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.historical_activity import (
    HistoricalActivityCaps,
    HistoricalActivityCoordinator,
    SafeLogicalParser,
)
from vault_next.historical_cross_wave import (
    HistoricalCrossWaveCoordinator,
    HistoricalCrossWaveError,
    PreparedCrossWaveReconciliation,
)


class HistoricalCrossWaveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-h2x-", dir="/private/tmp")
        self.root = Path(self.temporary.name)
        self.cross = HistoricalCrossWaveCoordinator(self.harness.schemas)
        self.activity = HistoricalActivityCoordinator(
            self.root, self.harness.schemas, None, id_factory=self.harness.ids
        )
        self.parent = {
            "parent_event_id": "event_h1_synthetic",
            "parent_manifest_digest": "a" * 64,
            "catalogue_digest": "0" * 64,
        }
        self.records = (
            self._record("vault:file:first.md", "First meeting\nFirst cited decision\n"),
            self._record("vault:file:second.md", "Second meeting\nSecond cited follow-up\n"),
            self._record("vault:file:third.md", "Third meeting\nThird cited outcome\n"),
        )
        self.catalogue = self._catalogue()
        self.parent["catalogue_digest"] = self.catalogue["catalogue_digest"]
        self.first = self._observation(
            self.records[0], "artifact_first", "2026-08-01T10:00:00Z",
            ("pricing", "cinde"),
        )
        self.second = self._observation(
            self.records[1], "artifact_second", "2026-08-02T10:00:00Z", ("pricing",),
        )
        self.third = self._observation(
            self.records[2], "artifact_third", "2026-08-03T10:00:00Z", ("cinde",),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    @staticmethod
    def _member(member_ref: str, material: bytes) -> dict:
        return {
            "member_ref": member_ref, "source_class": "legacy_vault",
            "profile": "markdown_text", "content_sha256": sha256_hex(material),
            "byte_count": len(material),
        }

    def _record(self, member_ref: str, text: str):
        material = text.encode()
        return SafeLogicalParser(HistoricalActivityCaps()).parse(
            self._member(member_ref, material), material
        )[0]

    def _catalogue(self) -> dict:
        catalogue = {
            "schema_version": "1.0",
            "component": "vault-next-historical-reconstruction/1.0.0",
            "parent_event_id": "event_h1_synthetic",
            "parent_manifest_digest": "a" * 64,
            "entries": [
                {
                    "member_ref": record.member_ref,
                    "lane_id": "vault", "member_id": record.member_ref.split(":", 1)[1],
                    "relative_locator": record.member_ref.split(":", 2)[-1],
                    "profile": "markdown_text", "byte_count": len(record.content.encode()),
                    "content_sha256": record.object_digest,
                    "duplicate_group": record.object_digest,
                    "source_class": "legacy_vault",
                }
                for record in self.records
            ],
            "excluded_member_count": 0,
        }
        catalogue["catalogue_digest"] = canonical_sha256(catalogue)
        return catalogue

    @staticmethod
    def _semantic(label: str, citation: str, **extra) -> dict:
        return {"label": label, "citation_refs": [citation], **extra}

    def _observation(
        self, record, identifier: str, started_at: str, strands: tuple[str, ...],
        *, ended_at: str | None = None,
    ) -> dict:
        first, second = (anchor["anchor_id"] for anchor in record.anchors[:2])
        times = [
            {
                "field": "event_started_at", "value": started_at,
                "earliest": None, "latest": None, "precision": "instant",
                "basis": "explicit_content", "confidence": "high",
                "citation_refs": [first], "conflicts": [], "timezone_assumption": None,
            }
        ]
        if ended_at:
            times.append(
                {
                    "field": "event_ended_at", "value": ended_at,
                    "earliest": None, "latest": None, "precision": "instant",
                    "basis": "explicit_content", "confidence": "high",
                    "citation_refs": [first], "conflicts": [], "timezone_assumption": None,
                }
            )
        payload = {
            "item_class": "meeting_debrief", "temporal_assertions": times,
            "people": [self._semantic("Invented Person", first, role="participant")],
            "meeting_types": [self._semantic("staff_meeting", first)],
            "strands": [
                self._semantic(value, second, merge_authorized=False) for value in strands
            ],
            "inputs": [self._semantic("invented transcript", first)],
            "generated_artifacts": [self._semantic("invented debrief", second)],
            "skill_triggers": [],
            "statements": [self._semantic("invented statement", second, kind="proposal")],
            "owner_dispositions": [self._semantic("historical", second, state="source_reported")],
            "conflicts": [], "omissions": [], "child_event_occurrences": [],
        }
        observation = self.activity.build_item_observation(record, self.parent, payload)
        observation["observation_id"] = identifier
        observation["observation_digest"] = canonical_sha256(
            {key: value for key, value in observation.items() if key != "observation_digest"}
        )
        return observation

    def _coverage(
        self, observations=(), calibrated=(), dispositions=None, memberships=None
    ) -> dict:
        return self.cross.coverage_register(
            catalogue=self.catalogue, observations=tuple(observations),
            calibrated_member_refs=tuple(calibrated), dispositions=dispositions,
            cohort_memberships=memberships,
        )

    def _relationship(self, subject: dict, obj: dict, **extra) -> dict:
        return self.cross.build_relationship(
            relationship_id=extra.pop("relationship_id", "candidate-first-second"),
            subject_ref=subject["observation_id"], object_ref=obj["observation_id"],
            predicate=extra.pop("predicate", "supports"),
            evidence_refs=(subject["citation_refs"][0], obj["citation_refs"][0]),
            **extra,
        )

    def test_h2c_x01_calibration_is_coverage_only_and_never_admission(self) -> None:
        register = self._coverage(calibrated=(self.records[0].member_ref,))
        self.assertEqual(register["counts"]["calibrated_only"], 1)
        self.assertEqual(register["counts"]["admitted"], 0)
        self.assertFalse(any(self.root.iterdir()))

    def test_h2c_x02_exactly_once_lineage_and_append_only_revision(self) -> None:
        coverage = self._coverage(
            observations=(self.first,),
            memberships={self.records[0].member_ref: ("cohort-1",)},
        )
        first = self.cross.prepare_incremental(
            cohort_id="cohort-1", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(self.first,), prior_observations=(), prior_lineages=(),
            relationships=(), prior_relationships=(), selected_prior_endpoint_digests=(),
            coverage_register=coverage,
        )
        lineage = first.package["lineages"][0]
        revised = self.activity.revise_item_observation(
            self.first, self.records[0], self.parent,
            {
                "item_class": self.first["item_class"],
                **{
                    key: deepcopy(self.first[key])
                    for key in (
                        "temporal_assertions", "people", "meeting_types", "strands", "inputs",
                        "generated_artifacts", "skill_triggers", "statements", "owner_dispositions",
                        "conflicts", "omissions", "child_event_occurrences",
                    )
                },
            },
        )
        second = self.cross.prepare_incremental(
            cohort_id="cohort-2", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(revised,), prior_observations=(self.first,),
            prior_lineages=(lineage,), relationships=(), prior_relationships=(),
            selected_prior_endpoint_digests=(), coverage_register=coverage,
            prior_cohort_digests=(first.package["reconciliation_digest"],),
        )
        self.assertEqual(len(second.package["lineages"]), 1)
        self.assertEqual(
            [item["observation_version"] for item in second.package["lineages"][0]["versions"]],
            [1, 2],
        )
        hostile = deepcopy(revised)
        hostile["observation_id"] = "artifact_second_identity"
        hostile["observation_digest"] = canonical_sha256(
            {key: value for key, value in hostile.items() if key != "observation_digest"}
        )
        with self.assertRaises(HistoricalCrossWaveError):
            self.cross.prepare_incremental(
                cohort_id="cohort-hostile", catalogue_digest=self.catalogue["catalogue_digest"],
                new_observations=(hostile,), prior_observations=(self.first,),
                prior_lineages=(lineage,), relationships=(), prior_relationships=(),
                selected_prior_endpoint_digests=(), coverage_register=coverage,
            )

    def test_h2c_x03_independently_cited_multistrand_not_cohort_derived(self) -> None:
        coverage = self._coverage(
            observations=(self.first,),
            memberships={self.records[0].member_ref: ("cohort-1",)},
        )
        prepared = self.cross.prepare_incremental(
            cohort_id="cohort-1", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(self.first,), prior_observations=(), prior_lineages=(),
            relationships=(), prior_relationships=(), selected_prior_endpoint_digests=(),
            coverage_register=coverage,
        )
        self.assertEqual(set(prepared.package["global_views"]["strands"]), {"cinde", "pricing"})
        hostile = deepcopy(self.first)
        hostile["strands"][0]["label"] = "cohort-1"
        hostile["observation_digest"] = canonical_sha256(
            {key: value for key, value in hostile.items() if key != "observation_digest"}
        )
        with self.assertRaises(HistoricalCrossWaveError):
            self.cross.prepare_incremental(
                cohort_id="cohort-1", catalogue_digest=self.catalogue["catalogue_digest"],
                new_observations=(hostile,), prior_observations=(), prior_lineages=(),
                relationships=(), prior_relationships=(), selected_prior_endpoint_digests=(),
                coverage_register=coverage,
            )

    def test_h2c_x04_exact_prior_endpoint_scope_rejects_hidden_expansion(self) -> None:
        relationship = self._relationship(self.second, self.first)
        coverage = self._coverage(
            observations=(self.first, self.second),
            memberships={
                self.records[0].member_ref: ("cohort-1",),
                self.records[1].member_ref: ("cohort-2",),
            },
        )
        prepared = self.cross.prepare_incremental(
            cohort_id="cohort-2", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(self.second,), prior_observations=(self.first,), prior_lineages=(),
            relationships=(relationship,), prior_relationships=(),
            selected_prior_endpoint_digests=(self.first["observation_digest"],),
            coverage_register=coverage,
        )
        self.assertEqual(
            prepared.package["prior_endpoint_digests"], [self.first["observation_digest"]]
        )
        with self.assertRaises(HistoricalCrossWaveError):
            self.cross.prepare_incremental(
                cohort_id="cohort-2", catalogue_digest=self.catalogue["catalogue_digest"],
                new_observations=(self.second,), prior_observations=(self.first, self.third),
                prior_lineages=(), relationships=(relationship,), prior_relationships=(),
                selected_prior_endpoint_digests=(
                    self.first["observation_digest"], self.third["observation_digest"]
                ),
                coverage_register=coverage,
            )

    def test_h2c_x05_temporal_reconciliation_retains_impossible_ordering(self) -> None:
        impossible = self._observation(
            self.records[2], "artifact_impossible", "2026-08-03T12:00:00Z", ("cinde",),
            ended_at="2026-08-03T11:00:00Z",
        )
        coverage = self._coverage(
            observations=(impossible,),
            memberships={self.records[2].member_ref: ("cohort-time",)},
        )
        prepared = self.cross.prepare_incremental(
            cohort_id="cohort-time", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(impossible,), prior_observations=(), prior_lineages=(),
            relationships=(), prior_relationships=(), selected_prior_endpoint_digests=(),
            coverage_register=coverage,
        )
        fields = {item["field"] for item in prepared.package["temporal_reconciliation"]["assertions"]}
        self.assertTrue({"event_started_at", "event_ended_at", "recorded_at"} <= fields)
        self.assertEqual(
            prepared.package["temporal_reconciliation"]["findings"][0]["kind"],
            "impossible_ordering",
        )

    def test_h2c_x06_relationship_versions_append_and_reject_mutation_or_adoption(self) -> None:
        first = self._relationship(self.second, self.first)
        revised = self._relationship(
            self.second, self.first, prior=first, status="source_reported", confidence="high"
        )
        self.assertEqual(revised["relationship_version"], 2)
        self.assertEqual(revised["predecessor_digest"], first["relationship_digest"])
        with self.assertRaises(HistoricalCrossWaveError):
            self.cross.build_relationship(
                relationship_id=first["relationship_id"],
                subject_ref=self.second["observation_id"], object_ref=self.third["observation_id"],
                predicate="supports", evidence_refs=(self.second["citation_refs"][0],), prior=first,
            )
        with self.assertRaises(Exception):
            self.cross.build_relationship(
                relationship_id="owner-adopted", subject_ref=self.second["observation_id"],
                object_ref=self.first["observation_id"], predicate="supports",
                evidence_refs=(self.second["citation_refs"][0],), status="owner_confirmed",
            )

    def test_h2c_x07_coverage_and_global_views_rebuild_identically(self) -> None:
        coverage = self._coverage(
            observations=(self.first,), calibrated=(self.records[1].member_ref,),
            dispositions={self.records[2].member_ref: ("deferred", "future cohort")},
            memberships={self.records[0].member_ref: ("cohort-1",)},
        )
        prepared = self.cross.prepare_incremental(
            cohort_id="cohort-1", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(self.first,), prior_observations=(), prior_lineages=(),
            relationships=(), prior_relationships=(), selected_prior_endpoint_digests=(),
            coverage_register=coverage,
        )
        derived = self.root / "derived"
        first = self.cross.rebuild_views(derived, (prepared,))
        (derived / "global-reconciliation.json").unlink()
        second = self.cross.verify_rebuild(derived, (prepared,))
        self.assertEqual(first, second)
        self.assertEqual(coverage["counts"]["admitted"], 1)
        self.assertEqual(coverage["counts"]["calibrated_only"], 1)
        self.assertEqual(coverage["counts"]["deferred"], 1)

    def test_h2c_x08_full_corpus_closure_preserves_parent_packages(self) -> None:
        relationship = self._relationship(self.second, self.first)
        coverage = self._coverage(
            observations=(self.first, self.second),
            memberships={
                self.records[0].member_ref: ("cohort-1",),
                self.records[1].member_ref: ("cohort-2",),
            },
        )
        incremental = self.cross.prepare_incremental(
            cohort_id="cohort-2", catalogue_digest=self.catalogue["catalogue_digest"],
            new_observations=(self.second,), prior_observations=(self.first,), prior_lineages=(),
            relationships=(relationship,), prior_relationships=(),
            selected_prior_endpoint_digests=(self.first["observation_digest"],),
            coverage_register=coverage,
        )
        frozen = deepcopy(incremental.package)
        closure = self.cross.prepare_full_corpus(
            closure_id="closure-1", catalogue_digest=self.catalogue["catalogue_digest"],
            observations=(self.first, self.second),
            lineages=tuple(incremental.package["lineages"]), relationships=(relationship,),
            coverage_register=coverage,
            cohort_digests=(incremental.package["reconciliation_digest"],),
        )
        self.assertEqual(incremental.package, frozen)
        self.assertEqual(closure.package["reconciliation_kind"], "full_corpus")
        self.assertTrue(closure.package["candidate_only"])
        self.assertTrue(closure.package["no_current_work"])
        hostile = deepcopy(closure.package)
        hostile["no_current_work"] = False
        hostile["reconciliation_digest"] = canonical_sha256(
            {key: value for key, value in hostile.items() if key != "reconciliation_digest"}
        )
        with self.assertRaises(HistoricalCrossWaveError):
            self.cross.rebuild_views(
                self.root / "hostile", (PreparedCrossWaveReconciliation(hostile),)
            )


if __name__ == "__main__":
    unittest.main()
