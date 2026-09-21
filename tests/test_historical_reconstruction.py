"""Hostile-synthetic S6-H2 catalogue and reconstruction tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.historical_reconstruction import (
    PURPOSE,
    HistoricalReconstructionCoordinator,
    HistoricalReconstructionError,
    HistoricalRelationship,
    PreparedHistoricalReconstruction,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeHistoricalAuthority:
    """Purpose-limited existing-v2 double with no real authority or Keychain access."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_historical_reconstruction(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": "2026-09-16T00:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = {"fixture": "historical-reconstruction", "manifest": manifest, "receipt": receipt}
        signed = {"fixture": "signed-historical-reconstruction", "manifest": manifest, "receipt": receipt}
        self.records[receipt["receipt_id"]] = receipt, canonical_bytes(display), canonical_bytes(signed)
        return receipt

    def verify_historical_reconstruction(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("hostile receipt substitution")
        return receipt

    def read_historical_reconstruction_evidence(self, receipt_id: str, manifest: dict) -> tuple[bytes, bytes]:
        self.verify_historical_reconstruction(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_historical_reconstruction(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (display_root / f"{receipt_id}.json").read_bytes() != display or (
            receipt_root / f"{receipt_id}.json"
        ).read_bytes() != signed:
            raise RuntimeError("hostile archived evidence substitution")
        return self.verify_historical_reconstruction(receipt_id, manifest)


class HistoricalReconstructionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-h2-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeHistoricalAuthority(self.harness)
        self.coordinator = HistoricalReconstructionCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _parent(self) -> tuple[dict, dict]:
        manifest = {
            "schema_version": "1.0", "component": "vault-next-archive-preservation/1.0.0",
            "purpose": "archive_preservation", "authority_id": AUTHORITY_ID,
            "admission_id": "private_admission_synthetic", "bundle_id": "private_bundle_synthetic",
            "lanes": [
                {
                    "lane_id": "claude", "source_class": "claude_export",
                    "source_label": "invented-export", "source_scope_sha256": "a" * 64,
                },
                {
                    "lane_id": "vault", "source_class": "legacy_vault",
                    "source_label": "invented-vault", "source_scope_sha256": "b" * 64,
                },
            ],
            "members": [
                {
                    "lane_id": "claude", "member_id": "zip:conversation.json",
                    "relative_locator": "conversation.json", "byte_count": 43,
                    "content_sha256": "1" * 64, "profile": "json", "disposition": "preserved",
                    "duplicate_group": "1" * 64,
                },
                {
                    "lane_id": "vault", "member_id": "file:meeting.md", "relative_locator": "meeting.md",
                    "byte_count": 43, "content_sha256": "1" * 64, "profile": "markdown_text",
                    "disposition": "preserved", "duplicate_group": "1" * 64,
                },
                {
                    "lane_id": "vault", "member_id": "file:work.md", "relative_locator": "work.md",
                    "byte_count": 29, "content_sha256": "2" * 64, "profile": "markdown_text",
                    "disposition": "preserved", "duplicate_group": "2" * 64,
                },
            ],
            "exclusions": [{
                "lane_id": "vault", "member_id": "symlink:generated", "relative_locator": "generated",
                "disposition": "excluded_unsafe_symlink", "unresolved_link_text_sha256": "e" * 64,
            }],
            "disclosure": "local_only_no_content_index", "retention": "append_only_local_preservation",
            "operations": [
                "stage_opaque_members", "append_one_archive_preservation_event", "build_metadata_catalogue",
            ],
            "expires_at": "2026-09-16T00:10:00Z",
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        event = {
            "event_id": "event_synthetic_h1", "publication_type": "archive_preservation",
            "manifest_digest": manifest["manifest_digest"],
        }
        return event, manifest

    def _prepared(self) -> PreparedHistoricalReconstruction:
        event, parent = self._parent()
        catalogue = self.coordinator.catalogue(event, parent)
        refs = tuple(item["member_ref"] for item in catalogue["entries"])
        relationship = HistoricalRelationship(
            refs[0], refs[1], "same_bytes", "exact_bytes", (refs[0], refs[1]),
            status="structurally_verified", confidence="high",
        )
        return self.coordinator.prepare(
            catalogue=catalogue, bundle_id="private_bundle_synthetic", selected_member_refs=refs,
            relationships=(relationship,),
            primary={"artifact_id": "synthetic-primary", "title": "Invented history"},
            supporting_artifacts=({"artifact_id": "synthetic-support", "title": "Invented evidence"},),
            exceptions=({"code": "unresolved-history", "detail": "invented omission"},),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_h2_t01_t03_catalogue_is_metadata_only_and_preserves_duplicate_provenance(self) -> None:
        event, parent = self._parent()
        catalogue = self.coordinator.catalogue(event, parent)
        self.assertEqual(catalogue["excluded_member_count"], 1)
        self.assertEqual(len(catalogue["entries"]), 3)
        self.assertNotIn("content", catalogue["entries"][0])
        same = [entry for entry in catalogue["entries"] if entry["duplicate_group"] == "1" * 64]
        self.assertEqual({entry["lane_id"] for entry in same}, {"claude", "vault"})
        self.assertEqual({entry["source_class"] for entry in same}, {"claude_export", "legacy_vault"})
        self.assertNotIn("symlink:generated", {entry["member_ref"] for entry in catalogue["entries"]})

    def test_catalogue_accepts_codex_export_as_opaque_distinct_provenance(self) -> None:
        event, parent = self._parent()
        parent["lanes"].append(
            {
                "lane_id": "codex", "source_class": "codex_export",
                "source_label": "invented-codex-export", "source_scope_sha256": "c" * 64,
            }
        )
        parent["members"].append(
            {
                "lane_id": "codex", "member_id": "zip:artifact.md", "relative_locator": "artifact.md",
                "byte_count": 43, "content_sha256": "1" * 64, "profile": "markdown_text",
                "disposition": "preserved", "duplicate_group": "1" * 64,
            }
        )
        parent["manifest_digest"] = canonical_sha256(
            {key: value for key, value in parent.items() if key != "manifest_digest"}
        )
        event["manifest_digest"] = parent["manifest_digest"]
        catalogue = self.coordinator.catalogue(event, parent)
        codex = next(entry for entry in catalogue["entries"] if entry["lane_id"] == "codex")
        self.assertEqual(codex["source_class"], "codex_export")
        self.assertEqual(codex["duplicate_group"], "1" * 64)
        self.assertNotIn("content", codex)

    def test_h2_t02_t04_t05_exact_selection_and_candidate_relationships_fail_closed(self) -> None:
        prepared = self._prepared()
        self.assertEqual(
            prepared.manifest["selected_member_refs"],
            [entry["member_ref"] for entry in prepared.catalogue["entries"]],
        )
        relation = prepared.package["relationships"][0]
        self.assertEqual(relation["basis_type"], "exact_bytes")
        self.assertEqual(relation["status"], "structurally_verified")
        with self.assertRaises(HistoricalReconstructionError):
            self.coordinator.prepare(
                catalogue=prepared.catalogue, bundle_id="private_bundle_synthetic",
                selected_member_refs=("vault:missing",),
                relationships=(), primary={"artifact_id": "x"}, supporting_artifacts=({"artifact_id": "y"},),
                exceptions=(), expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        refs = tuple(item["member_ref"] for item in prepared.catalogue["entries"])
        invalid = HistoricalRelationship(
            refs[0], refs[1], "revises", "timestamp_adjacency", (refs[0],),
            status="structurally_verified",
        )
        with self.assertRaises(HistoricalReconstructionError):
            self.coordinator.prepare(
                catalogue=prepared.catalogue, bundle_id="private_bundle_synthetic", selected_member_refs=refs,
                relationships=(invalid,), primary={"artifact_id": "x"}, supporting_artifacts=({"artifact_id": "y"},),
                exceptions=(), expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )

    def test_h2_t06_t08_candidate_barrier_and_temporary_primary_view(self) -> None:
        prepared = self._prepared()
        view = self.coordinator.temporary_view(prepared)
        self.assertEqual(view["persistence"], "ephemeral")
        self.assertEqual(view["primary"]["artifact_id"], "synthetic-primary")
        self.assertTrue(
            all(
                prepared.package[key]
                for key in ("candidate_only", "no_activation", "no_knowledge_promotion", "no_current_work", "no_u2")
            )
        )
        refs = tuple(item["member_ref"] for item in prepared.catalogue["entries"])
        owner_confirmed = HistoricalRelationship(
            refs[0], refs[1], "same_bytes", "exact_bytes", refs[:2], status="owner_confirmed"
        )
        with self.assertRaises(HistoricalReconstructionError):
            self.coordinator.prepare(
                catalogue=prepared.catalogue, bundle_id="private_bundle_synthetic", selected_member_refs=refs,
                relationships=(owner_confirmed,), primary={"artifact_id": "x"},
                supporting_artifacts=({"artifact_id": "y"},),
                exceptions=(), expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        self.assertFalse((self.root / "canonical" / "historical-reconstruction-events").exists())

    def test_h2_t07_t09_append_only_publish_restart_idempotence_and_mirror_rollback(self) -> None:
        prepared = self._prepared()
        h1 = self.root / "canonical" / "archive-preservation-events" / "h1.json"
        w1 = self.root / "canonical" / "private-admission-events" / "w1.json"
        h1.parent.mkdir(exist_ok=True)
        w1.parent.mkdir(exist_ok=True)
        h1.write_bytes(b"h1-byte-sentinel")
        w1.write_bytes(b"w1-byte-sentinel")
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        self.assertEqual(h1.read_bytes(), b"h1-byte-sentinel")
        self.assertEqual(w1.read_bytes(), b"w1-byte-sentinel")
        self.assertEqual(
            self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"]).status, "complete"
        )
        self.assertEqual(
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status, "already_complete"
        )
        self.assertTrue(
            self.coordinator.append_disposable_mirror_rollback(result.event_id)["parent_events_unchanged"]
        )

    def test_h2_t10_tamper_interruption_and_receipt_replay_fail_closed(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        changed = replace(
            prepared, package={**prepared.package, "primary": {"artifact_id": "substituted"}}
        )
        with self.assertRaises(HistoricalReconstructionError):
            self.coordinator.publish(changed, receipt_id=receipt["receipt_id"])
        interrupted = HistoricalReconstructionCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids, fail_before_event=True
        )
        with self.assertRaises(HistoricalReconstructionError):
            interrupted.publish(prepared, receipt_id=receipt["receipt_id"])
        event_root = self.root / "canonical" / "historical-reconstruction-events"
        self.assertFalse(event_root.exists() and list(event_root.iterdir()))
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        replay = self.coordinator.authorize(prepared)
        with self.assertRaises(HistoricalReconstructionError):
            self.coordinator.publish(prepared, receipt_id=replay["receipt_id"])
        self.assertEqual(result.status, "complete")
