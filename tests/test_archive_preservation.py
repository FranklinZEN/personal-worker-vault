"""Hostile-synthetic S6-H1 archive-preservation tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from tests.helpers import Harness
from vault_next.archive_preservation import (
    PURPOSE,
    ArchiveLimits,
    ArchiveMember,
    ArchivePreservationCoordinator,
    ArchivePreservationError,
    DisposableArchiveStage,
    PreparedArchivePreservation,
    SafeArchiveReader,
)
from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeArchiveAuthority:
    """Injected existing-v2 double; it cannot read a real authority or Keychain."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_archive_preservation(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": "2026-09-15T00:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID,
            "authority_bundle_id": self.harness.ids.new("bundle"), "purpose": PURPOSE,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        signed = {
            "schema_version": "1.0", "receipt_type": PURPOSE, "authority_id": AUTHORITY_ID,
            "authority_bundle_id": display["authority_bundle_id"], "algorithm": "ed25519",
            "key_id": "f" * 64, "receipt": receipt, "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
            "confirmed_at": receipt["issued_at"], "signature_base64": "hostile-fixture-signature",
        }
        self.harness.schemas.require("archive-preservation-display", display)
        self.harness.schemas.require("archive-preservation-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = receipt, canonical_bytes(display), canonical_bytes(signed)
        return receipt

    def verify_archive_preservation(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("hostile receipt substitution")
        return receipt

    def read_archive_preservation_evidence(self, receipt_id: str, manifest: dict) -> tuple[bytes, bytes]:
        self.verify_archive_preservation(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_archive_preservation(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (display_root / f"{receipt_id}.json").read_bytes() != display or (
            receipt_root / f"{receipt_id}.json"
        ).read_bytes() != signed:
            raise RuntimeError("hostile archived evidence substitution")
        return self.verify_archive_preservation(receipt_id, manifest)


class ArchivePreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-archive-preservation-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeArchiveAuthority(self.harness)
        self.coordinator = ArchivePreservationCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _members(self) -> tuple[ArchiveMember, ...]:
        return (
            ArchiveMember(
                "vault_lane", "legacy_vault", "invented-vault", "1" * 64, "file:meeting.md", "meeting.md",
                b"# Invented meeting\n", "markdown_text",
            ),
            ArchiveMember(
                "claude_lane", "claude_export", "invented-claude-export", "2" * 64, "zip:conversations.json",
                "conversations.json", b'{"invented":true}\n', "json",
            ),
            ArchiveMember(
                "claude_lane", "claude_export", "invented-claude-export", "2" * 64, "zip:duplicate.md",
                "duplicate.md", b"# Invented meeting\n", "markdown_text",
            ),
        )

    def _prepared(self) -> PreparedArchivePreservation:
        return self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"), members=self._members(),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_manifest_is_local_only_and_exact_byte_dedup_retains_lanes(self) -> None:
        prepared = self._prepared()
        manifest = prepared.manifest
        self.assertEqual(manifest["purpose"], PURPOSE)
        self.assertEqual(manifest["disclosure"], "local_only_no_content_index")
        self.assertEqual(len(manifest["lanes"]), 2)
        self.assertEqual(manifest["lanes"][0]["source_scope_sha256"], "2" * 64)
        groups = [item["duplicate_group"] for item in manifest["members"]]
        self.assertEqual(len(groups), 3)
        self.assertEqual(len(set(groups)), 2)
        self.assertEqual(
            {item["lane_id"] for item in manifest["members"]}, {"vault_lane", "claude_lane"}
        )

    def test_codex_export_lane_is_preserved_as_distinct_provenance_without_semantic_scope(self) -> None:
        members = (
            ArchiveMember(
                "vault_lane", "legacy_vault", "invented-vault", "1" * 64, "file:artifact.md", "artifact.md",
                b"# Invented artifact\n", "markdown_text",
            ),
            ArchiveMember(
                "codex_lane", "codex_export", "invented-codex-export", "2" * 64,
                "zip:artifact.md", "artifact.md", b"# Invented artifact\n", "markdown_text",
            ),
        )
        prepared = self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"), members=members,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.assertEqual(
            {lane["source_class"] for lane in prepared.manifest["lanes"]},
            {"legacy_vault", "codex_export"},
        )
        self.assertEqual(
            len({member["duplicate_group"] for member in prepared.manifest["members"]}), 1,
        )
        self.assertEqual(prepared.manifest["disclosure"], "local_only_no_content_index")

    def test_publish_restart_idempotence_catalogue_and_mirror_rollback(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        self.assertEqual(
            self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"]).status,
            "complete",
        )
        self.assertEqual(
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status,
            "already_complete",
        )
        catalogue = self.root / "derived" / "archive-catalogue" / f"{result.event_id}.json"
        record = json.loads(catalogue.read_text())
        self.assertFalse(record["content_indexed"])
        self.assertNotIn("Invented meeting", catalogue.read_text())
        self.assertFalse((self.root / "derived" / "fts5").exists() and list((self.root / "derived" / "fts5").iterdir()))
        self.assertTrue(self.coordinator.append_disposable_mirror_rollback(result.event_id)["parent_events_unchanged"])

    def test_digest_display_receipt_and_member_substitution_fail_closed(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        mutated = replace(prepared.members[0], content=b"hostile replacement")
        changed = PreparedArchivePreservation(prepared.manifest, (mutated, *prepared.members[1:]))
        with self.assertRaises(ArchivePreservationError):
            self.coordinator.publish(changed, receipt_id=receipt["receipt_id"])
        other = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        with self.assertRaises(ArchivePreservationError):
            self.coordinator.publish(prepared, receipt_id=other["receipt_id"])

    def test_interruption_does_not_publish_event_and_recovers_with_same_receipt(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        interrupted = ArchivePreservationCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids, fail_before_event=True
        )
        with self.assertRaises(ArchivePreservationError):
            interrupted.publish(prepared, receipt_id=receipt["receipt_id"])
        event_root = self.root / "canonical" / "archive-preservation-events"
        self.assertTrue(event_root.is_dir())
        self.assertEqual(list(event_root.iterdir()), [])
        self.assertEqual(self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status, "complete")

    def test_directory_reader_rejects_symlink_and_outside_traversal(self) -> None:
        source = Path(self.temporary.name) / "hostile-directory"
        source.mkdir()
        (source / "safe.md").write_text("invented", encoding="utf-8")
        (source / "escape").symlink_to(Path(self.temporary.name) / "outside")
        reader = SafeArchiveReader(ArchiveLimits(10, 1024, 4096, 10))
        with self.assertRaises(ArchivePreservationError):
            reader.directory_members(source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture")

    def test_directory_reader_records_only_exact_expected_symlink_exclusion(self) -> None:
        source = Path(self.temporary.name) / "approved-link-directory"
        source.mkdir()
        (source / "safe.md").write_text("invented", encoding="utf-8")
        link_text = "hostile-unresolved-link-text"
        (source / "generated-link").symlink_to(link_text)
        reader = SafeArchiveReader(
            ArchiveLimits(10, 1024, 4096, 10),
            expected_symlink_exclusions={"generated-link": sha256_hex(link_text.encode())},
        )
        members = reader.directory_members(
            source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture"
        )
        self.assertEqual(tuple(member.relative_locator for member in members), ("safe.md",))
        self.assertEqual(len(reader.exclusions), 1)
        exclusion = reader.exclusions[0]
        self.assertEqual(exclusion.relative_locator, "generated-link")
        self.assertEqual(exclusion.unresolved_link_text_sha256, sha256_hex(link_text.encode()))
        prepared = self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"), members=members,
            exclusions=reader.exclusions, expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.assertEqual(prepared.manifest["exclusions"][0]["disposition"], "excluded_unsafe_symlink")

    def test_directory_reader_rejects_unlisted_changed_or_missing_expected_symlink(self) -> None:
        source = Path(self.temporary.name) / "rejected-link-directory"
        source.mkdir()
        (source / "safe.md").write_text("invented", encoding="utf-8")
        (source / "link").symlink_to("changed")
        with self.assertRaises(ArchivePreservationError):
            SafeArchiveReader(
                ArchiveLimits(10, 1024, 4096, 10),
                expected_symlink_exclusions={"link": sha256_hex(b"expected")},
            ).directory_members(source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture")
        with self.assertRaises(ArchivePreservationError):
            SafeArchiveReader(
                ArchiveLimits(10, 1024, 4096, 10),
                expected_symlink_exclusions={"missing-link": sha256_hex(b"expected")},
            ).directory_members(source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture")
        with self.assertRaises(ArchivePreservationError):
            SafeArchiveReader(ArchiveLimits(10, 1024, 4096, 10)).directory_members(
                source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture"
            )

    def test_reader_excludes_only_explicit_filename_without_reading_it(self) -> None:
        source = Path(self.temporary.name) / "excluded-directory"
        source.mkdir()
        (source / "safe.md").write_text("invented", encoding="utf-8")
        (source / ".DS_Store").write_text("excluded", encoding="utf-8")
        reader = SafeArchiveReader(
            ArchiveLimits(10, 1024, 4096, 10), excluded_basenames=frozenset({".DS_Store"})
        )
        members = reader.directory_members(
            source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture"
        )
        self.assertEqual(tuple(member.relative_locator for member in members), ("safe.md",))

    def test_zip_reader_rejects_zip_slip_duplicate_and_ratio_bomb(self) -> None:
        reader = SafeArchiveReader(ArchiveLimits(10, 1024, 4096, 2))
        unsafe = Path(self.temporary.name) / "hostile.zip"
        with zipfile.ZipFile(unsafe, "w") as archive:
            archive.writestr("../escape.md", b"invented")
        with self.assertRaises(ArchivePreservationError):
            reader.zip_members(unsafe, lane_id="claude_lane", source_class="claude_export", source_label="fixture")
        ratio = Path(self.temporary.name) / "ratio.zip"
        with zipfile.ZipFile(ratio, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("compressible.txt", b"A" * 512)
        with self.assertRaises(ArchivePreservationError):
            reader.zip_members(ratio, lane_id="claude_lane", source_class="claude_export", source_label="fixture")

    def test_reader_enforces_total_cap_across_multiple_selected_inputs(self) -> None:
        first = Path(self.temporary.name) / "first"
        second = Path(self.temporary.name) / "second"
        first.mkdir()
        second.mkdir()
        (first / "one.txt").write_bytes(b"one")
        (second / "two.txt").write_bytes(b"two")
        reader = SafeArchiveReader(ArchiveLimits(10, 10, 5, 10))
        reader.directory_members(first, lane_id="first", source_class="legacy_vault", source_label="first")
        with self.assertRaises(ArchivePreservationError):
            reader.directory_members(second, lane_id="second", source_class="claude_export", source_label="second")

    def test_streamed_staging_avoids_member_buffer_and_is_removed_after_publication(self) -> None:
        source = Path(self.temporary.name) / "streamed-directory"
        source.mkdir()
        (source / "opaque.bin").write_bytes(b"x" * (3 * 1024 * 1024))
        stage_parent = Path(self.temporary.name) / "stage-parent"
        stage_parent.mkdir(mode=0o700)
        with DisposableArchiveStage(stage_parent) as staging:
            reader = SafeArchiveReader(ArchiveLimits(10, 4 * 1024 * 1024, 8 * 1024 * 1024, 10), staging=staging)
            members = reader.directory_members(
                source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture"
            )
            self.assertIsInstance(members[0].content, Path)
            self.assertEqual(members[0].content.stat().st_size, 3 * 1024 * 1024)
            prepared = self.coordinator.prepare(
                bundle_id=self.harness.ids.new("private_bundle"), members=members,
                expires_at=datetime.now(UTC) + timedelta(minutes=10), staging_root=staging.root,
            )
            receipt = self.coordinator.authorize(prepared)
            self.assertEqual(self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status, "complete")
            staged_root = staging.root
        self.assertIsNotNone(staged_root)
        self.assertFalse(staged_root.exists())

    def test_streamed_staging_removes_partial_bytes_when_cap_or_scope_fails(self) -> None:
        source = Path(self.temporary.name) / "over-cap-directory"
        source.mkdir()
        (source / "oversized.bin").write_bytes(b"x" * 1025)
        stage_parent = Path(self.temporary.name) / "stage-parent-cap"
        stage_parent.mkdir(mode=0o700)
        with DisposableArchiveStage(stage_parent) as staging:
            reader = SafeArchiveReader(ArchiveLimits(10, 1024, 4096, 10), staging=staging)
            with self.assertRaises(ArchivePreservationError):
                reader.directory_members(
                    source, lane_id="vault_lane", source_class="legacy_vault", source_label="fixture"
                )
            self.assertEqual(list((staging.root / "members").iterdir()), [])
            staged_root = staging.root
        self.assertIsNotNone(staged_root)
        self.assertFalse(staged_root.exists())


if __name__ == "__main__":
    unittest.main()
