"""S1-A hostile-boundary regressions using only disposable fixture workspaces."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, ValidationError
from vault_next.migration import (
    RULESET_VERSION,
    MigrationDryRun,
    MigrationSnapshot,
    SyntheticFixtureWorkspace,
    SyntheticMigrationLab,
)
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry
from tests.helpers import SCHEMA_ROOT


class MigrationBoundaryTests(unittest.TestCase):
    """Each attack reaches the intended migration boundary with a valid control."""

    def setUp(self) -> None:
        self.workspace = SyntheticFixtureWorkspace()
        self.paths = RuntimePaths(
            self.workspace.runtime,
            protected_roots=(self.workspace.source, self.workspace.backup),
        )
        self.paths.initialize()
        self.schemas = SchemaRegistry(SCHEMA_ROOT)
        self.lab = SyntheticMigrationLab(self.paths, self.schemas)
        self._populate_valid_tree()

    def tearDown(self) -> None:
        self.workspace.close()

    def _populate_valid_tree(self) -> None:
        source = self.workspace.source
        (source / "history" / "tasks").mkdir(parents=True)
        (source / "history" / "tasks" / "old-task.md").write_text("invented task history\n")
        (source / "notes.md").write_text("invented notes\n")
        (source / "other").mkdir()
        (source / "other" / "notes.md").write_text("invented collision\n")
        (source / "binary.bin").write_bytes(b"\x00invented binary")
        (source / "unsupported.tmp").write_text("invented unsupported\n")

    def _snapshot(self) -> MigrationSnapshot:
        return self.lab.discover(self.workspace.admission)

    def _run(self) -> MigrationDryRun:
        return self.lab.dry_run(self.workspace.admission, self._snapshot())

    def _snapshot_with(self, snapshot: MigrationSnapshot, **changes: object) -> MigrationSnapshot:
        record = snapshot.to_record()
        record.update(changes)
        material = {
            "items": record["items"],
            "repositories": list(record["repositories"]),
            "ruleset_version": record["ruleset_version"],
            "source_label": record["source_label"],
        }
        return MigrationSnapshot(
            source_label=record["source_label"],
            items=tuple(record["items"]),
            repositories=tuple(record["repositories"]),
            snapshot_sha256=canonical_sha256(material),
        )

    def _run_with(self, run: MigrationDryRun, **changes: object) -> MigrationDryRun:
        return replace(run, **changes)

    def _assert_code(self, caught: unittest.case._AssertRaisesContext[ValidationError], code: ErrorCode) -> None:
        self.assertIn(code, {issue.code for issue in caught.exception.issues})

    def test_a_t01_admitted_control_is_deterministic_reconciled_and_staging_only(self) -> None:
        before_source = _tree_digest(self.workspace.source)
        before_backup = _tree_digest(self.workspace.backup)
        before_canonical = _tree_digest(self.paths.semantic_root)
        first_snapshot = self._snapshot()
        first = self.lab.dry_run(self.workspace.admission, first_snapshot)
        second = self.lab.dry_run(self.workspace.admission, self._snapshot())
        self.assertEqual(first_snapshot.to_record(), self._snapshot().to_record())
        self.assertEqual(first.to_record(), second.to_record())
        self.assertEqual(len(first.reconciliation), len(first_snapshot.items))
        self.assertEqual(before_source, _tree_digest(self.workspace.source))
        self.assertEqual(before_backup, _tree_digest(self.workspace.backup))
        self.assertEqual(before_canonical, _tree_digest(self.paths.semantic_root))

    def test_a_t02_admission_marker_and_replaced_root_fail_before_source_access(self) -> None:
        opened: list[str] = []
        observer_lab = SyntheticMigrationLab(
            self.paths, self.schemas, source_open_observer=opened.append
        )
        with self.assertRaises(ValidationError) as caught:
            observer_lab.discover(self.workspace.source)  # old marker-only call
        self._assert_code(caught, ErrorCode.MIGRATION_ADMISSION_REQUIRED)
        self.assertEqual([], opened)

        marker = self.workspace.source / ".vault-next-synthetic-migration-fixture.json"
        marker.write_text("{}\n")
        with self.assertRaises(ValidationError) as caught:
            observer_lab.discover(self.workspace.admission)
        self._assert_code(caught, ErrorCode.MIGRATION_FIXTURE_MARKER_INVALID)
        self.assertEqual([], opened)

        foreign = SyntheticFixtureWorkspace()
        try:
            with self.assertRaises(ValidationError) as caught:
                observer_lab.discover(foreign.admission)
            self._assert_code(caught, ErrorCode.MIGRATION_ADMISSION_INVALID)
        finally:
            foreign.close()

        old_source = self.workspace.source.with_name("replaced-source")
        self.workspace.source.rename(old_source)
        self.workspace.source.mkdir()
        (self.workspace.source / marker.name).write_bytes((old_source / marker.name).read_bytes())
        with self.assertRaises(ValidationError) as caught:
            observer_lab.discover(self.workspace.admission)
        self._assert_code(caught, ErrorCode.MIGRATION_SOURCE_REPLACED)
        self.assertEqual([], opened)

    def test_a_t03_snapshot_tampering_is_rejected_before_copy(self) -> None:
        snapshot = self._snapshot()
        changed = list(snapshot.items)
        changed[0] = {**changed[0], "relative_path": "../outside.bin"}
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, replace(snapshot, items=tuple(changed)))
        self._assert_code(caught, ErrorCode.MIGRATION_DIGEST_MISMATCH)

        rebound = self._snapshot_with(snapshot, items=changed)
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, rebound)
        self._assert_code(caught, ErrorCode.MIGRATION_PATH_INVALID)

    def test_a_t04_paths_and_repository_metadata_are_checked_before_open(self) -> None:
        snapshot = self._snapshot()
        bad_item = {**snapshot.items[0], "relative_path": "/absolute.bin"}
        bad_path = self._snapshot_with(snapshot, items=[bad_item, *snapshot.items[1:]])
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, bad_path)
        self._assert_code(caught, ErrorCode.MIGRATION_PATH_INVALID)

        bad_repo = self._snapshot_with(snapshot, repositories=("../repository",))
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, bad_repo)
        self._assert_code(caught, ErrorCode.MIGRATION_PATH_INVALID)

    def test_a_t05_each_nested_row_family_rejects_empty_wrong_and_extra_rows(self) -> None:
        os.symlink("notes.md", self.workspace.source / "inside-link")
        (self.workspace.source / "hard-source.bin").write_bytes(b"invented hard link")
        os.link(
            self.workspace.source / "hard-source.bin",
            self.workspace.source / "hard-alias.bin",
        )
        snapshot = self._snapshot()
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, replace(snapshot, items=({},)))
        self._assert_code(caught, ErrorCode.SCHEMA_REQUIRED)

        for kind in ("file", "directory", "symlink", "inaccessible"):
            with self.subTest(item_kind=kind):
                index = next(index for index, item in enumerate(snapshot.items) if item["kind"] == kind)
                missing = dict(snapshot.items[index])
                missing.pop("relative_path")
                items = list(snapshot.items)
                items[index] = missing
                with self.assertRaises(ValidationError) as caught:
                    self.lab.dry_run(
                        self.workspace.admission,
                        self._snapshot_with(snapshot, items=items),
                    )
                self._assert_code(caught, ErrorCode.SCHEMA_REQUIRED)

                wrong = dict(snapshot.items[index])
                wrong["byte_count"] = True
                items[index] = wrong
                with self.assertRaises(ValidationError) as caught:
                    self.lab.dry_run(
                        self.workspace.admission,
                        self._snapshot_with(snapshot, items=items),
                    )
                self._assert_code(caught, ErrorCode.SCHEMA_TYPE)

        run = self._run()
        for field in ("candidates", "provenance", "exceptions", "reconciliation", "fidelity"):
            with self.subTest(field=field), self.assertRaises(ValidationError) as caught:
                self.lab.deactivate(self._run_with(run, **{field: ({},)}), reason="invented")
            self._assert_code(caught, ErrorCode.SCHEMA_REQUIRED)

        wrong_fields = {
            "candidates": "candidate_id",
            "provenance": "candidate_id",
            "exceptions": "code",
            "reconciliation": "disposition",
            "fidelity": "candidate_id",
        }
        for field, key in wrong_fields.items():
            wrong = dict(getattr(run, field)[0])
            wrong[key] = False
            with self.subTest(field=field), self.assertRaises(ValidationError) as caught:
                self.lab.deactivate(self._run_with(run, **{field: (wrong,)}), reason="invented")
            self._assert_code(caught, ErrorCode.SCHEMA_TYPE)

        item = dict(snapshot.items[0])
        item["unexpected"] = "invented"
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, self._snapshot_with(snapshot, items=[item, *snapshot.items[1:]]))
        self._assert_code(caught, ErrorCode.SCHEMA_ADDITIONAL_PROPERTY)

    def test_a_t06_relationships_collisions_and_missing_fidelity_are_rejected(self) -> None:
        run = self._run()
        duplicate = self._run_with(run, candidates=(run.candidates[0], run.candidates[0]))
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(duplicate, reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RECORD_INVALID)

        missing_fidelity = self._run_with(run, fidelity=())
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(missing_fidelity, reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RECORD_INVALID)

        dangling = dict(run.provenance[0])
        dangling["candidate_id"] = "candidate_sha256_" + "0" * 64
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(self._run_with(run, provenance=(dangling,)), reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RECORD_INVALID)

        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(self._run_with(run, reconciliation=()), reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RECORD_INVALID)

        snapshot = self._snapshot()
        duplicate_paths = [snapshot.items[0], {**snapshot.items[0]}, *snapshot.items[1:]]
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(
                self.workspace.admission,
                self._snapshot_with(snapshot, items=duplicate_paths),
            )
        self._assert_code(caught, ErrorCode.MIGRATION_RECORD_INVALID)

        collisions = [
            candidate["candidate_id"]
            for candidate in run.candidates
            if candidate["proposed_target"] == "historical/notes.json"
        ]
        self.assertGreaterEqual(len(collisions), 2)
        with self.assertRaises(ValidationError) as caught:
            self.lab.pilot_commit_proposal(run, candidate_ids=collisions)
        self._assert_code(caught, ErrorCode.MIGRATION_PROPOSAL_INVALID)

    def test_a_t07_forged_staging_fields_and_persisted_manifest_are_rejected(self) -> None:
        run = self._run()
        forged_path = self._run_with(run, staging_path=self.workspace.backup)
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(forged_path, reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_INVALID)
        self.assertFalse((self.workspace.backup / "DEACTIVATED.json").exists())

        forged_digest = self._run_with(run, run_sha256="0" * 64)
        with self.assertRaises(ValidationError) as caught:
            self.lab.pilot_commit_proposal(forged_digest, candidate_ids=[run.candidates[0]["candidate_id"]])
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_INVALID)

        manifest = run.staging_path / "dry-run.json"
        payload = json.loads(manifest.read_text())
        payload["candidates"][0]["source_relative_path"] = "other/notes.md"
        manifest.write_text(json.dumps(payload))
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(run, reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_STAGING_TAMPERED)

    def test_a_t08_symlinks_special_files_hard_links_and_swaps_do_not_escape(self) -> None:
        outside = self.workspace.source.parent / "outside"
        outside.mkdir()
        (outside / "sentinel.bin").write_bytes(b"outside invented bytes")
        os.symlink(outside / "sentinel.bin", self.workspace.source / "outside-link")
        (self.workspace.source / "hard.bin").write_bytes(b"hard-link invented")
        os.link(self.workspace.source / "hard.bin", self.workspace.source / "hard-alias.bin")
        os.mkfifo(self.workspace.source / "never-read.fifo")
        snapshot = self._snapshot()
        self.assertEqual("symlink", _item(snapshot, "outside-link")["kind"])
        self.assertEqual("inaccessible", _item(snapshot, "hard.bin")["kind"])
        self.assertEqual("inaccessible", _item(snapshot, "never-read.fifo")["kind"])

        source = self.workspace.source
        (source / "swap" ).mkdir()
        (source / "swap" / "inside.bin").write_bytes(b"inside")
        before = self._snapshot()
        swapped = False

        def swap_on_open(relative_path: str) -> None:
            nonlocal swapped
            if relative_path == "swap" and not swapped:
                swapped = True
                (source / "swap").rename(source / "swap-old")
                os.symlink(outside, source / "swap")

        swapping_lab = SyntheticMigrationLab(self.paths, self.schemas, source_open_observer=swap_on_open)
        with self.assertRaises(ValidationError) as caught:
            swapping_lab.dry_run(self.workspace.admission, before)
        self._assert_code(caught, ErrorCode.MIGRATION_SOURCE_REPLACED)

    def test_a_t09_staging_redirection_is_never_followed_or_overwritten(self) -> None:
        run = self._run()
        copies = run.staging_path / "copies"
        outside = self.workspace.source.parent / "staging-outside"
        outside.mkdir()
        shutil.rmtree(copies)
        os.symlink(outside, copies)
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, self._snapshot())
        self._assert_code(caught, ErrorCode.MIGRATION_STAGING_TAMPERED)
        self.assertEqual([], list(outside.iterdir()))

    def test_a_t10_source_drift_idempotent_retry_and_conflicting_copy(self) -> None:
        snapshot = self._snapshot()
        (self.workspace.source / "binary.bin").write_bytes(b"\x00changed invented binary")
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, snapshot)
        self._assert_code(caught, ErrorCode.MIGRATION_SOURCE_CHANGED)

        fresh = self._snapshot()
        run = self.lab.dry_run(self.workspace.admission, fresh)
        copy = run.staging_path / "copies" / f"{_exact_candidate(run)['candidate_id']}.bin"
        copy.write_bytes(b"conflicting invented bytes")
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, fresh)
        self._assert_code(caught, ErrorCode.MIGRATION_STAGING_COLLISION)

    def test_a_t11_incomplete_publication_is_not_proposable_and_retry_recovers(self) -> None:
        def fail_after_fidelity(stage: str) -> None:
            if stage == "after-fidelity-report":
                raise OSError("injected invented failure")

        failing = SyntheticMigrationLab(self.paths, self.schemas, publication_hook=fail_after_fidelity)
        snapshot = self._snapshot()
        with self.assertRaises(OSError):
            failing.dry_run(self.workspace.admission, snapshot)
        staging_dirs = list((self.paths.staging_root / "migrations").iterdir())
        self.assertEqual(1, len(staging_dirs))
        partial = _run_from_staging(staging_dirs[0])
        with self.assertRaises(ValidationError) as caught:
            self.lab.pilot_commit_proposal(partial, candidate_ids=[partial.candidates[0]["candidate_id"]])
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_INCOMPLETE)
        retried = self.lab.dry_run(self.workspace.admission, snapshot)
        self.assertTrue((retried.staging_path / "COMPLETE.json").exists())

    def test_a_t12_deactivation_is_idempotent_but_blocks_proposals(self) -> None:
        run = self._run()
        marker = self.lab.deactivate(run, reason="invented deactivation")
        self.assertEqual(marker, self.lab.deactivate(run, reason="invented deactivation"))
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(run, reason="different invented reason")
        self._assert_code(caught, ErrorCode.MIGRATION_STAGING_COLLISION)
        with self.assertRaises(ValidationError) as caught:
            self.lab.pilot_commit_proposal(run, candidate_ids=[run.candidates[0]["candidate_id"]])
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_DEACTIVATED)

    def test_a_t13_proposal_selection_is_exact_and_non_mutating(self) -> None:
        run = self._run()
        candidate = _exact_candidate(run)["candidate_id"]
        proposal = self.lab.pilot_commit_proposal(run, candidate_ids=[candidate])
        self.assertEqual(tuple(sorted((run.run_id, candidate))), proposal.source_refs)
        for candidate_ids in ([], ["candidate_sha256_" + "0" * 64]):
            with self.subTest(candidate_ids=candidate_ids), self.assertRaises(ValidationError) as caught:
                self.lab.pilot_commit_proposal(run, candidate_ids=candidate_ids)
            self._assert_code(caught, ErrorCode.MIGRATION_PROPOSAL_INVALID)
        self.assertEqual(canonical_sha256([]), _tree_digest(self.paths.semantic_root))

    def test_a_t14_missing_safe_io_capability_and_unbound_staging_fail_closed(self) -> None:
        with patch("vault_next.migration_io.os.O_NOFOLLOW", 0), self.assertRaises(ValidationError) as caught:
            SyntheticMigrationLab(self.paths, self.schemas)
        self._assert_code(caught, ErrorCode.MIGRATION_IO_UNSUPPORTED)

        run = self._run()
        (run.staging_path / "snapshot.json").unlink()
        with self.assertRaises(ValidationError) as caught:
            self.lab.deactivate(run, reason="invented")
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_INCOMPLETE)
        with self.assertRaises(ValidationError) as caught:
            self.lab.dry_run(self.workspace.admission, self._snapshot())
        self._assert_code(caught, ErrorCode.MIGRATION_RUN_INCOMPLETE)


def _item(snapshot: MigrationSnapshot, relative_path: str) -> dict[str, object]:
    return next(item for item in snapshot.items if item["relative_path"] == relative_path)


def _exact_candidate(run: MigrationDryRun) -> dict[str, object]:
    return next(candidate for candidate in run.candidates if candidate["disposition"] == "exact-copy")


def _run_from_staging(staging_path: Path) -> MigrationDryRun:
    record = json.loads((staging_path / "dry-run.json").read_text())
    return MigrationDryRun(
        run_id=record["run_id"],
        run_sha256=record["run_sha256"],
        snapshot_sha256=record["snapshot_sha256"],
        candidates=tuple(record["candidates"]),
        provenance=tuple(record["provenance"]),
        exceptions=tuple(record["exceptions"]),
        reconciliation=tuple(record["reconciliation"]),
        fidelity=tuple(record["fidelity"]),
        staging_path=staging_path,
    )


def _tree_digest(root: Path) -> str:
    if not root.exists():
        return canonical_sha256([])
    items = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            items.append({"path": relative, "kind": "symlink", "target": os.readlink(path)})
        elif path.is_file():
            items.append({"path": relative, "kind": "file", "sha256": sha256_hex(path.read_bytes())})
        elif path.is_dir():
            items.append({"path": relative, "kind": "directory"})
    return canonical_sha256(items)
