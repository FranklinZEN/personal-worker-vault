"""Synthetic-only Phase 6 discovery and staging-dry-run acceptance checks."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, ValidationError
from vault_next.migration import SyntheticFixtureWorkspace, SyntheticMigrationLab
from vault_next.paths import RuntimePaths
from vault_next.policy import PolicyEngine
from vault_next.records import SchemaRegistry
from tests.helpers import SCHEMA_ROOT


class Phase6MigrationAcceptanceTests(unittest.TestCase):
    """Exercise AT-020/021 against hostile disposable trees only."""

    def setUp(self) -> None:
        self.workspace = SyntheticFixtureWorkspace()
        base = self.workspace.source.parent
        self.runtime_root = self.workspace.runtime
        self.source = self.workspace.source
        self.backup = self.workspace.backup
        self.outside = base / "outside"
        self.outside.mkdir()
        (self.source / "history" / "tasks").mkdir(parents=True)
        (self.source / "history" / "artifacts").mkdir(parents=True)
        (self.source / "history" / "tasks" / "old-task.md").write_text("invented task history\n")
        (self.source / "history" / "artifacts" / "old-artifact.md").write_text("invented artifact history\n")
        (self.source / "notes.md").write_text("invented markdown history\n")
        (self.source / "other").mkdir()
        (self.source / "other" / "notes.md").write_text("invented colliding history\n")
        (self.source / "binary.bin").write_bytes(b"\x00invented binary")
        (self.source / "unsupported.tmp").write_text("invented unsupported\n")
        (self.source / ".git").mkdir()
        (self.source / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (self.outside / "secret.txt").write_text("outside synthetic target\n")
        os.symlink(self.outside / "secret.txt", self.source / "outside-link")
        self.paths = RuntimePaths(
            self.runtime_root, protected_roots=(self.source, self.backup)
        )
        self.paths.initialize()
        self.lab = SyntheticMigrationLab(self.paths, SchemaRegistry(SCHEMA_ROOT))

    def tearDown(self) -> None:
        self.workspace.close()

    def test_at_020_discovery_is_read_only_and_refuses_unmarked_roots(self) -> None:
        source_before = _tree_digest(self.source)
        backup_before = _tree_digest(self.backup)
        snapshot = self.lab.discover(self.workspace.admission)
        source_after = _tree_digest(self.source)
        backup_after = _tree_digest(self.backup)
        self.assertEqual(source_before, source_after)
        self.assertEqual(backup_before, backup_after)
        self.assertIn(".", snapshot.repositories)
        link = next(item for item in snapshot.items if item["relative_path"] == "outside-link")
        self.assertEqual(link["kind"], "symlink")
        self.assertFalse(link["symlink_inside_source"])
        with self.assertRaises(ValidationError) as caught:
            self.lab.discover(self.outside)
        self.assertTrue(
            any(issue.code == ErrorCode.MIGRATION_ADMISSION_REQUIRED for issue in caught.exception.issues)
        )

    def test_at_021_dry_run_is_deterministic_reconciled_and_staging_only(self) -> None:
        source_before = _tree_digest(self.source)
        backup_before = _tree_digest(self.backup)
        canonical_before = _tree_digest(self.paths.semantic_root)
        snapshot = self.lab.discover(self.workspace.admission)
        first = self.lab.dry_run(self.workspace.admission, snapshot)
        second = self.lab.dry_run(self.workspace.admission, snapshot)
        self.assertEqual(first.to_record(), second.to_record())
        self.assertEqual(len(snapshot.items), len(_dry_run_items(first.staging_path)))
        self.assertTrue(any(item["disposition"] == "exact-copy" for item in first.candidates))
        self.assertTrue(any(item["code"] == "UNSUPPORTED" for item in first.exceptions))
        self.assertTrue(
            any(item["code"] == ErrorCode.MIGRATION_SYMLINK_OUT_OF_SCOPE for item in first.exceptions)
        )
        self.assertTrue(any(item["code"] == "TARGET_COLLISION" for item in first.exceptions))
        for candidate in first.candidates:
            if candidate["disposition"] != "exact-copy":
                continue
            copy = first.staging_path / "copies" / f"{candidate['candidate_id']}.bin"
            self.assertEqual(sha256_hex(copy.read_bytes()), candidate["source_content_sha256"])
        self.assertEqual(source_before, _tree_digest(self.source))
        self.assertEqual(backup_before, _tree_digest(self.backup))
        self.assertEqual(canonical_before, _tree_digest(self.paths.semantic_root))

    def test_pilot_interface_requires_normal_policy_and_deactivation_preserves_staging_evidence(self) -> None:
        run = self.lab.dry_run(self.workspace.admission, self.lab.discover(self.workspace.admission))
        proposal = self.lab.pilot_commit_proposal(
            run, candidate_ids=[run.candidates[0]["candidate_id"]]
        )
        policy = PolicyEngine(self.paths, SchemaRegistry(SCHEMA_ROOT))
        result = policy.evaluate(proposal, now=_now())
        self.assertEqual(result.result, "requires_owner_approval")
        marker = self.lab.deactivate(run, reason="synthetic rollback rehearsal")
        self.assertTrue(marker.exists())
        self.assertTrue((run.staging_path / "dry-run.json").exists())


def _dry_run_items(path: Path) -> list[dict]:
    import json

    return json.loads((path / "dry-run.json").read_text())["reconciliation"]


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


def _now():
    from datetime import UTC, datetime

    return datetime(2026, 9, 4, tzinfo=UTC)


if __name__ == "__main__":
    unittest.main()
