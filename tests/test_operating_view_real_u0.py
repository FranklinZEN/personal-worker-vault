"""Hostile fixtures for the production sibling of the R1 operating-view reader."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.operating_view_real_u0 import (
    RealOperatingViewError,
    RealOperatingViewPage,
    RealOperatingViewReader,
)
from vault_next.private_workspace import _render_page


class RealOperatingViewReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-real-operating-view-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        self.event_id = "event_01M2H67P9QKF8YNKN48NCCEN1X"
        self._write_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fixture(self) -> None:
        citation_text = [
            ["W1:line:000001-000001", sha256_hex(b"Invented continuity evidence.")],
            ["W2:line:000001-000001", sha256_hex(b"Invented decision evidence.")],
            ["W3:line:000001-000001", sha256_hex(b"Invented next evidence.")],
        ]
        result = {
            "schema_version": "1.0",
            "component": "vault-next-work-continuity-wave/0.1.0",
            "continuity_id": "work_item_invented",
            "candidate_lifecycle": "inactive",
            "persistence": "ephemeral_pending_u1",
            "no_effects": ["no_activation"],
            "executive_spine": [self._claim("Invented continuity claim.", "W1:line:000001-000001", "reported")],
            "reconciliation": [self._claim("Invented conflict.", "W2:line:000001-000001", "conflicting")],
            "decision_dependency_ledger": [self._claim("Invented decision gap.", "W2:line:000001-000001", "reported")],
            "next_evidence": [self._claim("Invented evidence request.", "W3:line:000001-000001", "proposed")],
            "omissions": [self._claim("Invented unavailable claim.", "M1:line:000084-000084", "unknown")],
            "source_set_sha256": "1" * 64,
            "wave_id": "S6-W2-C1",
        }
        result["result_sha256"] = canonical_sha256(result)
        items = [
            self._item("work", "CINDE Activate — Work Continuity", "continuity", "W1:line:000001-000001"),
            self._item(
                "decision", "CINDE Activate — Decision and Dependency Ledger", "decision",
                "W2:line:000001-000001",
            ),
            self._item("work", "CINDE Activate — Next Evidence Preparation", "evidence", "W3:line:000001-000001"),
        ]
        artifact = {
            "schema_version": "1.0", "artifact_kind": "work_continuity_wave", "wave_id": "S6-W2-C1",
            "u0_result_sha256": result["result_sha256"], "result": result,
            "citation_text": citation_text, "workspace_items": items,
        }
        encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        self.artifact_sha = sha256_hex(encoded)
        artifact_path = self.root / "canonical" / "artifact-objects" / self.artifact_sha
        artifact_path.parent.mkdir(mode=0o700, parents=True)
        artifact_path.write_bytes(encoded)
        event = {
            "admission_id": "private_admission_invented", "artifact_object_sha256": self.artifact_sha,
            "candidate_package_object_sha256": "2" * 64, "event_id": self.event_id,
            "manifest_digest": "3" * 64, "publication_type": "chat_first_u1_multi_source_save",
            "receipt_id": "receipt_invented", "recorded_at": "2026-09-14T00:00:00Z",
            "relationship_ledger_object_sha256": "4" * 64, "schema_version": "1.0",
            "source_items": [{"role": role} for role in ("M1", "W1", "W2", "W3")],
        }
        event_path = self.root / "canonical" / "events" / f"{self.event_id}.json"
        event_path.parent.mkdir(mode=0o700, parents=True)
        event_path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        self.pages = (
            RealOperatingViewPage("continuity", "workspace/Work/continuity.md"),
            RealOperatingViewPage("decision_dependency", "workspace/Decisions/ledger.md"),
            RealOperatingViewPage("next_evidence", "workspace/Work/evidence.md"),
        )
        for page, item in zip(self.pages, items, strict=True):
            target = self.root / page.relative_path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            body = (
                f"# {item['display_alias']}\n\nStatus: final.\nSource event: {self.event_id}.\n\n"
                f"## Content\n\n{item['body']}\n\n## Citations\n\n- {item['citations'][0]}\n"
            )
            metadata = {
                "canonical_object_sha256": self.artifact_sha, "component": "fixture", "do_not_edit": True,
                "family": item["family"], "item_id": item["item_id"], "projection_sha256": "0" * 64,
                "schema_version": "1.0", "status": "final", "version_id": item["version_id"], "view": "reported",
                "workspace_build_digest": "5" * 64,
            }
            metadata["projection_sha256"] = sha256_hex(_render_page(metadata, body).encode())
            target.write_text(_render_page(metadata, body), encoding="utf-8")
        database = self.root / "derived" / "fts5" / "citations.sqlite3"
        database.parent.mkdir(mode=0o700, parents=True)
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE VIRTUAL TABLE citations USING fts5(event_id UNINDEXED, anchor UNINDEXED, text)")
            connection.executemany(
                "INSERT INTO citations(event_id, anchor, text) VALUES (?, ?, ?)",
                [
                    (self.event_id, "W1:line:000001-000001", "Invented continuity evidence."),
                    (self.event_id, "W2:line:000001-000001", "Invented decision evidence."),
                    (self.event_id, "W3:line:000001-000001", "Invented next evidence."),
                ],
            )
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _claim(statement: str, anchor: str, claim_class: str) -> dict[str, object]:
        return {"statement": statement, "citations": [anchor], "claim_class": claim_class, "owner": None, "due": None}

    @staticmethod
    def _item(family: str, alias: str, token: str, anchor: str) -> dict[str, object]:
        return {
            "family": family, "view": "reported", "display_alias": alias,
            "item_id": f"artifact-{token}", "version_id": f"artifact-version-{token}", "status": "final",
            "body": f"# {alias}\n\nInvented generated body.\n", "citations": [anchor], "candidate_inactive": False,
        }

    def _reader(self) -> RealOperatingViewReader:
        return RealOperatingViewReader(
            self.root, event_id=self.event_id, artifact_sha256=self.artifact_sha, pages=self.pages
        )

    def test_r1u0_01_natural_requests_select_only_the_bound_saved_view(self) -> None:
        for prompt, intent in (
            ("What is the continuity for Cindy/Activate?", "continuity"),
            ("Which decisions and dependencies remain unresolved?", "decision_dependency"),
            ("What evidence should I gather before the next review?", "next_evidence"),
        ):
            result = self._reader().query(prompt)
            self.assertEqual(result.intent, intent)
            self.assertIn("[E1]", result.markdown)
            self.assertIn("Source anchor", result.evidence_companion)
            self.assertTrue(result.sidecar["ephemeral"])
            self.assertEqual(result.sidecar["withheld_claim_count"], 1 if intent != "decision_dependency" else 0)
            if intent != "decision_dependency":
                self.assertIn("claim(s) are withheld", result.markdown)

    def test_r1u0_02_event_artifact_and_page_bindings_fail_closed(self) -> None:
        event = self.root / "canonical" / "events" / f"{self.event_id}.json"
        changed = json.loads(event.read_text())
        changed["artifact_object_sha256"] = "9" * 64
        event.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(RealOperatingViewError):
            self._reader().query("What is the continuity?")

    def test_r1u0_03_fts_citation_substitution_withholds_only_affected_claims(self) -> None:
        database = self.root / "derived" / "fts5" / "citations.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("DELETE FROM citations WHERE anchor = ?", ("W1:line:000001-000001",))
            connection.execute(
                "INSERT INTO citations(event_id, anchor, text) VALUES (?, ?, ?)",
                (self.event_id, "W1:line:000001-000001", "Substituted"),
            )
            connection.commit()
        finally:
            connection.close()
        result = self._reader().query("What is the continuity?")
        self.assertNotIn("Invented continuity claim.", result.markdown)
        self.assertIn("Invented conflict.", result.markdown)
        self.assertEqual(result.sidecar["withheld_claim_count"], 2)

    def test_r1u0_03_all_unavailable_claims_render_an_explicit_empty_view(self) -> None:
        database = self.root / "derived" / "fts5" / "citations.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("DELETE FROM citations")
            connection.commit()
        finally:
            connection.close()
        result = self._reader().query("What is the continuity?")
        self.assertIn("No claims are displayed", result.markdown)
        self.assertIn("claim(s) are withheld", result.markdown)
        self.assertNotIn("[E1]", result.markdown)
        self.assertEqual(result.sidecar["withheld_claim_count"], 3)

    def test_r1u0_04_reader_never_discovers_sources_or_writes(self) -> None:
        before = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        self._reader().query("What is the continuity?")
        after = sorted(path.relative_to(self.root) for path in self.root.rglob("*"))
        self.assertEqual(after, before)
        with self.assertRaises(RealOperatingViewError):
            self._reader().query("Search the whole vault for everything")

    def test_r1u0_05_root_escape_and_unlisted_page_are_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        bad_pages = (
            RealOperatingViewPage("continuity", "../outside.md"),
            self.pages[1], self.pages[2],
        )
        with self.assertRaises(RealOperatingViewError):
            RealOperatingViewReader(
                self.root, event_id=self.event_id, artifact_sha256=self.artifact_sha, pages=bad_pages
            )


if __name__ == "__main__":
    unittest.main()
