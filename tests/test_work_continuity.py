"""Hostile-synthetic S6-W2 work-continuity orchestration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import sha256_hex
from vault_next.multi_source_admission import MultiSourceItem
from vault_next.work_continuity import S6WorkContinuityCoordinator, WorkContinuityError
from vault_next.working_artifact import WorkingArtifactCoordinator


class WorkContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-work-continuity-", dir="/private/tmp")
        self.items = tuple(
            MultiSourceItem(
                role=role,
                source_locator=f"/synthetic/{role.lower()}.md",
                safe_label=f"{role.lower()}.md",
                source_bytes=f"# {role}\nInvented {role} evidence.\n".encode(),
                source_version={
                    "source_version_id": self.harness.ids.new("source_version"),
                    "content_sha256": sha256_hex(f"# {role}\nInvented {role} evidence.\n".encode()),
                    "byte_count": len(f"# {role}\nInvented {role} evidence.\n".encode()),
                    "profile_id": "markdown_text",
                    "provenance_sha256": {"M1": "1", "W1": "2", "W2": "3", "W3": "4"}[role] * 64,
                },
            )
            for role in ("M1", "W1", "W2", "W3")
        )
        self.coordinator = S6WorkContinuityCoordinator(self.harness.schemas, id_factory=self.harness.ids)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    @staticmethod
    def _assertion(claim_class: str, anchor: str) -> dict:
        return {
            "claim_class": claim_class,
            "statement": "Invented cited statement.",
            "citations": [anchor],
            "owner": None,
            "due": None,
        }

    def _result(self) -> dict:
        return {
            "executive_spine": [self._assertion("reported", "W1:line:000001-000001")],
            "reconciliation": [self._assertion("conflicting", "W2:line:000001-000001")],
            "decision_dependency_ledger": [self._assertion("reported", "W3:line:000001-000001")],
            "next_evidence": [self._assertion("proposed", "W1:line:000001-000001")],
            "omissions": [self._assertion("unknown", "M1:line:000001-000001")],
        }

    def test_w2_01_exact_sources_cited_result_and_inactive_candidate_packet(self) -> None:
        wave = self.coordinator.prepare_u0(
            source_items=self.items,
            hosted_result=self._result(),
            portable_core=("Report selected source state.", "Never adopt current work."),
        )
        review = WorkingArtifactCoordinator(
            Path(self.temporary.name) / "review",
            self.harness.schemas,
            citation_catalog=wave.citation_catalog,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        views = (
            review.create(
                artifact_kind="work_continuity", display_alias="Invented continuity", markdown="# Continuity\n",
                citations=("W1:line:000001-000001",), provenance=wave.provenance, idempotency_key="continuity",
            ),
            review.create(
                artifact_kind="decision", display_alias="Invented ledger", markdown="# Ledger\n",
                citations=("W3:line:000001-000001",), provenance=wave.provenance, idempotency_key="ledger",
            ),
            review.create(
                artifact_kind="work_preparation", display_alias="Invented next evidence", markdown="# Evidence\n",
                citations=("W2:line:000001-000001",), provenance=wave.provenance, idempotency_key="evidence",
            ),
        )
        packet = self.coordinator.build_packet(
            wave=wave,
            source_items=self.items,
            selections=tuple(
                review.select_for_u1(view.artifact_id, view.revision_id, target_state="final")
                for view in views
            ),
            coordinator=review,
            bundle_id=self.harness.ids.new("private_bundle"),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        self.assertEqual([item["role"] for item in packet.manifest["source_items"]], ["M1", "W1", "W2", "W3"])
        self.assertEqual(packet.candidate_package["lifecycle"], "inactive")
        self.assertEqual(len(packet.workspace_items), 3)

    def test_w2_02_out_of_scope_anchor_and_source_order_fail_closed(self) -> None:
        bad = self._result()
        bad["executive_spine"][0]["citations"] = ["outside:line:000001-000001"]
        with self.assertRaises(WorkContinuityError):
            self.coordinator.prepare_u0(
                source_items=self.items,
                hosted_result=bad,
                portable_core=("Report state.",),
            )
        with self.assertRaises(WorkContinuityError):
            self.coordinator.prepare_u0(
                source_items=self.items[::-1],
                hosted_result=self._result(),
                portable_core=("Report state.",),
            )


if __name__ == "__main__":
    unittest.main()
