"""Hostile synthetic coverage for exact-parent historical migration amendments."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.historical_migration_amendment import (
    PURPOSE,
    HistoricalMigrationAmendmentCoordinator,
    HistoricalMigrationAmendmentError,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeAuthority:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_historical_migration_amendment(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-20T00:00:00Z",
            "expires_at": manifest["expires_at"],
        }
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID,
            "authority_bundle_id": self.harness.ids.new("bundle"),
            "purpose": PURPOSE,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        signed = {
            "schema_version": "1.0",
            "receipt_type": PURPOSE,
            "authority_id": AUTHORITY_ID,
            "authority_bundle_id": display["authority_bundle_id"],
            "algorithm": "ed25519",
            "key_id": "fixture-key",
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
            "confirmed_at": receipt["issued_at"],
            "signature_base64": "fixture-signature",
        }
        self.harness.schemas.require("historical-migration-amendment-receipt", receipt)
        self.harness.schemas.require("historical-migration-amendment-display", display)
        self.harness.schemas.require("historical-migration-amendment-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = (
            receipt,
            canonical_bytes(display),
            canonical_bytes(signed),
        )
        return receipt

    def verify_historical_migration_amendment(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture receipt substitution")
        return receipt

    def read_historical_migration_amendment_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        self.verify_historical_migration_amendment(receipt_id, manifest)
        return self.records[receipt_id][1:]

    def verify_archived_historical_migration_amendment(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archived evidence substitution")
        return receipt


class HistoricalMigrationAmendmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-amendment-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.parent = self._parent()
        self.authority = FakeAuthority(self.harness)
        self.coordinator = HistoricalMigrationAmendmentCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _parent(self) -> dict[str, str]:
        event_id = self.harness.ids.new("event")
        package_material = {
            "schema_version": "1.0",
            "weekly_wave": {"decisions": [{"label": "Invented decision"}]},
        }
        package_digest = canonical_sha256(package_material)
        package = {**package_material, "package_digest": package_digest}
        receipt_id = self.harness.ids.new("receipt")
        event = {
            "schema_version": "1.0",
            "event_id": event_id,
            "package_digest": package_digest,
            "receipt_id": receipt_id,
        }
        event_bytes = canonical_bytes(event)
        event_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{event_id}.json"
        package_path = self.root / "canonical" / "historical-weekly-activity-packages" / package_digest
        event_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        package_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        event_path.write_bytes(event_bytes)
        package_path.write_bytes(canonical_bytes(package))
        return {
            "event_id": event_id,
            "event_sha256": sha256_hex(event_bytes),
            "package_digest": package_digest,
            "receipt_id": receipt_id,
        }

    def _prepared(self):
        review = {
            "recorded_at": "2026-09-20T20:00:00Z",
            "ratings": [
                {"dimension": value, "rating": "pass"}
                for value in ("mechanics", "coverage", "strands", "lineage", "usefulness")
            ],
            "choices": [
                {"entry_id": key, "choice": choice}
                for key, choice in (
                    ("A", "advance"),
                    ("B", "advance"),
                    ("C", "advance"),
                    ("D", "defer_to_M1"),
                    ("E", "retain_for_M1"),
                )
            ],
        }
        entries = tuple(
            {
                "entry_id": key,
                "change_class": "decision_attribution" if key == "A" else "strand_allocation",
                "target_ref": f"fixture:{key}",
                "payload": {"fixture": key},
                "evidence_refs": [f"fixture:{key}:line-1"],
            }
            for key in ("A", "B", "C")
        )
        deferred = (
            {"entry_id": "D", "disposition": "defer_to_M1"},
            {"entry_id": "E", "disposition": "retain_for_M1"},
        )
        return self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"),
            parent_binding=self.parent,
            owner_review=review,
            entries=entries,
            deferred_entries=deferred,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_append_restart_idempotence_search_and_parent_immutability(self) -> None:
        prepared = self._prepared()
        parent_path = (
            self.root / "canonical" / "historical-weekly-activity-events"
            / f"{self.parent['event_id']}.json"
        )
        before = parent_path.read_bytes()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual("complete", result.status)
        self.assertEqual(
            "complete",
            self.coordinator.verify_restart(
                prepared, receipt_id=receipt["receipt_id"]
            ).status,
        )
        self.assertEqual(
            "already_complete",
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status,
        )
        self.assertEqual(before, parent_path.read_bytes())
        database = sqlite3.connect(
            self.root / "derived" / "historical-migration-amendment" / f"{result.event_id}.sqlite3"
        )
        try:
            self.assertEqual(3, database.execute("SELECT count(*) FROM amendments_fts").fetchone()[0])
        finally:
            database.close()

    def test_parent_or_approved_scope_mutation_fails_closed(self) -> None:
        prepared = self._prepared()
        mutated = deepcopy(prepared.package)
        mutated["entries"][0]["entry_id"] = "D"
        with self.assertRaises(HistoricalMigrationAmendmentError):
            self.coordinator.prepare(
                bundle_id=self.harness.ids.new("private_bundle"),
                parent_binding=self.parent,
                owner_review=prepared.package["owner_review"],
                entries=tuple(mutated["entries"]),
                deferred_entries=tuple(prepared.package["deferred_entries"]),
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
        parent_path = self.root / "canonical" / "historical-weekly-activity-events" / f"{self.parent['event_id']}.json"
        parent_path.write_text("{}", encoding="utf-8")
        receipt = self.coordinator.authorize(prepared)
        with self.assertRaises(HistoricalMigrationAmendmentError):
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
