"""Hostile fixtures for the append-only owner-confirmed historical-context lane."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.historical_owner_context import (
    PURPOSE,
    HistoricalOwnerContextCoordinator,
    HistoricalOwnerContextError,
    OwnerContextStatement,
    ParentEventBinding,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeAuthority:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_historical_owner_confirmed_continuity_supplement(self, manifest: dict) -> dict:
        receipt = {"schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
                   "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
                   "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
                   "manifest_digest": manifest["manifest_digest"], "issued_at": "2026-09-19T00:00:00Z",
                   "expires_at": manifest["expires_at"]}
        display = {"schema_version": "1.0", "authority_id": AUTHORITY_ID,
                   "authority_bundle_id": self.harness.ids.new("bundle"), "purpose": PURPOSE,
                   "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt}
        signed = {"schema_version": "1.0", "receipt_type": PURPOSE, "authority_id": AUTHORITY_ID,
                  "authority_bundle_id": display["authority_bundle_id"], "algorithm": "ed25519",
                  "key_id": "f" * 64, "receipt": receipt, "manifest": manifest,
                  "manifest_digest": manifest["manifest_digest"],
                  "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
                  "confirmed_at": receipt["issued_at"], "signature_base64": "hostile-fixture-signature"}
        self.harness.schemas.require("historical-owner-confirmed-continuity-supplement-display", display)
        self.harness.schemas.require("historical-owner-confirmed-continuity-supplement-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = (receipt, canonical_bytes(display), canonical_bytes(signed))
        return receipt

    def verify_historical_owner_confirmed_continuity_supplement(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture receipt substitution")
        return receipt

    def read_historical_owner_confirmed_continuity_supplement_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        self.verify_historical_owner_confirmed_continuity_supplement(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_historical_owner_confirmed_continuity_supplement(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archived evidence substitution")
        return receipt


class HistoricalOwnerContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(
            prefix="vault-next-owner-context-", dir="/private/tmp"
        )
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.parents = self._parents()
        self.authority = FakeAuthority(self.harness)
        self.coordinator = HistoricalOwnerContextCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _parents(self) -> tuple[ParentEventBinding, ...]:
        result = []
        for _ in range(4):
            event_id = self.harness.ids.new("event")
            event = {
                "schema_version": "1.0",
                "event_id": event_id,
                "publication_type": "hostile_fixture_week",
            }
            event_bytes = canonical_bytes(event)
            coverage = {"complete_disposition_count": 1, "silent_orphans": 0}
            relationships = [{"relationship_id": f"fixture-{event_id}"}]
            views = {"primary_artifact_digest": "a" * 64, "support_view_digests": {}}
            primary = {"artifact_digest": "a" * 64}
            package = {
                "weekly_wave": {"views": views},
                "cross_wave_reconciliation": {
                    "coverage_register": coverage,
                    "relationships": relationships,
                },
                "primary_artifact": primary,
            }
            materials = {
                "event": event_bytes,
                "package": canonical_bytes(package),
                "coverage": canonical_bytes(coverage),
                "relationship": canonical_bytes(relationships),
                "workspace": canonical_bytes(views),
            }
            names = {
                key: sha256_hex(materials[key])
                for key in ("package", "coverage", "relationship", "workspace")
            }
            paths = {
                "event": self.root / "canonical" / "historical-weekly-activity-events" / f"{event_id}.json",
                "package": self.root / "canonical" / "historical-weekly-activity-packages" / names["package"],
                "coverage": self.root / "canonical" / "historical-weekly-activity-coverage" / names["coverage"],
                "relationship": (
                    self.root / "canonical" / "historical-weekly-activity-relationships"
                    / names["relationship"]
                ),
                "workspace": (
                    self.root / "workspace" / "_views" / "historical-weekly-activity"
                    / names["workspace"]
                ),
            }
            for key, path in paths.items():
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(materials[key])
            result.append(
                ParentEventBinding(
                    event_id,
                    sha256_hex(event_bytes),
                    sha256_hex(materials["package"]),
                    primary["artifact_digest"],
                    sha256_hex(materials["coverage"]),
                    sha256_hex(materials["relationship"]),
                    sha256_hex(materials["workspace"]),
                )
            )
        return tuple(result)

    def _prepared(self):
        ids = tuple(parent.event_id for parent in self.parents)
        statements = tuple(
            OwnerContextStatement(
                f"OC{index}", f"Topic {index}", f"Invented hostile owner context {index}.",
                (ids[index],),
            )
            for index in range(4)
        )
        return self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"),
            parents=self.parents,
            statements=statements,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_append_restart_idempotence_and_mirror_rollback(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual("complete", result.status)
        self.assertEqual(
            "complete",
            self.coordinator.verify_restart(prepared, receipt_id=receipt["receipt_id"]).status,
        )
        self.assertEqual(
            "already_complete",
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status,
        )
        rollback = self.coordinator.append_disposable_mirror_rollback(result.event_id)
        self.assertTrue(rollback["parent_events_unchanged"])
        rendered = (
            self.root / "workspace" / "History" / "Continuity Supplements"
            / f"{result.event_id}.md"
        ).read_text()
        self.assertIn("not a source-extracted claim", rendered)

    def test_rejects_statement_scope_mutation_and_parent_substitution(self) -> None:
        prepared = self._prepared()
        prepared.supplement["statements"][0]["text"] = "mutated"  # type: ignore[index]
        with self.assertRaises(HistoricalOwnerContextError):
            self.coordinator.authorize(prepared)
        prepared = self._prepared()
        self.root.joinpath(
            "canonical", "historical-weekly-activity-packages", self.parents[0].package_digest
        ).write_bytes(b"substituted")
        receipt = self.coordinator.authorize(prepared)
        with self.assertRaises(HistoricalOwnerContextError):
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])

    def test_interruption_never_appends_event(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        failing = HistoricalOwnerContextCoordinator(
            self.root,
            self.harness.schemas,
            self.authority,
            id_factory=self.harness.ids,
            fail_before_event=True,
        )
        with self.assertRaises(HistoricalOwnerContextError):
            failing.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertFalse((self.root / "canonical" / "historical-owner-context-events").exists())
