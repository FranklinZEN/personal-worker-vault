"""Hostile-synthetic S6-P1 three-wave primary-artifact retrofit tests."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.primary_artifact_retrofit import (
    KINDS,
    PURPOSE,
    WAVES,
    ParentEventBinding,
    PreparedPrimaryArtifactRetrofit,
    PrimaryArtifactRetrofitCoordinator,
    PrimaryArtifactRetrofitDraft,
    PrimaryArtifactRetrofitError,
    SupportReference,
)
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout


class FakeRetrofitAuthority:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_chat_first_u1_primary_artifact_retrofit(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-15T00:00:00Z",
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
            "key_id": "f" * 64,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
            "confirmed_at": receipt["issued_at"],
            "signature_base64": "hostile-fixture-signature",
        }
        self.harness.schemas.require("chat-first-u1-primary-artifact-retrofit-display", display)
        self.harness.schemas.require(
            "chat-first-u1-primary-artifact-retrofit-signed-receipt", signed
        )
        self.records[receipt["receipt_id"]] = (
            receipt,
            canonical_bytes(display),
            canonical_bytes(signed),
        )
        return receipt

    def verify_chat_first_u1_primary_artifact_retrofit(
        self, receipt_id: str, manifest: dict
    ) -> dict:
        receipt = self.records[receipt_id][0]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture retrofit manifest mismatch")
        return receipt

    def read_chat_first_u1_primary_artifact_retrofit_evidence(
        self, receipt_id: str, manifest: dict
    ) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_primary_artifact_retrofit(receipt_id, manifest)
        _, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_chat_first_u1_primary_artifact_retrofit(
        self,
        receipt_id: str,
        manifest: dict,
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archived retrofit evidence mismatch")
        return receipt


class PrimaryArtifactRetrofitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-primary-retrofit-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeRetrofitAuthority(self.harness)
        self.parents = self._parents()
        self.drafts = self._drafts()
        self.coordinator = PrimaryArtifactRetrofitCoordinator(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _parents(self) -> tuple[ParentEventBinding, ...]:
        bindings = []
        for wave in WAVES:
            event_id = self.harness.ids.new("event")
            event = {
                "schema_version": "1.0",
                "publication_type": "hostile_fixture_parent",
                "event_id": event_id,
                "wave_id": wave,
            }
            material = canonical_bytes(event)
            (self.root / "canonical" / "events" / f"{event_id}.json").write_bytes(material)
            supports: tuple[tuple[str, str], ...] = ()
            if wave == "S6-W2":
                recovery_id = self.harness.ids.new("event")
                recovery = {
                    "schema_version": "1.0",
                    "publication_type": "chat_first_u1_citation_recovery",
                    "event_id": recovery_id,
                    "parent_event_id": event_id,
                }
                recovery_bytes = canonical_bytes(recovery)
                recovery_root = self.root / "canonical" / "citation-recovery-events"
                recovery_root.mkdir(mode=0o700, exist_ok=True)
                (recovery_root / f"{recovery_id}.json").write_bytes(recovery_bytes)
                supports = ((recovery_id, sha256_hex(recovery_bytes)),)
            bindings.append(
                ParentEventBinding(wave, event_id, sha256_hex(material), supports)
            )
        return tuple(bindings)

    def _drafts(self) -> tuple[PrimaryArtifactRetrofitDraft, ...]:
        aliases = (
            "Invented Hostile Meeting Debrief",
            "Invented Hostile Workstream Status",
            "Invented Hostile Deep Dive",
        )
        roles = (
            ("continuity", "preparation"),
            ("decision_ledger", "next_evidence"),
            ("knowledge", "timeline", "navigation"),
        )
        result = []
        for wave, kind, alias, support_roles in zip(WAVES, KINDS, aliases, roles, strict=True):
            citations = {
                "schema_version": "1.0",
                "wave_id": wave,
                "claims": [
                    {
                        "claim_sha256": sha256_hex(f"{wave} hostile claim".encode()),
                        "bindings": [{"anchor": f"{wave}:fixture:1", "digest": "a" * 64}],
                    }
                ],
            }
            result.append(
                PrimaryArtifactRetrofitDraft(
                    wave_id=wave,
                    artifact_id=self.harness.ids.new("artifact"),
                    revision_id=self.harness.ids.new("artifact_version"),
                    revision_number=1,
                    artifact_kind=kind,
                    display_alias=alias,
                    markdown=f"# {alias}\n\nHostile invented {wave} primary record.\n",
                    citation_companion=citations,
                    support_refs=tuple(
                        SupportReference(
                            role,
                            "workspace_page",
                            f"workspace/_views/{wave}/{role}.md",
                            sha256_hex(f"{wave}:{role}".encode()),
                        )
                        for role in support_roles
                    ),
                )
            )
        return tuple(result)

    def _prepared(self) -> PreparedPrimaryArtifactRetrofit:
        return self.coordinator.prepare(
            bundle_id=self.harness.ids.new("private_bundle"),
            parents=self.parents,
            drafts=self.drafts,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

    def test_exact_three_wave_manifest_and_purpose_separation(self) -> None:
        prepared = self._prepared()
        self.assertEqual(prepared.manifest["purpose"], PURPOSE)
        self.assertEqual(
            tuple(item["wave_id"] for item in prepared.manifest["retrofits"]), WAVES
        )
        self.assertEqual(len(prepared.manifest["retrofits"]), 3)
        self.assertEqual(len(prepared.manifest["retrofits"][1]["support_event_ids"]), 1)
        with self.assertRaises(PrimaryArtifactRetrofitError):
            self.coordinator.prepare(
                bundle_id=self.harness.ids.new("private_bundle"),
                parents=self.parents[:2],
                drafts=self.drafts[:2],
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )

    def test_publish_restart_idempotence_retrieval_and_workspace(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")
        self.assertEqual(
            self.coordinator.verify_restart(
                prepared, receipt_id=receipt["receipt_id"]
            ).status,
            "complete",
        )
        self.assertEqual(
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"]).status,
            "already_complete",
        )
        database = self.root / "derived" / "fts5" / f"primary-{result.event_id}.sqlite3"
        rows = sqlite3.connect(database).execute(
            "SELECT wave_id, title FROM primary_artifacts ORDER BY rowid"
        ).fetchall()
        self.assertEqual(tuple(row[0] for row in rows), WAVES)
        for wave in WAVES:
            directory = self.root / "workspace" / "_views" / "primary" / result.event_id / wave
            self.assertTrue((directory / "primary.md").is_file())
            self.assertTrue((directory / "primary.citations.json").is_file())
            self.assertTrue((directory / "supporting-package.md").is_file())

    def test_parent_revision_and_receipt_substitution_fail_closed(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        parent = self.root / "canonical" / "events" / f"{self.parents[0].event_id}.json"
        parent.write_bytes(canonical_bytes({"event_id": self.parents[0].event_id, "mutated": True}))
        with self.assertRaises(PrimaryArtifactRetrofitError):
            self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])

        parent.write_bytes(
            canonical_bytes(
                {
                    "schema_version": "1.0",
                    "publication_type": "hostile_fixture_parent",
                    "event_id": self.parents[0].event_id,
                    "wave_id": "S6-W1",
                }
            )
        )
        changed_draft = replace(self.drafts[0], markdown="# Mutated\n")
        changed = PreparedPrimaryArtifactRetrofit(
            prepared.manifest,
            prepared.parents,
            (changed_draft, *prepared.drafts[1:]),
            prepared.packages,
        )
        with self.assertRaises(PrimaryArtifactRetrofitError):
            self.coordinator.publish(changed, receipt_id=receipt["receipt_id"])

    def test_interruption_is_uncommitted_and_same_receipt_can_recover(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        interrupted = PrimaryArtifactRetrofitCoordinator(
            self.root,
            self.harness.schemas,
            self.authority,
            id_factory=self.harness.ids,
            fail_before_event=True,
        )
        with self.assertRaises(PrimaryArtifactRetrofitError):
            interrupted.publish(prepared, receipt_id=receipt["receipt_id"])
        event_root = self.root / "canonical" / "primary-artifact-retrofit-events"
        self.assertFalse(event_root.exists())
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        self.assertEqual(result.status, "complete")

    def test_replay_receipt_change_and_non_disposable_rollback_fail_closed(self) -> None:
        prepared = self._prepared()
        receipt = self.coordinator.authorize(prepared)
        result = self.coordinator.publish(prepared, receipt_id=receipt["receipt_id"])
        second = self.coordinator.authorize(prepared)
        with self.assertRaises(PrimaryArtifactRetrofitError):
            self.coordinator.publish(prepared, receipt_id=second["receipt_id"])
        rollback = self.coordinator.append_disposable_mirror_rollback(result.event_id)
        self.assertEqual(rollback["target_event_id"], result.event_id)
        self.assertTrue(rollback["parent_events_unchanged"])


if __name__ == "__main__":
    unittest.main()
