"""Hostile-synthetic coverage for the purpose-separated four-source U1 publisher."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.multi_source_admission import (
    PURPOSE,
    MultiSourceAdmissionError,
    MultiSourceAdmissionInput,
    MultiSourceAdmissionPublisher,
    MultiSourceItem,
    build_multi_source_u1_manifest,
)
from vault_next.private_admission import PrivateAdmissionPublisher
from vault_next.private_workspace import AUTHORITY_ID, PrivateBundleLayout, PrivateWorkspaceItem


class FakeMultiSourceAuthority:
    """Injected fake v2 boundary; it signs neither generic nor real material."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_chat_first_u1_multi_source_save(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0", "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID, "purpose": PURPOSE,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": "2026-09-14T00:00:00Z",
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
            "key_id": "a" * 64, "receipt": receipt, "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(canonical_bytes(display)),
            "confirmed_at": receipt["issued_at"], "signature_base64": "fixture-signature",
        }
        self.harness.schemas.require("chat-first-u1-multi-source-save-display", display)
        self.harness.schemas.require("chat-first-u1-multi-source-save-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = (receipt, canonical_bytes(display), canonical_bytes(signed))
        return receipt

    def verify_chat_first_u1_multi_source_save(self, receipt_id: str, manifest: dict) -> dict:
        receipt, _display, _signed = self.records[receipt_id]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture manifest mismatch")
        return receipt

    def read_chat_first_u1_multi_source_save_evidence(self, receipt_id: str, manifest: dict) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_multi_source_save(receipt_id, manifest)
        _receipt, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_chat_first_u1_multi_source_save(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archive mismatch")
        return self.verify_chat_first_u1_multi_source_save(receipt_id, manifest)


class MultiSourceAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-multi-u1-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeMultiSourceAuthority(self.harness)
        self.publisher = MultiSourceAdmissionPublisher(
            self.root, self.harness.schemas, self.authority,
            id_factory=self.harness.ids, clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _packet(self) -> MultiSourceAdmissionInput:
        items = tuple(
            MultiSourceItem(
                role=role,
                source_locator=f"/synthetic-vault/{role.lower()}.md",
                safe_label=f"{role.lower()}.md",
                source_bytes=f"# {role}\nInvented hostile {role} record.\n".encode(),
                source_version={
                    "source_version_id": self.harness.ids.new("source_version"),
                    "content_sha256": sha256_hex(f"# {role}\nInvented hostile {role} record.\n".encode()),
                    "byte_count": len(f"# {role}\nInvented hostile {role} record.\n".encode()),
                    "profile_id": "markdown_text",
                    "provenance_sha256": {"M1": "1", "W1": "2", "W2": "3", "W3": "4"}[role] * 64,
                },
            )
            for role in ("M1", "W1", "W2", "W3")
        )
        citations = tuple((f"{item.role}:paragraph:1", f"Invented hostile {item.role} record.") for item in items)
        workspace_items = (
            PrivateWorkspaceItem(
                item_id="invented-workstream", version_id="continuity-v1", family="work", view="reported",
                status="reported", display_alias="Invented Continuity", canonical_object_sha256="0" * 64,
                admission_event_id="event-placeholder", body="# Continuity\n\nReported only.",
                citations=("W1:paragraph:1",), candidate_inactive=True,
            ),
            PrivateWorkspaceItem(
                item_id="invented-decision", version_id="ledger-v1", family="decision", view="reported",
                status="reported", display_alias="Invented Decision Ledger", canonical_object_sha256="0" * 64,
                admission_event_id="event-placeholder", body="# Decision ledger\n\nReported only.",
                citations=("W3:paragraph:1",), candidate_inactive=True,
            ),
            PrivateWorkspaceItem(
                item_id="invented-next-evidence", version_id="preparation-v1", family="work", view="reported",
                status="inactive", display_alias="Invented Next Evidence", canonical_object_sha256="0" * 64,
                admission_event_id="event-placeholder", body="# Next evidence\n\nNo work adopted.",
                citations=("W2:paragraph:1",), candidate_inactive=True,
            ),
        )
        candidate = {
            "schema_version": "1.0", "candidate_id": self.harness.ids.new("skill_candidate"),
            "family": "work_continuity", "method_name": "state-check", "method_version": "0.1.0",
            "method_source_sha256": sha256_hex(items[0].source_bytes),
            "method_source_markdown": items[0].source_bytes.decode(),
            "portable_core": ["Report source state.", "Do not adopt current work."],
            "prohibitions": ["no_activation", "no_current_work", "no_u2", "no_s2_apply"],
            "lifecycle": "inactive",
        }
        relationship = {
            "assertion_id": self.harness.ids.new("relationship_ledger"),
            "origin_version_id": items[1].source_version["source_version_id"],
            "target_version_id": "continuity-v1", "type": "about_initiative",
            "source_anchor": "W1:paragraph:1", "state": "reported",
        }
        artifact = {
            "schema_version": "1.0", "artifact_kind": "work_continuity_wave",
            "u0_result_sha256": "3" * 64, "citation_text": [list(row) for row in citations],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item) for item in workspace_items],
        }
        manifest = build_multi_source_u1_manifest(
            ids=self.harness.ids, expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"), source_items=items,
            u0_result_sha256="3" * 64, artifact_sha256=canonical_sha256(artifact),
            candidate_package_sha256=canonical_sha256(candidate),
            relationship_ledger_sha256=canonical_sha256([relationship]),
            citations=tuple(anchor for anchor, _text in citations), schemas=self.harness.schemas,
        )
        return MultiSourceAdmissionInput(
            manifest=manifest, source_items=items, artifact=artifact, candidate_package=candidate,
            relationship_assertions=(relationship,), citation_text=citations, workspace_items=workspace_items,
        )

    def _receipt(self, packet: MultiSourceAdmissionInput) -> str:
        return self.authority.authorize_chat_first_u1_multi_source_save(packet.manifest)["receipt_id"]

    def test_msu1_01_atomic_ordered_publish_restart_fts_workspace_and_idempotence(self) -> None:
        packet = self._packet()
        receipt = self._receipt(packet)
        result = self.publisher.publish(packet, receipt)
        self.assertEqual(result.status, "complete")
        self.assertEqual(self.publisher.verify_restart()["event_count"], 1)
        event_path = next((self.root / "canonical" / "events").iterdir())
        event = json.loads(event_path.read_text())
        self.assertEqual(
            [item["role"] for item in event["source_items"]],
            ["M1", "W1", "W2", "W3"],
        )
        self.assertEqual(len(list((self.root / "canonical" / "source-objects").iterdir())), 4)
        self.assertTrue(list((self.root / "workspace" / "Work").rglob("*.md")))
        self.assertTrue((self.root / "derived" / "fts5" / "citations.sqlite3").is_file())
        self.assertEqual(self.publisher.publish(packet, receipt).status, "already_admitted")

    def test_msu1_02_reorder_mutation_receipt_substitution_and_tamper_fail_closed(self) -> None:
        packet = self._packet()
        swapped = MultiSourceAdmissionInput(**{**packet.__dict__, "source_items": packet.source_items[::-1]})
        with self.assertRaises(MultiSourceAdmissionError):
            self.publisher.publish(swapped, self._receipt(packet))
        changed_items = list(packet.source_items)
        changed_items[2] = MultiSourceItem(**{**changed_items[2].__dict__, "source_bytes": b"changed"})
        changed = MultiSourceAdmissionInput(**{**packet.__dict__, "source_items": tuple(changed_items)})
        with self.assertRaises(MultiSourceAdmissionError):
            self.publisher.publish(changed, self._receipt(packet))
        receipt = self._receipt(packet)
        self.publisher.publish(packet, receipt)
        with self.assertRaises(MultiSourceAdmissionError):
            self.publisher.publish(packet, self._receipt(packet))
        event = json.loads(next((self.root / "canonical" / "events").iterdir()).read_text())
        target = self.root / "canonical" / "source-objects" / event["source_items"][0]["source_sha256"]
        target.write_bytes(b"substituted")
        with self.assertRaises(MultiSourceAdmissionError):
            self.publisher.verify_restart()

    def test_msu1_03_interruption_never_creates_a_visibility_event_and_recovery_is_safe(self) -> None:
        packet = self._packet()

        def interrupt(point: str) -> None:
            if point == "after_objects":
                raise RuntimeError("invented interruption")

        faulting = MultiSourceAdmissionPublisher(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids,
            clock=lambda: self.harness.current, fault_injector=interrupt,
        )
        with self.assertRaises(RuntimeError):
            faulting.publish(packet, self._receipt(packet))
        self.assertEqual(list((self.root / "canonical" / "events").iterdir()), [])
        self.assertEqual(faulting.recover()["status"], "complete")
        self.assertEqual(self.publisher.publish(packet, self._receipt(packet)).status, "complete")

    def test_msu1_04_existing_one_source_publisher_remains_independent(self) -> None:
        packet = self._packet()
        self.publisher.publish(packet, self._receipt(packet))
        # The historical publisher does not interpret multi-purpose events as one-source events.
        self.assertEqual(self.publisher.legacy.verify_restart()["event_count"], 0)


if __name__ == "__main__":
    unittest.main()
