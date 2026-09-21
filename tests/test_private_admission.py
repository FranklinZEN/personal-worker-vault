"""S5-RW1-P1 hostile-synthetic tests for the real-private admission publisher."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.private_admission import (
    PrivateAdmissionError,
    PrivateAdmissionInput,
    PrivateAdmissionPublisher,
)
from vault_next.private_workspace import (
    AUTHORITY_ID,
    PURPOSE,
    PrivateBundleLayout,
    PrivateWorkspaceItem,
    build_u1_manifest,
)


class FakeArchiveAuthority:
    """Injected fake existing v2 authority; it has no generic signing or source capability."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.records: dict[str, tuple[dict, bytes, bytes]] = {}

    def authorize_chat_first_u1_save(self, manifest: dict) -> dict:
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.harness.ids.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": PURPOSE,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": "2026-09-14T00:00:00Z",
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
        self.harness.schemas.require("chat-first-u1-save-display", display)
        self.harness.schemas.require("chat-first-u1-save-signed-receipt", signed)
        self.records[receipt["receipt_id"]] = (receipt, canonical_bytes(display), canonical_bytes(signed))
        return receipt

    def verify_chat_first_u1_save(self, receipt_id: str, manifest: dict) -> dict:
        receipt, _display, _signed = self.records[receipt_id]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("fixture manifest mismatch")
        if datetime.fromisoformat(receipt["expires_at"].replace("Z", "+00:00")) <= datetime.now(UTC):
            raise RuntimeError("fixture receipt expired")
        return receipt

    def read_chat_first_u1_save_evidence(self, receipt_id: str, manifest: dict) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_save(receipt_id, manifest)
        _receipt, display, signed = self.records[receipt_id]
        return display, signed

    def verify_archived_chat_first_u1_save(
        self, receipt_id: str, manifest: dict, *, display_root: Path, receipt_root: Path
    ) -> dict:
        receipt, display, signed = self.records[receipt_id]
        if (
            (display_root / f"{receipt_id}.json").read_bytes() != display
            or (receipt_root / f"{receipt_id}.json").read_bytes() != signed
        ):
            raise RuntimeError("fixture archived evidence mismatch")
        return self.verify_chat_first_u1_save(receipt_id, manifest)


class PrivateAdmissionPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-p1-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.authority = FakeArchiveAuthority(self.harness)
        self.publisher = PrivateAdmissionPublisher(
            self.root, self.harness.schemas, self.authority,
            id_factory=self.harness.ids, clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _packet(self) -> PrivateAdmissionInput:
        source = b"VAULT_NEXT_HOSTILE_FIXTURE\nThe invented meeting made no real commitment.\n"
        citations = (("paragraph:1", "The invented meeting made no real commitment."),)
        item = PrivateWorkspaceItem(
            item_id="meeting-invented", version_id="debrief-v1", family="meeting", view="debriefs",
            status="reported", display_alias="Invented Meeting", canonical_object_sha256="0" * 64,
            admission_event_id="event-placeholder", body="Invented cited debrief.",
            citations=("paragraph:1",), candidate_inactive=True,
        )
        package = {
            "schema_version": "1.0", "candidate_id": self.harness.ids.new("skill_candidate"),
            "family": "meeting_workflow", "package_version": "1.0",
            "ingress_profiles": ["plain_text"], "required_sections": ["claims"],
            "prohibitions": ["no_activation"], "lifecycle": "inactive",
        }
        relation = {
            "assertion_id": self.harness.ids.new("relationship_ledger"),
            "origin_version_id": self.harness.ids.new("source_version"),
            "target_version_id": "debrief-v1", "type": "debriefs", "source_anchor": "paragraph:1",
            "state": "reported",
        }
        artifact = {
            "schema_version": "1.0", "artifact_kind": "meeting_debrief",
            "u0_result_sha256": "3" * 64, "citation_text": [list(row) for row in citations],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item)],
        }
        manifest = build_u1_manifest(
            ids=self.harness.ids, expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"), ingress_envelope_sha256="1" * 64,
            source_sha256=sha256_hex(source), source_size=len(source), u0_result_sha256="3" * 64,
            artifact_sha256=canonical_sha256(artifact), candidate_package_sha256=canonical_sha256(package),
            relationship_ledger_sha256=canonical_sha256([relation]), profile_id="plain_text",
            safe_label="invented.txt", citations=("paragraph:1",), schemas=self.harness.schemas,
        )
        return PrivateAdmissionInput(
            manifest=manifest, source_bytes=source,
            source_version={
                "source_version_id": relation["origin_version_id"],
                "content_sha256": sha256_hex(source),
                "byte_count": len(source),
            },
            artifact=artifact, candidate_package=package, relationship_assertions=(relation,),
            citation_text=citations, workspace_items=(item,),
        )

    def _receipt(self, packet: PrivateAdmissionInput) -> str:
        return self.authority.authorize_chat_first_u1_save(packet.manifest)["receipt_id"]

    def test_p1_01_to_p1_04_publish_restart_fts_and_workspace(self) -> None:
        packet = self._packet()
        receipt_id = self._receipt(packet)
        result = self.publisher.publish(packet, receipt_id)
        self.assertEqual(result.status, "complete")
        self.assertEqual(self.publisher.verify_restart()["event_count"], 1)
        self.assertTrue(list((self.root / "workspace" / "Meetings").rglob("*.md")))
        self.assertTrue((self.root / "derived" / "fts5" / "citations.sqlite3").is_file())
        self.assertEqual(self.publisher.publish(packet, receipt_id).status, "already_admitted")

    def test_p1_05_replay_mutation_and_missing_authority_fail_closed(self) -> None:
        packet = self._packet()
        receipt_id = self._receipt(packet)
        changed = PrivateAdmissionInput(
            **{**packet.__dict__, "source_bytes": packet.source_bytes + b"changed"}
        )
        with self.assertRaises(PrivateAdmissionError):
            self.publisher.publish(changed, receipt_id)
        self.publisher.publish(packet, receipt_id)
        alternate = self._receipt(packet)
        with self.assertRaises(PrivateAdmissionError):
            self.publisher.publish(packet, alternate)

    def test_p1_06_tamper_interrupt_unsafe_root_and_no_source_fallback(self) -> None:
        packet = self._packet()
        receipt_id = self._receipt(packet)

        def interrupt(point: str) -> None:
            if point == "after_objects":
                raise RuntimeError("invented interruption")

        faulting = PrivateAdmissionPublisher(
            self.root, self.harness.schemas, self.authority, id_factory=self.harness.ids,
            clock=lambda: self.harness.current, fault_injector=interrupt,
        )
        with self.assertRaises(RuntimeError):
            faulting.publish(packet, receipt_id)
        self.assertEqual(faulting.recover()["recovered_stages"], 0)
        self.assertEqual(self.publisher.publish(packet, receipt_id).status, "complete")
        event_path = next((self.root / "canonical" / "events").iterdir())
        event = json.loads(event_path.read_text())
        source = self.root / "canonical" / "source-objects" / event["source_object_sha256"]
        source.write_bytes(b"replacement")
        with self.assertRaises(PrivateAdmissionError):
            self.publisher.verify_restart()

    def test_p1_07_to_p1_12_display_expiry_missing_authority_root_and_write_fences(self) -> None:
        packet = self._packet()
        receipt_id = self._receipt(packet)
        _receipt, display, signed = self.authority.records[receipt_id]
        self.authority.records[receipt_id] = (_receipt, display + b" ", signed)
        with self.assertRaises(PrivateAdmissionError):
            self.publisher.publish(packet, receipt_id)
        self.authority.records[receipt_id] = (_receipt, display, signed)

        expired_manifest = dict(packet.manifest)
        expired_manifest["expires_at"] = "2000-01-01T00:00:00Z"
        expired_manifest["manifest_digest"] = canonical_sha256(
            {key: value for key, value in expired_manifest.items() if key != "manifest_digest"}
        )
        expired_packet = PrivateAdmissionInput(**{**packet.__dict__, "manifest": expired_manifest})
        expired_receipt = self._receipt(expired_packet)
        with self.assertRaises(RuntimeError):
            self.publisher.publish(expired_packet, expired_receipt)

        workspace = self.root / "workspace"
        shutil.rmtree(workspace)
        workspace.symlink_to(self.temporary.name)
        with self.assertRaises(Exception):
            self.publisher.publish(packet, self._receipt(packet))
        workspace.unlink()
        workspace.mkdir(mode=0o700)
        for relative in ("Conversations", "Meetings", "Decisions", "Knowledge", "Work", "People", "Skills", "_views"):
            (workspace / relative).mkdir(mode=0o700)

        outside = Path(self.temporary.name) / "outside"
        outside.mkdir(mode=0o700)
        self.assertEqual(list(outside.iterdir()), [])
        saved_receipt = self._receipt(packet)
        self.publisher.publish(packet, saved_receipt)
        self.assertEqual(list(outside.iterdir()), [])
        signed_path = self.root / "receipts" / "chat-first-u1-save" / f"{saved_receipt}.json"
        self.assertTrue(signed_path.is_file())


if __name__ == "__main__":
    unittest.main()
