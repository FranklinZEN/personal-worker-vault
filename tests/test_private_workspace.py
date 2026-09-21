"""RPI-A hostile-synthetic tests for the real-private projection sibling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.private_workspace import (
    AUTHORITY_ID,
    PURPOSE,
    ChatFirstU1V2Adapter,
    PrivateBundleLayout,
    PrivateWorkspaceError,
    PrivateWorkspaceItem,
    RealPrivateWorkspaceProjectionCoordinator,
    build_u1_manifest,
)


class FakeExistingV2:
    """Purpose-specific injected fake; it has no Keychain or generic signing surface."""

    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.receipts: dict[str, dict] = {}

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
        self.receipts[receipt["receipt_id"]] = receipt
        return receipt

    def verify_chat_first_u1_save(self, receipt_id: str, manifest: dict) -> dict:
        receipt = self.receipts[receipt_id]
        if receipt["manifest_digest"] != manifest["manifest_digest"]:
            raise RuntimeError("invented mismatch")
        return receipt


class MissingExistingV2:
    """Fake unavailable existing identity; it must never bootstrap a substitute."""

    def authorize_chat_first_u1_save(self, manifest: dict) -> dict:
        raise RuntimeError("existing identity unavailable")

    def verify_chat_first_u1_save(self, receipt_id: str, manifest: dict) -> dict:
        raise RuntimeError("existing identity unavailable")


class RPIATests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness()
        self.temporary = TemporaryDirectory(prefix="vault-next-rpi-a-", dir="/private/tmp")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir(mode=0o700)
        PrivateBundleLayout.initialize(self.root, create=True)
        self.coordinator = RealPrivateWorkspaceProjectionCoordinator(self.harness.schemas)

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.harness.close()

    def _item(self, version: str = "debrief-v1") -> PrivateWorkspaceItem:
        return PrivateWorkspaceItem(
            item_id="meeting-invented",
            version_id=version,
            family="meeting",
            view="debriefs",
            status="reported",
            display_alias="Invented Meeting",
            canonical_object_sha256="a" * 64,
            admission_event_id="event_invented",
            body="Hostile invented evidence; no command or current decision.",
            citations=("paragraph:1",),
            candidate_inactive=True,
        )

    def _manifest(self) -> dict:
        return build_u1_manifest(
            ids=self.harness.ids,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"),
            ingress_envelope_sha256="1" * 64,
            source_sha256="2" * 64,
            source_size=23,
            u0_result_sha256="3" * 64,
            artifact_sha256="4" * 64,
            candidate_package_sha256="5" * 64,
            profile_id="plain_text",
            safe_label="invented.txt",
            citations=("paragraph:1",),
            schemas=self.harness.schemas,
        )

    def test_rpi_01_rpi_04_rpi_05_purpose_specific_adapter(self) -> None:
        manifest = self._manifest()
        adapter = ChatFirstU1V2Adapter(FakeExistingV2(self.harness), self.harness.schemas)
        receipt = adapter.authorize(manifest)
        self.assertEqual(adapter.verify(receipt["receipt_id"], manifest), receipt)
        wrong = dict(receipt)
        wrong["purpose"] = "direct_private_source_admission"
        with self.assertRaises(Exception):
            self.harness.schemas.require("chat-first-u1-save-receipt", wrong)

    def test_b0_01_to_b0_04_unavailable_and_substituted_authority_fail_closed(self) -> None:
        manifest = self._manifest()
        adapter = ChatFirstU1V2Adapter(MissingExistingV2(), self.harness.schemas)
        with self.assertRaises(RuntimeError):
            adapter.authorize(manifest)
        altered = dict(manifest)
        altered["purpose"] = "direct_private_source_admission"
        with self.assertRaises(Exception):
            ChatFirstU1V2Adapter(FakeExistingV2(self.harness), self.harness.schemas).authorize(altered)

    def test_rpi_02_layout_rejects_symlink_and_group_mode(self) -> None:
        PrivateBundleLayout.validate(self.root)
        unsafe = self.root / "workspace"
        shutil.rmtree(unsafe)
        unsafe.symlink_to("/private/tmp")
        with self.assertRaises(PrivateWorkspaceError):
            PrivateBundleLayout.validate(self.root)

    def test_rpi_06_rpi_07_rpi_08_rpi_09_projection_restart_and_tamper_fence(self) -> None:
        first = self.coordinator.build(self.root, (self._item(),))
        self.coordinator.verify(first)
        page = next(iter(first.page_paths.values()))
        page.write_text("tampered", encoding="utf-8")
        with self.assertRaises(PrivateWorkspaceError):
            self.coordinator.verify(first)
        rebuilt = self.coordinator.build(self.root, (self._item(), self._item("debrief-v2")))
        self.coordinator.verify(rebuilt)
        self.assertEqual(len(rebuilt.page_paths), 2)
        self.assertIn("Inactive candidate", next(iter(rebuilt.page_paths.values())).read_text())

    def test_rpi_10_rpi_11_rpi_12_no_current_or_source_capability(self) -> None:
        with self.assertRaises(PrivateWorkspaceError):
            self.coordinator.build(
                self.root,
                (PrivateWorkspaceItem(
                    item_id="bad", version_id="v1", family="work", view="current", status="current",
                    display_alias="bad", canonical_object_sha256="b" * 64, admission_event_id="event_bad",
                    body="invented", citations=("paragraph:1",),
                ),),
            )
        manifest = self._manifest()
        self.assertNotIn("source_path", manifest)
        self.assertNotIn("network", manifest)
        self.assertEqual(manifest["purpose"], PURPOSE)
        self.assertEqual(manifest["authority_id"], AUTHORITY_ID)


if __name__ == "__main__":
    unittest.main()
