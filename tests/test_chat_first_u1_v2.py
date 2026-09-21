"""B0 hostile tests for the concrete v2 Chat-first U1 purpose bridge."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.local_confirmation import ConfirmationUI, KeychainStore
from vault_next.local_confirmation_v2 import (
    AUTHORITY_ID_V2,
    ArchivePreservationV2ReceiptVerifier,
    ChatFirstU1MultiSourceKnowledgeSaveV2ReceiptVerifier,
    ChatFirstU1MultiSourceSaveV2ReceiptVerifier,
    ChatFirstU1PrimaryArtifactRetrofitV2ReceiptVerifier,
    ChatFirstU1SaveV2ReceiptVerifier,
    DurableLocalAuthority,
    HistoricalActivityReconstructionV2ReceiptVerifier,
    HistoricalWeeklyActivityReconstructionV2ReceiptVerifier,
    LocalConfirmationV2Declined,
    LocalConfirmationV2Error,
    MacOSChatFirstU1SaveConfirmationUI,
)
from vault_next.multi_source_admission import (
    KNOWLEDGE_LINEAGE_PROFILE,
    MultiSourceItem,
    build_multi_source_u1_manifest,
)
from vault_next.private_workspace import ChatFirstU1V2Adapter, build_u1_manifest
from vault_next.runtime import CaseSessionRuntime


class _ExistingOnlyKeychain(KeychainStore):
    """A test-only preloaded identity that rejects all creation attempts."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}
        self.create_calls = 0

    def find(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def create(self, service: str, account: str, secret: bytes) -> None:
        self.create_calls += 1
        raise AssertionError("Chat-first U1 must never bootstrap a Keychain identity")

    def remove(self, service: str, account: str) -> None:
        self.items.pop((service, account), None)


class _UnusedTransactionConfirmation(ConfirmationUI):
    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        raise AssertionError("Chat-first U1 must not use transaction confirmation")


class _FakeChatFirstLauncher:
    """Fakeable native UI with no TextEdit, AppleScript, socket, or subprocess use."""

    def __init__(
        self,
        *,
        response: str | None = None,
        open_result: bool = True,
        mutate_display: bool = False,
    ) -> None:
        self.response = response
        self.open_result = open_result
        self.mutate_display = mutate_display
        self.opened: list[Path] = []
        self.prompts: list[str] = []

    def open_textedit(self, display_path: Path) -> bool:
        self.opened.append(display_path)
        if self.mutate_display:
            display_path.write_bytes(b'{"hostile":"replacement"}')
        return self.open_result

    def request_digest(self, *, expected_manifest_digest: str) -> str:
        self.prompts.append(expected_manifest_digest)
        return expected_manifest_digest if self.response is None else self.response


class ChatFirstU1V2BridgeTests(unittest.TestCase):
    """B0-01–B0-05 run entirely on a temporary runtime and injected fake authority boundary."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id="synthetic-chat-first-u1-b0",
        )
        self.authority_temporary = TemporaryDirectory(
            prefix="vault-next-chat-first-u1-authority-", dir="/private/tmp"
        )
        self.authority_root = Path(self.authority_temporary.name) / "authority"
        self.keychain = _ExistingOnlyKeychain()
        self.launcher = _FakeChatFirstLauncher()
        self.durable = self._existing_authority(self.launcher)

    def tearDown(self) -> None:
        self.authority_temporary.cleanup()
        self.harness.close()

    def _existing_authority(
        self, launcher: _FakeChatFirstLauncher, *, clock=None
    ) -> DurableLocalAuthority:
        authority = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.keychain,
            _UnusedTransactionConfirmation(),
            id_factory=self.harness.ids,
            clock=clock or (lambda: datetime.now(UTC)),
            chat_first_u1_save_confirmation_ui=MacOSChatFirstU1SaveConfirmationUI(launcher),
        )
        bundle_id = self.harness.ids.new("bundle")
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        service = f"{AUTHORITY_ID_V2}:{bundle_id}"
        self.keychain.items[(service, "ed25519-private-key")] = private_bytes
        record = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": bundle_id,
            "algorithm": "ed25519",
            "key_id": sha256(public_bytes).hexdigest(),
            "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
            "keychain_service_sha256": sha256(service.encode("utf-8")).hexdigest(),
            "status": "active",
        }
        self.harness.schemas.require(
            "local-confirmation-v2-authority", record, schema_version="2.0"
        )
        self.authority_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        authority.authority_path.write_bytes(canonical_bytes(record))
        return authority

    def _manifest(self) -> dict:
        return build_u1_manifest(
            ids=self.harness.ids,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"),
            ingress_envelope_sha256="1" * 64,
            source_sha256="2" * 64,
            source_size=41,
            u0_result_sha256="3" * 64,
            artifact_sha256="4" * 64,
            candidate_package_sha256="5" * 64,
            profile_id="docx_wordprocessingml",
            safe_label="invented-transcript.docx",
            citations=("paragraph:1",),
            schemas=self.harness.schemas,
        )

    def _multi_source_manifest(self) -> dict:
        items = tuple(
            MultiSourceItem(
                role=role,
                source_locator=f"/synthetic/{role.lower()}.md",
                safe_label=f"{role.lower()}.md",
                source_bytes=f"# {role}\nInvented only.\n".encode(),
                source_version={
                    "source_version_id": self.harness.ids.new("source_version"),
                    "content_sha256": sha256_hex(f"# {role}\nInvented only.\n".encode()),
                    "byte_count": len(f"# {role}\nInvented only.\n".encode()),
                    "profile_id": "markdown_text",
                    "provenance_sha256": {"M1": "1", "W1": "2", "W2": "3", "W3": "4"}[role] * 64,
                },
            )
            for role in ("M1", "W1", "W2", "W3")
        )
        return build_multi_source_u1_manifest(
            ids=self.harness.ids,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"),
            source_items=items,
            u0_result_sha256="3" * 64,
            artifact_sha256="4" * 64,
            candidate_package_sha256="5" * 64,
            relationship_ledger_sha256="6" * 64,
            citations=("M1:paragraph:1", "W1:paragraph:1", "W2:paragraph:1", "W3:paragraph:1"),
            schemas=self.harness.schemas,
        )

    def _knowledge_multi_source_manifest(self) -> dict:
        items = tuple(
            MultiSourceItem(
                role=role,
                source_locator=f"/synthetic/{role.lower()}.md",
                safe_label=f"{role.lower()}.md",
                source_bytes=f"# {role}\nInvented only.\n".encode(),
                source_version={
                    "source_version_id": self.harness.ids.new("source_version"),
                    "content_sha256": sha256_hex(f"# {role}\nInvented only.\n".encode()),
                    "byte_count": len(f"# {role}\nInvented only.\n".encode()),
                    "profile_id": "markdown_text",
                    "provenance_sha256": str(("K1", "K2", "K3", "K4").index(role) + 1) * 64,
                },
            )
            for role in ("K1", "K2", "K3", "K4")
        )
        return build_multi_source_u1_manifest(
            ids=self.harness.ids, expires_at=datetime.now(UTC) + timedelta(minutes=5),
            bundle_id=self.harness.ids.new("private_bundle"), source_items=items,
            u0_result_sha256="3" * 64, artifact_sha256="4" * 64,
            candidate_package_sha256="5" * 64, relationship_ledger_sha256="6" * 64,
            citations=(
                "K1:paragraph:1", "K2:paragraph:1", "K3:paragraph:1", "K4:paragraph:1",
            ),
            schemas=self.harness.schemas, profile=KNOWLEDGE_LINEAGE_PROFILE,
        )

    def _primary_artifact_retrofit_manifest(self) -> dict:
        retrofits = []
        for index, (wave, kind) in enumerate(
            zip(
                ("S6-W1", "S6-W2", "S6-W3"),
                ("meeting_debrief", "work_continuity", "deep_dive"),
                strict=True,
            ),
            start=1,
        ):
            support = []
            if wave == "S6-W2":
                support = [
                    {
                        "event_id": self.harness.ids.new("event"),
                        "event_sha256": "9" * 64,
                    }
                ]
            retrofits.append(
                {
                    "wave_id": wave,
                    "parent_event_id": self.harness.ids.new("event"),
                    "parent_event_sha256": str(index) * 64,
                    "support_event_ids": support,
                    "primary_artifact_id": self.harness.ids.new("artifact"),
                    "primary_revision_id": self.harness.ids.new("artifact_version"),
                    "primary_revision_number": 1,
                    "primary_artifact_kind": kind,
                    "primary_display_alias": f"Invented {wave} primary artifact",
                    "primary_markdown_sha256": "a" * 64,
                    "citation_companion_sha256": "b" * 64,
                    "support_package_sha256": "c" * 64,
                }
            )
        manifest = {
            "schema_version": "1.0",
            "component": "vault-next-primary-artifact-retrofit/1.0.0",
            "purpose": "chat_first_u1_primary_artifact_retrofit",
            "authority_id": AUTHORITY_ID_V2,
            "admission_id": self.harness.ids.new("private_admission"),
            "bundle_id": self.harness.ids.new("private_bundle"),
            "retrofits": retrofits,
            "disclosure": "visible_hosted_reasoning_fixed_admitted_scope",
            "retention": "append_only_primary_artifact_retrofit",
            "operations": [
                "stage_three_primary_artifacts",
                "append_one_retrofit_event",
                "build_primary_first_fts5",
                "build_primary_first_workspace",
            ],
            "expires_at": (
                datetime.now(UTC) + timedelta(minutes=5)
            ).isoformat().replace("+00:00", "Z"),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        return manifest

    def _archive_preservation_manifest(self) -> dict:
        material = b"hostile opaque archive member"
        manifest = {
            "schema_version": "1.0", "component": "vault-next-archive-preservation/1.0.0",
            "purpose": "archive_preservation", "authority_id": AUTHORITY_ID_V2,
            "admission_id": self.harness.ids.new("private_admission"),
            "bundle_id": self.harness.ids.new("private_bundle"),
            "lanes": [{
                "lane_id": "vault_lane", "source_class": "legacy_vault",
                "source_label": "invented", "source_scope_sha256": "1" * 64,
            }],
            "members": [{
                "lane_id": "vault_lane", "member_id": "file:invented.md",
                "relative_locator": "invented.md", "byte_count": len(material),
                "content_sha256": sha256_hex(material), "profile": "markdown_text",
                "disposition": "preserved", "duplicate_group": sha256_hex(material),
            }],
            "exclusions": [],
            "disclosure": "local_only_no_content_index", "retention": "append_only_archive_preservation",
            "operations": ["stage_opaque_members", "append_one_archive_preservation_event", "build_metadata_catalogue"],
            "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        return manifest

    def _historical_activity_manifest(self) -> dict:
        manifest = {
            "schema_version": "1.0",
            "component": "vault-next-historical-activity-reconstruction/1.0.0",
            "purpose": "historical_activity_reconstruction",
            "authority_id": AUTHORITY_ID_V2,
            "admission_id": self.harness.ids.new("private_admission"),
            "bundle_id": self.harness.ids.new("private_bundle"),
            "family": "meeting_workstream_history",
            "parent_event_id": "event_h1_synthetic",
            "parent_manifest_digest": "1" * 64,
            "catalogue_digest": "2" * 64,
            "cutoff": "2026-08-01T00:00:00Z",
            "selected_member_refs": ["vault_lane:file:invented.md"],
            "logical_record_digests": ["3" * 64],
            "item_observation_digests": ["4" * 64],
            "conversation_observation_digests": [],
            "reconstruction_digest": "5" * 64,
            "cross_wave_reconciliation_digest": "6" * 64,
            "disclosure": "hybrid_visible_hosted_exact_packs_local_private_storage",
            "candidate_only": True,
            "operations": [
                "append_candidate_historical_activity",
                "build_candidate_fts5",
                "build_historical_activity_views",
            ],
            "expires_at": (datetime.now(UTC) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        return manifest

    def _historical_weekly_activity_manifest(self) -> dict:
        parents = [
            {
                "parent_event_id": "event_h1_vault",
                "parent_manifest_digest": "1" * 64,
                "catalogue_digest": "2" * 64,
                "source_lane": "legacy_vault",
            },
            {
                "parent_event_id": "event_h1_codex",
                "parent_manifest_digest": "3" * 64,
                "catalogue_digest": "4" * 64,
                "source_lane": "codex_export",
            },
        ]
        manifest = {
            "schema_version": "1.0",
            "component": "vault-next-historical-weekly-activity-reconstruction/1.0.0",
            "purpose": "historical_weekly_activity_reconstruction",
            "authority_id": AUTHORITY_ID_V2,
            "admission_id": self.harness.ids.new("private_admission"),
            "bundle_id": self.harness.ids.new("private_bundle"),
            "family": "meeting_workstream_history",
            "week_start": "2026-08-31T00:00:00Z",
            "week_end": "2026-09-07T00:00:00Z",
            "parent_bindings": parents,
            "parent_set_digest": canonical_sha256(parents),
            "catalogue_set_digest": canonical_sha256(
                [parent["catalogue_digest"] for parent in parents]
            ),
            "selected_sources": [
                {
                    "parent_event_id": "event_h1_vault",
                    "parent_manifest_digest": "1" * 64,
                    "catalogue_digest": "2" * 64,
                    "member_ref": "vault:file:invented.md",
                    "logical_record_id": "vault:file:invented.md",
                    "object_digest": "5" * 64,
                    "parser_identity": "safe_logical_parser/1.1.0",
                }
            ],
            "logical_record_digests": ["6" * 64],
            "item_observation_digests": ["7" * 64],
            "conversation_observation_digests": [],
            "weekly_wave_digest": "8" * 64,
            "cross_wave_reconciliation_digest": "9" * 64,
            "primary_artifact_digest": "a" * 64,
            "support_view_digests": {"timeline": "b" * 64},
            "disclosure": "hybrid_visible_hosted_exact_packs_local_private_storage",
            "candidate_only": True,
            "operations": [
                "append_candidate_historical_weekly_activity",
                "build_candidate_weekly_fts5",
                "build_historical_weekly_views",
            ],
            "expires_at": (datetime.now(UTC) + timedelta(minutes=5))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        return manifest

    def _rewrite_signed_times(
        self,
        receipt_id: str,
        *,
        issued_at: datetime,
        confirmed_at: datetime,
    ) -> None:
        receipt_path = self.durable.chat_first_u1_save_receipt_root / f"{receipt_id}.json"
        display_path = self.durable.chat_first_u1_save_display_root / f"{receipt_id}.json"
        record = json.loads(receipt_path.read_bytes())
        display = json.loads(display_path.read_bytes())
        record["receipt"]["issued_at"] = issued_at.isoformat().replace("+00:00", "Z")
        record["confirmed_at"] = confirmed_at.isoformat().replace("+00:00", "Z")
        display["receipt"] = record["receipt"]
        display_bytes = canonical_bytes(display)
        record["confirmation_display_sha256"] = sha256_hex(display_bytes)
        private_bytes = next(iter(self.keychain.items.values()))
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        signature_material = {
            key: value for key, value in record.items() if key != "signature_base64"
        }
        record["signature_base64"] = base64.b64encode(
            private_key.sign(canonical_bytes(signature_material))
        ).decode("ascii")
        display_path.write_bytes(display_bytes)
        receipt_path.write_bytes(canonical_bytes(record))

    def test_b0_01_purpose_is_narrow_and_existing_identity_only(self) -> None:
        manifest = self._manifest()
        receipt = self.durable.authorize_chat_first_u1_save(manifest)
        self.assertEqual(receipt["purpose"], "chat_first_u1_save")
        self.assertEqual(self.keychain.create_calls, 0)
        changed = dict(manifest)
        changed["purpose"] = "direct_private_source_admission"
        with self.assertRaises(Exception):
            self.durable.authorize_chat_first_u1_save(changed)

    def test_b0_02_exact_display_and_replay_verification(self) -> None:
        manifest = self._manifest()
        adapter = ChatFirstU1V2Adapter(self.durable, self.harness.schemas)
        receipt = adapter.authorize(manifest)
        self.assertEqual(adapter.verify(receipt["receipt_id"], manifest), receipt)
        self.assertEqual(len(self.launcher.opened), 1)
        self.assertEqual(self.launcher.prompts, [manifest["manifest_digest"]])
        replayed = ChatFirstU1SaveV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=self.durable.clock,
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)

    def test_b0_03_missing_identity_does_not_bootstrap(self) -> None:
        unavailable_root = Path(self.authority_temporary.name) / "unavailable"
        unavailable = DurableLocalAuthority(
            self.harness.paths,
            unavailable_root,
            self.harness.schemas,
            _ExistingOnlyKeychain(),
            _UnusedTransactionConfirmation(),
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            chat_first_u1_save_confirmation_ui=MacOSChatFirstU1SaveConfirmationUI(
                _FakeChatFirstLauncher()
            ),
        )
        with self.assertRaises(LocalConfirmationV2Error):
            unavailable.authorize_chat_first_u1_save(self._manifest())
        self.assertFalse(unavailable_root.exists())

    def test_b0_04_decline_tamper_expiry_and_receipt_substitution_fail_closed(self) -> None:
        manifest = self._manifest()
        rejected = self._existing_authority(_FakeChatFirstLauncher(response="wrong-digest"))
        with self.assertRaises(LocalConfirmationV2Declined):
            rejected.authorize_chat_first_u1_save(manifest)
        mutated = self._existing_authority(_FakeChatFirstLauncher(mutate_display=True))
        with self.assertRaises(LocalConfirmationV2Error):
            mutated.authorize_chat_first_u1_save(manifest)
        receipt = self.durable.authorize_chat_first_u1_save(manifest)
        changed = dict(manifest)
        changed["safe_label"] = "changed.docx"
        with self.assertRaises(LocalConfirmationV2Error):
            self.durable.verify_chat_first_u1_save(receipt["receipt_id"], changed)
        expired = self._existing_authority(
            _FakeChatFirstLauncher(), clock=lambda: datetime.now(UTC) + timedelta(minutes=6)
        )
        with self.assertRaises(LocalConfirmationV2Error):
            expired.authorize_chat_first_u1_save(manifest)

    def test_b0_05_fake_boundary_uses_no_subprocess_and_preserves_existing_seams(self) -> None:
        manifest = self._manifest()
        with patch("subprocess.run", side_effect=AssertionError("subprocess called")):
            receipt = self.durable.authorize_chat_first_u1_save(manifest)
            self.assertEqual(
                self.durable.verify_chat_first_u1_save(receipt["receipt_id"], manifest), receipt
            )
        self.assertEqual(self.keychain.create_calls, 0)
        self.assertFalse((self.harness.paths.evidence_root / "local-confirmation-v2" / "direct-private").exists())

    def test_b0_08_multi_source_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._multi_source_manifest()
        receipt = self.durable.authorize_chat_first_u1_multi_source_save(manifest)
        self.assertEqual(receipt["purpose"], "chat_first_u1_multi_source_save")
        self.assertEqual(
            self.durable.verify_chat_first_u1_multi_source_save(receipt["receipt_id"], manifest), receipt
        )
        replayed = ChatFirstU1MultiSourceSaveV2ReceiptVerifier(
            self.harness.paths, self.authority_root, self.harness.schemas, clock=self.durable.clock
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_chat_first_u1_save(receipt["receipt_id"], manifest)
        self.assertEqual(self.keychain.create_calls, 0)

    def test_b0_09_knowledge_multi_source_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._knowledge_multi_source_manifest()
        receipt = self.durable.authorize_chat_first_u1_multi_source_knowledge_save(manifest)
        self.assertEqual(receipt["purpose"], "chat_first_u1_multi_source_knowledge_save")
        self.assertEqual(
            self.durable.verify_chat_first_u1_multi_source_knowledge_save(receipt["receipt_id"], manifest),
            receipt,
        )
        replayed = ChatFirstU1MultiSourceKnowledgeSaveV2ReceiptVerifier(
            self.harness.paths, self.authority_root, self.harness.schemas, clock=self.durable.clock
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_chat_first_u1_multi_source_save(receipt["receipt_id"], manifest)
        self.assertEqual(self.keychain.create_calls, 0)

    def test_primary_artifact_retrofit_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._primary_artifact_retrofit_manifest()
        receipt = self.durable.authorize_chat_first_u1_primary_artifact_retrofit(manifest)
        self.assertEqual(receipt["purpose"], "chat_first_u1_primary_artifact_retrofit")
        self.assertEqual(
            self.durable.verify_chat_first_u1_primary_artifact_retrofit(
                receipt["receipt_id"], manifest
            ),
            receipt,
        )
        replayed = ChatFirstU1PrimaryArtifactRetrofitV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=self.durable.clock,
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_chat_first_u1_citation_recovery(
                receipt["receipt_id"], manifest
            )
        self.assertEqual(self.keychain.create_calls, 0)

    def test_archive_preservation_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._archive_preservation_manifest()
        receipt = self.durable.authorize_archive_preservation(manifest)
        self.assertEqual(receipt["purpose"], "archive_preservation")
        self.assertEqual(self.durable.verify_archive_preservation(receipt["receipt_id"], manifest), receipt)
        replayed = ArchivePreservationV2ReceiptVerifier(
            self.harness.paths, self.authority_root, self.harness.schemas, clock=self.durable.clock
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_chat_first_u1_save(receipt["receipt_id"], manifest)
        self.assertEqual(self.keychain.create_calls, 0)

    def test_historical_activity_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._historical_activity_manifest()
        receipt = self.durable.authorize_historical_activity_reconstruction(manifest)
        self.assertEqual(receipt["purpose"], "historical_activity_reconstruction")
        self.assertEqual(
            self.durable.verify_historical_activity_reconstruction(
                receipt["receipt_id"], manifest
            ),
            receipt,
        )
        replayed = HistoricalActivityReconstructionV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=self.durable.clock,
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_archive_preservation(receipt["receipt_id"], manifest)
        self.assertEqual(self.keychain.create_calls, 0)

    def test_historical_weekly_activity_purpose_is_separate_and_replay_verifies(self) -> None:
        manifest = self._historical_weekly_activity_manifest()
        receipt = self.durable.authorize_historical_weekly_activity_reconstruction(manifest)
        self.assertEqual(receipt["purpose"], "historical_weekly_activity_reconstruction")
        self.assertEqual(
            self.durable.verify_historical_weekly_activity_reconstruction(
                receipt["receipt_id"], manifest
            ),
            receipt,
        )
        replayed = HistoricalWeeklyActivityReconstructionV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=self.durable.clock,
        ).verify(receipt["receipt_id"], manifest)
        self.assertEqual(replayed, receipt)
        with self.assertRaises(Exception):
            self.durable.verify_historical_activity_reconstruction(
                receipt["receipt_id"], manifest
            )
        self.assertEqual(self.keychain.create_calls, 0)

    def test_b0_06_expired_archive_replays_but_expired_live_receipt_cannot_publish(self) -> None:
        instant = datetime.now(UTC)
        durable = self._existing_authority(_FakeChatFirstLauncher(), clock=lambda: instant)
        manifest = self._manifest()
        receipt = durable.authorize_chat_first_u1_save(manifest)
        after_expiry = datetime.fromisoformat(
            receipt["expires_at"].replace("Z", "+00:00")
        ) + timedelta(seconds=1)
        verifier = ChatFirstU1SaveV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=lambda: after_expiry,
        )
        with self.assertRaises(LocalConfirmationV2Error):
            verifier.verify(receipt["receipt_id"], manifest)
        self.assertEqual(verifier.verify_archived(receipt["receipt_id"], manifest), receipt)

    def test_b0_07_archive_rejects_future_or_out_of_window_signed_times(self) -> None:
        instant = datetime.now(UTC)
        manifest = self._manifest()
        receipt = self.durable.authorize_chat_first_u1_save(manifest)
        verifier = ChatFirstU1SaveV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=lambda: instant,
        )
        self._rewrite_signed_times(
            receipt["receipt_id"],
            issued_at=instant + timedelta(minutes=1),
            confirmed_at=instant + timedelta(minutes=1),
        )
        with self.assertRaises(LocalConfirmationV2Error):
            verifier.verify_archived(receipt["receipt_id"], manifest)

        second = self.durable.authorize_chat_first_u1_save(manifest)
        expires_at = datetime.fromisoformat(second["expires_at"].replace("Z", "+00:00"))
        self._rewrite_signed_times(
            second["receipt_id"],
            issued_at=expires_at,
            confirmed_at=expires_at,
        )
        after_expiry = ChatFirstU1SaveV2ReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=lambda: expires_at + timedelta(seconds=1),
        )
        with self.assertRaises(LocalConfirmationV2Error):
            after_expiry.verify_archived(second["receipt_id"], manifest)


if __name__ == "__main__":
    unittest.main()
