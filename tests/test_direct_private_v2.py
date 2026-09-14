"""S5-DP B1 tests use a fake existing v2 authority and hostile disposable fixtures only."""

from __future__ import annotations

import base64
from datetime import timedelta
from hashlib import sha256
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes
from vault_next.direct_private import (
    DirectPrivateAdmissionCoordinator,
    DirectPrivateDeclined,
    DirectPrivateError,
)
from vault_next.direct_private_v2 import (
    V2DirectPrivateAuthority,
    V2DirectPrivateReceiptVerifier,
    validate_direct_private_bundle_layout,
)
from vault_next.local_confirmation import ConfirmationUI, KeychainStore
from vault_next.local_confirmation_v2 import (
    AUTHORITY_ID_V2,
    DirectPrivateV2ReceiptVerifier,
    DurableLocalAuthority,
    LocalConfirmationV2Error,
    MacOSDirectPrivateConfirmationUI,
)
from vault_next.runtime import CaseSessionRuntime


class _ExistingOnlyKeychain(KeychainStore):
    """A test-only preloaded v2 identity which rejects all bootstrap attempts."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}
        self.create_calls = 0

    def find(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def create(self, service: str, account: str, secret: bytes) -> None:
        self.create_calls += 1
        raise AssertionError("B1 direct-private authority must never bootstrap a Keychain item")

    def remove(self, service: str, account: str) -> None:
        self.items.pop((service, account), None)


class _UnusedTransactionConfirmation(ConfirmationUI):
    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        raise AssertionError("direct-private B1 must not use transaction confirmation")


class _FakeDirectPrivateLauncher:
    """Fakeable local display launcher; it never starts TextEdit or osascript."""

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
        self.prompts: list[tuple[str, str]] = []

    def open_textedit(self, display_path: Path) -> bool:
        self.opened.append(display_path)
        if self.mutate_display:
            display_path.write_bytes(b'{"replacement":"hostile"}')
        return self.open_result

    def request_digest(self, *, purpose: str, expected_manifest_digest: str) -> str:
        self.prompts.append((purpose, expected_manifest_digest))
        return expected_manifest_digest if self.response is None else self.response


class DirectPrivateV2BridgeTests(unittest.TestCase):
    """Every test runs only against a generated fixture marker and a temporary fake identity."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id="synthetic-s5dp-b1",
        )
        case = self.runtime.create_case("Invented S5-DP B1 case")
        self.session_id = self.runtime.create_session(
            case["case_id"], "Bridge invented direct-private confirmation only"
        )["session_id"]
        for state in ("routed", "authorized", "active"):
            self.runtime.transition_session(
                self.session_id, state, reason="synthetic S5-DP B1 setup"
            )
        self.source_temporary = TemporaryDirectory(
            prefix="vault-next-s5dp-b1-source-", dir="/private/tmp"
        )
        self.authority_temporary = TemporaryDirectory(
            prefix="vault-next-s5dp-b1-authority-", dir="/private/tmp"
        )
        self.authority_root = Path(self.authority_temporary.name) / "authority"
        self.keychain = _ExistingOnlyKeychain()
        self.launcher = _FakeDirectPrivateLauncher()
        self.durable = self._existing_authority(self.launcher)
        self.adapter = V2DirectPrivateAuthority(self.durable)
        self.coordinator = DirectPrivateAdmissionCoordinator(
            self.runtime,
            self.harness.schemas,
            self.adapter,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )

    def tearDown(self) -> None:
        self.authority_temporary.cleanup()
        self.source_temporary.cleanup()
        self.harness.close()

    def _existing_authority(
        self,
        launcher: _FakeDirectPrivateLauncher,
        *,
        clock=None,
    ) -> DurableLocalAuthority:
        authority = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.keychain,
            _UnusedTransactionConfirmation(),
            id_factory=self.harness.ids,
            clock=clock or (lambda: self.harness.current),
            direct_private_confirmation_ui=MacOSDirectPrivateConfirmationUI(launcher),
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

    def _fixture(self) -> object:
        return self.coordinator.create_fixture(
            Path(self.source_temporary.name) / "fixture",
            "nested/invented.md",
            (
                b"VAULT_NEXT_SYNTHETIC_FIXTURE\n"
                b"# Invented B1 heading\n\n"
                b"S5DP_B1_HOSTILE_BODY must never enter a report.\n"
            ),
            safe_label="invented-s5dp-b1",
        )

    def _snapshot(self, fixture: object) -> tuple[dict, dict, dict]:
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-b1-pilot",
            authority_record_sha256="b" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.adapter.authorize_snapshot(manifest)
        result = self.coordinator.take_snapshot(fixture, manifest, receipt["receipt_id"])
        return manifest, receipt, result

    def _complete(self) -> tuple[object, dict, dict, dict, dict]:
        fixture = self._fixture()
        _snapshot_manifest, snapshot_receipt, snapshot = self._snapshot(fixture)
        manifest = self.coordinator.prepare_admission(
            snapshot,
            candidate_treatment="source_only",
            candidate_proposal=None,
            idempotency_key="synthetic-s5dp-b1-complete",
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.adapter.authorize_admission(manifest)
        result = self.coordinator.admit(
            fixture, snapshot, manifest, receipt["receipt_id"], candidate_proposal=None
        )
        return fixture, snapshot, manifest, receipt, result

    def test_s5dp_b01_requires_an_existing_matching_v2_identity(self) -> None:
        fixture = self._fixture()
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-b1-pilot",
            authority_record_sha256="b" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        receipt = self.adapter.authorize_snapshot(manifest)
        self.assertEqual(receipt["purpose"], "direct_private_snapshot_scope")
        self.assertEqual(self.keychain.create_calls, 0)

        unavailable_root = Path(self.authority_temporary.name) / "unavailable"
        unavailable = DurableLocalAuthority(
            self.harness.paths,
            unavailable_root,
            self.harness.schemas,
            _ExistingOnlyKeychain(),
            _UnusedTransactionConfirmation(),
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            direct_private_confirmation_ui=MacOSDirectPrivateConfirmationUI(
                _FakeDirectPrivateLauncher()
            ),
        )
        with self.assertRaises(DirectPrivateError):
            V2DirectPrivateAuthority(unavailable).authorize_snapshot(manifest)
        self.assertFalse(unavailable_root.exists())

    def test_s5dp_b02_native_display_requires_the_exact_digest_and_stays_immutable(self) -> None:
        fixture = self._fixture()
        manifest = self.coordinator.prepare_snapshot(
            fixture,
            pilot_id="synthetic-s5dp-b1-pilot",
            authority_record_sha256="b" * 64,
            source_family_id=self.harness.ids.new("source"),
            max_bytes=1_048_576,
            expires_at=self.harness.current + timedelta(minutes=5),
        )
        rejected = V2DirectPrivateAuthority(
            self._existing_authority(_FakeDirectPrivateLauncher(response="wrong-digest"))
        )
        with self.assertRaises(DirectPrivateDeclined):
            rejected.authorize_snapshot(manifest)

        mutated = V2DirectPrivateAuthority(
            self._existing_authority(_FakeDirectPrivateLauncher(mutate_display=True))
        )
        with self.assertRaises(DirectPrivateError):
            mutated.authorize_snapshot(manifest)

        instants = iter(
            (
                self.harness.current,
                self.harness.current + timedelta(minutes=6),
            )
        )
        expired = V2DirectPrivateAuthority(
            self._existing_authority(
                _FakeDirectPrivateLauncher(),
                clock=lambda: next(instants),
            )
        )
        with self.assertRaises(DirectPrivateError):
            expired.authorize_snapshot(manifest)
        self.assertFalse(
            list(
                (
                    self.harness.paths.evidence_root
                    / "local-confirmation-v2"
                    / "direct-private"
                    / "direct_private_snapshot_scope"
                    / "receipts"
                ).glob("*.json")
            )
        )

    def test_s5dp_b03_receipts_are_purpose_bound_and_replay_verify(self) -> None:
        fixture, snapshot, manifest, admission_receipt, result = self._complete()
        self.assertEqual(result["status"], "complete")
        verifier = V2DirectPrivateReceiptVerifier(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            clock=lambda: self.harness.current,
        )
        replayed, replayed_manifest = verifier.verify(
            admission_receipt["receipt_id"],
            purpose="direct_private_source_admission",
            manifest_digest=manifest["manifest_digest"],
        )
        self.assertEqual(replayed["receipt_id"], admission_receipt["receipt_id"])
        self.assertEqual(replayed_manifest, manifest)
        with self.assertRaises(DirectPrivateError):
            V2DirectPrivateReceiptVerifier(
                self.harness.paths,
                self.authority_root,
                self.harness.schemas,
                clock=lambda: self.harness.current,
            ).verify(
                admission_receipt["receipt_id"],
                purpose="direct_private_snapshot_scope",
                manifest_digest=manifest["manifest_digest"],
            )
        self.assertTrue(fixture)
        self.assertTrue(snapshot["utf8_valid"])

    def test_s5dp_b04_coordinator_accepts_the_narrow_v2_adapter_and_runtime_binding(self) -> None:
        fixture, _snapshot, manifest, _receipt, result = self._complete()
        self.assertEqual(result["status"], "complete")
        changed = dict(manifest)
        changed["runtime_id"] = "0" * 64
        with self.assertRaises(DirectPrivateError):
            self.coordinator.admit(
                fixture,
                self._snapshot(fixture)[2],
                changed,
                "receipt_missing",
                candidate_proposal=None,
            )

    def test_s5dp_b05_protected_bundle_layout_rejects_unsafe_roots(self) -> None:
        with self.assertRaises(LocalConfirmationV2Error):
            DurableLocalAuthority(
                self.harness.paths,
                self.harness.paths.root / "unsafe-authority",
                self.harness.schemas,
                _ExistingOnlyKeychain(),
                _UnusedTransactionConfirmation(),
            )

        bundle = Path(self.authority_temporary.name) / "bundle"
        staging = bundle / "data" / "staging" / "migrations"
        bundle.mkdir(mode=0o700)
        staging.mkdir(mode=0o700, parents=True)
        validate_direct_private_bundle_layout(
            bundle,
            staging,
            self.authority_root,
            excluded_roots=(Path(self.source_temporary.name),),
        )
        with self.assertRaises(DirectPrivateError):
            validate_direct_private_bundle_layout(
                bundle,
                staging,
                self.authority_root,
                excluded_roots=(bundle,),
            )

        bundle.chmod(0o755)
        with self.assertRaises(DirectPrivateError):
            validate_direct_private_bundle_layout(bundle, staging, self.authority_root)
        bundle.chmod(0o700)

        redirected = Path(self.authority_temporary.name) / "redirected-bundle"
        os.symlink(bundle, redirected)
        with self.assertRaises(DirectPrivateError):
            validate_direct_private_bundle_layout(redirected, staging, self.authority_root)

        alternate_staging = Path(self.authority_temporary.name) / "alternate-staging"
        alternate_staging.mkdir(mode=0o700)
        with self.assertRaises(DirectPrivateError):
            validate_direct_private_bundle_layout(
                bundle, alternate_staging, self.authority_root
            )

        def cross_filesystem(path: Path) -> os.stat_result:
            value = os.stat(path)
            if Path(path).resolve() == staging.resolve():
                return os.stat_result(
                    (
                        value.st_mode,
                        value.st_ino,
                        value.st_dev + 1,
                        value.st_nlink,
                        value.st_uid,
                        value.st_gid,
                        value.st_size,
                        value.st_atime,
                        value.st_mtime,
                        value.st_ctime,
                    )
                )
            return value

        with self.assertRaises(DirectPrivateError):
            validate_direct_private_bundle_layout(
                bundle,
                staging,
                self.authority_root,
                stat_fn=cross_filesystem,
            )

    def test_s5dp_b06_fake_native_boundary_uses_no_socket_or_subprocess(self) -> None:
        with (
            patch.object(socket, "socket", side_effect=AssertionError("socket called")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess called")),
        ):
            _fixture, _snapshot, _manifest, _receipt, result = self._complete()
        self.assertEqual(result["status"], "complete")
        self.assertGreaterEqual(len(self.launcher.opened), 2)
        self.assertEqual(
            {purpose for purpose, _digest in self.launcher.prompts},
            {"direct_private_snapshot_scope", "direct_private_source_admission"},
        )

    def test_s5dp_b07_restart_rebuilds_without_a_source_fallback(self) -> None:
        _fixture, _snapshot, _manifest, _receipt, result = self._complete()
        self.assertEqual(result["status"], "complete")
        restarted = DirectPrivateAdmissionCoordinator(
            CaseSessionRuntime(self.harness.paths, self.harness.schemas),
            self.harness.schemas,
            self.adapter,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
        )
        self.assertEqual(restarted.rebuild_index()["state"], "fresh")
        self.assertEqual(len(restarted.retrieve("hostile")["citations"]), 1)

    def test_s5dp_b08_displays_and_receipts_omit_fixture_body(self) -> None:
        _fixture, _snapshot, _manifest, receipt, _result = self._complete()
        root = (
            self.harness.paths.evidence_root
            / "local-confirmation-v2"
            / "direct-private"
            / "direct_private_source_admission"
        )
        display = (root / "displays" / f"{receipt['receipt_id']}.json").read_text()
        record = (root / "receipts" / f"{receipt['receipt_id']}.json").read_text()
        self.assertNotIn("S5DP_B1_HOSTILE_BODY", display)
        self.assertNotIn("S5DP_B1_HOSTILE_BODY", record)

    def test_s5dp_b09_existing_v2_receipt_domains_do_not_verify_as_direct_private(self) -> None:
        _fixture, _snapshot, manifest, receipt, _result = self._complete()
        with self.assertRaises(DirectPrivateError):
            V2DirectPrivateReceiptVerifier(
                self.harness.paths,
                self.authority_root,
                self.harness.schemas,
                clock=lambda: self.harness.current,
            ).verify(
                receipt["receipt_id"],
                purpose="source_capture",
                manifest_digest=manifest["manifest_digest"],
            )
        self.assertEqual(self.keychain.create_calls, 0)


if __name__ == "__main__":
    unittest.main()
