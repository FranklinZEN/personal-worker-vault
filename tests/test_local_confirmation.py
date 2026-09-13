"""S1-D local authority mechanics using hostile disposable invented records only."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import SCHEMA_ROOT
from vault_next.contracts import OwnerReceipt, ReceiptVerificationStatus
from vault_next.local_confirmation import (
    AUTHORITY_ID,
    ConfirmationUI,
    KeychainStore,
    LocalConfirmationDeclined,
    LocalConfirmationReceiptVerifier,
    run_synthetic_local_confirmation_proof,
)
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry


class _MemoryKeychain(KeychainStore):
    """Test-only stand-in; it is not evidence of actual Keychain behavior."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}

    def find(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def create(self, service: str, account: str, secret: bytes) -> None:
        key = (service, account)
        if key in self.items:
            raise RuntimeError("test Keychain item already exists")
        self.items[key] = secret

    def remove(self, service: str, account: str) -> None:
        self.items.pop((service, account), None)


class _ExactConfirmation(ConfirmationUI):
    """Test double that returns only the digest it was shown."""

    def __init__(self, response: str | None = None) -> None:
        self.response = response
        self.display_path: Path | None = None

    def confirm(self, display_path: Path, expected_work_proposal_digest: str) -> str:
        self.display_path = display_path
        return self.response if self.response is not None else expected_work_proposal_digest


class LocalConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-s1d-test-")
        self.root = Path(self.temporary.name) / "runtime"
        self.keychain = _MemoryKeychain()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_s1d_t01_signed_receipt_commits_and_replays_after_restart(self) -> None:
        confirmation = _ExactConfirmation()
        result = run_synthetic_local_confirmation_proof(
            self.root,
            SCHEMA_ROOT,
            keychain=self.keychain,
            confirmation_ui=confirmation,
        )
        self.assertEqual(result.authority_id, AUTHORITY_ID)
        self.assertTrue(result.replay_verified)
        self.assertTrue(result.keychain_identity_removed)
        self.assertFalse(self.keychain.items)
        assert confirmation.display_path is not None
        display = confirmation.display_path.read_text()
        self.assertIn("work_change_proposal", display)
        self.assertIn("policy_proposal_digest", display)

    def test_s1d_t02_rejection_issues_no_receipt_or_batch_commit(self) -> None:
        confirmation = _ExactConfirmation("not-the-displayed-digest")
        with self.assertRaises(LocalConfirmationDeclined):
            run_synthetic_local_confirmation_proof(
                self.root,
                SCHEMA_ROOT,
                keychain=self.keychain,
                confirmation_ui=confirmation,
            )
        receipt_root = self.root / "data" / "evidence" / "local-confirmation-v1" / "receipts"
        self.assertFalse(receipt_root.exists())
        semantic_files = sorted((self.root / "data" / "events" / "semantic").glob("*.jsonl"))
        self.assertTrue(semantic_files)
        self.assertNotIn("work_batch.committed", "\n".join(path.read_text() for path in semantic_files))
        self.assertFalse(self.keychain.items)

    def test_s1d_t03_changed_signed_material_and_wrong_authority_fail_closed(self) -> None:
        result = run_synthetic_local_confirmation_proof(
            self.root,
            SCHEMA_ROOT,
            keychain=self.keychain,
            confirmation_ui=_ExactConfirmation(),
        )
        paths = RuntimePaths(self.root)
        schemas = SchemaRegistry(SCHEMA_ROOT)
        receipt_path = (
            paths.evidence_root
            / "local-confirmation-v1"
            / "receipts"
            / f"{result.receipt_id}.json"
        )
        record = json.loads(receipt_path.read_text())
        owner_receipt = _owner_receipt(record)
        verifier = LocalConfirmationReceiptVerifier(paths, schemas)
        self.assertEqual(verifier.verify(owner_receipt).status, ReceiptVerificationStatus.VERIFIED)

        wrong = OwnerReceipt(
            owner_receipt.receipt_id,
            "wrong-local-authority",
            owner_receipt.approval_id,
            owner_receipt.proposal_digest,
            owner_receipt.targets,
            owner_receipt.consequence_class,
            owner_receipt.issued_at,
            owner_receipt.expires_at,
        )
        self.assertEqual(verifier.verify(wrong).status, ReceiptVerificationStatus.REJECTED)

        changed = copy.deepcopy(record)
        changed["work_change_proposal"]["operations"][0]["next_state"]["statement"] = (
            "Hostile replacement"
        )
        receipt_path.write_text(json.dumps(changed))
        self.assertEqual(verifier.verify(owner_receipt).status, ReceiptVerificationStatus.REJECTED)


def _owner_receipt(record: dict[str, object]) -> OwnerReceipt:
    value = record["owner_receipt"]
    assert isinstance(value, dict)
    expires_at = value["expires_at"]
    assert isinstance(expires_at, str)
    return OwnerReceipt(
        receipt_id=str(value["receipt_id"]),
        authority_id=str(value["authority_id"]),
        approval_id=str(value["approval_id"]),
        proposal_digest=str(value["proposal_digest"]),
        targets=tuple(str(item) for item in value["targets"]),
        consequence_class=str(value["consequence_class"]),
        issued_at=datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(expires_at.replace("Z", "+00:00")),
    )


if __name__ == "__main__":
    unittest.main()

