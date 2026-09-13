"""Hostile synthetic S2-B proofs for durable confirmation and global work transactions."""

from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.helpers import Harness
from vault_next.canonical import canonical_bytes
from vault_next.contracts import OwnerReceipt, ReceiptVerificationStatus, finalize_work_transaction_manifest
from vault_next.errors import ErrorCode, LedgerCorruptionError, ValidationError
from vault_next.local_confirmation import ConfirmationUI, KeychainStore
from vault_next.local_confirmation_v2 import (
    DurableLocalAuthority,
    DurableLocalReceiptVerifier,
    LocalConfirmationV2Declined,
    LocalConfirmationV2Error,
    MacOSDurableKeychain,
)
from vault_next.policy import Approval, PolicyEngine
from vault_next.records import RUNTIME_ACTOR, build_event, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import build_current_work_view, fold_work_items
from vault_next.work_batches import WorkBatchCoordinator, finalize_work_batch_proposal
from vault_next.work_transactions import WorkTransactionCoordinator


class _MemoryKeychain(KeychainStore):
    """Synthetic-only private-key store; it is never evidence about the macOS Keychain."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}

    def find(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def create(self, service: str, account: str, secret: bytes) -> None:
        key = (service, account)
        if key in self.items:
            raise RuntimeError("synthetic Keychain identity already exists")
        self.items[key] = secret

    def remove(self, service: str, account: str) -> None:
        self.items.pop((service, account), None)


class _NativeKeychainBindingsDouble:
    """Records raw-byte calls made through the v2 native Keychain boundary."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[str, str, str, bytes | None]] = []

    def find(self, service: str, account: str) -> bytes | None:
        self.calls.append(("find", service, account, None))
        return self.items.get((service, account))

    def create(self, service: str, account: str, secret: bytes) -> None:
        self.calls.append(("create", service, account, secret))
        self.items[(service, account)] = secret

    def remove(self, service: str, account: str) -> None:
        self.calls.append(("remove", service, account, None))
        self.items.pop((service, account), None)


class _ExactConfirmation(ConfirmationUI):
    """Return the manifest digest that was supplied to this synthetic UI boundary."""

    def __init__(self, response: str | None = None, *, mutate_display: bool = False) -> None:
        self.response = response
        self.mutate_display = mutate_display
        self.display_path: Path | None = None

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        self.display_path = display_path
        if self.mutate_display:
            display_path.write_bytes(b"{\"hostile\":true}")
        return self.response if self.response is not None else expected_manifest_digest


class SimulatedCrash(RuntimeError):
    """Interrupt after the canonical append but before noncanonical finalization."""


class WorkTransactionTests(unittest.TestCase):
    """Every test uses only invented cases and a fresh disposable filesystem root."""

    def setUp(self) -> None:
        self.harness = Harness()
        self.harness.start()
        self.runtime = CaseSessionRuntime(
            self.harness.paths,
            self.harness.schemas,
            id_factory=self.harness.ids,
            clock=lambda: self.harness.current,
            correlation_id=self.harness.correlation_id,
        )
        self.second_case_id = self.harness.ids.new("case")
        self.second_session_id = self.harness.ids.new("session")
        self._append_case_and_session(self.second_case_id, self.second_session_id)
        self.first_item_id = self.harness.ids.new("work_item")
        self.second_item_id = self.harness.ids.new("work_item")
        self._record_legacy_work(
            self.harness.case_id,
            self.harness.session_id,
            self.first_item_id,
            "Invented first transaction item",
        )
        self._record_legacy_work(
            self.second_case_id,
            self.second_session_id,
            self.second_item_id,
            "Invented second transaction item",
        )
        self.authority_temporary = TemporaryDirectory(prefix="vault-next-s2b-authority-")
        self.authority_root = Path(self.authority_temporary.name) / "authority"
        self.keychain = _MemoryKeychain()
        self.confirmation = _ExactConfirmation()
        self.authority = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.keychain,
            self.confirmation,
            self.harness.ids,
            lambda: self.harness.current,
        )
        self.verifier = DurableLocalReceiptVerifier(
            self.harness.paths, self.authority_root, self.harness.schemas
        )
        self.policy = PolicyEngine(
            self.harness.paths, self.harness.schemas, receipt_verifier=self.verifier
        )
        self.coordinator = WorkTransactionCoordinator(
            self.runtime, self.policy, self.harness.schemas
        )

    def tearDown(self) -> None:
        self.authority_temporary.cleanup()
        self.harness.close()

    def test_s2b_v2_native_keychain_boundary_passes_private_material_as_bytes(self) -> None:
        native = _NativeKeychainBindingsDouble()
        keychain = MacOSDurableKeychain(native)
        service = "vault-next-local-confirmation/v2:bundle_synthetic"
        secret = bytes(range(32))

        self.assertIsNone(keychain.find(service, "ed25519-private-key"))
        keychain.create(service, "ed25519-private-key", secret)
        self.assertEqual(keychain.find(service, "ed25519-private-key"), secret)
        keychain.remove(service, "ed25519-private-key")
        self.assertIsNone(keychain.find(service, "ed25519-private-key"))

        self.assertEqual(
            native.calls,
            [
                ("find", service, "ed25519-private-key", None),
                ("create", service, "ed25519-private-key", secret),
                ("find", service, "ed25519-private-key", None),
                ("remove", service, "ed25519-private-key", None),
                ("find", service, "ed25519-private-key", None),
            ],
        )

    def test_s2b_a01_t01_exact_confirmation_replays_one_global_commit_after_restart(self) -> None:
        manifest = self._manifest()
        receipt, owner_receipt = self._authorize_and_commit(manifest)

        self.assertEqual(
            self.verifier.verify(owner_receipt).status, ReceiptVerificationStatus.VERIFIED
        )
        events = self.runtime.semantic.read_all()
        transactions = [
            event for event in events if event["event_type"] == "work_transaction.committed"
        ]
        self.assertEqual(len(transactions), 1)
        event = transactions[0]
        self.assertIsNone(event["case_id"])
        self.assertIsNone(event["session_id"])
        self.assertEqual(event["payload"]["affected_case_ids"], manifest["affected_case_ids"])
        self.assertEqual(receipt["committed_watermark"], event["integrity"]["event_sha256"])

        restarted_paths = self.harness.paths.__class__(
            self.harness.runtime_root,
            protected_roots=(self.harness.legacy_root, self.harness.backup_root),
        )
        restarted_schemas = self.harness.schemas.__class__(self.harness.schemas.schema_root)
        restarted_events = CaseSessionRuntime(restarted_paths, restarted_schemas).semantic.read_all()
        restarted_verifier = DurableLocalReceiptVerifier(
            restarted_paths, self.authority_root, restarted_schemas
        )
        self.assertEqual(
            restarted_verifier.verify(owner_receipt).status, ReceiptVerificationStatus.VERIFIED
        )
        items = fold_work_items(restarted_events)
        self.assertEqual(items[self.first_item_id]["status"], "in_progress")
        self.assertEqual(items[self.second_item_id]["status"], "in_progress")
        view = build_current_work_view(
            restarted_events,
            as_of_date="2026-09-01",
            time_zone="UTC",
            minimum_watermark=receipt["committed_watermark"],
        )
        self.assertEqual(view["committed_watermark"], receipt["committed_watermark"])

    def test_s2b_a02_rejects_cancel_display_mutation_key_change_expiry_and_changed_manifest(self) -> None:
        manifest = self._manifest()
        self.coordinator.prepare(manifest)
        rejected = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.keychain,
            _ExactConfirmation("not-the-displayed-digest"),
            self.harness.ids,
            lambda: self.harness.current,
        )
        with self.assertRaises(LocalConfirmationV2Declined):
            rejected.authorize_transaction(manifest)
        self.assertFalse(self._transactions())

        mutated = DurableLocalAuthority(
            self.harness.paths,
            self.authority_root,
            self.harness.schemas,
            self.keychain,
            _ExactConfirmation(mutate_display=True),
            self.harness.ids,
            lambda: self.harness.current,
        )
        with self.assertRaises(LocalConfirmationV2Error):
            mutated.authorize_transaction(manifest)
        self.assertFalse(self._transactions())

        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        original_authority = self.authority.authority_path.read_bytes()
        changed_key = json.loads(original_authority)
        changed_key["key_id"] = "f" * 64
        self.authority.authority_path.write_bytes(canonical_bytes(changed_key))
        with self.assertRaises(ValidationError):
            self.coordinator.commit(manifest, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

        revoked = json.loads(original_authority)
        revoked["status"] = "revoked"
        self.authority.authority_path.write_bytes(canonical_bytes(revoked))
        with self.assertRaises(ValidationError):
            self.coordinator.commit(manifest, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())
        self.authority.authority_path.write_bytes(original_authority)

        changed = self._manifest(selection_suffix="changed")
        self.coordinator.prepare(changed)
        with self.assertRaises(ValidationError):
            self.coordinator.commit(changed, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

        expired = self._manifest(expires_at=self.harness.current - timedelta(seconds=1))
        self.coordinator.prepare(expired)
        with self.assertRaises(ValidationError):
            self.coordinator.commit(expired, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

    def test_s2b_a03_missing_keychain_identity_keeps_reads_available_and_blocks_apply(self) -> None:
        first = self._manifest()
        self.coordinator.prepare(first)
        self.authority.authorize_transaction(first)
        self.keychain.items.clear()
        second = self._manifest()
        self.coordinator.prepare(second)
        with self.assertRaises(LocalConfirmationV2Error):
            self.authority.authorize_transaction(second)

        items = fold_work_items(self.runtime.semantic.read_all())
        self.assertEqual(items[self.first_item_id]["status"], "open")
        self.assertEqual(items[self.second_item_id]["status"], "open")
        self.assertFalse(self._transactions())

    def test_s2b_t02_prepared_only_is_invisible_and_never_auto_applies_after_restart(self) -> None:
        manifest = self._manifest()
        prepared = self.coordinator.prepare(manifest)
        self.assertTrue(prepared.exists())
        self.assertFalse(self._transactions())

        restarted = WorkTransactionCoordinator(
            CaseSessionRuntime(
                self.harness.paths,
                self.harness.schemas,
                id_factory=self.harness.ids,
                clock=lambda: self.harness.current,
                correlation_id=self.harness.correlation_id,
            ),
            self.policy,
            self.harness.schemas,
        )
        self.assertTrue(restarted.prepared_path(manifest["transaction_id"]).exists())
        self.assertFalse(self._transactions())
        self.assertEqual(fold_work_items(self.runtime.semantic.read_all())[self.first_item_id]["status"], "open")

    def test_s2b_t03_post_append_crash_recovers_one_exact_receipt_without_duplicate(self) -> None:
        manifest = self._manifest()
        self.coordinator.prepare(manifest)
        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        with self.assertRaises(SimulatedCrash):
            self.coordinator.commit(
                manifest,
                approval=approval,
                owner_receipt=owner_receipt,
                after_append=lambda _event: (_ for _ in ()).throw(SimulatedCrash()),
            )
        self.assertEqual(len(self._transactions()), 1)
        self.assertFalse(self.coordinator.finalized_path(manifest["transaction_id"]).exists())

        restarted = WorkTransactionCoordinator(
            CaseSessionRuntime(
                self.harness.paths,
                self.harness.schemas,
                id_factory=self.harness.ids,
                clock=lambda: self.harness.current,
                correlation_id=self.harness.correlation_id,
            ),
            self.policy,
            self.harness.schemas,
        )
        receipt = restarted.commit(manifest, approval=approval, owner_receipt=owner_receipt)
        self.assertEqual(len(self._transactions()), 1)
        self.assertTrue(restarted.finalized_path(manifest["transaction_id"]).exists())
        self.assertEqual(receipt["transaction_id"], manifest["transaction_id"])

    def test_s2b_t04_stale_scope_missing_and_idempotency_conflicts_are_all_or_nothing(self) -> None:
        stale = self._manifest(expected_revision=9)
        self._reject_before_visibility(stale)

        scope_escape = self._manifest()
        scope_escape["operations"][0]["session_id"] = self.second_session_id
        scope_escape = finalize_work_transaction_manifest(scope_escape)
        self._reject_before_visibility(scope_escape)

        missing = self._manifest()
        missing["operations"][0]["case_id"] = self.harness.ids.new("case")
        missing = finalize_work_transaction_manifest(missing)
        self._reject_before_visibility(missing)

        committed = self._manifest()
        self._authorize_and_commit(committed)
        conflict = self._manifest(idempotency_key=committed["idempotency_key"])
        self.coordinator.prepare(conflict)
        approval, owner_receipt = self.authority.authorize_transaction(conflict)
        with self.assertRaises(ValidationError) as caught:
            self.coordinator.commit(conflict, approval=approval, owner_receipt=owner_receipt)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.WORK_BATCH_IDEMPOTENCY_CONFLICT)
        self.assertEqual(len(self._transactions()), 1)

    def test_s2b_t05_tampering_partial_records_and_future_versions_fail_closed(self) -> None:
        manifest = self._manifest()
        prepared = self.coordinator.prepare(manifest)
        prepared.write_bytes(b"{")
        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        with self.assertRaises(ValidationError):
            self.coordinator.commit(manifest, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

        intact = self._manifest()
        self.coordinator.prepare(intact)
        approval, owner_receipt = self.authority.authorize_transaction(intact)
        receipt_path = self.verifier.receipt_root / f"{owner_receipt.receipt_id}.json"
        receipt_path.write_bytes(b"{}")
        with self.assertRaises(ValidationError):
            self.coordinator.commit(intact, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

        candidate = self._transaction_candidate(intact, owner_receipt)
        candidate["payload"]["transaction_manifest_digest"] = "0" * 64
        with self.assertRaises(ValidationError):
            self.runtime.semantic.append(candidate)
        self.assertFalse(self._transactions())

        future = copy.deepcopy(candidate)
        future["schema_version"] = "4.0"
        with self.assertRaises(ValidationError) as caught:
            self.runtime.semantic.append(future)
        self.assertEqual(caught.exception.issues[0].code, ErrorCode.SCHEMA_VERSION_UNSUPPORTED)

        partition = next(self.harness.paths.semantic_root.glob("*.jsonl"))
        with partition.open("ab") as stream:
            stream.write(b"{\"partial\"")
        with self.assertRaises(LedgerCorruptionError):
            self.runtime.semantic.read_all()

    def test_s2b_t06_prepared_is_hidden_and_v3_fences_legacy_work_writers(self) -> None:
        hidden = self._manifest()
        self.coordinator.prepare(hidden)
        self.assertEqual(fold_work_items(self.runtime.semantic.read_all())[self.first_item_id]["status"], "open")

        committed = self._manifest()
        self._authorize_and_commit(committed)
        before = len(self.runtime.semantic.read_all())
        legacy_work_item_id = self.harness.ids.new("work_item")
        legacy = build_event(
            event_type="work_item.recorded",
            case_id=self.harness.case_id,
            session_id=self.harness.session_id,
            payload=self._legacy_payload(legacy_work_item_id, "Hostile legacy write"),
            actor={"type": "owner", "id": "synthetic-owner"},
            subject_refs=[legacy_work_item_id],
            correlation_id=self.harness.correlation_id,
            occurred_at=self.harness.tick(),
            recorded_at=self.harness.current,
            id_factory=self.harness.ids,
        )
        with self.assertRaises(ValidationError):
            self.runtime.semantic.append(legacy)
        self.assertEqual(len(self.runtime.semantic.read_all()), before)

        batch = finalize_work_batch_proposal(
            {
                "schema_version": "1.0",
                "batch_id": self.harness.ids.new("work_batch"),
                "request_id": self.harness.ids.new("request"),
                "idempotency_key": "legacy-fenced",
                "case_id": self.harness.case_id,
                "operations": [
                    {
                        "work_item_id": self.harness.ids.new("work_item"),
                        "expected_revision": 0,
                        "operation": "record",
                        "next_state": self._next_state("Fenced legacy batch", "open"),
                    }
                ],
                "proposal_digest": "",
                "expires_at": timestamp(self.harness.current + timedelta(minutes=5)),
            }
        )
        with self.assertRaises(ValidationError):
            WorkBatchCoordinator(self.runtime, self.policy, self.harness.schemas).commit(
                batch,
                approval=approval_from_manifest(self.harness, committed),
                owner_receipt=receipt_from_manifest(self.harness, committed),
            )
        self.assertEqual(len(self.runtime.semantic.read_all()), before)

    def test_s2b_t07_concurrent_exact_retries_serialize_to_one_fresh_commit(self) -> None:
        manifest = self._manifest()
        self.coordinator.prepare(manifest)
        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = list(
                executor.map(
                    lambda _index: self.coordinator.commit(
                        manifest, approval=approval, owner_receipt=owner_receipt
                    ),
                    range(2),
                )
            )
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual(len(self._transactions()), 1)
        view = build_current_work_view(
            self.runtime.semantic.read_all(),
            as_of_date="2026-09-01",
            time_zone="UTC",
            minimum_watermark=receipts[0]["committed_watermark"],
        )
        self.assertEqual(view["committed_watermark"], receipts[0]["committed_watermark"])

    def _append_case_and_session(self, case_id: str, session_id: str) -> None:
        self.harness.semantic.append(
            build_event(
                event_type="case.created",
                case_id=case_id,
                session_id=None,
                payload={"title": "Invented second case"},
                subject_refs=[case_id],
                correlation_id=self.harness.correlation_id,
                occurred_at=self.harness.tick(),
                recorded_at=self.harness.current,
                id_factory=self.harness.ids,
            )
        )
        self.harness.semantic.append(
            build_event(
                event_type="session.started",
                case_id=case_id,
                session_id=session_id,
                payload={"manifest_sha256": "b" * 64},
                subject_refs=[session_id],
                correlation_id=self.harness.correlation_id,
                occurred_at=self.harness.tick(),
                recorded_at=self.harness.current,
                id_factory=self.harness.ids,
            )
        )

    def _record_legacy_work(
        self, case_id: str, session_id: str, work_item_id: str, statement: str
    ) -> None:
        self.harness.semantic.append(
            build_event(
                event_type="work_item.recorded",
                case_id=case_id,
                session_id=session_id,
                payload=self._legacy_payload(work_item_id, statement),
                actor={"type": "owner", "id": "synthetic-owner"},
                subject_refs=[work_item_id],
                correlation_id=self.harness.correlation_id,
                occurred_at=self.harness.tick(),
                recorded_at=self.harness.current,
                id_factory=self.harness.ids,
            )
        )

    def _legacy_payload(self, work_item_id: str, statement: str) -> dict[str, object]:
        return {
            "work_item_id": work_item_id,
            "statement": statement,
            "status": "open",
            "source_kind": "owner_instruction",
            "priority": "normal",
            "due_on": None,
            "next_review_on": None,
            "blocker": None,
            "explicit_confirmation": True,
        }

    def _manifest(
        self,
        *,
        expected_revision: int = 1,
        idempotency_key: str | None = None,
        expires_at: object | None = None,
        selection_suffix: str = "exact",
    ) -> dict[str, object]:
        expiry = expires_at or self.harness.current + timedelta(minutes=5)
        return finalize_work_transaction_manifest(
            {
                "schema_version": "3.0",
                "transaction_id": self.harness.ids.new("work_transaction"),
                "request_id": self.harness.ids.new("request"),
                "idempotency_key": idempotency_key
                or f"synthetic-transaction-{self.harness.ids.new_body()}",
                "affected_case_ids": [],
                "operations": [
                    {
                        "case_id": self.harness.case_id,
                        "session_id": self.harness.session_id,
                        "work_item_id": self.first_item_id,
                        "expected_revision": expected_revision,
                        "operation": "status_change",
                        "next_state": self._next_state(
                            "Invented first transaction item", "in_progress"
                        ),
                        "selection_binding": {
                            "selection_kind": "displayed_ordinal",
                            "displayed_view_digest": "a" * 64,
                            "binding_label": selection_suffix,
                        },
                    },
                    {
                        "case_id": self.second_case_id,
                        "session_id": self.second_session_id,
                        "work_item_id": self.second_item_id,
                        "expected_revision": expected_revision,
                        "operation": "status_change",
                        "next_state": self._next_state(
                            "Invented second transaction item", "in_progress"
                        ),
                        "selection_binding": None,
                    },
                ],
                "expires_at": timestamp(expiry),
                "compatibility": {
                    "minimum_semantic_schema_version": "3.0",
                    "minimum_reader_version": "0.4.0",
                },
                "manifest_digest": "",
            }
        )

    @staticmethod
    def _next_state(statement: str, status: str) -> dict[str, object]:
        return {
            "statement": statement,
            "status": status,
            "source_kind": "owner_instruction",
            "priority": "normal",
            "due_on": None,
            "next_review_on": None,
            "blocker": None,
        }

    def _authorize_and_commit(self, manifest: dict[str, object]) -> tuple[dict[str, object], OwnerReceipt]:
        self.coordinator.prepare(manifest)
        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        return self.coordinator.commit(manifest, approval=approval, owner_receipt=owner_receipt), owner_receipt

    def _reject_before_visibility(self, manifest: dict[str, object]) -> None:
        self.coordinator.prepare(manifest)
        approval, owner_receipt = self.authority.authorize_transaction(manifest)
        with self.assertRaises(ValidationError):
            self.coordinator.commit(manifest, approval=approval, owner_receipt=owner_receipt)
        self.assertFalse(self._transactions())

    def _transaction_candidate(
        self, manifest: dict[str, object], owner_receipt: OwnerReceipt
    ) -> dict[str, object]:
        return build_event(
            event_type="work_transaction.committed",
            case_id=None,
            session_id=None,
            payload={
                "transaction_id": manifest["transaction_id"],
                "transaction_manifest": manifest,
                "transaction_manifest_digest": manifest["manifest_digest"],
                "affected_case_ids": manifest["affected_case_ids"],
                "owner_receipt": owner_receipt.to_record(),
                "transaction_receipt_id": self.harness.ids.new("receipt"),
                "request_id": manifest["request_id"],
                "idempotency_key": manifest["idempotency_key"],
                "compatibility": manifest["compatibility"],
            },
            actor=dict(RUNTIME_ACTOR),
            subject_refs=[self.first_item_id, self.second_item_id],
            correlation_id=self.harness.correlation_id,
            approval_ref=owner_receipt.approval_id,
            schema_version="3.0",
            occurred_at=self.harness.tick(),
            recorded_at=self.harness.current,
            id_factory=self.harness.ids,
        )

    def _transactions(self) -> list[dict[str, object]]:
        return [
            event
            for event in self.runtime.semantic.read_all()
            if event["event_type"] == "work_transaction.committed"
        ]


def approval_from_manifest(harness: Harness, manifest: dict[str, object]) -> Approval:
    return Approval(
        approval_id=harness.ids.new("approval"),
        proposal_digest="0" * 64,
        targets=(),
        consequence_class="owner_decision",
        granted_at=harness.current,
        expires_at=harness.current + timedelta(minutes=5),
        owner_actor_id="synthetic-owner",
    )


def receipt_from_manifest(harness: Harness, manifest: dict[str, object]) -> OwnerReceipt:
    return OwnerReceipt(
        receipt_id=harness.ids.new("receipt"),
        authority_id="synthetic-authority",
        approval_id=harness.ids.new("approval"),
        proposal_digest="0" * 64,
        targets=(),
        consequence_class="owner_decision",
        issued_at=harness.current,
        expires_at=harness.current + timedelta(minutes=5),
    )


if __name__ == "__main__":
    unittest.main()
