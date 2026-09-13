"""Synthetic test harness shared by Phase 1 tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from vault_next.contracts import OwnerReceipt, ReceiptVerification, ReceiptVerificationStatus
from vault_next.ids import ULIDFactory
from vault_next.ledger import OperationalLedger, SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.policy import PolicyEngine
from vault_next.records import SchemaRegistry, build_event

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PROJECT_ROOT / "schemas" / "v1"


class SyntheticFixtureReceiptVerifier:
    """Test-only receipt verifier for disposable, invented fixtures."""

    def __init__(self) -> None:
        self.receipt_ids: set[str] = set()

    def register(self, receipt: OwnerReceipt) -> None:
        self.receipt_ids.add(receipt.receipt_id)

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        status = (
            ReceiptVerificationStatus.VERIFIED
            if receipt.receipt_id in self.receipt_ids
            else ReceiptVerificationStatus.REJECTED
        )
        return ReceiptVerification(status, "synthetic-fixture-authority")


class Harness:
    """One isolated runtime with invented identities and timestamps."""

    def __init__(self) -> None:
        self.temporary = TemporaryDirectory(prefix="vault-next-test-")
        base = Path(self.temporary.name)
        self.runtime_root = base / "runtime"
        self.legacy_root = base / "synthetic-legacy"
        self.backup_root = base / "synthetic-backup"
        self.legacy_root.mkdir()
        self.backup_root.mkdir()
        self.paths = RuntimePaths(
            self.runtime_root,
            protected_roots=(self.legacy_root, self.backup_root),
        )
        self.paths.initialize()
        self.schemas = SchemaRegistry(SCHEMA_ROOT)
        self.semantic = SemanticLedger(self.paths, self.schemas)
        self.operational = OperationalLedger(self.paths, self.schemas)
        self.receipt_verifier = SyntheticFixtureReceiptVerifier()
        self.policy = PolicyEngine(
            self.paths, self.schemas, receipt_verifier=self.receipt_verifier
        )
        self.current = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
        self.ids = ULIDFactory(
            now_ms=lambda: int(self.current.timestamp() * 1000),
            random_source=lambda length: b"\x01" * length,
        )
        self.case_id = self.ids.new("case")
        self.session_id = self.ids.new("session")
        self.correlation_id = "synthetic-test"
        self.last_event_id: str | None = None

    def issue_fixture_receipt(self, approval: Any) -> OwnerReceipt:
        """Issue and register an invented receipt for a test approval only."""

        receipt = OwnerReceipt(
            self.ids.new("receipt"),
            "synthetic-fixture-authority",
            approval.approval_id,
            approval.proposal_digest,
            approval.targets,
            approval.consequence_class,
            self.current,
            approval.expires_at,
        )
        self.receipt_verifier.register(receipt)
        return receipt

    def close(self) -> None:
        self.temporary.cleanup()

    def tick(self) -> datetime:
        value = self.current
        self.current += timedelta(seconds=1)
        return value

    def candidate(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        actor: dict[str, str] | None = None,
        subject_refs: list[str] | None = None,
        provenance: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        when = self.tick()
        return build_event(
            event_type=event_type,
            case_id=self.case_id,
            session_id=session_id,
            payload=payload,
            actor=actor,
            subject_refs=subject_refs,
            provenance=provenance,
            correlation_id=self.correlation_id,
            causation_event_id=self.last_event_id,
            occurred_at=when,
            recorded_at=when,
            id_factory=self.ids,
        )

    def append(self, candidate: dict[str, Any]) -> dict[str, Any]:
        event = self.semantic.append(candidate)
        self.last_event_id = event["event_id"]
        return event

    def start(self) -> tuple[dict[str, Any], dict[str, Any]]:
        case_event = self.append(
            self.candidate(
                "case.created",
                {"title": "Invented case"},
                subject_refs=[self.case_id],
            )
        )
        session_event = self.append(
            self.candidate(
                "session.started",
                {"manifest_sha256": "a" * 64},
                session_id=self.session_id,
                subject_refs=[self.session_id],
            )
        )
        return case_event, session_event
