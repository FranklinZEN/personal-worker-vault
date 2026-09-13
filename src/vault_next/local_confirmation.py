"""S1-D owner-operated local confirmation for disposable synthetic proofs.

The authority is deliberately outside chat and connector code. A macOS user reviews a complete
local proposal display and types its digest; an Ed25519 private key held in the login Keychain
then signs a receipt that the core can verify from root-local public material after restart.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.contracts import (
    OwnerReceipt,
    OwnerReceiptVerifier,
    ReceiptVerification,
    ReceiptVerificationStatus,
    require_work_change_proposal,
)
from vault_next.errors import ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.paths import RuntimePaths
from vault_next.policy import Approval, PolicyEngine
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import build_current_work_view, fold_work_items
from vault_next.work_batches import (
    WorkBatchCoordinator,
    finalize_work_batch_proposal,
    policy_proposal_for_work_batch,
)

AUTHORITY_ID = "vault-next-local-confirmation/v1"
ALGORITHM = "ed25519"
_KEYCHAIN_ACCOUNT = "ed25519-private-key"


class LocalConfirmationError(RuntimeError):
    """The local authority could not establish an exact user confirmation."""


class LocalConfirmationDeclined(LocalConfirmationError):
    """The local user rejected, cancelled, or did not exactly confirm a proposal."""


class KeychainStore(Protocol):
    """Small Keychain boundary; test doubles never stand in for actual-host evidence."""

    def find(self, service: str, account: str) -> bytes | None: ...

    def create(self, service: str, account: str, secret: bytes) -> None: ...

    def remove(self, service: str, account: str) -> None: ...


class ConfirmationUI(Protocol):
    """The only UI result accepted by the authority is the displayed full digest."""

    def confirm(self, display_path: Path, expected_work_proposal_digest: str) -> str: ...


class MacOSKeychain:
    """Store private key bytes in the login Keychain without command-line secrets."""

    executable = "/usr/bin/security"
    keychain_label = "Vault Next disposable local confirmation key"

    def find(self, service: str, account: str) -> bytes | None:
        result = subprocess.run(
            [self.executable, "find-generic-password", "-a", account, "-s", service, "-w"],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            try:
                return base64.b64decode(result.stdout.strip(), validate=True)
            except ValueError as exc:
                raise LocalConfirmationError("Keychain identity contains invalid key material") from exc
        message = result.stderr.decode("utf-8", errors="replace")
        if "could not be found" in message:
            return None
        raise LocalConfirmationError("Keychain identity could not be read")

    def create(self, service: str, account: str, secret: bytes) -> None:
        result = subprocess.run(
            [
                self.executable,
                "add-generic-password",
                "-a",
                account,
                "-s",
                service,
                "-l",
                self.keychain_label,
                "-w",
            ],
            input=base64.b64encode(secret),
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise LocalConfirmationError("Keychain identity could not be created")

    def remove(self, service: str, account: str) -> None:
        result = subprocess.run(
            [self.executable, "delete-generic-password", "-a", account, "-s", service],
            check=False,
            capture_output=True,
        )
        if result.returncode and b"could not be found" not in result.stderr:
            raise LocalConfirmationError("Keychain identity could not be removed")


class MacOSConfirmationUI:
    """Display the entire local proposal in TextEdit and require a typed exact digest."""

    open_executable = "/usr/bin/open"
    osascript_executable = "/usr/bin/osascript"

    def confirm(self, display_path: Path, expected_work_proposal_digest: str) -> str:
        opened = subprocess.run(
            [self.open_executable, "-a", "TextEdit", str(display_path)],
            check=False,
            capture_output=True,
        )
        if opened.returncode != 0:
            raise LocalConfirmationError("full proposal display could not be opened")
        script = "\n".join(
            (
                "on run argv",
                "    set expectedDigest to item 1 of argv",
                "    try",
                '        set promptText to "Vault Next requests a local confirmation." & ¬',
                '            "\\n\\nThe complete exact synthetic proposal is open in TextEdit." & ¬',
                '            " Review it there, then type its full work-proposal digest below." & ¬',
                '            "\\n\\nExpected digest:\\n"',
                "        set answerText to text returned of (display dialog (promptText & expectedDigest) ¬",
                '            default answer "" buttons {"Reject", "Approve"} default button "Approve" ¬',
                '            cancel button "Reject" with title "Vault Next local confirmation" with icon caution)',
                "        return answerText",
                "    on error number -128",
                '        return ""',
                "    end try",
                "end run",
            )
        )
        result = subprocess.run(
            [self.osascript_executable, "-e", script, expected_work_proposal_digest],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()


@dataclass(frozen=True)
class LocalConfirmationProofResult:
    """Minimal actual-host proof summary without copying the synthetic proposal into output."""

    runtime_root: str
    authority_id: str
    receipt_id: str
    committed_watermark: str
    replay_verified: bool
    keychain_identity_removed: bool

    def to_record(self) -> dict[str, Any]:
        return {
            "runtime_root": self.runtime_root,
            "authority_id": self.authority_id,
            "receipt_id": self.receipt_id,
            "committed_watermark": self.committed_watermark,
            "replay_verified": self.replay_verified,
            "keychain_identity_removed": self.keychain_identity_removed,
        }


class LocalConfirmationAuthority:
    """Issue local signed owner receipts after exact owner-operated confirmation."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        keychain: KeychainStore,
        confirmation_ui: ConfirmationUI,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self.keychain = keychain
        self.confirmation_ui = confirmation_ui
        self.ids = id_factory
        self.clock = clock

    @property
    def root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v1"
        )

    @property
    def authority_path(self) -> Path:
        return self.paths.ensure_runtime_write_target(self.root / "authority.json")

    @property
    def receipt_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(self.root / "receipts")

    @property
    def display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(self.root / "displays")

    @property
    def _keychain_service(self) -> str:
        root_digest = sha256(str(self.paths.root).encode("utf-8")).hexdigest()
        return f"{AUTHORITY_ID}:{root_digest}"

    def authorize_work_batch(self, proposal: dict[str, Any]) -> tuple[Approval, OwnerReceipt]:
        """Show and sign one complete, short-lived, exact work-change proposal."""

        require_work_change_proposal(proposal, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(proposal["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationError("cannot confirm an expired work proposal")

        identity = self._signing_identity()
        policy_proposal = policy_proposal_for_work_batch(proposal)
        approval = Approval(
            approval_id=self.ids.new("approval"),
            proposal_digest=policy_proposal.proposal_digest,
            targets=policy_proposal.targets,
            consequence_class=policy_proposal.consequence_class,
            granted_at=now,
            expires_at=expires_at,
            owner_actor_id="local-confirmation-owner",
        )
        owner_receipt = OwnerReceipt(
            receipt_id=self.ids.new("receipt"),
            authority_id=AUTHORITY_ID,
            approval_id=approval.approval_id,
            proposal_digest=policy_proposal.proposal_digest,
            targets=policy_proposal.targets,
            consequence_class=policy_proposal.consequence_class,
            issued_at=now,
            expires_at=expires_at,
        )
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID,
            "work_change_proposal": proposal,
            "work_change_proposal_digest": proposal["proposal_digest"],
            "policy_proposal": policy_proposal.to_record(),
            "policy_proposal_digest": policy_proposal.proposal_digest,
            "owner_receipt": owner_receipt.to_record(),
        }
        display_bytes = canonical_bytes(display)
        display_digest = sha256_hex(display_bytes)
        display_path = self.paths.ensure_runtime_write_target(
            self.display_root / f"{owner_receipt.receipt_id}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, proposal["proposal_digest"])
        if not hmac.compare_digest(response, proposal["proposal_digest"]):
            raise LocalConfirmationDeclined("local confirmation did not match the exact proposal digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationError("proposal display changed before receipt issuance")

        record = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID,
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "owner_receipt": owner_receipt.to_record(),
            "work_change_proposal": proposal,
            "work_change_proposal_digest": proposal["proposal_digest"],
            "confirmation_display_sha256": display_digest,
            "confirmed_at": timestamp(now),
            "signature_base64": "pending",
        }
        signature = identity.private_key.sign(canonical_bytes(_signature_material(record)))
        record["signature_base64"] = base64.b64encode(signature).decode("ascii")
        self.schemas.require("local-confirmation-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.receipt_root / f"{owner_receipt.receipt_id}.json"
            ),
            canonical_bytes(record),
        )
        return approval, owner_receipt

    def remove_disposable_identity(self) -> None:
        """Remove only this root-derived proof identity after restart verification."""

        self.keychain.remove(self._keychain_service, _KEYCHAIN_ACCOUNT)

    def _signing_identity(self) -> "_SigningIdentity":
        existing = self._load_authority()
        private_bytes = self.keychain.find(self._keychain_service, _KEYCHAIN_ACCOUNT)
        created = False
        if private_bytes is None:
            if existing is not None:
                raise LocalConfirmationError("authority record exists but Keychain identity is unavailable")
            private_key = Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            self.keychain.create(self._keychain_service, _KEYCHAIN_ACCOUNT, private_bytes)
            created = True
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            key_id = sha256(public_bytes).hexdigest()
            authority = {
                "schema_version": "1.0",
                "authority_id": AUTHORITY_ID,
                "algorithm": ALGORITHM,
                "key_id": key_id,
                "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
                "keychain_service_sha256": sha256(
                    self._keychain_service.encode("utf-8")
                ).hexdigest(),
            }
            self.schemas.require("local-confirmation-authority", authority)
            if existing is not None and existing != authority:
                raise LocalConfirmationError("Keychain public key does not match authority record")
            _write_immutable(self.authority_path, canonical_bytes(authority))
        except Exception:
            if created:
                self.keychain.remove(self._keychain_service, _KEYCHAIN_ACCOUNT)
            raise
        return _SigningIdentity(key_id, private_key)

    def _load_authority(self) -> dict[str, Any] | None:
        if not self.authority_path.exists():
            return None
        return _load_record(self.authority_path, self.schemas, "local-confirmation-authority")


@dataclass(frozen=True)
class _SigningIdentity:
    key_id: str
    private_key: Ed25519PrivateKey


class LocalConfirmationReceiptVerifier(OwnerReceiptVerifier):
    """Replay-verify local signed receipts with root-local public material only."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.schemas = schemas

    @property
    def root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v1"
        )

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        if receipt.authority_id != AUTHORITY_ID:
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID)
        try:
            self.schemas.require("owner-receipt", receipt.to_record())
            authority = _load_record(
                self.paths.ensure_runtime_write_target(self.root / "authority.json"),
                self.schemas,
                "local-confirmation-authority",
            )
            record = _load_record(
                self.paths.ensure_runtime_write_target(
                    self.root / "receipts" / f"{receipt.receipt_id}.json"
                ),
                self.schemas,
                "local-confirmation-receipt",
            )
            require_work_change_proposal(record["work_change_proposal"], self.schemas)
            if any(
                (
                    authority["authority_id"] != AUTHORITY_ID,
                    authority["algorithm"] != ALGORITHM,
                    authority["key_id"] != record["key_id"],
                    record["authority_id"] != receipt.authority_id,
                    record["owner_receipt"] != receipt.to_record(),
                    record["work_change_proposal_digest"]
                    != record["work_change_proposal"]["proposal_digest"],
                    record["owner_receipt"]["proposal_digest"] != receipt.proposal_digest,
                )
            ):
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID)
            public_bytes = base64.b64decode(authority["public_key_base64"], validate=True)
            signature = base64.b64decode(record["signature_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature, canonical_bytes(_signature_material(record))
            )
        except (
            InvalidSignature,
            KeyError,
            TypeError,
            ValidationError,
            ValueError,
            OSError,
            LocalConfirmationError,
        ):
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID)
        return ReceiptVerification(ReceiptVerificationStatus.VERIFIED, AUTHORITY_ID)


def run_synthetic_local_confirmation_proof(
    runtime_root: Path,
    schema_root: Path,
    *,
    keychain: KeychainStore | None = None,
    confirmation_ui: ConfirmationUI | None = None,
) -> LocalConfirmationProofResult:
    """Run the one-item S1-D proof; defaults intentionally require actual macOS confirmation."""

    synthetic_protected_roots = (
        runtime_root / "synthetic-legacy",
        runtime_root / "synthetic-backup",
    )
    paths = RuntimePaths(runtime_root, protected_roots=synthetic_protected_roots)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    current = aware_utc_now()
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        clock=lambda: current,
        correlation_id="s1d-local-proof",
    )
    case = runtime.create_case("Invented S1-D local confirmation case")
    runtime.create_session(case["case_id"], "Confirm one invented update")
    proposal = finalize_work_batch_proposal(
        {
            "schema_version": "1.0",
            "batch_id": runtime.ids.new("work_batch"),
            "request_id": runtime.ids.new("request"),
            "idempotency_key": "s1d-local-confirmation-proof",
            "case_id": case["case_id"],
            "operations": [
                {
                    "work_item_id": runtime.ids.new("work_item"),
                    "expected_revision": 0,
                    "operation": "record",
                    "next_state": {
                        "statement": "Invented S1-D local confirmation proof work",
                        "status": "open",
                        "source_kind": "owner_instruction",
                        "priority": "normal",
                        "due_on": None,
                        "next_review_on": None,
                        "blocker": None,
                    },
                }
            ],
            "proposal_digest": "",
            "expires_at": timestamp(current + timedelta(minutes=5)),
        }
    )
    authority = LocalConfirmationAuthority(
        paths,
        schemas,
        keychain=keychain or MacOSKeychain(),
        confirmation_ui=confirmation_ui or MacOSConfirmationUI(),
        clock=lambda: current,
    )
    try:
        approval, owner_receipt = authority.authorize_work_batch(proposal)
        verifier = LocalConfirmationReceiptVerifier(paths, schemas)
        policy = PolicyEngine(paths, schemas, receipt_verifier=verifier)
        receipt = WorkBatchCoordinator(runtime, policy, schemas).commit(
            proposal,
            approval=approval,
            owner_receipt=owner_receipt,
            now=current,
        )

        restarted_paths = RuntimePaths(
            runtime_root,
            protected_roots=synthetic_protected_roots,
        )
        restarted_schemas = SchemaRegistry(schema_root)
        restarted_verifier = LocalConfirmationReceiptVerifier(restarted_paths, restarted_schemas)
        replay_verified = (
            restarted_verifier.verify(owner_receipt).status
            == ReceiptVerificationStatus.VERIFIED
        )
        if not replay_verified:
            raise LocalConfirmationError("signed receipt did not verify after restart")
        restarted_events = CaseSessionRuntime(restarted_paths, restarted_schemas).semantic.read_all()
        view = build_current_work_view(
            restarted_events,
            as_of_date=current.date().isoformat(),
            time_zone="UTC",
            minimum_watermark=receipt["committed_watermark"],
        )
        work_item_id = proposal["operations"][0]["work_item_id"]
        if fold_work_items(restarted_events)[work_item_id]["status"] != "open" or not view:
            raise LocalConfirmationError("committed synthetic update was not visible after restart")
    finally:
        authority.remove_disposable_identity()
    return LocalConfirmationProofResult(
        runtime_root=str(restarted_paths.root),
        authority_id=AUTHORITY_ID,
        receipt_id=owner_receipt.receipt_id,
        committed_watermark=receipt["committed_watermark"],
        replay_verified=True,
        keychain_identity_removed=True,
    )


def _signature_material(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "signature_base64"}


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _write_immutable(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if _read_bytes(path) != data:
            raise LocalConfirmationError(
                f"immutable local confirmation record already differs: {path.name}"
            )
        return
    try:
        written = os.write(descriptor, data)
        if written != len(data):
            raise OSError("short immutable record write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        while data := os.read(descriptor, 65536):
            chunks.append(data)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_record(path: Path, schemas: SchemaRegistry, schema_name: str) -> dict[str, Any]:
    try:
        record = json.loads(_read_bytes(path))
    except (json.JSONDecodeError, OSError) as exc:
        raise LocalConfirmationError(
            f"local confirmation record is unreadable: {path.name}"
        ) from exc
    if not isinstance(record, dict):
        raise LocalConfirmationError(f"local confirmation record is not an object: {path.name}")
    schemas.require(schema_name, record)
    return record
