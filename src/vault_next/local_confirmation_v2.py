"""Durable owner-operated local confirmation for exact v3 transaction manifests.

This component is deliberately not a host adapter.  It keeps only public authority metadata in
the owner-selected bundle root; each displayed invented proposal and signed receipt belongs to the
runtime that requested it.  The login-Keychain private key is bound to the durable bundle ID, not
to a filesystem path, and is never regenerated when an existing authority loses its key.
"""

from __future__ import annotations

import base64
import ctypes
import hmac
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.contracts import (
    OwnerReceipt,
    OwnerReceiptVerifier,
    ReceiptVerification,
    ReceiptVerificationStatus,
    require_work_transaction_manifest,
)
from vault_next.errors import ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.local_confirmation import ConfirmationUI, KeychainStore
from vault_next.paths import DEFAULT_PROTECTED_ROOTS, RuntimePaths
from vault_next.policy import Approval, PolicyEngine
from vault_next.records import RUNTIME_ACTOR, SchemaRegistry, aware_utc_now, timestamp
from vault_next.work_transaction_policy import policy_proposal_for_transaction

AUTHORITY_ID_V2 = "vault-next-local-confirmation/v2"
ALGORITHM = "ed25519"
_KEYCHAIN_ACCOUNT = "ed25519-private-key"
PUBLIC_RESEARCH_EXECUTION_ATTESTATION = (
    "I attest that I am authorized under the applicable terms, copyright/rights, organizational "
    "policy, and network policy to make this one direct request to the displayed URL within the "
    "displayed time window. I understand that Vault Next will not fetch terms, robots data, another "
    "page, or an alternate source to decide this for me."
)


class LocalConfirmationV2Error(RuntimeError):
    """The durable local authority could not establish an exact confirmation."""


class LocalConfirmationV2Declined(LocalConfirmationV2Error):
    """The local user rejected, cancelled, or altered an exact transaction confirmation."""


@dataclass(frozen=True)
class SourceCaptureReceipt:
    """Purpose-limited v2 receipt for one owner-confirmed synthetic source handoff.

    This is intentionally not an ``OwnerReceipt``: the policy / work-transaction verifier cannot
    accept it, and the source-capture verifier cannot accept an ``OwnerReceipt``.
    """

    receipt_id: str
    authority_id: str
    capture_id: str
    capture_manifest_digest: str
    content_sha256: str
    byte_count: int
    issued_at: datetime
    expires_at: datetime

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "receipt_id": self.receipt_id,
            "authority_id": self.authority_id,
            "purpose": "source_capture",
            "capture_id": self.capture_id,
            "capture_manifest_digest": self.capture_manifest_digest,
            "content_sha256": self.content_sha256,
            "byte_count": self.byte_count,
            "issued_at": timestamp(self.issued_at),
            "expires_at": timestamp(self.expires_at),
        }


@dataclass(frozen=True)
class PublicResearchReceipt:
    """A receipt that is valid for exactly one public-research purpose and manifest."""

    receipt_id: str
    authority_id: str
    purpose: str
    subject_id: str
    manifest_digest: str
    issued_at: datetime
    expires_at: datetime
    schema_version: str = "2.0"

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "authority_id": self.authority_id,
            "purpose": self.purpose,
            "subject_id": self.subject_id,
            "manifest_digest": self.manifest_digest,
            "issued_at": timestamp(self.issued_at),
            "expires_at": timestamp(self.expires_at),
        }


class _NativeKeychainBindings(Protocol):
    """Native Keychain calls kept behind the small v2 private-key boundary."""

    def find(self, service: str, account: str) -> bytes | None: ...

    def create(self, service: str, account: str, secret: bytes) -> None: ...

    def remove(self, service: str, account: str) -> None: ...


class _SecurityFrameworkKeychain:
    """Direct Security.framework binding; private bytes never enter a process argv."""

    _ITEM_NOT_FOUND = -25300

    def __init__(self) -> None:
        try:
            security = ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security"
            )
            core_foundation = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
        except OSError as exc:
            raise LocalConfirmationV2Error(
                "native macOS Keychain framework is unavailable"
            ) from exc

        self._security = security
        self._core_foundation = core_foundation
        self._copy_default = security.SecKeychainCopyDefault
        self._copy_default.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self._copy_default.restype = ctypes.c_int32
        self._find = security.SecKeychainFindGenericPassword
        self._find.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._find.restype = ctypes.c_int32
        self._add = security.SecKeychainAddGenericPassword
        self._add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._add.restype = ctypes.c_int32
        self._delete = security.SecKeychainItemDelete
        self._delete.argtypes = [ctypes.c_void_p]
        self._delete.restype = ctypes.c_int32
        self._free_content = security.SecKeychainItemFreeContent
        self._free_content.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._free_content.restype = ctypes.c_int32
        self._release = core_foundation.CFRelease
        self._release.argtypes = [ctypes.c_void_p]
        self._release.restype = None

    @staticmethod
    def _names(service: str, account: str) -> tuple[bytes, bytes]:
        try:
            return service.encode("utf-8"), account.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise LocalConfirmationV2Error("Keychain identifiers must be UTF-8") from exc

    def find(self, service: str, account: str) -> bytes | None:
        service_bytes, account_bytes = self._names(service, account)
        password_length = ctypes.c_uint32()
        password_data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._find(
            None,
            len(service_bytes),
            service_bytes,
            len(account_bytes),
            account_bytes,
            ctypes.byref(password_length),
            ctypes.byref(password_data),
            ctypes.byref(item),
        )
        if status == self._ITEM_NOT_FOUND:
            return None
        if status != 0:
            raise LocalConfirmationV2Error("Keychain identity could not be read")
        try:
            return ctypes.string_at(password_data, password_length.value)
        finally:
            if password_data:
                self._free_content(None, password_data)
            if item:
                self._release(item)

    def create(self, service: str, account: str, secret: bytes) -> None:
        if not secret:
            raise LocalConfirmationV2Error("Keychain identity cannot be empty")
        service_bytes, account_bytes = self._names(service, account)
        keychain = ctypes.c_void_p()
        status = self._copy_default(ctypes.byref(keychain))
        if status != 0 or not keychain:
            raise LocalConfirmationV2Error("default login Keychain is unavailable")
        item = ctypes.c_void_p()
        secret_buffer = ctypes.create_string_buffer(secret, len(secret))
        try:
            status = self._add(
                keychain,
                len(service_bytes),
                service_bytes,
                len(account_bytes),
                account_bytes,
                len(secret),
                ctypes.cast(secret_buffer, ctypes.c_void_p),
                ctypes.byref(item),
            )
        finally:
            self._release(keychain)
        if item:
            self._release(item)
        if status != 0:
            raise LocalConfirmationV2Error("Keychain identity could not be created")

    def remove(self, service: str, account: str) -> None:
        service_bytes, account_bytes = self._names(service, account)
        password_length = ctypes.c_uint32()
        password_data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._find(
            None,
            len(service_bytes),
            service_bytes,
            len(account_bytes),
            account_bytes,
            ctypes.byref(password_length),
            ctypes.byref(password_data),
            ctypes.byref(item),
        )
        if status == self._ITEM_NOT_FOUND:
            return
        if status != 0 or not item:
            raise LocalConfirmationV2Error("Keychain identity could not be removed")
        try:
            status = self._delete(item)
        finally:
            if password_data:
                self._free_content(None, password_data)
            self._release(item)
        if status != 0:
            raise LocalConfirmationV2Error("Keychain identity could not be removed")


class MacOSDurableKeychain(KeychainStore):
    """Durable v2 Keychain store using native macOS calls instead of the `security` CLI."""

    def __init__(self, bindings: _NativeKeychainBindings | None = None) -> None:
        self._bindings = bindings if bindings is not None else _SecurityFrameworkKeychain()

    def find(self, service: str, account: str) -> bytes | None:
        return self._bindings.find(service, account)

    def create(self, service: str, account: str, secret: bytes) -> None:
        self._bindings.create(service, account, secret)

    def remove(self, service: str, account: str) -> None:
        self._bindings.remove(service, account)


class MacOSTransactionConfirmationUI:
    """Open the complete transaction manifest locally and request its exact digest."""

    open_executable = "/usr/bin/open"
    osascript_executable = "/usr/bin/osascript"

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        opened = subprocess.run(
            [self.open_executable, "-a", "TextEdit", str(display_path)],
            check=False,
            capture_output=True,
        )
        if opened.returncode != 0:
            raise LocalConfirmationV2Error("full transaction display could not be opened")
        script = "\n".join(
            (
                "on run argv",
                "    set expectedDigest to item 1 of argv",
                "    try",
                '        set promptText to "Vault Next requests a local transaction confirmation." & ¬',
                '            "\\n\\nThe complete exact synthetic transaction is open in TextEdit." & ¬',
                '            " Review every operation there, then type its full manifest digest below." & ¬',
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
            [self.osascript_executable, "-e", script, expected_manifest_digest],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()


@dataclass(frozen=True)
class DurableLocalAuthority:
    """Issue a local signed receipt for one immutable v3 transaction manifest."""

    paths: RuntimePaths
    authority_root: Path
    schemas: SchemaRegistry
    keychain: KeychainStore
    confirmation_ui: ConfirmationUI
    id_factory: ULIDFactory = field(default_factory=lambda: DEFAULT_FACTORY)
    clock: Callable[[], datetime] = aware_utc_now

    def __post_init__(self) -> None:
        root = self.authority_root.resolve()
        if not root.is_absolute():
            raise LocalConfirmationV2Error("durable authority root must be an absolute path")
        if _is_within(root, self.paths.root):
            raise LocalConfirmationV2Error("durable authority root must be outside the runtime root")
        if any(_is_within(root, protected.resolve()) for protected in DEFAULT_PROTECTED_ROOTS):
            raise LocalConfirmationV2Error("durable authority root cannot be inside a protected vault")
        object.__setattr__(self, "authority_root", root)

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    @property
    def receipt_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "receipts"
        )

    @property
    def display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "displays"
        )

    @property
    def source_capture_receipt_root(self) -> Path:
        """Keep capture receipts physically and semantically separate from work receipts."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "source-capture" / "receipts"
        )

    @property
    def source_capture_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "source-capture" / "displays"
        )

    @property
    def public_research_receipt_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "public-research" / "receipts"
        )

    @property
    def public_research_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "public-research" / "displays"
        )

    def authorize_transaction(
        self, manifest: dict[str, Any]
    ) -> tuple[Approval, OwnerReceipt]:
        """Display, exactly confirm, and sign one unexpired complete transaction manifest."""

        require_work_transaction_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired transaction manifest")
        identity, authority = self._signing_identity()
        policy_proposal = policy_proposal_for_transaction(manifest)
        approval = Approval(
            approval_id=self.id_factory.new("approval"),
            proposal_digest=policy_proposal.proposal_digest,
            targets=policy_proposal.targets,
            consequence_class=policy_proposal.consequence_class,
            granted_at=now,
            expires_at=expires_at,
            owner_actor_id="local-confirmation-owner",
        )
        owner_receipt = OwnerReceipt(
            receipt_id=self.id_factory.new("receipt"),
            authority_id=AUTHORITY_ID_V2,
            approval_id=approval.approval_id,
            proposal_digest=policy_proposal.proposal_digest,
            targets=policy_proposal.targets,
            consequence_class=policy_proposal.consequence_class,
            issued_at=now,
            expires_at=expires_at,
        )
        display = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "authority_root": str(self.authority_root),
            "transaction_manifest": manifest,
            "transaction_manifest_digest": manifest["manifest_digest"],
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
        response = self.confirmation_ui.confirm(display_path, manifest["manifest_digest"])
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact transaction manifest digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("transaction display changed before receipt issuance")

        record = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "owner_receipt": owner_receipt.to_record(),
            "transaction_manifest": manifest,
            "transaction_manifest_digest": manifest["manifest_digest"],
            "transaction_id": manifest["transaction_id"],
            "policy_proposal_digest": policy_proposal.proposal_digest,
            "confirmation_display_sha256": display_digest,
            "confirmed_at": timestamp(now),
            "signature_base64": "pending",
        }
        signature = identity.private_key.sign(canonical_bytes(_signature_material(record)))
        record["signature_base64"] = base64.b64encode(signature).decode("ascii")
        self.schemas.require("local-confirmation-v2-receipt", record, schema_version="2.0")
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.receipt_root / f"{owner_receipt.receipt_id}.json"
            ),
            canonical_bytes(record),
        )
        return approval, owner_receipt

    def authorize_source_capture(self, manifest: dict[str, Any]) -> SourceCaptureReceipt:
        """Display, exactly confirm, and sign one scoped synthetic source capture.

        This extension may use an existing v2 Keychain identity but must never bootstrap one.  A
        missing/revoked/mismatched durable authority therefore fails closed instead of creating a
        new persistent identity or changing authority scope by accident.
        """

        require_source_capture_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired source-capture manifest")
        identity, authority = self._signing_identity(allow_create=False)
        source_capture_receipt = SourceCaptureReceipt(
            receipt_id=self.id_factory.new("receipt"),
            authority_id=AUTHORITY_ID_V2,
            capture_id=manifest["capture_id"],
            capture_manifest_digest=manifest["capture_manifest_digest"],
            content_sha256=manifest["content_sha256"],
            byte_count=manifest["byte_count"],
            issued_at=now,
            expires_at=expires_at,
        )
        receipt_record = source_capture_receipt.to_record()
        self.schemas.require("source-capture-receipt", receipt_record, schema_version="2.0")
        display = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "capture_manifest": manifest,
            "capture_manifest_digest": manifest["capture_manifest_digest"],
            "source_capture_receipt": receipt_record,
        }
        self.schemas.require("source-capture-display", display, schema_version="2.0")
        display_bytes = canonical_bytes(display)
        display_digest = sha256_hex(display_bytes)
        display_path = self.paths.ensure_runtime_write_target(
            self.source_capture_display_root / f"{source_capture_receipt.receipt_id}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, manifest["capture_manifest_digest"])
        if not hmac.compare_digest(response, manifest["capture_manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact source-capture manifest digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("source-capture display changed before receipt issuance")
        record = {
            "schema_version": "2.0",
            "receipt_type": "source_capture",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "source_capture_receipt": receipt_record,
            "capture_manifest": manifest,
            "capture_manifest_digest": manifest["capture_manifest_digest"],
            "confirmation_display_sha256": display_digest,
            "confirmed_at": timestamp(now),
            "signature_base64": "pending",
        }
        signature = identity.private_key.sign(canonical_bytes(_signature_material(record)))
        record["signature_base64"] = base64.b64encode(signature).decode("ascii")
        self.schemas.require("source-capture-signed-receipt", record, schema_version="2.0")
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.source_capture_receipt_root / f"{source_capture_receipt.receipt_id}.json"
            ),
            canonical_bytes(record),
        )
        return source_capture_receipt

    def authorize_public_research_scope(self, manifest: dict[str, Any]) -> PublicResearchReceipt:
        """Confirm only a bounded public-research scope; it grants no item capture."""

        return self._authorize_public_research(manifest, "public_research_scope")

    def authorize_public_item_capture(self, manifest: dict[str, Any]) -> PublicResearchReceipt:
        """Confirm only a captured citation item already bound to a scope receipt."""

        return self._authorize_public_research(manifest, "public_item_capture")

    def _authorize_public_research(
        self, manifest: dict[str, Any], expected_purpose: str
    ) -> PublicResearchReceipt:
        require_public_research_manifest(manifest, self.schemas)
        if manifest["purpose"] != expected_purpose:
            raise LocalConfirmationV2Error("public-research receipt purpose does not match manifest")
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired public-research manifest")
        identity, authority = self._signing_identity(allow_create=False)
        subject_id = manifest["scope_id"] if expected_purpose == "public_research_scope" else manifest["item_id"]
        if not isinstance(subject_id, str):
            raise LocalConfirmationV2Error("public-research receipt lacks its purpose subject")
        receipt = PublicResearchReceipt(
            receipt_id=self.id_factory.new("receipt"),
            authority_id=AUTHORITY_ID_V2,
            purpose=expected_purpose,
            subject_id=subject_id,
            manifest_digest=manifest["manifest_digest"],
            issued_at=now,
            expires_at=expires_at,
            schema_version=manifest["schema_version"],
        )
        receipt_record = receipt.to_record()
        self.schemas.require("public-research-receipt", receipt_record, schema_version="2.0")
        display = {
            "schema_version": manifest["schema_version"],
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "purpose": expected_purpose,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "public_research_receipt": receipt_record,
        }
        display_bytes = canonical_bytes(display)
        display_digest = sha256_hex(display_bytes)
        display_path = self.paths.ensure_runtime_write_target(
            self.public_research_display_root / f"{receipt.receipt_id}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, manifest["manifest_digest"])
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact public-research manifest digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("public-research display changed before receipt issuance")
        record = {
            "schema_version": manifest["schema_version"],
            "purpose": expected_purpose,
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "public_research_receipt": receipt_record,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": display_digest,
            "confirmed_at": timestamp(now),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("public-research-signed-receipt", record, schema_version="2.0")
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.public_research_receipt_root / f"{receipt.receipt_id}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def _signing_identity(
        self, *, allow_create: bool = True
    ) -> tuple["_SigningIdentity", dict[str, Any]]:
        existing = self._load_authority()
        if existing is not None and existing["status"] != "active":
            raise LocalConfirmationV2Error("durable authority is revoked")
        if existing is None and not allow_create:
            raise LocalConfirmationV2Error("existing durable authority is required for this purpose")
        bundle_id = existing["bundle_id"] if existing is not None else self.id_factory.new("bundle")
        service = f"{AUTHORITY_ID_V2}:{bundle_id}"
        private_bytes = self.keychain.find(service, _KEYCHAIN_ACCOUNT)
        created = False
        if private_bytes is None:
            if existing is not None:
                raise LocalConfirmationV2Error(
                    "authority record exists but its Keychain identity is unavailable"
                )
            if not allow_create:
                raise LocalConfirmationV2Error("existing durable authority Keychain identity is required")
            private_key = Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            self.keychain.create(service, _KEYCHAIN_ACCOUNT, private_bytes)
            created = True
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            authority = {
                "schema_version": "2.0",
                "authority_id": AUTHORITY_ID_V2,
                "bundle_id": bundle_id,
                "algorithm": ALGORITHM,
                "key_id": sha256(public_bytes).hexdigest(),
                "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
                "keychain_service_sha256": sha256(service.encode("utf-8")).hexdigest(),
                "status": "active",
            }
            self.schemas.require("local-confirmation-v2-authority", authority, schema_version="2.0")
            if existing is not None and existing != authority:
                raise LocalConfirmationV2Error(
                    "Keychain public key does not match durable authority record"
                )
            # Once a durable authority exists, every confirmation path is read-only with respect
            # to its persistent bundle record.  In particular C1 source capture is prohibited
            # from touching the owner-selected root even with an idempotent rewrite attempt.
            if existing is None:
                self.authority_root.mkdir(mode=0o700, parents=True, exist_ok=True)
                _write_immutable(self.authority_path, canonical_bytes(authority))
        except Exception:
            if created:
                self.keychain.remove(service, _KEYCHAIN_ACCOUNT)
            raise
        return _SigningIdentity(authority["key_id"], private_key), authority

    def _load_authority(self) -> dict[str, Any] | None:
        if not self.authority_path.exists():
            return None
        return _load_record(
            self.authority_path,
            self.schemas,
            "local-confirmation-v2-authority",
            schema_version="2.0",
        )


@dataclass(frozen=True)
class _SigningIdentity:
    key_id: str
    private_key: Ed25519PrivateKey


class DurableLocalReceiptVerifier(OwnerReceiptVerifier):
    """Replay-verify v2 receipts from runtime evidence and durable public authority material."""

    def __init__(self, paths: RuntimePaths, authority_root: Path, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.authority_root = authority_root.resolve()
        self.schemas = schemas

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    @property
    def receipt_root(self) -> Path:
        return self.paths.evidence_root / "local-confirmation-v2" / "receipts"

    def verify(self, receipt: OwnerReceipt) -> ReceiptVerification:
        if receipt.authority_id != AUTHORITY_ID_V2:
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        try:
            self.schemas.require("owner-receipt", receipt.to_record())
            authority = _load_record(
                self.authority_path,
                self.schemas,
                "local-confirmation-v2-authority",
                schema_version="2.0",
            )
            if authority["status"] != "active":
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
            record = _load_record(
                self.receipt_root / f"{receipt.receipt_id}.json",
                self.schemas,
                "local-confirmation-v2-receipt",
                schema_version="2.0",
            )
            manifest = record["transaction_manifest"]
            require_work_transaction_manifest(manifest, self.schemas)
            policy_proposal = policy_proposal_for_transaction(manifest)
            if any(
                (
                    authority["authority_id"] != AUTHORITY_ID_V2,
                    authority["algorithm"] != ALGORITHM,
                    authority["bundle_id"] != record["bundle_id"],
                    authority["key_id"] != record["key_id"],
                    record["authority_id"] != receipt.authority_id,
                    record["owner_receipt"] != receipt.to_record(),
                    record["transaction_id"] != manifest["transaction_id"],
                    record["transaction_manifest_digest"] != manifest["manifest_digest"],
                    record["policy_proposal_digest"] != policy_proposal.proposal_digest,
                    record["owner_receipt"]["proposal_digest"]
                    != policy_proposal.proposal_digest,
                    tuple(record["owner_receipt"]["targets"]) != policy_proposal.targets,
                )
            ):
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
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
            LocalConfirmationV2Error,
        ):
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        return ReceiptVerification(ReceiptVerificationStatus.VERIFIED, AUTHORITY_ID_V2)


class SourceCaptureReceiptVerifier:
    """Replay-verify only signed ``source_capture`` receipts from v2 runtime evidence."""

    def __init__(self, paths: RuntimePaths, authority_root: Path, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.authority_root = authority_root.resolve()
        self.schemas = schemas

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    @property
    def receipt_root(self) -> Path:
        return self.paths.evidence_root / "local-confirmation-v2" / "source-capture" / "receipts"

    def verify(self, receipt: SourceCaptureReceipt) -> ReceiptVerification:
        if receipt.authority_id != AUTHORITY_ID_V2:
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        try:
            self.schemas.require("source-capture-receipt", receipt.to_record(), schema_version="2.0")
            authority = _load_record(
                self.authority_path,
                self.schemas,
                "local-confirmation-v2-authority",
                schema_version="2.0",
            )
            if authority["status"] != "active":
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
            record = _load_record(
                self.receipt_root / f"{receipt.receipt_id}.json",
                self.schemas,
                "source-capture-signed-receipt",
                schema_version="2.0",
            )
            manifest = record["capture_manifest"]
            require_source_capture_manifest(manifest, self.schemas)
            if any(
                (
                    record["receipt_type"] != "source_capture",
                    authority["authority_id"] != AUTHORITY_ID_V2,
                    authority["algorithm"] != ALGORITHM,
                    authority["bundle_id"] != record["bundle_id"],
                    authority["key_id"] != record["key_id"],
                    record["authority_id"] != receipt.authority_id,
                    record["source_capture_receipt"] != receipt.to_record(),
                    record["capture_manifest_digest"] != manifest["capture_manifest_digest"],
                    receipt.capture_id != manifest["capture_id"],
                    receipt.content_sha256 != manifest["content_sha256"],
                    receipt.byte_count != manifest["byte_count"],
                )
            ):
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
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
            LocalConfirmationV2Error,
        ):
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        return ReceiptVerification(ReceiptVerificationStatus.VERIFIED, AUTHORITY_ID_V2)

    def load_verified(self, receipt_id: str) -> tuple[SourceCaptureReceipt, dict[str, Any]]:
        """Load a receipt only after signature and purpose verification."""

        record = _load_record(
            self.receipt_root / f"{receipt_id}.json",
            self.schemas,
            "source-capture-signed-receipt",
            schema_version="2.0",
        )
        receipt_record = record["source_capture_receipt"]
        self.schemas.require("source-capture-receipt", receipt_record, schema_version="2.0")
        receipt = SourceCaptureReceipt(
            receipt_id=receipt_record["receipt_id"],
            authority_id=receipt_record["authority_id"],
            capture_id=receipt_record["capture_id"],
            capture_manifest_digest=receipt_record["capture_manifest_digest"],
            content_sha256=receipt_record["content_sha256"],
            byte_count=receipt_record["byte_count"],
            issued_at=_parse_timestamp(receipt_record["issued_at"]),
            expires_at=_parse_timestamp(receipt_record["expires_at"]),
        )
        if self.verify(receipt).status != ReceiptVerificationStatus.VERIFIED:
            raise LocalConfirmationV2Error("source-capture receipt did not verify")
        return receipt, record["capture_manifest"]


class PublicResearchReceiptVerifier:
    """Replay-verify purpose-separated public-research receipts from runtime evidence."""

    def __init__(self, paths: RuntimePaths, authority_root: Path, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.authority_root = authority_root.resolve()
        self.schemas = schemas

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    @property
    def receipt_root(self) -> Path:
        return self.paths.evidence_root / "local-confirmation-v2" / "public-research" / "receipts"

    def verify(self, receipt: PublicResearchReceipt, *, purpose: str) -> ReceiptVerification:
        if receipt.authority_id != AUTHORITY_ID_V2 or receipt.purpose != purpose:
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        try:
            self.schemas.require("public-research-receipt", receipt.to_record(), schema_version="2.0")
            authority = _load_record(
                self.authority_path, self.schemas, "local-confirmation-v2-authority", schema_version="2.0"
            )
            record = _load_record(
                self.receipt_root / f"{receipt.receipt_id}.json",
                self.schemas,
                "public-research-signed-receipt",
                schema_version="2.0",
            )
            manifest = record["manifest"]
            require_public_research_manifest(manifest, self.schemas)
            if any((
                authority["status"] != "active",
                authority["authority_id"] != AUTHORITY_ID_V2,
                authority["algorithm"] != ALGORITHM,
                authority["bundle_id"] != record["bundle_id"],
                authority["key_id"] != record["key_id"],
                record["purpose"] != purpose,
                record["authority_id"] != AUTHORITY_ID_V2,
                record["public_research_receipt"] != receipt.to_record(),
                record["manifest_digest"] != manifest["manifest_digest"],
                record["schema_version"] != manifest["schema_version"],
                receipt.schema_version != manifest["schema_version"],
                receipt.manifest_digest != manifest["manifest_digest"],
                receipt.subject_id != (
                    manifest["scope_id"] if purpose == "public_research_scope" else manifest["item_id"]
                ),
            )):
                return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
            public_bytes = base64.b64decode(authority["public_key_base64"], validate=True)
            signature = base64.b64decode(record["signature_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature, canonical_bytes(_signature_material(record))
            )
        except (
            InvalidSignature, KeyError, TypeError, ValidationError, ValueError, OSError,
            LocalConfirmationV2Error,
        ):
            return ReceiptVerification(ReceiptVerificationStatus.REJECTED, AUTHORITY_ID_V2)
        return ReceiptVerification(ReceiptVerificationStatus.VERIFIED, AUTHORITY_ID_V2)

    def load_verified(
        self, receipt_id: str, *, purpose: str
    ) -> tuple[PublicResearchReceipt, dict[str, Any]]:
        record = _load_record(
            self.receipt_root / f"{receipt_id}.json",
            self.schemas,
            "public-research-signed-receipt",
            schema_version="2.0",
        )
        receipt_record = record["public_research_receipt"]
        self.schemas.require("public-research-receipt", receipt_record, schema_version="2.0")
        receipt = PublicResearchReceipt(
            receipt_id=receipt_record["receipt_id"],
            authority_id=receipt_record["authority_id"],
            purpose=receipt_record["purpose"],
            subject_id=receipt_record["subject_id"],
            manifest_digest=receipt_record["manifest_digest"],
            issued_at=_parse_timestamp(receipt_record["issued_at"]),
            expires_at=_parse_timestamp(receipt_record["expires_at"]),
            schema_version=receipt_record["schema_version"],
        )
        if self.verify(receipt, purpose=purpose).status != ReceiptVerificationStatus.VERIFIED:
            raise LocalConfirmationV2Error("public-research receipt did not verify for its purpose")
        return receipt, record["manifest"]


@dataclass(frozen=True)
class LocalConfirmationV2ProofResult:
    """Minimal actual-host proof summary that never copies the invented transaction into output."""

    runtime_root: str
    authority_id: str
    bundle_id: str
    receipt_id: str
    committed_watermark: str
    replay_verified: bool
    finalized: bool

    def to_record(self) -> dict[str, Any]:
        return {
            "runtime_root": self.runtime_root,
            "authority_id": self.authority_id,
            "bundle_id": self.bundle_id,
            "receipt_id": self.receipt_id,
            "committed_watermark": self.committed_watermark,
            "replay_verified": self.replay_verified,
            "finalized": self.finalized,
        }


def run_synthetic_work_transaction_confirmation_proof(
    runtime_root: Path,
    schema_root: Path,
    authority_root: Path,
) -> LocalConfirmationV2ProofResult:
    """Run the one real local confirmation proof over two invented disposable cases only."""

    from vault_next.contracts import finalize_work_transaction_manifest
    from vault_next.runtime import CaseSessionRuntime
    from vault_next.state import build_current_work_view, fold_work_items
    from vault_next.work_transactions import WorkTransactionCoordinator

    protected_roots = (runtime_root / "synthetic-legacy", runtime_root / "synthetic-backup")
    paths = RuntimePaths(runtime_root, protected_roots=protected_roots)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    current = aware_utc_now()
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        clock=lambda: current,
        correlation_id="s2b-local-confirmation-proof",
    )
    operations: list[dict[str, Any]] = []
    for number in (1, 2):
        case = runtime.create_case(f"Invented S2-B case {number}")
        session = runtime.create_session(case["case_id"], f"Invented S2-B session {number}")
        session_id = session["session_id"]
        runtime.transition_session(session_id, "routed", reason="synthetic proof setup")
        runtime.transition_session(session_id, "authorized", reason="synthetic proof setup")
        runtime.transition_session(session_id, "active", reason="synthetic proof setup")
        work_item_id = runtime.ids.new("work_item")
        statement = f"Invented S2-B work item {number}"
        runtime._append(
            "work_item.recorded",
            case["case_id"],
            session_id,
            {
                "work_item_id": work_item_id,
                "statement": statement,
                "status": "open",
                "source_kind": "owner_instruction",
                "priority": "normal",
                "due_on": None,
                "next_review_on": None,
                "blocker": None,
                "explicit_confirmation": True,
            },
            subject_refs=[work_item_id],
            actor={"type": "owner", "id": "synthetic-owner"},
            when=current,
        )
        operations.append(
            {
                "case_id": case["case_id"],
                "session_id": session_id,
                "work_item_id": work_item_id,
                "expected_revision": 1,
                "operation": "status_change",
                "next_state": {
                    "statement": statement,
                    "status": "in_progress",
                    "source_kind": "owner_instruction",
                    "priority": "normal",
                    "due_on": None,
                    "next_review_on": None,
                    "blocker": None,
                },
                "selection_binding": None,
            }
        )
    manifest = finalize_work_transaction_manifest(
        {
            "schema_version": "3.0",
            "transaction_id": runtime.ids.new("work_transaction"),
            "request_id": runtime.ids.new("request"),
            "idempotency_key": "s2b-local-confirmation-proof",
            "affected_case_ids": [],
            "operations": operations,
            "expires_at": timestamp(current + timedelta(minutes=5)),
            "compatibility": {
                "minimum_semantic_schema_version": "3.0",
                "minimum_reader_version": RUNTIME_ACTOR["id"].rsplit("/", maxsplit=1)[1],
            },
            "manifest_digest": "",
        }
    )
    authority = DurableLocalAuthority(
        paths,
        authority_root,
        schemas,
        MacOSDurableKeychain(),
        MacOSTransactionConfirmationUI(),
        clock=lambda: current,
    )
    coordinator = WorkTransactionCoordinator(
        runtime,
        PolicyEngine(
            paths,
            schemas,
            receipt_verifier=DurableLocalReceiptVerifier(paths, authority_root, schemas),
        ),
        schemas,
    )
    coordinator.prepare(manifest)
    approval, owner_receipt = authority.authorize_transaction(manifest)
    receipt = coordinator.commit(
        manifest,
        approval=approval,
        owner_receipt=owner_receipt,
        now=current,
    )
    restarted_paths = RuntimePaths(runtime_root, protected_roots=protected_roots)
    restarted_schemas = SchemaRegistry(schema_root)
    restarted_verifier = DurableLocalReceiptVerifier(
        restarted_paths, authority_root, restarted_schemas
    )
    replay_verified = (
        restarted_verifier.verify(owner_receipt).status == ReceiptVerificationStatus.VERIFIED
    )
    restarted_events = CaseSessionRuntime(restarted_paths, restarted_schemas).semantic.read_all()
    view = build_current_work_view(
        restarted_events,
        as_of_date=current.date().isoformat(),
        time_zone="UTC",
        minimum_watermark=receipt["committed_watermark"],
    )
    if not replay_verified or not view or any(
        fold_work_items(restarted_events)[operation["work_item_id"]]["status"] != "in_progress"
        for operation in operations
    ):
        raise LocalConfirmationV2Error("confirmed synthetic transaction did not verify after restart")
    authority_record = _load_record(
        authority.authority_path,
        schemas,
        "local-confirmation-v2-authority",
        schema_version="2.0",
    )
    return LocalConfirmationV2ProofResult(
        runtime_root=str(restarted_paths.root),
        authority_id=AUTHORITY_ID_V2,
        bundle_id=authority_record["bundle_id"],
        receipt_id=owner_receipt.receipt_id,
        committed_watermark=receipt["committed_watermark"],
        replay_verified=True,
        finalized=coordinator.finalized_path(manifest["transaction_id"]).exists(),
    )


def _signature_material(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "signature_base64"}


def finalize_source_capture_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return one capture manifest with its exact, non-circular purpose digest."""

    finalized = dict(manifest)
    finalized["capture_manifest_digest"] = canonical_sha256(
        {key: value for key, value in finalized.items() if key != "capture_manifest_digest"}
    )
    return finalized


def require_source_capture_manifest(manifest: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate the narrow C1 contract independently of work-transaction confirmation."""

    schemas.require("source-capture-manifest", manifest, schema_version="2.0")
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "capture_manifest_digest"}
    )
    if not hmac.compare_digest(manifest["capture_manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("source-capture manifest digest does not match its contents")
    if manifest["byte_count"] < 0:
        raise LocalConfirmationV2Error("source-capture byte count cannot be negative")
    if manifest["permitted_processors"]:
        raise LocalConfirmationV2Error("C1 synthetic capture cannot disclose to any processor")
    captured_at = _parse_timestamp(manifest["captured_at"])
    expires_at = _parse_timestamp(manifest["expires_at"])
    if expires_at <= captured_at:
        raise LocalConfirmationV2Error("source-capture expiry must be after local preflight")


def finalize_public_research_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Bind a public-research purpose to every one of its declared fields."""

    finalized = dict(manifest)
    finalized["manifest_digest"] = canonical_sha256(
        {key: value for key, value in finalized.items() if key != "manifest_digest"}
    )
    return finalized


def require_public_research_manifest(manifest: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Enforce the citation-only, fixed-URL contract beyond structural schema checks."""

    schemas.require("public-research-manifest", manifest, schema_version="2.0")
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("public-research manifest digest does not match its contents")
    if manifest["permitted_model_recipients"] or manifest["permitted_processors"]:
        raise LocalConfirmationV2Error("citation-only public research cannot disclose to recipients")
    if manifest["schema_version"] == "2.1":
        fields = (
            "execution_component_id",
            "execution_component_version",
            "execution_mode",
            "execution_runtime_root",
            "execution_t0",
            "owner_terms_rights_attestation",
        )
        if any(not isinstance(manifest.get(field), str) for field in fields):
            raise LocalConfirmationV2Error("execution-bound public-research manifest lacks a binding")
        if (
            manifest["execution_component_id"] != "vault-next-direct-https-transport"
            or manifest["execution_component_version"] != "0.2.0"
            or manifest["execution_mode"] != "live_one_request"
            or manifest["owner_terms_rights_attestation"] != PUBLIC_RESEARCH_EXECUTION_ATTESTATION
        ):
            raise LocalConfirmationV2Error("execution-bound public-research manifest has an invalid authority binding")
        runtime_root = Path(manifest["execution_runtime_root"])
        if (
            not runtime_root.is_absolute()
            or runtime_root.parent != Path("/private/tmp")
            or not runtime_root.name.startswith("vault-next-s3c-live.")
        ):
            raise LocalConfirmationV2Error("execution runtime root is not the approved disposable shape")
        t0 = _parse_timestamp(manifest["execution_t0"])
        if _parse_timestamp(manifest["expires_at"]) != t0 + timedelta(minutes=10):
            raise LocalConfirmationV2Error("execution receipt expiry must be exactly ten minutes after T0")
    if manifest["purpose"] == "public_research_scope":
        if any(manifest[field] is not None for field in (
            "item_id", "scope_receipt_id", "http_status", "media_type", "byte_count",
            "content_sha256", "final_url", "redirect_chain", "retrieved_at",
        )):
            raise LocalConfirmationV2Error("public-research scope cannot contain item response data")
    else:
        if any(manifest[field] is None for field in (
            "item_id", "scope_receipt_id", "http_status", "media_type", "byte_count",
            "content_sha256", "final_url", "redirect_chain", "retrieved_at",
        )):
            raise LocalConfirmationV2Error("public item capture must bind complete response metadata")
        if (
            manifest["http_status"] != 200
            or manifest["media_type"].lower() != "text/plain"
            or manifest["byte_count"] < 0
            or manifest["byte_count"] > 65536
            or manifest["final_url"] != manifest["url"]
            or manifest["redirect_chain"] != []
        ):
            raise LocalConfirmationV2Error("public item capture violates fixed citation-only transport bounds")
    if _parse_timestamp(manifest["expires_at"]) <= (
        _parse_timestamp(manifest["retrieved_at"])
        if manifest["retrieved_at"] is not None
        else datetime.min.replace(tzinfo=UTC)
    ):
        raise LocalConfirmationV2Error("public-research receipt expiry must follow retrieval")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _write_immutable(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if _read_bytes(path) != data:
            raise LocalConfirmationV2Error(
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


def _load_record(
    path: Path,
    schemas: SchemaRegistry,
    schema_name: str,
    *,
    schema_version: str,
) -> dict[str, Any]:
    try:
        record = json.loads(_read_bytes(path))
    except (json.JSONDecodeError, OSError) as exc:
        raise LocalConfirmationV2Error(
            f"local confirmation record is unreadable: {path.name}"
        ) from exc
    if not isinstance(record, dict):
        raise LocalConfirmationV2Error(f"local confirmation record is not an object: {path.name}")
    schemas.require(schema_name, record, schema_version=schema_version)
    return record
