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


class DirectPrivateNativeLauncher(Protocol):
    """The only host surface permitted for a future direct-private confirmation."""

    def open_textedit(self, display_path: Path) -> bool: ...

    def request_digest(self, *, purpose: str, expected_manifest_digest: str) -> str: ...


class DirectPrivateConfirmationUI(Protocol):
    """Exact-digest display confirmation for a purpose-limited direct-private receipt."""

    def confirm(
        self,
        display_path: Path,
        *,
        purpose: str,
        expected_manifest_digest: str,
    ) -> str: ...


class MacOSDirectPrivateLauncher:
    """Launch only the fixed local TextEdit and AppleScript confirmation surfaces."""

    open_executable = "/usr/bin/open"
    osascript_executable = "/usr/bin/osascript"

    def open_textedit(self, display_path: Path) -> bool:
        result = subprocess.run(
            [self.open_executable, "-a", "TextEdit", str(display_path)],
            check=False,
            capture_output=True,
        )
        return result.returncode == 0

    def request_digest(self, *, purpose: str, expected_manifest_digest: str) -> str:
        if purpose not in {"direct_private_snapshot_scope", "direct_private_source_admission"}:
            raise LocalConfirmationV2Error("direct-private confirmation purpose is unsupported")
        label = (
            "snapshot scope"
            if purpose == "direct_private_snapshot_scope"
            else "source admission"
        )
        script = "\n".join(
            (
                "on run argv",
                "    set expectedDigest to item 1 of argv",
                "    set purposeLabel to item 2 of argv",
                "    try",
                '        set promptText to "Vault Next requests a local direct-private " & purposeLabel & ¬',
                '            " confirmation." & ¬',
                '            "\\n\\nThe complete local-only proposal is open in TextEdit." & ¬',
                '            " Review it, then type its full manifest digest below." & ¬',
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
            [self.osascript_executable, "-e", script, expected_manifest_digest, label],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()


class MacOSDirectPrivateConfirmationUI:
    """Fakeable native route for a future direct-private local confirmation."""

    def __init__(self, launcher: DirectPrivateNativeLauncher | None = None) -> None:
        self.launcher = launcher if launcher is not None else MacOSDirectPrivateLauncher()

    def confirm(
        self,
        display_path: Path,
        *,
        purpose: str,
        expected_manifest_digest: str,
    ) -> str:
        if not self.launcher.open_textedit(display_path):
            raise LocalConfirmationV2Error("direct-private confirmation display could not be opened")
        return self.launcher.request_digest(
            purpose=purpose,
            expected_manifest_digest=expected_manifest_digest,
        )


class ChatFirstU1SaveNativeLauncher(Protocol):
    """The only local UI surface for an ordinary generated Chat-first U1 proposal."""

    def open_textedit(self, display_path: Path) -> bool: ...

    def request_digest(self, *, expected_manifest_digest: str) -> str: ...


class ChatFirstU1SaveConfirmationUI(Protocol):
    """Exact-digest confirmation for the purpose-limited Chat-first U1 receipt."""

    def confirm(self, display_path: Path, *, expected_manifest_digest: str) -> str: ...


class MacOSChatFirstU1SaveLauncher:
    """Open only the generated local proposal and prompt for its exact digest."""

    open_executable = "/usr/bin/open"
    osascript_executable = "/usr/bin/osascript"

    def open_textedit(self, display_path: Path) -> bool:
        result = subprocess.run(
            [self.open_executable, "-a", "TextEdit", str(display_path)],
            check=False,
            capture_output=True,
        )
        return result.returncode == 0

    def request_digest(self, *, expected_manifest_digest: str) -> str:
        script = "\n".join(
            (
                "on run argv",
                "    set expectedDigest to item 1 of argv",
                "    try",
                '        set promptText to "Vault Next requests a local Save to Vault Next confirmation." & ¬',
                '            "\\n\\nThe complete generated proposal is open in TextEdit." & ¬',
                '            " Review it, then type its full manifest digest below." & ¬',
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


class MacOSChatFirstU1SaveConfirmationUI:
    """Fakeable native exact-digest route for one generated U1 save proposal."""

    def __init__(self, launcher: ChatFirstU1SaveNativeLauncher | None = None) -> None:
        self.launcher = launcher if launcher is not None else MacOSChatFirstU1SaveLauncher()

    def confirm(self, display_path: Path, *, expected_manifest_digest: str) -> str:
        if not self.launcher.open_textedit(display_path):
            raise LocalConfirmationV2Error("Chat-first U1 confirmation display could not be opened")
        return self.launcher.request_digest(expected_manifest_digest=expected_manifest_digest)


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
    direct_private_confirmation_ui: DirectPrivateConfirmationUI | None = None
    chat_first_u1_save_confirmation_ui: ChatFirstU1SaveConfirmationUI | None = None

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

    def direct_private_receipt_root(self, purpose: str) -> Path:
        """Keep each direct-private purpose physically separate from every other receipt class."""

        _require_direct_private_purpose(purpose)
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose
            / "receipts"
        )

    def direct_private_display_root(self, purpose: str) -> Path:
        """Keep direct-private displays owner-local and receipt-purpose separated."""

        _require_direct_private_purpose(purpose)
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose
            / "displays"
        )

    @property
    def chat_first_u1_save_receipt_root(self) -> Path:
        """Keep ordinary U1 receipts separate from every existing v2 purpose domain."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-save" / "receipts"
        )

    @property
    def chat_first_u1_save_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-save" / "displays"
        )

    @property
    def chat_first_u1_multi_source_save_receipt_root(self) -> Path:
        """Keep ordered multi-source U1 receipts separate from ordinary one-source saves."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-multi-source-save" / "receipts"
        )

    @property
    def chat_first_u1_multi_source_save_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-multi-source-save" / "displays"
        )

    @property
    def chat_first_u1_multi_source_knowledge_save_receipt_root(self) -> Path:
        """Keep knowledge-lineage U1 receipts physically separate from work-continuity U1."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "chat-first-u1-multi-source-knowledge-save" / "receipts"
        )

    @property
    def chat_first_u1_multi_source_knowledge_save_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "chat-first-u1-multi-source-knowledge-save" / "displays"
        )

    @property
    def chat_first_u1_citation_recovery_receipt_root(self) -> Path:
        """Keep append-only recovery receipts separate from every save purpose."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-citation-recovery" / "receipts"
        )

    @property
    def chat_first_u1_citation_recovery_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "chat-first-u1-citation-recovery" / "displays"
        )

    @property
    def chat_first_u1_primary_artifact_retrofit_receipt_root(self) -> Path:
        """Keep the batched presentation retrofit separate from all save/recovery purposes."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "chat-first-u1-primary-artifact-retrofit" / "receipts"
        )

    @property
    def chat_first_u1_primary_artifact_retrofit_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "chat-first-u1-primary-artifact-retrofit" / "displays"
        )

    @property
    def archive_preservation_receipt_root(self) -> Path:
        """Keep opaque archival-preservation evidence separate from every U1 save purpose."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "archive-preservation" / "receipts"
        )

    @property
    def archive_preservation_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "archive-preservation" / "displays"
        )

    @property
    def historical_activity_reconstruction_receipt_root(self) -> Path:
        """Keep historical candidate migration receipts separate from archive preservation."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-activity-reconstruction" / "receipts"
        )

    @property
    def historical_activity_reconstruction_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-activity-reconstruction" / "displays"
        )

    @property
    def historical_weekly_activity_reconstruction_receipt_root(self) -> Path:
        """Keep additive multi-parent weekly receipts separate from single-parent H2."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-weekly-activity-reconstruction" / "receipts"
        )

    @property
    def historical_weekly_activity_reconstruction_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-weekly-activity-reconstruction" / "displays"
        )

    @property
    def historical_owner_confirmed_continuity_supplement_receipt_root(self) -> Path:
        """Keep owner-confirmed historical context separate from source-extracted migration."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-owner-confirmed-continuity-supplement" / "receipts"
        )

    @property
    def historical_owner_confirmed_continuity_supplement_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-owner-confirmed-continuity-supplement" / "displays"
        )

    @property
    def historical_migration_amendment_receipt_root(self) -> Path:
        """Keep source-grounded migration amendments separate from owner context."""

        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-migration-amendment" / "receipts"
        )

    @property
    def historical_migration_amendment_display_root(self) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2"
            / "historical-migration-amendment" / "displays"
        )

    def authorize_chat_first_u1_save(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm and sign one complete generated Chat-first U1 save proposal.

        This purpose can use an existing v2 identity only. It has no generic signing, bootstrap,
        transaction, direct-private, source-capture, or publication capability.
        """

        _require_chat_first_u1_save_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired Chat-first U1 manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("Chat-first U1 native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2,
            "purpose": "chat_first_u1_save",
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("chat-first-u1-save-receipt", receipt)
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "purpose": "chat_first_u1_save",
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        self.schemas.require("chat-first-u1-save-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.chat_first_u1_save_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path,
            expected_manifest_digest=manifest["manifest_digest"],
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact Chat-first U1 manifest digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("Chat-first U1 display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("Chat-first U1 confirmation expired before receipt issuance")
        record = {
            "schema_version": "1.0",
            "receipt_type": "chat_first_u1_save",
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("chat-first-u1-save-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.chat_first_u1_save_receipt_root / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_chat_first_u1_save(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Replay-verify exactly one existing Chat-first U1 receipt without Keychain access."""

        return ChatFirstU1SaveV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_chat_first_u1_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        """Return the already-verified, purpose-limited display and signed receipt bytes.

        This is deliberately a read-only evidence handoff: it neither exposes signing nor reads
        Keychain material.  A private publisher may archive these exact bytes under its separate
        bundle so a later restart can verify the same confirmation without a transient runtime.
        """

        self.verify_chat_first_u1_save(receipt_id, manifest)
        return (
            _read_bytes(self.chat_first_u1_save_display_root / f"{receipt_id}.json"),
            _read_bytes(self.chat_first_u1_save_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_chat_first_u1_save(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        """Replay-verify exact archived evidence using only the v2 public authority record."""

        return ChatFirstU1SaveV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_chat_first_u1_multi_source_save(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm one ordered M1/W1/W2/W3 U1 proposal with the existing v2 identity only."""

        _require_chat_first_u1_multi_source_save_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired multi-source U1 manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("multi-source U1 native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": "chat_first_u1_multi_source_save",
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("chat-first-u1-multi-source-save-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": receipt["purpose"],
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("chat-first-u1-multi-source-save-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.chat_first_u1_multi_source_save_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined("local confirmation did not match the exact multi-source U1 digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("multi-source U1 display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("multi-source U1 confirmation expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": receipt["purpose"], "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "algorithm": ALGORITHM, "key_id": identity.key_id,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes), "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("chat-first-u1-multi-source-save-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.chat_first_u1_multi_source_save_receipt_root / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_chat_first_u1_multi_source_save(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return ChatFirstU1MultiSourceSaveV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_chat_first_u1_multi_source_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_multi_source_save(receipt_id, manifest)
        return (
            _read_bytes(self.chat_first_u1_multi_source_save_display_root / f"{receipt_id}.json"),
            _read_bytes(self.chat_first_u1_multi_source_save_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_chat_first_u1_multi_source_save(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return ChatFirstU1MultiSourceSaveV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_chat_first_u1_multi_source_knowledge_save(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm one ordered K1/K2/K3/K4 knowledge U1 proposal with the existing v2 identity."""

        _require_chat_first_u1_multi_source_knowledge_save_manifest(manifest, self.schemas)
        return self._authorize_multi_source_knowledge_save(manifest)

    def _authorize_multi_source_knowledge_save(self, manifest: dict[str, Any]) -> dict[str, Any]:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired knowledge U1 manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("knowledge U1 native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "chat_first_u1_multi_source_knowledge_save"
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("chat-first-u1-multi-source-knowledge-save-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": purpose,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("chat-first-u1-multi-source-knowledge-save-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.chat_first_u1_multi_source_knowledge_save_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined("local confirmation did not match the exact knowledge U1 digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("knowledge U1 display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("knowledge U1 confirmation expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": purpose, "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "algorithm": ALGORITHM, "key_id": identity.key_id,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes), "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("chat-first-u1-multi-source-knowledge-save-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.chat_first_u1_multi_source_knowledge_save_receipt_root / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_chat_first_u1_multi_source_knowledge_save(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return ChatFirstU1MultiSourceKnowledgeSaveV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_chat_first_u1_multi_source_knowledge_save_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_multi_source_knowledge_save(receipt_id, manifest)
        return (
            _read_bytes(self.chat_first_u1_multi_source_knowledge_save_display_root / f"{receipt_id}.json"),
            _read_bytes(self.chat_first_u1_multi_source_knowledge_save_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_chat_first_u1_multi_source_knowledge_save(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path,
    ) -> dict[str, Any]:
        return ChatFirstU1MultiSourceKnowledgeSaveV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock,
            display_root=display_root, receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_chat_first_u1_citation_recovery(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm one append-only recovery proposal with the existing v2 identity only."""

        _require_chat_first_u1_citation_recovery_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired citation-recovery U1 manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("citation-recovery U1 native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": "chat_first_u1_citation_recovery",
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("chat-first-u1-citation-recovery-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": receipt["purpose"],
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("chat-first-u1-citation-recovery-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.chat_first_u1_citation_recovery_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined("local confirmation did not match the exact citation-recovery digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("citation-recovery U1 display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("citation-recovery U1 confirmation expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": receipt["purpose"], "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "algorithm": ALGORITHM, "key_id": identity.key_id,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes), "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("chat-first-u1-citation-recovery-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.chat_first_u1_citation_recovery_receipt_root / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_chat_first_u1_citation_recovery(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return ChatFirstU1CitationRecoveryV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_chat_first_u1_citation_recovery_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_citation_recovery(receipt_id, manifest)
        return (
            _read_bytes(self.chat_first_u1_citation_recovery_display_root / f"{receipt_id}.json"),
            _read_bytes(self.chat_first_u1_citation_recovery_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_chat_first_u1_citation_recovery(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return ChatFirstU1CitationRecoveryV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_chat_first_u1_primary_artifact_retrofit(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Confirm one exact W1/W2/W3 append-only presentation retrofit."""

        _require_chat_first_u1_primary_artifact_retrofit_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired primary-artifact retrofit")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("primary-artifact retrofit native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "chat_first_u1_primary_artifact_retrofit"
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("chat-first-u1-primary-artifact-retrofit-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": purpose,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("chat-first-u1-primary-artifact-retrofit-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.chat_first_u1_primary_artifact_retrofit_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact primary-artifact retrofit digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("primary-artifact retrofit display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("primary-artifact retrofit expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": purpose, "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "algorithm": ALGORITHM,
            "key_id": identity.key_id, "receipt": receipt, "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at), "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("chat-first-u1-primary-artifact-retrofit-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.chat_first_u1_primary_artifact_retrofit_receipt_root / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_chat_first_u1_primary_artifact_retrofit(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return ChatFirstU1PrimaryArtifactRetrofitV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_chat_first_u1_primary_artifact_retrofit_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_chat_first_u1_primary_artifact_retrofit(receipt_id, manifest)
        return (
            _read_bytes(self.chat_first_u1_primary_artifact_retrofit_display_root / f"{receipt_id}.json"),
            _read_bytes(self.chat_first_u1_primary_artifact_retrofit_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_chat_first_u1_primary_artifact_retrofit(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return ChatFirstU1PrimaryArtifactRetrofitV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock,
            display_root=display_root, receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_archive_preservation(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm one opaque local-only archive preservation proposal with existing v2 identity."""

        _require_archive_preservation_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired archive preservation manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("archive preservation native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": "archive_preservation",
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("archive-preservation-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": "archive_preservation",
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("archive-preservation-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.archive_preservation_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined("local confirmation did not match archive preservation digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("archive preservation display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("archive preservation expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": "archive_preservation",
            "authority_id": AUTHORITY_ID_V2, "authority_bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM, "key_id": identity.key_id, "receipt": receipt, "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at), "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("archive-preservation-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.archive_preservation_receipt_root / f"{receipt['receipt_id']}.json"
            ), canonical_bytes(record)
        )
        return receipt

    def verify_archive_preservation(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return ArchivePreservationV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_archive_preservation_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_archive_preservation(receipt_id, manifest)
        return (
            _read_bytes(self.archive_preservation_display_root / f"{receipt_id}.json"),
            _read_bytes(self.archive_preservation_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_archive_preservation(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]:
        return ArchivePreservationV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock,
            display_root=display_root, receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_historical_activity_reconstruction(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Confirm one candidate-only historical cohort using the existing v2 identity."""

        _require_historical_activity_reconstruction_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired historical activity manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error(
                "historical activity native confirmation UI is not configured"
            )
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "historical_activity_reconstruction"
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("historical-activity-reconstruction-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": purpose,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        self.schemas.require("historical-activity-reconstruction-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.historical_activity_reconstruction_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match historical activity digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error(
                "historical activity display changed before receipt issuance"
            )
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error(
                "historical activity confirmation expired before receipt issuance"
            )
        record = {
            "schema_version": "1.0", "receipt_type": purpose,
            "authority_id": AUTHORITY_ID_V2, "authority_bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM, "key_id": identity.key_id, "receipt": receipt,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at), "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("historical-activity-reconstruction-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.historical_activity_reconstruction_receipt_root
                / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_historical_activity_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return HistoricalActivityReconstructionV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_historical_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_historical_activity_reconstruction(receipt_id, manifest)
        return (
            _read_bytes(
                self.historical_activity_reconstruction_display_root / f"{receipt_id}.json"
            ),
            _read_bytes(
                self.historical_activity_reconstruction_receipt_root / f"{receipt_id}.json"
            ),
        )

    def verify_archived_historical_activity_reconstruction(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return HistoricalActivityReconstructionV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_historical_weekly_activity_reconstruction(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Confirm one additive multi-parent weekly cohort with the existing v2 identity."""

        _require_historical_weekly_activity_reconstruction_manifest(manifest, self.schemas)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired historical weekly manifest")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error(
                "historical weekly native confirmation UI is not configured"
            )
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "historical_weekly_activity_reconstruction"
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2,
            "purpose": purpose,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("historical-weekly-activity-reconstruction-receipt", receipt)
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "purpose": purpose,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        self.schemas.require("historical-weekly-activity-reconstruction-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.historical_weekly_activity_reconstruction_display_root
            / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match historical weekly digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error(
                "historical weekly display changed before receipt issuance"
            )
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error(
                "historical weekly confirmation expired before receipt issuance"
            )
        record = {
            "schema_version": "1.0",
            "receipt_type": purpose,
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("historical-weekly-activity-reconstruction-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.historical_weekly_activity_reconstruction_receipt_root
                / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_historical_weekly_activity_reconstruction(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return HistoricalWeeklyActivityReconstructionV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_historical_weekly_activity_reconstruction_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_historical_weekly_activity_reconstruction(receipt_id, manifest)
        return (
            _read_bytes(
                self.historical_weekly_activity_reconstruction_display_root
                / f"{receipt_id}.json"
            ),
            _read_bytes(
                self.historical_weekly_activity_reconstruction_receipt_root
                / f"{receipt_id}.json"
            ),
        )

    def verify_archived_historical_weekly_activity_reconstruction(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return HistoricalWeeklyActivityReconstructionV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_historical_owner_confirmed_continuity_supplement(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Sign only one fixed-scope, owner-confirmed historical-context supplement."""

        _require_historical_owner_confirmed_continuity_supplement_manifest(manifest, self.schemas)
        now = self.clock()
        expires_at = _parse_timestamp(manifest["expires_at"])
        if now.tzinfo is None or now.utcoffset() is None or expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("owner-context confirmation window is invalid")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("owner-context native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "historical_owner_confirmed_continuity_supplement"
        receipt = {
            "schema_version": "1.0", "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2, "purpose": purpose,
            "admission_id": manifest["admission_id"], "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"], "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("historical-owner-confirmed-continuity-supplement-receipt", receipt)
        display = {
            "schema_version": "1.0", "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "purpose": purpose,
            "manifest": manifest, "manifest_digest": manifest["manifest_digest"], "receipt": receipt,
        }
        self.schemas.require("historical-owner-confirmed-continuity-supplement-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.historical_owner_confirmed_continuity_supplement_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined("local confirmation did not match owner-context digest")
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("owner-context display changed before receipt issuance")
        confirmed_at = self.clock()
        if (
            confirmed_at.tzinfo is None
            or confirmed_at.utcoffset() is None
            or expires_at <= confirmed_at.astimezone(UTC)
        ):
            raise LocalConfirmationV2Error("owner-context confirmation expired before receipt issuance")
        record = {
            "schema_version": "1.0", "receipt_type": purpose, "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"], "algorithm": ALGORITHM, "key_id": identity.key_id,
            "receipt": receipt, "manifest": manifest, "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes), "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("historical-owner-confirmed-continuity-supplement-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.historical_owner_confirmed_continuity_supplement_receipt_root / f"{receipt['receipt_id']}.json"
            ), canonical_bytes(record)
        )
        return receipt

    def verify_historical_owner_confirmed_continuity_supplement(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return HistoricalOwnerConfirmedContinuitySupplementV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_historical_owner_confirmed_continuity_supplement_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_historical_owner_confirmed_continuity_supplement(receipt_id, manifest)
        return (
            _read_bytes(self.historical_owner_confirmed_continuity_supplement_display_root / f"{receipt_id}.json"),
            _read_bytes(self.historical_owner_confirmed_continuity_supplement_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_historical_owner_confirmed_continuity_supplement(
        self, receipt_id: str, manifest: dict[str, Any], *, display_root: Path, receipt_root: Path
    ) -> dict[str, Any]:
        return HistoricalOwnerConfirmedContinuitySupplementV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock,
            display_root=display_root, receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

    def authorize_historical_migration_amendment(
        self, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        """Sign one exact-parent, append-only historical migration amendment."""

        _require_historical_migration_amendment_manifest(manifest, self.schemas)
        now = self.clock()
        expires_at = _parse_timestamp(manifest["expires_at"])
        if now.tzinfo is None or now.utcoffset() is None or expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("historical amendment confirmation window is invalid")
        if self.chat_first_u1_save_confirmation_ui is None:
            raise LocalConfirmationV2Error("historical amendment native confirmation UI is not configured")
        identity, authority = self._signing_identity(allow_create=False)
        purpose = "historical_migration_amendment"
        receipt = {
            "schema_version": "1.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2,
            "purpose": purpose,
            "admission_id": manifest["admission_id"],
            "bundle_id": manifest["bundle_id"],
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require("historical-migration-amendment-receipt", receipt)
        display = {
            "schema_version": "1.0",
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "purpose": purpose,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        self.schemas.require("historical-migration-amendment-display", display)
        display_bytes = canonical_bytes(display)
        display_path = self.paths.ensure_runtime_write_target(
            self.historical_migration_amendment_display_root / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.chat_first_u1_save_confirmation_ui.confirm(
            display_path, expected_manifest_digest=manifest["manifest_digest"]
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match historical amendment digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error(
                "historical amendment display changed before receipt issuance"
            )
        confirmed_at = self.clock()
        if (
            confirmed_at.tzinfo is None
            or confirmed_at.utcoffset() is None
            or expires_at <= confirmed_at.astimezone(UTC)
        ):
            raise LocalConfirmationV2Error(
                "historical amendment confirmation expired before receipt issuance"
            )
        record = {
            "schema_version": "1.0",
            "receipt_type": purpose,
            "authority_id": AUTHORITY_ID_V2,
            "authority_bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("historical-migration-amendment-signed-receipt", record)
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.historical_migration_amendment_receipt_root
                / f"{receipt['receipt_id']}.json"
            ),
            canonical_bytes(record),
        )
        return receipt

    def verify_historical_migration_amendment(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> dict[str, Any]:
        return HistoricalMigrationAmendmentV2ReceiptVerifier(
            self.paths, self.authority_root, self.schemas, clock=self.clock
        ).verify(receipt_id, manifest)

    def read_historical_migration_amendment_evidence(
        self, receipt_id: str, manifest: dict[str, Any]
    ) -> tuple[bytes, bytes]:
        self.verify_historical_migration_amendment(receipt_id, manifest)
        return (
            _read_bytes(self.historical_migration_amendment_display_root / f"{receipt_id}.json"),
            _read_bytes(self.historical_migration_amendment_receipt_root / f"{receipt_id}.json"),
        )

    def verify_archived_historical_migration_amendment(
        self,
        receipt_id: str,
        manifest: dict[str, Any],
        *,
        display_root: Path,
        receipt_root: Path,
    ) -> dict[str, Any]:
        return HistoricalMigrationAmendmentV2ReceiptVerifier(
            self.paths,
            self.authority_root,
            self.schemas,
            clock=self.clock,
            display_root=display_root,
            receipt_root=receipt_root,
        ).verify_archived(receipt_id, manifest)

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

    def authorize_direct_private_snapshot(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm a synthetic direct-private pre-read scope with an existing v2 identity only."""

        return self._authorize_direct_private(manifest, "direct_private_snapshot_scope")

    def authorize_direct_private_admission(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm a synthetic direct-private admission bound to its exact snapshot result."""

        return self._authorize_direct_private(manifest, "direct_private_source_admission")

    def _authorize_direct_private(
        self, manifest: dict[str, Any], expected_purpose: str
    ) -> dict[str, Any]:
        _require_direct_private_manifest(manifest, self.schemas, expected_purpose)
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        expires_at = _parse_timestamp(manifest["expires_at"])
        if expires_at <= now.astimezone(UTC):
            raise LocalConfirmationV2Error("cannot confirm an expired direct-private manifest")
        if self.direct_private_confirmation_ui is None:
            raise LocalConfirmationV2Error("direct-private native confirmation UI is not configured")
        # Direct-private is deliberately a side-purpose: it can never bootstrap, rotate, or
        # rewrite the v2 identity. A missing identity leaves later source work unavailable.
        identity, authority = self._signing_identity(allow_create=False)
        subject_id = (
            manifest["snapshot_id"]
            if expected_purpose == "direct_private_snapshot_scope"
            else manifest["admission_id"]
        )
        receipt = {
            "schema_version": "2.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID_V2,
            "purpose": expected_purpose,
            "subject_id": subject_id,
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        receipt_schema = (
            "direct-private-snapshot-receipt"
            if expected_purpose == "direct_private_snapshot_scope"
            else "direct-private-admission-receipt"
        )
        self.schemas.require(receipt_schema, receipt, schema_version="2.0")
        display = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "purpose": expected_purpose,
            "synthetic_only": manifest["synthetic_only"],
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        self.schemas.require("direct-private-display", display, schema_version="2.0")
        display_bytes = canonical_bytes(display)
        display_digest = sha256_hex(display_bytes)
        display_path = self.paths.ensure_runtime_write_target(
            self.direct_private_display_root(expected_purpose) / f"{receipt['receipt_id']}.json"
        )
        _write_immutable(display_path, display_bytes)
        response = self.direct_private_confirmation_ui.confirm(
            display_path,
            purpose=expected_purpose,
            expected_manifest_digest=manifest["manifest_digest"],
        )
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise LocalConfirmationV2Declined(
                "local confirmation did not match the exact direct-private manifest digest"
            )
        if _read_bytes(display_path) != display_bytes:
            raise LocalConfirmationV2Error("direct-private display changed before receipt issuance")
        confirmed_at = self.clock()
        if confirmed_at.tzinfo is None or confirmed_at.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware instant")
        if expires_at <= confirmed_at.astimezone(UTC):
            raise LocalConfirmationV2Error("direct-private confirmation expired before receipt issuance")
        record = {
            "schema_version": "2.0",
            "receipt_type": "direct_private",
            "authority_id": AUTHORITY_ID_V2,
            "bundle_id": authority["bundle_id"],
            "algorithm": ALGORITHM,
            "key_id": identity.key_id,
            "purpose": expected_purpose,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": display_digest,
            "confirmed_at": timestamp(confirmed_at),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            identity.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("direct-private-signed-receipt", record, schema_version="2.0")
        _write_immutable(
            self.paths.ensure_runtime_write_target(
                self.direct_private_receipt_root(expected_purpose) / f"{receipt['receipt_id']}.json"
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


class DirectPrivateV2ReceiptVerifier:
    """Replay-verify only v2-signed direct-private receipts in their exact purpose domain."""

    def __init__(
        self,
        paths: RuntimePaths,
        authority_root: Path,
        schemas: SchemaRegistry,
        *,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.paths = paths
        self.authority_root = authority_root.resolve()
        self.schemas = schemas
        self.clock = clock

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    def receipt_root(self, purpose: str) -> Path:
        _require_direct_private_purpose(purpose)
        return self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose / "receipts"

    def display_root(self, purpose: str) -> Path:
        _require_direct_private_purpose(purpose)
        return self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose / "displays"

    def verify(
        self,
        receipt_id: str,
        *,
        purpose: str,
        manifest_digest: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return only an unexpired receipt and manifest with exact v2 bindings."""

        _require_direct_private_purpose(purpose)
        try:
            authority = _load_record(
                self.authority_path,
                self.schemas,
                "local-confirmation-v2-authority",
                schema_version="2.0",
            )
            record = _load_record(
                self.receipt_root(purpose) / f"{receipt_id}.json",
                self.schemas,
                "direct-private-signed-receipt",
                schema_version="2.0",
            )
            manifest = record["manifest"]
            _require_direct_private_manifest(manifest, self.schemas, purpose)
            receipt = record["receipt"]
            receipt_schema = (
                "direct-private-snapshot-receipt"
                if purpose == "direct_private_snapshot_scope"
                else "direct-private-admission-receipt"
            )
            self.schemas.require(receipt_schema, receipt, schema_version="2.0")
            display_bytes = _read_bytes(self.display_root(purpose) / f"{receipt_id}.json")
            subject_id = (
                manifest["snapshot_id"]
                if purpose == "direct_private_snapshot_scope"
                else manifest["admission_id"]
            )
            if any(
                (
                    authority["status"] != "active",
                    authority["authority_id"] != AUTHORITY_ID_V2,
                    authority["algorithm"] != ALGORITHM,
                    authority["bundle_id"] != record["bundle_id"],
                    authority["key_id"] != record["key_id"],
                    record["receipt_type"] != "direct_private",
                    record["authority_id"] != AUTHORITY_ID_V2,
                    record["purpose"] != purpose,
                    record["manifest_digest"] != manifest_digest,
                    record["manifest_digest"] != manifest["manifest_digest"],
                    record["receipt"] != receipt,
                    receipt["receipt_id"] != receipt_id,
                    receipt["authority_id"] != AUTHORITY_ID_V2,
                    receipt["purpose"] != purpose,
                    receipt["subject_id"] != subject_id,
                    receipt["manifest_digest"] != manifest_digest,
                    receipt["expires_at"] != manifest["expires_at"],
                    record["confirmation_display_sha256"] != sha256_hex(display_bytes),
                )
            ):
                raise LocalConfirmationV2Error("direct-private receipt binding is invalid")
            public_bytes = base64.b64decode(authority["public_key_base64"], validate=True)
            signature = base64.b64decode(record["signature_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature, canonical_bytes(_signature_material(record))
            )
            now = self.clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("clock must return a timezone-aware instant")
            if _parse_timestamp(receipt["expires_at"]) <= now.astimezone(UTC):
                raise LocalConfirmationV2Error("direct-private receipt is expired")
        except (
            InvalidSignature,
            KeyError,
            TypeError,
            ValidationError,
            ValueError,
            OSError,
            LocalConfirmationV2Error,
        ) as exc:
            raise LocalConfirmationV2Error("direct-private receipt did not verify") from exc
        return receipt, manifest


class ChatFirstU1SaveV2ReceiptVerifier:
    """Replay-verify only v2-signed receipts for one Chat-first U1 save manifest."""

    purpose = "chat_first_u1_save"
    manifest_schema = "chat-first-u1-save-manifest"
    receipt_schema = "chat-first-u1-save-receipt"
    signed_schema = "chat-first-u1-save-signed-receipt"
    receipt_directory = "chat-first-u1-save"

    def __init__(
        self,
        paths: RuntimePaths,
        authority_root: Path,
        schemas: SchemaRegistry,
        *,
        clock: Callable[[], datetime] = aware_utc_now,
        display_root: Path | None = None,
        receipt_root: Path | None = None,
    ) -> None:
        self.paths = paths
        self.authority_root = authority_root.resolve()
        self.schemas = schemas
        self.clock = clock
        self._display_root = display_root
        self._receipt_root = receipt_root

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "local-confirmation-v2.authority.json"

    @property
    def receipt_root(self) -> Path:
        if self._receipt_root is not None:
            return self._receipt_root
        return self.paths.evidence_root / "local-confirmation-v2" / self.receipt_directory / "receipts"

    @property
    def display_root(self) -> Path:
        if self._display_root is not None:
            return self._display_root
        return self.paths.evidence_root / "local-confirmation-v2" / self.receipt_directory / "displays"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_chat_first_u1_save_manifest(manifest, self.schemas)

    def verify(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """Return only an unexpired receipt bound to the exact displayed proposal."""

        return self._verify(receipt_id, manifest, archived=False)

    def verify_archived(self, receipt_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """Verify committed archival evidence after its authorization window has elapsed.

        Expiry limits when a receipt may authorize publication.  Once the exact evidence is bound by
        a canonical event, later recovery instead proves that issuance and confirmation happened
        inside that window.  Signature, display, authority and manifest checks remain identical.
        """

        return self._verify(receipt_id, manifest, archived=True)

    def _verify(
        self, receipt_id: str, manifest: dict[str, Any], *, archived: bool
    ) -> dict[str, Any]:
        """Verify shared bindings and apply live or archival time semantics."""

        self.require_manifest(manifest)
        try:
            authority = _load_record(
                self.authority_path,
                self.schemas,
                "local-confirmation-v2-authority",
                schema_version="2.0",
            )
            record = _load_record(
                self.receipt_root / f"{receipt_id}.json",
                self.schemas,
                self.signed_schema,
                schema_version="1.0",
            )
            receipt = record["receipt"]
            self.schemas.require(self.receipt_schema, receipt)
            stored_manifest = record["manifest"]
            self.require_manifest(stored_manifest)
            display_bytes = _read_bytes(self.display_root / f"{receipt_id}.json")
            if any(
                (
                    authority["status"] != "active",
                    authority["authority_id"] != AUTHORITY_ID_V2,
                    authority["algorithm"] != ALGORITHM,
                    authority["bundle_id"] != record["authority_bundle_id"],
                    authority["key_id"] != record["key_id"],
                    record["receipt_type"] != self.purpose,
                    record["authority_id"] != AUTHORITY_ID_V2,
                    record["manifest"] != manifest,
                    record["manifest_digest"] != manifest["manifest_digest"],
                    stored_manifest["manifest_digest"] != manifest["manifest_digest"],
                    receipt["receipt_id"] != receipt_id,
                    receipt["authority_id"] != AUTHORITY_ID_V2,
                    receipt["purpose"] != self.purpose,
                    receipt["admission_id"] != manifest["admission_id"],
                    receipt["bundle_id"] != manifest["bundle_id"],
                    receipt["manifest_digest"] != manifest["manifest_digest"],
                    receipt["expires_at"] != manifest["expires_at"],
                    record["confirmation_display_sha256"] != sha256_hex(display_bytes),
                )
            ):
                raise LocalConfirmationV2Error("Chat-first U1 receipt binding is invalid")
            public_bytes = base64.b64decode(authority["public_key_base64"], validate=True)
            signature = base64.b64decode(record["signature_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature, canonical_bytes(_signature_material(record))
            )
            now = self.clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("clock must return a timezone-aware instant")
            current = now.astimezone(UTC)
            issued_at = _parse_timestamp(receipt["issued_at"])
            confirmed_at = _parse_timestamp(record["confirmed_at"])
            expires_at = _parse_timestamp(receipt["expires_at"])
            if issued_at > current or confirmed_at > current:
                raise LocalConfirmationV2Error("Chat-first U1 receipt is future-issued")
            if confirmed_at < issued_at:
                raise LocalConfirmationV2Error("Chat-first U1 confirmation predates receipt issuance")
            if issued_at >= expires_at or confirmed_at >= expires_at:
                raise LocalConfirmationV2Error("Chat-first U1 receipt was issued outside its window")
            if not archived and expires_at <= current:
                raise LocalConfirmationV2Error("Chat-first U1 receipt is expired")
        except (
            InvalidSignature,
            KeyError,
            TypeError,
            ValidationError,
            ValueError,
            OSError,
            LocalConfirmationV2Error,
        ) as exc:
            raise LocalConfirmationV2Error("Chat-first U1 receipt did not verify") from exc
        return receipt


class ChatFirstU1MultiSourceSaveV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify only the separately purpose-bound ordered multi-source U1 receipts."""

    purpose = "chat_first_u1_multi_source_save"
    manifest_schema = "chat-first-u1-multi-source-save-manifest"
    receipt_schema = "chat-first-u1-multi-source-save-receipt"
    signed_schema = "chat-first-u1-multi-source-save-signed-receipt"
    receipt_directory = "chat-first-u1-multi-source-save"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_chat_first_u1_multi_source_save_manifest(manifest, self.schemas)


class ChatFirstU1MultiSourceKnowledgeSaveV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify only the separately purpose-bound knowledge-lineage U1 receipts."""

    purpose = "chat_first_u1_multi_source_knowledge_save"
    manifest_schema = "chat-first-u1-multi-source-knowledge-save-manifest"
    receipt_schema = "chat-first-u1-multi-source-knowledge-save-receipt"
    signed_schema = "chat-first-u1-multi-source-knowledge-save-signed-receipt"
    receipt_directory = "chat-first-u1-multi-source-knowledge-save"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_chat_first_u1_multi_source_knowledge_save_manifest(manifest, self.schemas)


class ChatFirstU1CitationRecoveryV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify only append-only citation-recovery U1 receipts."""

    purpose = "chat_first_u1_citation_recovery"
    manifest_schema = "chat-first-u1-citation-recovery-manifest"
    receipt_schema = "chat-first-u1-citation-recovery-receipt"
    signed_schema = "chat-first-u1-citation-recovery-signed-receipt"
    receipt_directory = "chat-first-u1-citation-recovery"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_chat_first_u1_citation_recovery_manifest(manifest, self.schemas)


class ChatFirstU1PrimaryArtifactRetrofitV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify only the purpose-separated three-wave presentation retrofit."""

    purpose = "chat_first_u1_primary_artifact_retrofit"
    manifest_schema = "chat-first-u1-primary-artifact-retrofit-manifest"
    receipt_schema = "chat-first-u1-primary-artifact-retrofit-receipt"
    signed_schema = "chat-first-u1-primary-artifact-retrofit-signed-receipt"
    receipt_directory = "chat-first-u1-primary-artifact-retrofit"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_chat_first_u1_primary_artifact_retrofit_manifest(manifest, self.schemas)


class ArchivePreservationV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify only local-only opaque archive-preservation receipts."""

    purpose = "archive_preservation"
    manifest_schema = "archive-preservation-manifest"
    receipt_schema = "archive-preservation-receipt"
    signed_schema = "archive-preservation-signed-receipt"
    receipt_directory = "archive-preservation"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_archive_preservation_manifest(manifest, self.schemas)


class HistoricalActivityReconstructionV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify candidate-only historical cohort receipts."""

    purpose = "historical_activity_reconstruction"
    manifest_schema = "historical-activity-reconstruction-manifest"
    receipt_schema = "historical-activity-reconstruction-receipt"
    signed_schema = "historical-activity-reconstruction-signed-receipt"
    receipt_directory = "historical-activity-reconstruction"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_historical_activity_reconstruction_manifest(manifest, self.schemas)


class HistoricalWeeklyActivityReconstructionV2ReceiptVerifier(
    ChatFirstU1SaveV2ReceiptVerifier
):
    """Replay-verify only additive multi-parent historical weekly receipts."""

    purpose = "historical_weekly_activity_reconstruction"
    manifest_schema = "historical-weekly-activity-reconstruction-manifest"
    receipt_schema = "historical-weekly-activity-reconstruction-receipt"
    signed_schema = "historical-weekly-activity-reconstruction-signed-receipt"
    receipt_directory = "historical-weekly-activity-reconstruction"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_historical_weekly_activity_reconstruction_manifest(manifest, self.schemas)


class HistoricalOwnerConfirmedContinuitySupplementV2ReceiptVerifier(
    ChatFirstU1SaveV2ReceiptVerifier
):
    """Replay-verify only append-only owner-confirmed historical context evidence."""

    purpose = "historical_owner_confirmed_continuity_supplement"
    manifest_schema = "historical-owner-confirmed-continuity-supplement-manifest"
    receipt_schema = "historical-owner-confirmed-continuity-supplement-receipt"
    signed_schema = "historical-owner-confirmed-continuity-supplement-signed-receipt"
    receipt_directory = "historical-owner-confirmed-continuity-supplement"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_historical_owner_confirmed_continuity_supplement_manifest(manifest, self.schemas)


class HistoricalMigrationAmendmentV2ReceiptVerifier(ChatFirstU1SaveV2ReceiptVerifier):
    """Replay-verify exact-parent append-only historical amendment receipts."""

    purpose = "historical_migration_amendment"
    manifest_schema = "historical-migration-amendment-manifest"
    receipt_schema = "historical-migration-amendment-receipt"
    signed_schema = "historical-migration-amendment-signed-receipt"
    receipt_directory = "historical-migration-amendment"

    def require_manifest(self, manifest: dict[str, Any]) -> None:
        _require_historical_migration_amendment_manifest(manifest, self.schemas)


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


def _require_chat_first_u1_save_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the ordinary U1 save contract independently of every other v2 purpose."""

    schemas.require("chat-first-u1-save-manifest", manifest)
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("Chat-first U1 manifest digest is invalid")
    if manifest["purpose"] != "chat_first_u1_save" or manifest["authority_id"] != AUTHORITY_ID_V2:
        raise LocalConfirmationV2Error("Chat-first U1 manifest is outside its purpose boundary")


def _require_chat_first_u1_multi_source_save_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the ordered multi-source U1 contract independently of ordinary one-source U1."""

    schemas.require("chat-first-u1-multi-source-save-manifest", manifest)
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("multi-source Chat-first U1 manifest digest is invalid")
    if (
        manifest["purpose"] != "chat_first_u1_multi_source_save"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or tuple(item["role"] for item in manifest["source_items"]) != ("M1", "W1", "W2", "W3")
        or canonical_sha256(manifest["source_items"]) != manifest["ingress_set_sha256"]
    ):
        raise LocalConfirmationV2Error("multi-source Chat-first U1 manifest is outside its purpose boundary")


def _require_chat_first_u1_multi_source_knowledge_save_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate knowledge-lineage U1 without widening one-source or work-continuity U1."""

    schemas.require("chat-first-u1-multi-source-knowledge-save-manifest", manifest)
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("knowledge multi-source Chat-first U1 manifest digest is invalid")
    if (
        manifest["purpose"] != "chat_first_u1_multi_source_knowledge_save"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or tuple(item["role"] for item in manifest["source_items"]) != ("K1", "K2", "K3", "K4")
        or canonical_sha256(manifest["source_items"]) != manifest["ingress_set_sha256"]
    ):
        raise LocalConfirmationV2Error("knowledge multi-source Chat-first U1 manifest is outside its purpose boundary")


def _require_chat_first_u1_citation_recovery_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the recovery purpose without widening either existing U1 purpose."""

    schemas.require("chat-first-u1-citation-recovery-manifest", manifest)
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("citation-recovery U1 manifest digest is invalid")
    if (
        manifest["purpose"] != "chat_first_u1_citation_recovery"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or tuple(item["role"] for item in manifest["source_items"]) != ("M1", "W1", "W2", "W3")
        or manifest["recovered_claim_count"] + manifest["withheld_claim_count"]
        != manifest["claim_count"]
    ):
        raise LocalConfirmationV2Error("citation-recovery U1 manifest is outside its purpose boundary")


def _require_chat_first_u1_primary_artifact_retrofit_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the new retrofit purpose without widening an existing U1 contract."""

    schemas.require("chat-first-u1-primary-artifact-retrofit-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("primary-artifact retrofit manifest digest changed")
    retrofits = manifest["retrofits"]
    if (
        manifest["purpose"] != "chat_first_u1_primary_artifact_retrofit"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or tuple(item["wave_id"] for item in retrofits) != ("S6-W1", "S6-W2", "S6-W3")
        or bool(retrofits[0]["support_event_ids"])
        or len(retrofits[1]["support_event_ids"]) != 1
        or bool(retrofits[2]["support_event_ids"])
    ):
        raise LocalConfirmationV2Error("primary-artifact retrofit is outside its purpose boundary")


def _require_archive_preservation_manifest(manifest: dict[str, Any], schemas: SchemaRegistry) -> None:
    """Validate the purpose without allowing content-index or semantic-migration scope."""

    schemas.require("archive-preservation-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("archive preservation manifest digest changed")
    if (
        manifest["purpose"] != "archive_preservation"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or manifest["disclosure"] != "local_only_no_content_index"
        or manifest["retention"] != "append_only_archive_preservation"
        or "build_metadata_catalogue" not in manifest["operations"]
    ):
        raise LocalConfirmationV2Error("archive preservation is outside its purpose boundary")


def _require_historical_activity_reconstruction_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the candidate-only historical migration purpose without current-state authority."""

    schemas.require("historical-activity-reconstruction-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("historical activity manifest digest changed")
    if (
        manifest["purpose"] != "historical_activity_reconstruction"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or manifest["family"] != "meeting_workstream_history"
        or manifest["candidate_only"] is not True
        or manifest["disclosure"]
        != "hybrid_visible_hosted_exact_packs_local_private_storage"
        or manifest["operations"]
        != [
            "append_candidate_historical_activity",
            "build_candidate_fts5",
            "build_historical_activity_views",
        ]
    ):
        raise LocalConfirmationV2Error("historical activity is outside its purpose boundary")


def _require_historical_weekly_activity_reconstruction_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Validate the additive multi-parent weekly purpose without changing older H2."""

    schemas.require("historical-weekly-activity-reconstruction-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("historical weekly manifest digest changed")
    if (
        manifest["purpose"] != "historical_weekly_activity_reconstruction"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or manifest["family"] != "meeting_workstream_history"
        or manifest["candidate_only"] is not True
        or manifest["disclosure"]
        != "hybrid_visible_hosted_exact_packs_local_private_storage"
        or manifest["operations"]
        != [
            "append_candidate_historical_weekly_activity",
            "build_candidate_weekly_fts5",
            "build_historical_weekly_views",
        ]
        or len(manifest["parent_bindings"]) < 2
        or manifest["parent_set_digest"] != canonical_sha256(manifest["parent_bindings"])
        or manifest["catalogue_set_digest"]
        != canonical_sha256(
            [binding.get("catalogue_digest") for binding in manifest["parent_bindings"]]
        )
    ):
        raise LocalConfirmationV2Error("historical weekly activity is outside its purpose boundary")


def _require_historical_owner_confirmed_continuity_supplement_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Keep owner-context statements separate from every source-extracted history purpose."""

    schemas.require("historical-owner-confirmed-continuity-supplement-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("owner-context manifest digest changed")
    if (
        manifest["purpose"] != "historical_owner_confirmed_continuity_supplement"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or manifest["disclosure"]
        != "local_private_owner_confirmed_context_fixed_admitted_scope"
        or manifest["retention"] != "append_only_owner_confirmed_historical_context"
        or manifest["operations"]
        != [
            "stage_owner_confirmed_continuity_supplement",
            "append_owner_confirmed_continuity_event",
            "build_owner_context_fts5",
            "build_owner_context_workspace",
        ]
        or manifest["candidate_only"] is not True
        or manifest["no_current_work_adoption"] is not True
        or len(manifest["parent_bindings"]) != 4
        or len(manifest["owner_context_statements"]) != 4
        or manifest["statement_ids"]
        != [item.get("statement_id") for item in manifest["owner_context_statements"]]
        or manifest["parent_set_digest"] != canonical_sha256(manifest["parent_bindings"])
    ):
        raise LocalConfirmationV2Error("owner-context supplement is outside its purpose boundary")


def _require_historical_migration_amendment_manifest(
    manifest: dict[str, Any], schemas: SchemaRegistry
) -> None:
    """Keep migration corrections parent-bound, candidate-only, and append-only."""

    schemas.require("historical-migration-amendment-manifest", manifest)
    material = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if manifest["manifest_digest"] != canonical_sha256(material):
        raise LocalConfirmationV2Error("historical amendment manifest digest changed")
    if (
        manifest["purpose"] != "historical_migration_amendment"
        or manifest["authority_id"] != AUTHORITY_ID_V2
        or manifest["disclosure"]
        != "local_private_exact_parent_append_only_amendment"
        or manifest["retention"] != "append_only_historical_migration_amendment"
        or manifest["operations"]
        != [
            "append_historical_migration_amendment",
            "build_amendment_fts5",
            "build_amendment_workspace",
        ]
        or manifest["candidate_only"] is not True
        or manifest["no_current_work"] is not True
        or len(manifest["entry_ids"]) != 3
        or len(set(manifest["entry_ids"])) != 3
    ):
        raise LocalConfirmationV2Error("historical amendment is outside its purpose boundary")


def _require_direct_private_purpose(purpose: str) -> None:
    if purpose not in {"direct_private_snapshot_scope", "direct_private_source_admission"}:
        raise LocalConfirmationV2Error("direct-private receipt purpose is unsupported")


def _require_direct_private_manifest(
    manifest: dict[str, Any],
    schemas: SchemaRegistry,
    expected_purpose: str,
) -> None:
    """Validate the B1 fixture-only contract without a real-path fallback."""

    _require_direct_private_purpose(expected_purpose)
    schema = (
        "direct-private-snapshot-manifest"
        if expected_purpose == "direct_private_snapshot_scope"
        else "direct-private-admission-manifest"
    )
    schemas.require(schema, manifest, schema_version="2.0")
    if manifest["purpose"] != expected_purpose or manifest["synthetic_only"] is not True:
        raise LocalConfirmationV2Error("direct-private manifest purpose is invalid")
    expected_digest = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if not hmac.compare_digest(manifest["manifest_digest"], expected_digest):
        raise LocalConfirmationV2Error("direct-private manifest digest is invalid")


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
