"""B1 adapter from synthetic direct-private contracts to an injected existing v2 authority.

This module never discovers a Keychain identity, source root, or private bundle.  It composes a
caller-supplied DurableLocalAuthority, whose direct-private methods require an already-existing
v2 identity, so tests can exercise the exact receipt boundary with disposable doubles only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import stat
from typing import Any, Callable

from vault_next.direct_private import (
    DirectPrivateAuthority,
    DirectPrivateDeclined,
    DirectPrivateError,
    DirectPrivateReceiptVerifierProtocol,
)
from vault_next.local_confirmation_v2 import (
    DirectPrivateV2ReceiptVerifier,
    DurableLocalAuthority,
    LocalConfirmationV2Declined,
    LocalConfirmationV2Error,
)
from vault_next.records import SchemaRegistry, aware_utc_now


@dataclass(frozen=True)
class V2DirectPrivateAuthority(DirectPrivateAuthority):
    """Expose only the two direct-private purposes of a supplied existing v2 authority."""

    authority: DurableLocalAuthority

    def authorize_snapshot(self, manifest: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.authority.authorize_direct_private_snapshot(manifest)
        except LocalConfirmationV2Declined as exc:
            raise DirectPrivateDeclined("direct-private snapshot confirmation was declined") from exc
        except LocalConfirmationV2Error as exc:
            raise DirectPrivateError("direct-private v2 snapshot authority is unavailable") from exc

    def authorize_admission(self, manifest: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.authority.authorize_direct_private_admission(manifest)
        except LocalConfirmationV2Declined as exc:
            raise DirectPrivateDeclined("direct-private admission confirmation was declined") from exc
        except LocalConfirmationV2Error as exc:
            raise DirectPrivateError("direct-private v2 admission authority is unavailable") from exc

    def receipt_verifier(
        self,
        paths: Any,
        schemas: SchemaRegistry,
        clock: Callable[[], datetime],
    ) -> DirectPrivateReceiptVerifierProtocol:
        return V2DirectPrivateReceiptVerifier(
            paths,
            self.authority.authority_root,
            schemas,
            clock=clock,
        )


@dataclass(frozen=True)
class V2DirectPrivateReceiptVerifier(DirectPrivateReceiptVerifierProtocol):
    """Translate v2 receipt failures into the narrow direct-private error domain."""

    paths: Any
    authority_root: Any
    schemas: SchemaRegistry
    clock: Callable[[], datetime] = aware_utc_now

    def verify(
        self,
        receipt_id: str,
        *,
        purpose: str,
        manifest_digest: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            return DirectPrivateV2ReceiptVerifier(
                self.paths,
                self.authority_root,
                self.schemas,
                clock=self.clock,
            ).verify(
                receipt_id,
                purpose=purpose,
                manifest_digest=manifest_digest,
            )
        except LocalConfirmationV2Error as exc:
            raise DirectPrivateError("direct-private v2 receipt is unavailable or invalid") from exc


def validate_direct_private_bundle_layout(
    bundle_root: Path,
    staging_root: Path,
    authority_root: Path,
    *,
    excluded_roots: tuple[Path, ...] = (),
    stat_fn: Callable[[Path], os.stat_result] = os.stat,
) -> None:
    """Validate only destination boundaries; it creates nothing and never touches a source root.

    A later real snapshot may compare an already-receipt-authorized source descriptor identity to
    these validated destination identities.  That source check is intentionally absent from B1.
    """

    bundle = _owner_only_directory(bundle_root, "private bundle", stat_fn)
    staging = _owner_only_directory(staging_root, "derived staging", stat_fn)
    authority = _owner_only_directory(authority_root, "v2 authority root", stat_fn)
    expected_staging = (bundle / "data" / "staging" / "migrations").resolve(strict=True)
    if staging != expected_staging:
        raise DirectPrivateError("direct-private staging root is not the derived bundle location")
    if stat_fn(bundle).st_dev != stat_fn(staging).st_dev:
        raise DirectPrivateError("direct-private staging is not on the private bundle filesystem")
    _require_disjoint(bundle, authority, "private bundle overlaps the v2 authority root")
    for excluded in excluded_roots:
        if not excluded.is_absolute():
            raise DirectPrivateError("direct-private excluded root is not absolute")
        _require_disjoint(
            bundle,
            excluded.resolve(strict=False),
            "private bundle overlaps an excluded root",
        )
        _require_disjoint(
            staging,
            excluded.resolve(strict=False),
            "direct-private staging overlaps an excluded root",
        )


def _owner_only_directory(
    path: Path,
    label: str,
    stat_fn: Callable[[Path], os.stat_result],
) -> Path:
    if not path.is_absolute():
        raise DirectPrivateError(f"{label} is not absolute")
    _require_no_symlink_components(path, label)
    try:
        resolved = path.resolve(strict=True)
        details = stat_fn(resolved)
    except OSError as exc:
        raise DirectPrivateError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(details.st_mode):
        raise DirectPrivateError(f"{label} is not a directory")
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
        raise DirectPrivateError(f"{label} is not owner-only")
    return resolved


def _require_no_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise DirectPrivateError(f"{label} contains a symlink")


def _require_disjoint(first: Path, second: Path, message: str) -> None:
    try:
        first.relative_to(second)
    except ValueError:
        try:
            second.relative_to(first)
        except ValueError:
            return
    raise DirectPrivateError(message)
