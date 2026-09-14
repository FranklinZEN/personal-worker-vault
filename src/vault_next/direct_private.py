"""Synthetic-only S5-DP direct-private admission rehearsal.

This module deliberately accepts only coordinator-created, invented fixtures.  It is not a
real-vault reader, a durable-local-authority integration, or a generic filesystem API.  The
purpose is to prove the contracts and crash boundaries with disposable roots before a separately
authorized real-run design supplies any real source capability.
"""

from __future__ import annotations

import base64
import codecs
import copy
import hmac
import json
import os
import shutil
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.ledger import SemanticLedger
from vault_next.records import RUNTIME_ACTOR, SchemaRegistry, aware_utc_now, build_event, timestamp
from vault_next.runtime import CaseSessionRuntime

COMPONENT_ID = "vault-next-direct-private-admission"
COMPONENT_VERSION = "0.1.0"
AUTHORITY_ID = "vault-next-local-confirmation/v2"
EXTRACTOR_VERSION = "utf8-structure-v1"
INDEX_VERSION = "fts5-v1"
_MAX_CHUNK_BYTES = 4_096
_SYNTHETIC_MARKER = b"VAULT_NEXT_SYNTHETIC_FIXTURE\n"


class DirectPrivateError(RuntimeError):
    """A direct-private synthetic operation could not safely complete."""


class DirectPrivateDeclined(DirectPrivateError):
    """The exact-digest confirmation was declined, replaced, or expired."""


class DirectPrivateConfirmationUI(Protocol):
    """Small exact-digest display boundary used only by the synthetic proof."""

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str: ...


class DirectPrivateReceiptVerifierProtocol(Protocol):
    """Replay verifier shared by isolated synthetic and later v2-backed authorities."""

    def verify(
        self,
        receipt_id: str,
        *,
        purpose: str,
        manifest_digest: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...


class DirectPrivateAuthority(Protocol):
    """Purpose-limited authority interface; it deliberately has no generic signing method."""

    def authorize_snapshot(self, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def authorize_admission(self, manifest: dict[str, Any]) -> dict[str, Any]: ...

    def receipt_verifier(
        self,
        paths: Any,
        schemas: SchemaRegistry,
        clock: Callable[[], datetime],
    ) -> DirectPrivateReceiptVerifierProtocol: ...


@dataclass(frozen=True)
class SyntheticDirectPrivateFixture:
    """One coordinator-created invented Markdown source outside the disposable runtime."""

    fixture_id: str
    root: Path
    relative_path: str
    safe_label: str
    locator_sha256: str


@dataclass(frozen=True)
class SyntheticDirectPrivateAuthority:
    """Disposable Ed25519 signer used only by hostile synthetic tests.

    It shares the future v2 authority identifier in order to exercise receipt domain separation,
    but creates no Keychain item and never reads the durable v2 authority root.
    """

    paths: Any
    authority_root: Path
    schemas: SchemaRegistry
    confirmation_ui: DirectPrivateConfirmationUI
    id_factory: ULIDFactory = field(default_factory=lambda: DEFAULT_FACTORY)
    clock: Callable[[], datetime] = aware_utc_now
    private_key: Ed25519PrivateKey | None = None

    def __post_init__(self) -> None:
        if not self.authority_root.is_absolute():
            raise DirectPrivateError("synthetic authority root must be absolute")
        if _lexically_overlaps(self.authority_root, self.paths.root):
            raise DirectPrivateError("synthetic authority root must be separate from runtime")
        self.authority_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = self.private_key or Ed25519PrivateKey.generate()
        object.__setattr__(self, "private_key", key)
        raw_public = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        record = {
            "schema_version": "synthetic-0.1",
            "authority_id": AUTHORITY_ID,
            "bundle_id": self.id_factory.new("bundle"),
            "algorithm": "ed25519",
            "key_id": sha256_hex(raw_public),
            "public_key_base64": base64.b64encode(raw_public).decode("ascii"),
            "test_only": True,
        }
        path = self.authority_root / "direct-private-synthetic-authority.json"
        _write_immutable(path, canonical_bytes(record))

    @property
    def authority_path(self) -> Path:
        return self.authority_root / "direct-private-synthetic-authority.json"

    def authorize_snapshot(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm and sign exactly one synthetic snapshot scope."""

        return self._authorize(manifest, "direct_private_snapshot_scope")

    def authorize_admission(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Confirm and sign exactly one synthetic direct-private admission scope."""

        return self._authorize(manifest, "direct_private_source_admission")

    def _authorize(self, manifest: dict[str, Any], purpose: str) -> dict[str, Any]:
        schema = (
            "direct-private-snapshot-manifest"
            if purpose == "direct_private_snapshot_scope"
            else "direct-private-admission-manifest"
        )
        receipt_schema = (
            "direct-private-snapshot-receipt"
            if purpose == "direct_private_snapshot_scope"
            else "direct-private-admission-receipt"
        )
        self.schemas.require(schema, manifest, schema_version="2.0")
        _require_manifest_digest(manifest)
        now = _aware(self.clock())
        if _parse_timestamp(manifest["expires_at"]) <= now:
            raise DirectPrivateDeclined("direct-private scope is expired")
        subject_id = manifest["snapshot_id"] if purpose.endswith("snapshot_scope") else manifest["admission_id"]
        receipt = {
            "schema_version": "2.0",
            "receipt_id": self.id_factory.new("receipt"),
            "authority_id": AUTHORITY_ID,
            "purpose": purpose,
            "subject_id": subject_id,
            "manifest_digest": manifest["manifest_digest"],
            "issued_at": timestamp(now),
            "expires_at": manifest["expires_at"],
        }
        self.schemas.require(receipt_schema, receipt, schema_version="2.0")
        authority = _read_json(self.authority_path)
        display = {
            "schema_version": "2.0",
            "authority_id": AUTHORITY_ID,
            "bundle_id": authority["bundle_id"],
            "synthetic_only": True,
            "purpose": purpose,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "receipt": receipt,
        }
        display_bytes = canonical_bytes(display)
        display_path = self._display_path(purpose, receipt["receipt_id"])
        _write_immutable(display_path, display_bytes)
        response = self.confirmation_ui.confirm(display_path, manifest["manifest_digest"])
        if not hmac.compare_digest(response, manifest["manifest_digest"]):
            raise DirectPrivateDeclined("exact synthetic direct-private confirmation was declined")
        if _read_bytes(display_path) != display_bytes:
            raise DirectPrivateError("direct-private confirmation display changed")
        assert self.private_key is not None
        record = {
            "schema_version": "2.0",
            "receipt_type": "direct_private",
            "authority_id": AUTHORITY_ID,
            "bundle_id": authority["bundle_id"],
            "algorithm": "ed25519",
            "key_id": authority["key_id"],
            "purpose": purpose,
            "receipt": receipt,
            "manifest": manifest,
            "manifest_digest": manifest["manifest_digest"],
            "confirmation_display_sha256": sha256_hex(display_bytes),
            "confirmed_at": timestamp(now),
            "signature_base64": "pending",
        }
        record["signature_base64"] = base64.b64encode(
            self.private_key.sign(canonical_bytes(_signature_material(record)))
        ).decode("ascii")
        self.schemas.require("direct-private-signed-receipt", record, schema_version="2.0")
        _write_immutable(self._receipt_path(purpose, receipt["receipt_id"]), canonical_bytes(record))
        return receipt

    def _display_path(self, purpose: str, receipt_id: str) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose
            / "displays" / f"{receipt_id}.json"
        )

    def _receipt_path(self, purpose: str, receipt_id: str) -> Path:
        return self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose
            / "receipts" / f"{receipt_id}.json"
        )

    def receipt_verifier(
        self,
        paths: Any,
        schemas: SchemaRegistry,
        clock: Callable[[], datetime],
    ) -> DirectPrivateReceiptVerifierProtocol:
        """Return only the synthetic verifier bound to this disposable authority root."""

        return DirectPrivateReceiptVerifier(paths, self.authority_root, schemas, clock)


@dataclass(frozen=True)
class DirectPrivateReceiptVerifier:
    """Replay verifier for the disposable synthetic signer only."""

    paths: Any
    authority_root: Path
    schemas: SchemaRegistry
    clock: Callable[[], datetime] = aware_utc_now

    def verify(
        self,
        receipt_id: str,
        *,
        purpose: str,
        manifest_digest: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load an exact signed receipt and its manifest without a durable authority fallback."""

        if purpose not in {"direct_private_snapshot_scope", "direct_private_source_admission"}:
            raise DirectPrivateError("direct-private receipt purpose is unsupported")
        path = self.paths.evidence_root / "local-confirmation-v2" / "direct-private" / purpose
        receipt_path = path / "receipts" / f"{receipt_id}.json"
        display_path = path / "displays" / f"{receipt_id}.json"
        try:
            record = _read_json(receipt_path)
            display_bytes = _read_bytes(display_path)
            authority = _read_json(self.authority_root / "direct-private-synthetic-authority.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise DirectPrivateError("direct-private receipt is unavailable") from exc
        self.schemas.require("direct-private-signed-receipt", record, schema_version="2.0")
        if (
            record["authority_id"] != AUTHORITY_ID
            or record["purpose"] != purpose
            or record["manifest_digest"] != manifest_digest
            or record["receipt"].get("receipt_id") != receipt_id
            or record["key_id"] != authority.get("key_id")
            or record["confirmation_display_sha256"] != sha256_hex(display_bytes)
        ):
            raise DirectPrivateError("direct-private receipt binding is invalid")
        receipt_schema = (
            "direct-private-snapshot-receipt"
            if purpose == "direct_private_snapshot_scope"
            else "direct-private-admission-receipt"
        )
        self.schemas.require(receipt_schema, record["receipt"], schema_version="2.0")
        if record["receipt"]["manifest_digest"] != manifest_digest:
            raise DirectPrivateError("direct-private receipt manifest is invalid")
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(authority["public_key_base64"]))
            public.verify(
                base64.b64decode(record["signature_base64"]),
                canonical_bytes(_signature_material(record)),
            )
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise DirectPrivateError("direct-private receipt signature is invalid") from exc
        now = _aware(self.clock())
        if _parse_timestamp(record["receipt"]["expires_at"]) <= now:
            raise DirectPrivateDeclined("direct-private receipt is expired")
        _require_manifest_digest(record["manifest"])
        return record["receipt"], record["manifest"]


class DirectPrivateAdmissionCoordinator:
    """Coordinate only the S5-DP hostile synthetic one-file rehearsal."""

    def __init__(
        self,
        runtime: CaseSessionRuntime,
        schemas: SchemaRegistry,
        authority: DirectPrivateAuthority,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.schemas = schemas
        self.authority = authority
        self.verifier = authority.receipt_verifier(runtime.paths, schemas, clock)
        self.ids = id_factory
        self.clock = clock
        self.fault_injector = fault_injector
        self.semantic = SemanticLedger(runtime.paths, schemas)
        self._fixtures: dict[str, SyntheticDirectPrivateFixture] = {}

    def create_fixture(
        self,
        root: Path,
        relative_path: str,
        content: bytes,
        *,
        safe_label: str = "invented-s5dp-markdown",
    ) -> SyntheticDirectPrivateFixture:
        """Create one hostile invented fixture outside the runtime; no real path is accepted."""

        if not root.is_absolute() or _lexically_overlaps(root, self.runtime.paths.root):
            raise DirectPrivateError("synthetic fixture root is not isolated")
        parts = _relative_parts(relative_path)
        if not isinstance(content, bytes) or not content.startswith(_SYNTHETIC_MARKER):
            raise DirectPrivateError("synthetic fixture marker is required")
        if not safe_label or len(safe_label) > 128:
            raise DirectPrivateError("synthetic fixture label is invalid")
        destination = root.joinpath(*parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_immutable(destination, content)
        fixture = SyntheticDirectPrivateFixture(
            fixture_id=self.ids.new("source"),
            root=root,
            relative_path="/".join(parts),
            safe_label=safe_label,
            locator_sha256=canonical_sha256(
                {"root": str(root), "relative_path": "/".join(parts), "synthetic": True}
            ),
        )
        self._fixtures[fixture.fixture_id] = fixture
        return fixture

    def prepare_snapshot(
        self,
        fixture: SyntheticDirectPrivateFixture,
        *,
        pilot_id: str,
        authority_record_sha256: str,
        source_family_id: str,
        max_bytes: int,
        expires_at: datetime,
    ) -> dict[str, Any]:
        """Create a no-read snapshot proposal for exactly one known synthetic fixture."""

        fixture = self._known_fixture(fixture)
        if not pilot_id or len(pilot_id) > 128 or max_bytes < 1:
            raise DirectPrivateError("synthetic snapshot proposal is invalid")
        if _aware(expires_at) <= _aware(self.clock()):
            raise DirectPrivateError("synthetic snapshot proposal is expired")
        if len(authority_record_sha256) != 64:
            raise DirectPrivateError("synthetic authority record digest is invalid")
        manifest = {
            "schema_version": "2.0",
            "purpose": "direct_private_snapshot_scope",
            "snapshot_id": self.ids.new("direct_private_snapshot"),
            "pilot_id": pilot_id,
            "authority_record_sha256": authority_record_sha256,
            "fixture_id": fixture.fixture_id,
            "source_family_id": source_family_id,
            "source_locator_sha256": fixture.locator_sha256,
            "safe_label": fixture.safe_label,
            "runtime_id": self._runtime_id(),
            "max_bytes": max_bytes,
            "operations": ["metadata_hash_snapshot"],
            "synthetic_only": True,
            "component_id": COMPONENT_ID,
            "component_version": COMPONENT_VERSION,
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("direct-private-snapshot-manifest", manifest, schema_version="2.0")
        return manifest

    def take_snapshot(
        self,
        fixture: SyntheticDirectPrivateFixture,
        manifest: dict[str, Any],
        receipt_id: str,
    ) -> dict[str, Any]:
        """Perform the single receipt-bound descriptor metadata/hash read."""

        fixture = self._known_fixture(fixture)
        self.schemas.require("direct-private-snapshot-manifest", manifest, schema_version="2.0")
        _require_manifest_digest(manifest)
        if manifest["runtime_id"] != self._runtime_id():
            raise DirectPrivateError("synthetic snapshot runtime binding is invalid")
        if manifest["fixture_id"] != fixture.fixture_id or manifest["source_locator_sha256"] != fixture.locator_sha256:
            raise DirectPrivateError("synthetic snapshot fixture binding is invalid")
        receipt, verified_manifest = self.verifier.verify(
            receipt_id,
            purpose="direct_private_snapshot_scope",
            manifest_digest=manifest["manifest_digest"],
        )
        if canonical_bytes(verified_manifest) != canonical_bytes(manifest):
            raise DirectPrivateError("synthetic snapshot receipt does not bind the supplied manifest")
        destination = self._snapshot_result_path(manifest["snapshot_id"])
        if destination.exists():
            loaded = _read_json(destination)
            if (
                loaded.get("snapshot_receipt_id") == receipt["receipt_id"]
                and loaded.get("snapshot_manifest_sha256") == manifest["manifest_digest"]
            ):
                return loaded
            raise DirectPrivateError("synthetic snapshot result is already bound differently")
        details = _describe_descriptor_file(fixture.root, fixture.relative_path, manifest["max_bytes"])
        result = {
            "schema_version": "2.0",
            "snapshot_receipt_id": receipt["receipt_id"],
            "snapshot_receipt_sha256": canonical_sha256(receipt),
            "snapshot_manifest_sha256": manifest["manifest_digest"],
            "root_dev": details["root_dev"],
            "root_inode": details["root_inode"],
            "file_dev": details["file_dev"],
            "file_inode": details["file_inode"],
            "file_mode": details["file_mode"],
            "file_link_count": details["file_link_count"],
            "byte_count": details["byte_count"],
            "content_sha256": details["content_sha256"],
            "utf8_valid": True,
            "component_version": COMPONENT_VERSION,
            "snapshot_at": timestamp(_aware(self.clock())),
        }
        self.schemas.require("direct-private-snapshot-result", result, schema_version="2.0")
        _write_immutable(destination, canonical_bytes(result))
        return result

    def prepare_admission(
        self,
        snapshot_result: dict[str, Any],
        *,
        candidate_treatment: str,
        candidate_proposal: dict[str, Any] | None,
        idempotency_key: str,
        expires_at: datetime,
    ) -> dict[str, Any]:
        """Construct the second, digest-bound no-copy admission proposal."""

        self.schemas.require("direct-private-snapshot-result", snapshot_result, schema_version="2.0")
        if candidate_treatment not in {"source_only", "knowledge_candidate", "skill_candidate"}:
            raise DirectPrivateError("synthetic candidate treatment is invalid")
        if candidate_treatment == "source_only":
            if candidate_proposal is not None:
                raise DirectPrivateError("source-only admission cannot carry a candidate")
        else:
            _validate_candidate_proposal(candidate_proposal)
        if not idempotency_key or len(idempotency_key) > 256 or _aware(expires_at) <= _aware(self.clock()):
            raise DirectPrivateError("synthetic admission proposal is invalid")
        snapshot_manifest = self._load_snapshot_manifest(snapshot_result)
        if snapshot_manifest["runtime_id"] != self._runtime_id():
            raise DirectPrivateError("synthetic snapshot runtime binding is invalid")
        family_id = snapshot_manifest["source_family_id"]
        manifest = {
            "schema_version": "2.0",
            "purpose": "direct_private_source_admission",
            "admission_id": self.ids.new("direct_private_admission"),
            "snapshot_receipt_id": snapshot_result["snapshot_receipt_id"],
            "snapshot_result_sha256": canonical_sha256(snapshot_result),
            "source_family_id": family_id,
            "source_version_id": self.ids.new("source_version"),
            "content_sha256": snapshot_result["content_sha256"],
            "byte_count": snapshot_result["byte_count"],
            "runtime_id": self._runtime_id(),
            "idempotency_key": idempotency_key,
            "candidate_treatment": candidate_treatment,
            "candidate_proposal_sha256": (
                None if candidate_proposal is None else canonical_sha256(candidate_proposal)
            ),
            "retention_mode": "synthetic_disposable",
            "operations": [
                "stage_exact_copy",
                "register_source_version",
                "extract_markdown_structure",
                "build_local_fts5",
                "retrieve_exact_scope",
                "cite_exact_source_version",
                "restart_verify",
                "repeat_import_check",
                "logical_deactivate",
            ],
            "synthetic_only": True,
            "component_id": COMPONENT_ID,
            "component_version": COMPONENT_VERSION,
            "expires_at": timestamp(expires_at),
        }
        manifest["manifest_digest"] = canonical_sha256(manifest)
        self.schemas.require("direct-private-admission-manifest", manifest, schema_version="2.0")
        return manifest

    def admit(
        self,
        fixture: SyntheticDirectPrivateFixture,
        snapshot_result: dict[str, Any],
        manifest: dict[str, Any],
        receipt_id: str,
        *,
        candidate_proposal: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Stage, preserve and publish exactly one admitted synthetic Markdown item."""

        fixture = self._known_fixture(fixture)
        self.schemas.require("direct-private-snapshot-result", snapshot_result, schema_version="2.0")
        self.schemas.require("direct-private-admission-manifest", manifest, schema_version="2.0")
        _require_manifest_digest(manifest)
        if manifest["runtime_id"] != self._runtime_id():
            raise DirectPrivateError("synthetic admission runtime binding is invalid")
        if manifest["snapshot_result_sha256"] != canonical_sha256(snapshot_result):
            raise DirectPrivateError("synthetic admission does not bind its snapshot result")
        if manifest["candidate_proposal_sha256"] != (
            None if candidate_proposal is None else canonical_sha256(candidate_proposal)
        ):
            raise DirectPrivateError("synthetic candidate proposal is not bound exactly")
        existing = self._existing_admission(manifest)
        if existing is not None:
            return self._result({**_result_from_event(existing, "already_imported"), "index": None})
        receipt, verified_manifest = self.verifier.verify(
            receipt_id,
            purpose="direct_private_source_admission",
            manifest_digest=manifest["manifest_digest"],
        )
        if canonical_bytes(verified_manifest) != canonical_bytes(manifest):
            raise DirectPrivateError("synthetic admission receipt does not bind the supplied manifest")
        snapshot_manifest = self._load_snapshot_manifest(snapshot_result)
        if snapshot_manifest["runtime_id"] != self._runtime_id():
            raise DirectPrivateError("synthetic snapshot runtime binding is invalid")
        if snapshot_manifest["fixture_id"] != fixture.fixture_id:
            raise DirectPrivateError("synthetic admission fixture binding is invalid")
        self._consume_receipt(receipt, manifest)
        stage = self._admission_stage_dir(manifest["admission_id"])
        stage.mkdir(mode=0o700, parents=True, exist_ok=False)
        state_path = stage / "state.json"
        _write_immutable(
            state_path,
            canonical_bytes(
                {
                    "admission_id": manifest["admission_id"],
                    "object_ref": _object_ref(manifest["content_sha256"]),
                    "content_sha256": manifest["content_sha256"],
                }
            ),
        )
        try:
            staged = stage / "source.md"
            copied = _copy_descriptor_file(
                fixture.root, fixture.relative_path, staged, manifest["byte_count"]
            )
            _require_snapshot_match(copied, snapshot_result)
            self._fault("after_stage")
            extraction = self._extract_staged(staged, manifest)
            object_path = self._move_to_immutable_object(staged, manifest["content_sha256"])
            self._fault("after_object")
            source_version = self._source_version(manifest, snapshot_result, receipt)
            candidate = self._candidate(manifest, extraction, candidate_proposal)
            payload = {
                "admission_manifest": manifest,
                "admission_manifest_sha256": manifest["manifest_digest"],
                "admission_receipt": receipt,
                "snapshot_result": snapshot_result,
                "snapshot_result_sha256": canonical_sha256(snapshot_result),
                "snapshot_receipt": self._snapshot_receipt(snapshot_result),
                "source_version": source_version,
                "source_version_sha256": canonical_sha256(source_version),
                "extraction": extraction,
                "extraction_sha256": canonical_sha256(extraction),
                "candidate": candidate,
                "candidate_sha256": None if candidate is None else canonical_sha256(candidate),
            }
            payload["commit_manifest_sha256"] = canonical_sha256(payload)
            event = self._append_admission_event(manifest, payload)
            self._fault("after_event")
            self._remove_stage(stage)
            index = self.rebuild_index()
            if not object_path.is_file() or object_path.is_symlink():
                raise DirectPrivateError("synthetic immutable object is unavailable")
            return self._result({**_result_from_event(event, "complete"), "index": index})
        except Exception:
            # The persisted stage state lets restart recovery clean only an inert synthetic residue.
            raise

    def rebuild_index(self) -> dict[str, Any]:
        """Rebuild a local FTS5 derivative from committed admission events only."""

        events = self._active_admissions()
        material: list[tuple[dict[str, Any], dict[str, Any], bytes]] = []
        for event in events:
            version = event["payload"]["source_version"]
            content = self._read_immutable_object(version)
            material.append((event, event["payload"]["extraction"], content))
        build_material = [
            {
                "event_id": event["event_id"],
                "source_version_id": event["payload"]["source_version"]["source_version_id"],
                "content_sha256": event["payload"]["source_version"]["content_sha256"],
                "extraction_sha256": event["payload"]["extraction_sha256"],
            }
            for event, _extraction, _content in material
        ]
        build_id = "direct_private_" + canonical_sha256(build_material)[:26]
        root = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.derived_root / "direct-private-retrieval"
        )
        build = self.runtime.paths.ensure_runtime_write_target(root / "builds" / build_id)
        if not build.exists():
            stage = self.runtime.paths.ensure_runtime_write_target(
                self.runtime.paths.staging_root / "migrations" / "direct-private-index" / build_id
            )
            if stage.exists():
                raise DirectPrivateError("synthetic direct-private index staging is unavailable")
            stage.mkdir(mode=0o700, parents=True, exist_ok=False)
            database = stage / "index.sqlite3"
            _write_direct_private_index(database, material)
            database_bytes = _read_bytes(database)
            manifest = {
                "build_id": build_id,
                "index_version": INDEX_VERSION,
                "material_sha256": canonical_sha256(build_material),
                "sqlite_sha256": sha256_hex(database_bytes),
                "sqlite_byte_count": len(database_bytes),
                "source_count": len(material),
            }
            _write_immutable(stage / "manifest.json", canonical_bytes(manifest))
            build.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(stage, build)
        manifest = _read_json(build / "manifest.json")
        if manifest.get("material_sha256") != canonical_sha256(build_material):
            raise DirectPrivateError("synthetic direct-private index is stale")
        _write_replace(
            root / "active.json",
            canonical_bytes({"build_id": build_id, "manifest_sha256": canonical_sha256(manifest)}),
        )
        return {"state": "fresh", "build_id": build_id, "source_count": len(material)}

    def retrieve(self, query: str, *, limit: int = 8) -> dict[str, Any]:
        """Return local FTS matches as exact safe citations, never source bodies."""

        if not query or len(query.encode("utf-8")) > 512 or not 1 <= limit <= 8:
            raise DirectPrivateError("synthetic direct-private query is invalid")
        root = self.runtime.paths.derived_root / "direct-private-retrieval"
        try:
            active = _read_json(root / "active.json")
            manifest = _read_json(root / "builds" / active["build_id"] / "manifest.json")
            database = root / "builds" / active["build_id"] / "index.sqlite3"
            if active["manifest_sha256"] != canonical_sha256(manifest):
                raise ValueError("active manifest mismatch")
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute(
                    "SELECT admission_event_id, source_version_id, source_object_sha256, "
                    "extraction_id, anchor, text_sha256 FROM direct_private_chunks "
                    "WHERE direct_private_chunks MATCH ? LIMIT ?",
                    (query, limit),
                ).fetchall()
            finally:
                connection.close()
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            raise DirectPrivateError("synthetic direct-private index is unavailable") from exc
        return {
            "status": "complete",
            "index": {"build_id": active["build_id"], "index_version": INDEX_VERSION},
            "citations": [
                {
                    "admission_event_id": row[0],
                    "source_version_id": row[1],
                    "source_object_sha256": row[2],
                    "extraction_id": row[3],
                    "anchor": row[4],
                    "chunk_text_sha256": row[5],
                }
                for row in rows
            ],
            "limitations": ["citations are locators; this synthetic API returns no source body"],
        }

    def cite(self, citation: dict[str, Any]) -> dict[str, Any]:
        """Verify one exact local citation without returning source body text."""

        required = {
            "admission_event_id",
            "source_version_id",
            "source_object_sha256",
            "extraction_id",
            "anchor",
            "chunk_text_sha256",
        }
        if set(citation) != required:
            raise DirectPrivateError("synthetic direct-private citation is invalid")
        event = next(
            (item for item in self._active_admissions() if item["event_id"] == citation["admission_event_id"]),
            None,
        )
        if event is None:
            raise DirectPrivateError("synthetic direct-private citation is unavailable")
        version = event["payload"]["source_version"]
        extraction = event["payload"]["extraction"]
        chunk = next((item for item in extraction["chunks"] if item["anchor"] == citation["anchor"]), None)
        if (
            chunk is None
            or version["source_version_id"] != citation["source_version_id"]
            or version["content_sha256"] != citation["source_object_sha256"]
            or extraction["extraction_id"] != citation["extraction_id"]
            or chunk["text_sha256"] != citation["chunk_text_sha256"]
        ):
            raise DirectPrivateError("synthetic direct-private citation binding is invalid")
        content = self._read_immutable_object(version)
        raw = content[chunk["byte_start"] : chunk["byte_end"]]
        if sha256_hex(raw) != chunk["text_sha256"]:
            raise DirectPrivateError("synthetic direct-private citation object is invalid")
        return {"status": "complete", "citation": dict(citation)}

    def deactivate(self, admission_id: str, *, reason: str, view_names: list[str]) -> dict[str, Any]:
        """Append an exact logical deactivation; source bytes and receipts remain immutable."""

        if not reason or len(reason) > 512 or not view_names:
            raise DirectPrivateError("synthetic direct-private deactivation is invalid")
        event = next(
            (
                item
                for item in self._admission_events()
                if item["payload"]["admission_manifest"]["admission_id"] == admission_id
            ),
            None,
        )
        if event is None or self._is_deactivated(event["event_id"]):
            raise DirectPrivateError("synthetic direct-private admission is unavailable")
        candidate = event["payload"]["candidate"]
        allowed = {"direct_private_retrieval"}
        if candidate is not None:
            allowed.add(
                "provisional_candidates"
                if candidate["lifecycle_state"] == "provisional"
                else "inactive_skill_candidates"
            )
        if set(view_names) - allowed or len(set(view_names)) != len(view_names):
            raise DirectPrivateError("synthetic direct-private view scope is invalid")
        session_id = self._session_id(event)
        session = self.runtime._session(session_id)
        now = _aware(self.clock())
        deactivated = self.semantic.append(
            build_event(
                event_type="direct_private_admission.deactivated",
                case_id=session.case_id,
                session_id=session_id,
                payload={
                    "admission_id": admission_id,
                    "admission_event_id": event["event_id"],
                    "reason": reason,
                    "view_names": sorted(view_names),
                },
                subject_refs=[admission_id, event["event_id"]],
                provenance=[{"ref": event["event_id"], "relation": "caused_by"}],
                correlation_id=self.runtime.correlation_id,
                causation_event_id=event["event_id"],
                sensitivity="none",
                occurred_at=now,
                recorded_at=now,
                id_factory=self.ids,
            )
        )
        return {"status": "complete", "event_id": deactivated["event_id"], "admission_id": admission_id}

    def recover_interrupted(self) -> dict[str, Any]:
        """Remove only identified inert synthetic staging/object residue after restart."""

        root = self.runtime.paths.staging_root / "migrations" / "direct-private"
        recovered: list[str] = []
        if not root.exists():
            return {"status": "complete", "recovered_admission_ids": recovered}
        committed = {
            event["payload"]["admission_manifest"]["admission_id"] for event in self._admission_events()
        }
        for stage in sorted(root.iterdir()):
            if stage.is_symlink() or not stage.is_dir():
                raise DirectPrivateError("synthetic direct-private staging is invalid")
            state_path = stage / "state.json"
            if state_path.is_symlink() or not state_path.is_file():
                raise DirectPrivateError("synthetic direct-private staging state is invalid")
            state = _read_json(state_path)
            admission_id = state.get("admission_id")
            if not isinstance(admission_id, str):
                raise DirectPrivateError("synthetic direct-private staging state is invalid")
            if admission_id not in committed:
                object_ref = state.get("object_ref")
                if isinstance(object_ref, str):
                    object_path = self.runtime.paths.source_root / "objects" / object_ref
                    if object_path.is_file() and not object_path.is_symlink():
                        object_path.unlink()
                recovered.append(admission_id)
            self._remove_stage(stage)
        return {"status": "complete", "recovered_admission_ids": recovered}

    def _known_fixture(self, fixture: SyntheticDirectPrivateFixture) -> SyntheticDirectPrivateFixture:
        known = self._fixtures.get(fixture.fixture_id)
        if known is None or known != fixture:
            raise DirectPrivateError("direct-private synthetic fixture is not coordinator-created")
        return known

    def _runtime_id(self) -> str:
        return canonical_sha256({"root": str(self.runtime.paths.root), "component": COMPONENT_ID})

    def _snapshot_result_path(self, snapshot_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.evidence_root / "direct-private" / "snapshots" / f"{snapshot_id}.json"
        )

    def _load_snapshot_manifest(self, snapshot_result: dict[str, Any]) -> dict[str, Any]:
        receipt_id = snapshot_result["snapshot_receipt_id"]
        receipt_path = self.runtime.paths.evidence_root / "local-confirmation-v2" / "direct-private"
        path = receipt_path / "direct_private_snapshot_scope" / "receipts" / f"{receipt_id}.json"
        record = _read_json(path)
        manifest = record.get("manifest")
        if not isinstance(manifest, dict):
            raise DirectPrivateError("synthetic snapshot manifest is unavailable")
        try:
            _require_manifest_digest(manifest)
        except DirectPrivateError as exc:
            raise DirectPrivateError("synthetic snapshot manifest is unavailable") from exc
        if manifest["manifest_digest"] != snapshot_result["snapshot_manifest_sha256"]:
            raise DirectPrivateError("synthetic snapshot manifest is unavailable")
        return manifest

    def _snapshot_receipt(self, snapshot_result: dict[str, Any]) -> dict[str, Any]:
        receipt_id = snapshot_result["snapshot_receipt_id"]
        receipt, _manifest = self.verifier.verify(
            receipt_id,
            purpose="direct_private_snapshot_scope",
            manifest_digest=snapshot_result["snapshot_manifest_sha256"],
        )
        if canonical_sha256(receipt) != snapshot_result["snapshot_receipt_sha256"]:
            raise DirectPrivateError("synthetic snapshot receipt digest is invalid")
        return receipt

    def _consume_receipt(self, receipt: dict[str, Any], manifest: dict[str, Any]) -> None:
        path = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.evidence_root / "direct-private" / "consumed" / f"{receipt['receipt_id']}.json"
        )
        record = {"receipt_id": receipt["receipt_id"], "manifest_digest": manifest["manifest_digest"]}
        if path.exists():
            if _read_json(path) == record:
                raise DirectPrivateError("synthetic direct-private receipt was already consumed")
            raise DirectPrivateError("synthetic direct-private receipt has conflicting use")
        _write_immutable(path, canonical_bytes(record))

    def _admission_stage_dir(self, admission_id: str) -> Path:
        return self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.staging_root / "migrations" / "direct-private" / admission_id
        )

    def _extract_staged(self, staged: Path, manifest: dict[str, Any]) -> dict[str, Any]:
        content = _read_bytes(staged)
        try:
            text = content.decode("utf-8")
            chunks, omissions = _markdown_chunks(text, content, manifest["source_version_id"])
        except (UnicodeDecodeError, ValueError):
            raise DirectPrivateError("synthetic staged Markdown extraction failed") from None
        extraction = {
            "schema_version": "2.0",
            "extraction_id": self.ids.new("source_extraction"),
            "admission_id": manifest["admission_id"],
            "source_version_id": manifest["source_version_id"],
            "source_object_sha256": manifest["content_sha256"],
            "extractor_version": EXTRACTOR_VERSION,
            "extracted_text_sha256": sha256_hex(text.encode("utf-8")),
            "status": "partial" if omissions else "complete",
            "chunks": chunks,
            "omissions": omissions,
            "extracted_at": timestamp(_aware(self.clock())),
            "request_id": self.ids.new("request"),
            "request_sha256": manifest["manifest_digest"],
        }
        self.schemas.require("direct-private-extraction", extraction, schema_version="2.0")
        return extraction

    def _move_to_immutable_object(self, staged: Path, content_sha256: str) -> Path:
        destination = self.runtime.paths.ensure_runtime_write_target(
            self.runtime.paths.source_root / "objects" / _object_ref(content_sha256)
        )
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.link(staged, destination)
            _fsync_file(destination)
        except FileExistsError:
            existing = _read_bytes(destination)
            if sha256_hex(existing) != content_sha256:
                raise DirectPrivateError("synthetic immutable object collision") from None
        return destination

    def _source_version(
        self,
        manifest: dict[str, Any],
        snapshot_result: dict[str, Any],
        admission_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        prior = self._latest_family_version(manifest["source_family_id"])
        if prior is not None and prior["content_sha256"] == manifest["content_sha256"]:
            raise DirectPrivateError("synthetic duplicate content requires idempotent replay")
        version = {
            "schema_version": "2.0",
            "source_family_id": manifest["source_family_id"],
            "source_version_id": manifest["source_version_id"],
            "prior_source_version_id": None if prior is None else prior["source_version_id"],
            "prior_content_sha256": None if prior is None else prior["content_sha256"],
            "content_sha256": manifest["content_sha256"],
            "byte_count": manifest["byte_count"],
            "media_type": "text/markdown",
            "object_ref": _object_ref(manifest["content_sha256"]),
            "declared_label": self._load_snapshot_manifest(snapshot_result)["safe_label"],
            "source_class": "direct_private_local_markdown",
            "captured_at": timestamp(_aware(self.clock())),
            "source_effective_at": None,
            "sensitivity_labels": ["none"],
            "access_policy": "exact_direct_private_admission",
            "capture_method": "direct_private_owner_confirmed_local",
            "snapshot_receipt_id": snapshot_result["snapshot_receipt_id"],
            "snapshot_manifest_sha256": snapshot_result["snapshot_manifest_sha256"],
            "snapshot_result_sha256": canonical_sha256(snapshot_result),
            "admission_receipt_id": admission_receipt["receipt_id"],
            "admission_manifest_sha256": manifest["manifest_digest"],
            "request_id": self.ids.new("request"),
            "idempotency_key": manifest["idempotency_key"],
            "request_sha256": manifest["manifest_digest"],
        }
        self.schemas.require("source-version", version, schema_version="2.0")
        return version

    def _candidate(
        self,
        manifest: dict[str, Any],
        extraction: dict[str, Any],
        proposal: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        treatment = manifest["candidate_treatment"]
        if treatment == "source_only":
            return None
        _validate_candidate_proposal(proposal)
        assert proposal is not None
        candidate_id = self.ids.new(
            "knowledge_candidate" if treatment == "knowledge_candidate" else "skill_candidate"
        )
        return {
            "schema_version": "synthetic-0.1",
            "candidate_id": candidate_id,
            "record_kind": treatment,
            "lifecycle_state": "provisional" if treatment == "knowledge_candidate" else "inactive",
            "title": proposal["title"],
            "statement": proposal["statement"],
            "applicability": proposal["applicability"],
            "limitations": proposal["limitations"],
            "source_version_id": manifest["source_version_id"],
            "extraction_id": extraction["extraction_id"],
            "candidate_sha256": canonical_sha256(
                {
                    "record_kind": treatment,
                    "proposal": proposal,
                    "source_version_id": manifest["source_version_id"],
                    "extraction_id": extraction["extraction_id"],
                }
            ),
        }

    def _append_admission_event(self, manifest: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        session_id = self._active_session_id()
        state = self.runtime._session(session_id)
        events = self.semantic.read_all()
        causation = next(
            (event["event_id"] for event in reversed(events) if event["session_id"] == session_id), None
        )
        now = _aware(self.clock())
        return self.semantic.append(
            build_event(
                event_type="direct_private_admission.recorded",
                case_id=state.case_id,
                session_id=session_id,
                payload=payload,
                subject_refs=[
                    manifest["source_family_id"],
                    manifest["source_version_id"],
                    manifest["admission_id"],
                ],
                correlation_id=self.runtime.correlation_id,
                causation_event_id=causation,
                sensitivity="none",
                occurred_at=now,
                recorded_at=now,
                id_factory=self.ids,
            )
        )

    def _active_session_id(self) -> str:
        states = self.runtime._session
        for event in reversed(self.semantic.read_all()):
            session_id = event.get("session_id")
            if session_id is not None:
                state = states(session_id)
                if state.status == "active" and not state.frozen:
                    return session_id
        raise DirectPrivateError("synthetic direct-private admission requires an active session")

    def _existing_admission(self, manifest: dict[str, Any]) -> dict[str, Any] | None:
        for event in self._admission_events():
            prior = event["payload"]["admission_manifest"]
            if prior["idempotency_key"] == manifest["idempotency_key"]:
                if prior["manifest_digest"] != manifest["manifest_digest"]:
                    raise DirectPrivateError("synthetic admission idempotency key is conflicting")
                return event
            version = event["payload"]["source_version"]
            if (
                version["source_family_id"] == manifest["source_family_id"]
                and version["content_sha256"] == manifest["content_sha256"]
            ):
                return event
        return None

    def _latest_family_version(self, family_id: str) -> dict[str, Any] | None:
        for event in reversed(self._admission_events()):
            version = event["payload"]["source_version"]
            if version["source_family_id"] == family_id:
                return version
        return None

    def _admission_events(self) -> list[dict[str, Any]]:
        return [
            event
            for event in self.semantic.read_all()
            if event["event_type"] == "direct_private_admission.recorded"
        ]

    def _active_admissions(self) -> list[dict[str, Any]]:
        return [event for event in self._admission_events() if not self._is_deactivated(event["event_id"])]

    def _is_deactivated(self, admission_event_id: str) -> bool:
        return any(
            event["event_type"] == "direct_private_admission.deactivated"
            and event["payload"].get("admission_event_id") == admission_event_id
            and "direct_private_retrieval" in event["payload"].get("view_names", [])
            for event in self.semantic.read_all()
        )

    @staticmethod
    def _session_id(event: dict[str, Any]) -> str:
        value = event.get("session_id")
        if not isinstance(value, str):
            raise DirectPrivateError("synthetic admission event is not session-scoped")
        return value

    def _read_immutable_object(self, version: dict[str, Any]) -> bytes:
        path = self.runtime.paths.source_root / "objects" / version["object_ref"]
        if path.is_symlink():
            raise DirectPrivateError("synthetic immutable source object is invalid")
        content = _read_bytes(path)
        if sha256_hex(content) != version["content_sha256"] or len(content) != version["byte_count"]:
            raise DirectPrivateError("synthetic immutable source object is invalid")
        return content

    def _remove_stage(self, stage: Path) -> None:
        if stage.exists():
            if stage.is_symlink() or not stage.is_dir():
                raise DirectPrivateError("synthetic direct-private staging is invalid")
            shutil.rmtree(stage)

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    def _result(self, value: dict[str, Any]) -> dict[str, Any]:
        result = {"schema_version": "2.0", **value}
        self.schemas.require("direct-private-admission-result", result, schema_version="2.0")
        return result


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
        raise DirectPrivateError("synthetic relative path is invalid")
    candidate = PurePosixPath(relative_path)
    parts = candidate.parts
    if (
        candidate.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or not parts[-1].endswith(".md")
    ):
        raise DirectPrivateError("synthetic relative path is invalid")
    return tuple(parts)


def _describe_descriptor_file(root: Path, relative_path: str, max_bytes: int) -> dict[str, int | str]:
    root_fd, file_fd, root_stat, file_stat = _open_descriptor_file(root, relative_path)
    try:
        if file_stat.st_size > max_bytes:
            raise DirectPrivateError("synthetic source exceeds its approved byte limit")
        digest = sha256()
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        byte_count = 0
        prefix = bytearray()
        while chunk := os.read(file_fd, 65_536):
            byte_count += len(chunk)
            if byte_count > max_bytes:
                raise DirectPrivateError("synthetic source exceeds its approved byte limit")
            digest.update(chunk)
            decoder.decode(chunk)
            if len(prefix) < len(_SYNTHETIC_MARKER):
                prefix.extend(chunk[: len(_SYNTHETIC_MARKER) - len(prefix)])
        decoder.decode(b"", final=True)
        if bytes(prefix) != _SYNTHETIC_MARKER:
            raise DirectPrivateError("synthetic source marker is invalid")
        final_stat = os.fstat(file_fd)
        if _file_identity(final_stat) != _file_identity(file_stat) or byte_count != final_stat.st_size:
            raise DirectPrivateError("synthetic source changed during descriptor read")
        return {
            "root_dev": root_stat.st_dev,
            "root_inode": root_stat.st_ino,
            "file_dev": file_stat.st_dev,
            "file_inode": file_stat.st_ino,
            "file_mode": stat.S_IMODE(file_stat.st_mode),
            "file_link_count": file_stat.st_nlink,
            "byte_count": byte_count,
            "content_sha256": digest.hexdigest(),
        }
    except UnicodeDecodeError as exc:
        raise DirectPrivateError("synthetic source is not strict UTF-8") from exc
    finally:
        os.close(file_fd)
        os.close(root_fd)


def _copy_descriptor_file(root: Path, relative_path: str, destination: Path, max_bytes: int) -> dict[str, int | str]:
    root_fd, file_fd, root_stat, file_stat = _open_descriptor_file(root, relative_path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    output_fd = os.open(destination, flags, 0o600)
    try:
        if file_stat.st_size > max_bytes:
            raise DirectPrivateError("synthetic source exceeds its approved byte limit")
        digest = sha256()
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        byte_count = 0
        prefix = bytearray()
        while chunk := os.read(file_fd, 65_536):
            byte_count += len(chunk)
            if byte_count > max_bytes:
                raise DirectPrivateError("synthetic source exceeds its approved byte limit")
            digest.update(chunk)
            decoder.decode(chunk)
            if len(prefix) < len(_SYNTHETIC_MARKER):
                prefix.extend(chunk[: len(_SYNTHETIC_MARKER) - len(prefix)])
            _write_all(output_fd, chunk)
        decoder.decode(b"", final=True)
        if bytes(prefix) != _SYNTHETIC_MARKER:
            raise DirectPrivateError("synthetic source marker is invalid")
        os.fsync(output_fd)
        final_stat = os.fstat(file_fd)
        if _file_identity(final_stat) != _file_identity(file_stat) or byte_count != final_stat.st_size:
            raise DirectPrivateError("synthetic source changed during descriptor read")
        return {
            "root_dev": root_stat.st_dev,
            "root_inode": root_stat.st_ino,
            "file_dev": file_stat.st_dev,
            "file_inode": file_stat.st_ino,
            "file_mode": stat.S_IMODE(file_stat.st_mode),
            "file_link_count": file_stat.st_nlink,
            "byte_count": byte_count,
            "content_sha256": digest.hexdigest(),
        }
    except UnicodeDecodeError as exc:
        raise DirectPrivateError("synthetic source is not strict UTF-8") from exc
    finally:
        os.close(output_fd)
        os.close(file_fd)
        os.close(root_fd)


def _open_descriptor_file(root: Path, relative_path: str) -> tuple[int, int, os.stat_result, os.stat_result]:
    parts = _relative_parts(relative_path)
    flags = os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise DirectPrivateError("descriptor-safe source access is unsupported")
    try:
        root_fd = os.open(root, flags | os.O_NOFOLLOW | os.O_DIRECTORY)
    except OSError as exc:
        raise DirectPrivateError("synthetic source root is unavailable") from exc
    current_fd = root_fd
    try:
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise DirectPrivateError("synthetic source root is invalid")
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            child_flags = flags | os.O_NOFOLLOW
            if not final:
                child_flags |= os.O_DIRECTORY
            child_fd = os.open(part, child_flags, dir_fd=current_fd)
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = child_fd
        file_stat = os.fstat(current_fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or stat.S_IMODE(file_stat.st_mode) & stat.S_IXUSR
        ):
            raise DirectPrivateError("synthetic source file type is invalid")
        return root_fd, current_fd, root_stat, file_stat
    except OSError as exc:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise DirectPrivateError("synthetic source descriptor is invalid") from exc
    except Exception:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise


def _markdown_chunks(
    text: str,
    content: bytes,
    source_version_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Use the existing bounded heading/paragraph semantics without rendering Markdown."""

    from vault_next.sources import _structure_chunks

    return _structure_chunks(text, content, source_version_id)


def _write_direct_private_index(
    database: Path,
    material: list[tuple[dict[str, Any], dict[str, Any], bytes]],
) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(
            "CREATE VIRTUAL TABLE direct_private_chunks USING fts5("
            "body, admission_event_id UNINDEXED, source_version_id UNINDEXED, "
            "source_object_sha256 UNINDEXED, extraction_id UNINDEXED, anchor UNINDEXED, "
            "text_sha256 UNINDEXED)"
        )
        for event, extraction, content in material:
            for chunk in extraction["chunks"]:
                raw = content[chunk["byte_start"] : chunk["byte_end"]]
                if sha256_hex(raw) != chunk["text_sha256"]:
                    raise DirectPrivateError("synthetic direct-private extraction is invalid")
                connection.execute(
                    "INSERT INTO direct_private_chunks VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        raw.decode("utf-8"),
                        event["event_id"],
                        event["payload"]["source_version"]["source_version_id"],
                        event["payload"]["source_version"]["content_sha256"],
                        extraction["extraction_id"],
                        chunk["anchor"],
                        chunk["text_sha256"],
                    ),
                )
        connection.commit()
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise DirectPrivateError("synthetic direct-private index validation failed")
    finally:
        connection.close()
    _fsync_file(database)


def _require_snapshot_match(observed: dict[str, int | str], snapshot: dict[str, Any]) -> None:
    for key in (
        "root_dev",
        "root_inode",
        "file_dev",
        "file_inode",
        "file_mode",
        "file_link_count",
        "byte_count",
        "content_sha256",
    ):
        if observed[key] != snapshot[key]:
            raise DirectPrivateError("synthetic source changed between confirmations")


def _validate_candidate_proposal(value: dict[str, Any] | None) -> None:
    required = {"title", "statement", "applicability", "limitations"}
    if not isinstance(value, dict) or set(value) != required:
        raise DirectPrivateError("synthetic candidate proposal is invalid")
    if not all(isinstance(value[key], str) and value[key] for key in required - {"limitations"}):
        raise DirectPrivateError("synthetic candidate proposal is invalid")
    limits = value["limitations"]
    if not isinstance(limits, list) or not limits or not all(isinstance(item, str) and item for item in limits):
        raise DirectPrivateError("synthetic candidate proposal is invalid")


def _result_from_event(event: dict[str, Any], status: str) -> dict[str, Any]:
    payload = event["payload"]
    return {
        "status": status,
        "admission_id": payload["admission_manifest"]["admission_id"],
        "event_id": event["event_id"],
        "source_version_id": payload["source_version"]["source_version_id"],
        "source_object_sha256": payload["source_version"]["content_sha256"],
        "candidate": None
        if payload["candidate"] is None
        else {
            "candidate_id": payload["candidate"]["candidate_id"],
            "record_kind": payload["candidate"]["record_kind"],
            "lifecycle_state": payload["candidate"]["lifecycle_state"],
        },
    }


def _object_ref(content_sha256: str) -> str:
    return f"sha256/{content_sha256[:2]}/{content_sha256}"


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_nlink, value.st_size


def _signature_material(record: dict[str, Any]) -> dict[str, Any]:
    material = copy.deepcopy(record)
    material.pop("signature_base64", None)
    return material


def _require_manifest_digest(manifest: dict[str, Any]) -> None:
    material = dict(manifest)
    digest = material.pop("manifest_digest", None)
    if not isinstance(digest, str) or canonical_sha256(material) != digest:
        raise DirectPrivateError("direct-private manifest digest is invalid")


def _parse_timestamp(value: str) -> datetime:
    try:
        return _aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (AttributeError, ValueError) as exc:
        raise DirectPrivateError("direct-private timestamp is invalid") from exc


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DirectPrivateError("direct-private clock must be timezone-aware")
    return value.astimezone(UTC)


def _lexically_overlaps(first: Path, second: Path) -> bool:
    first_text = os.path.abspath(str(first))
    second_text = os.path.abspath(str(second))
    try:
        return os.path.commonpath([first_text, second_text]) in {first_text, second_text}
    except ValueError:
        return True


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(_read_bytes(path))
    if not isinstance(value, dict):
        raise ValueError("JSON record must be an object")
    return value


def _read_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise OSError("path is not a direct regular file")
    return path.read_bytes()


def _write_immutable(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if _read_bytes(path) != content:
            raise DirectPrivateError("immutable synthetic record collision")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_replace(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = path.with_name(f".{path.name}.stage")
    if stage.exists():
        stage.unlink()
    _write_immutable(stage, content)
    os.replace(stage, path)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
