"""Synthetic-only content-addressed evidence registration for Phase 2."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next import __version__
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.ledger import SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry, aware_utc_now, build_event, timestamp


@dataclass(frozen=True)
class EvidenceRegistration:
    metadata: dict
    event: dict
    object_path: Path


class SyntheticEvidenceStore:
    """Store only invented fixtures; external and personal sources are out of scope."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        correlation_id: str = "vault-next-phase2",
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock
        self.correlation_id = correlation_id
        self.semantic = SemanticLedger(paths, schemas)

    def register(
        self,
        *,
        case_id: str,
        session_id: str,
        content: bytes,
        display_name: str,
        content_type: str = "text/plain",
        sensitivity_labels: list[str] | None = None,
        trust_classification: str = "synthetic_observation",
    ) -> EvidenceRegistration:
        digest = sha256_hex(content)
        evidence_id = f"evidence_sha256_{digest}"
        object_ref = f"sha256/{digest[:2]}/{digest}"
        object_path = self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "objects" / object_ref
        )
        _durable_create_if_absent(object_path, content)
        when = self.clock()
        metadata = {
            "schema_version": "1.0",
            "evidence_id": evidence_id,
            "content_sha256": digest,
            "byte_count": len(content),
            "content_type": content_type,
            "source_class": "synthetic_fixture",
            "original_display_name": display_name,
            "captured_at": timestamp(when),
            "source_event_time": None,
            "sensitivity_labels": sensitivity_labels or ["none"],
            "access_policy": "explicit_session_allowlist",
            "capture_method": "synthetic_fixture",
            "trust_classification": trust_classification,
            "actor": {"type": "runtime", "id": f"vault-next-runtime/{__version__}"},
            "object_ref": object_ref,
        }
        self.schemas.require("evidence-metadata", metadata)
        payload = {"metadata": metadata, "metadata_sha256": canonical_sha256(metadata)}
        event = self.semantic.append(
            build_event(
                event_type="evidence.registered",
                case_id=case_id,
                session_id=session_id,
                payload=payload,
                subject_refs=[evidence_id],
                correlation_id=self.correlation_id,
                occurred_at=when,
                recorded_at=when,
                id_factory=self.ids,
            )
        )
        return EvidenceRegistration(metadata, event, object_path)

    def read_verified(self, metadata: dict) -> bytes:
        path = self.paths.evidence_root / "objects" / metadata["object_ref"]
        data = path.read_bytes()
        if sha256_hex(data) != metadata["content_sha256"] or len(data) != metadata["byte_count"]:
            raise ValueError("evidence object does not match canonical metadata")
        return data


def _durable_create_if_absent(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError("content-addressed evidence collision")
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short evidence object write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
