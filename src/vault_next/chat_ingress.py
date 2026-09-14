"""Adapter-independent synthetic ingress for the Chat-first S5 vertical slice.

This module intentionally accepts only injected fixture transports.  It has no filesystem, URL,
browser, connector, model, or network client and cannot persist a U0 execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.content_profiles import ContentProfileRouter, SYNTHETIC_FIXTURE_MARKER
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.meeting_debrief import (
    FrozenEvidence,
    MeetingDebriefCoordinator,
    freeze_evidence,
)
from vault_next.records import SchemaRegistry


_INGRESS_KINDS = frozenset({"paste", "attachment", "local_file", "acquired_link"})


class ChatIngressError(RuntimeError):
    """An injected synthetic ingress did not meet the CF1 U0 contract."""


@dataclass(frozen=True)
class SyntheticIngressMaterial:
    """Fixture-owned bytes plus safe provenance metadata, never a path or live URL capability."""

    ingress_kind: str
    material_bytes: bytes
    safe_label: str
    declared_media_type: str | None
    declared_extension: str | None
    opaque_id: str
    detail_digests: tuple[str, ...] = ()
    synthetic_only: bool = True


class ChatIngressTransport(Protocol):
    """A narrow double that hands already-supplied synthetic bytes to the core."""

    def capture(self) -> SyntheticIngressMaterial: ...


@dataclass(frozen=True)
class SyntheticIngressTransport:
    """A disposable test double for one of the four user-facing ingress origins."""

    material: SyntheticIngressMaterial

    def capture(self) -> SyntheticIngressMaterial:
        """Return only the fixture material supplied at construction time."""

        return self.material


@dataclass(frozen=True)
class ChatIngressExecution:
    """One U0 result plus private in-memory bytes that an optional U1 coordinator may save."""

    result: dict[str, Any]
    material_bytes: bytes
    ingress_envelope: dict[str, Any]
    evidence: FrozenEvidence
    debrief: dict[str, Any]


@dataclass(frozen=True)
class ChatIngressPreparation:
    """Validated U0 material and evidence, ready for a bounded analyzer invocation.

    This internal split lets a host adapter expose the frozen evidence packet to a visible hosted
    model without giving that model a filesystem, persistence, or other Vault Next capability.
    """

    material_bytes: bytes
    ingress_envelope: dict[str, Any]
    evidence: FrozenEvidence


class ChatIngressCoordinator:
    """Run the U0 path: capture fixture bytes, normalize them, then request a cited debrief."""

    def __init__(
        self,
        schemas: SchemaRegistry,
        router: ContentProfileRouter,
        debrief: MeetingDebriefCoordinator,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
    ) -> None:
        self.schemas = schemas
        self.router = router
        self.debrief = debrief
        self.ids = id_factory

    def run(self, transport: ChatIngressTransport) -> ChatIngressExecution:
        """Return an ephemeral cited debrief without touching a runtime root."""

        prepared = self.prepare(transport)
        debrief = self.debrief.run(prepared.evidence)
        result = {
            "schema_version": "1.0",
            "status": "complete",
            "authority_level": "U0",
            "ingress_envelope": prepared.ingress_envelope,
            "evidence_packet": prepared.evidence.record(),
            "debrief": debrief,
            "save": None,
            "available_next_actions": ["save_to_vault_next"],
            "limitations": [
                "synthetic fixture mechanics only",
                "no host, model, source, network, connector, or persistence operation occurred",
                "Meeting Debrief remains an inactive candidate evaluation",
            ],
        }
        self.schemas.require("chat-ingress-result", result)
        return ChatIngressExecution(
            result=result,
            material_bytes=prepared.material_bytes,
            ingress_envelope=prepared.ingress_envelope,
            evidence=prepared.evidence,
            debrief=debrief,
        )

    def prepare(self, transport: ChatIngressTransport) -> ChatIngressPreparation:
        """Freeze marked synthetic material before any bounded analyzer is selected or called."""

        supplied = transport.capture()
        _validate_material(supplied)
        envelope = self._envelope(supplied)
        normalized = self.router.route(
            supplied.material_bytes,
            declared_media_type=supplied.declared_media_type,
            declared_extension=supplied.declared_extension,
        )
        if SYNTHETIC_FIXTURE_MARKER not in normalized.normalized_text:
            raise ChatIngressError("Chat-first CF1 accepts only marked hostile synthetic fixture content")
        evidence = freeze_evidence(self.schemas, envelope, normalized)
        return ChatIngressPreparation(
            material_bytes=supplied.material_bytes,
            ingress_envelope=envelope,
            evidence=evidence,
        )

    def _envelope(self, supplied: SyntheticIngressMaterial) -> dict[str, Any]:
        provenance = {
            "kind": supplied.ingress_kind,
            "opaque_id": supplied.opaque_id,
            "metadata_sha256": canonical_sha256(
                {
                    "safe_label": supplied.safe_label,
                    "declared_media_type": supplied.declared_media_type,
                    "declared_extension": supplied.declared_extension,
                }
            ),
            "detail_digests": list(supplied.detail_digests),
        }
        envelope = {
            "schema_version": "1.0",
            "ingress_id": self.ids.new("chat_ingress"),
            "ingress_kind": supplied.ingress_kind,
            "safe_label": supplied.safe_label,
            "declared_media_type": supplied.declared_media_type,
            "declared_extension": supplied.declared_extension,
            "byte_count": len(supplied.material_bytes),
            "material_sha256": sha256_hex(supplied.material_bytes),
            "provenance": provenance,
            "processing_surface": "synthetic_fixture",
            "authority_level": "U0",
            "synthetic_only": True,
        }
        self.schemas.require("chat-ingress-envelope", envelope)
        return envelope


def _validate_material(value: object) -> None:
    if not isinstance(value, SyntheticIngressMaterial):
        raise ChatIngressError("Chat-first CF1 requires a SyntheticIngressMaterial transport result")
    if value.ingress_kind not in _INGRESS_KINDS:
        raise ChatIngressError("synthetic ingress kind is unsupported")
    if not isinstance(value.material_bytes, bytes) or not value.material_bytes:
        raise ChatIngressError("synthetic ingress bytes are unavailable")
    if (
        not value.safe_label
        or len(value.safe_label) > 128
        or "/" in value.safe_label
        or "\\" in value.safe_label
        or "\x00" in value.safe_label
    ):
        raise ChatIngressError("synthetic ingress safe label is invalid")
    if value.declared_media_type is not None and (
        not isinstance(value.declared_media_type, str) or len(value.declared_media_type) > 128
    ):
        raise ChatIngressError("synthetic ingress declared media type is invalid")
    if value.declared_extension is not None and (
        not isinstance(value.declared_extension, str)
        or not value.declared_extension.startswith(".")
        or len(value.declared_extension) > 24
    ):
        raise ChatIngressError("synthetic ingress declared extension is invalid")
    if not isinstance(value.opaque_id, str) or not value.opaque_id or len(value.opaque_id) > 256:
        raise ChatIngressError("synthetic ingress opaque identity is invalid")
    if not value.synthetic_only:
        raise ChatIngressError("non-synthetic ingress is not authorized for CF1")
    if len(value.detail_digests) > 8 or any(
        not isinstance(item, str) or len(item) != 64 or set(item) - set("0123456789abcdef")
        for item in value.detail_digests
    ):
        raise ChatIngressError("synthetic ingress provenance detail digests are invalid")
