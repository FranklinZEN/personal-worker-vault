"""One-input, non-synthetic U0 boundary for the current Codex project task.

This sibling never invokes a model, network client, connector, receipt, transaction, or durable
writer. The host supplies exactly one already-authorized representation and one hosted analysis;
this module only freezes evidence and validates the resulting cited debrief in memory.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.content_profiles import ContentProfileRouter, NormalizedContent
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.meeting_debrief import FrozenEvidence, freeze_evidence, validate_analysis_payload
from vault_next.records import SchemaRegistry


ADAPTER_ID = "vault-next-codex-project-native-u0/0.1.0"
METHOD_PACKAGE = "meeting-debrief"
METHOD_VERSION = "0.2.0"
PROCESSING_SURFACE = "codex_project_native"
_INGRESS_KINDS = frozenset({"paste", "attachment", "local_file"})
_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


class CodexProjectNativeU0Error(RuntimeError):
    """The one-input current-task U0 boundary was not met."""


@dataclass(frozen=True)
class NativeIngressMaterial:
    """One current-task representation; no path, capability, or durable authority is retained."""

    ingress_kind: str
    material_bytes: bytes
    safe_label: str
    declared_media_type: str
    declared_extension: str
    opaque_id: str
    host_task_id: str
    detail_digests: tuple[str, ...] = ()
    synthetic_only: bool = False


@dataclass(frozen=True)
class NativeU0Preparation:
    """Frozen in-memory evidence and limited host presentation for exactly one U0 run."""

    ingress_envelope: dict[str, Any]
    evidence: FrozenEvidence
    normalized: NormalizedContent


class CodexProjectNativeU0Coordinator:
    """Prepare one selected input and validate one cited hosted result without persistence."""

    def __init__(
        self,
        schemas: SchemaRegistry,
        router: ContentProfileRouter | None = None,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
    ) -> None:
        self.schemas = schemas
        self.router = router or ContentProfileRouter()
        self.ids = id_factory

    def prepare(self, material: NativeIngressMaterial) -> NativeU0Preparation:
        """Freeze one explicitly supplied in-memory representation before hosted reasoning."""

        _validate_material(material)
        envelope = self._envelope(material)
        normalized = self.router.route(
            material.material_bytes,
            declared_media_type=material.declared_media_type,
            declared_extension=material.declared_extension,
        )
        evidence = freeze_evidence(
            self.schemas,
            envelope,
            normalized,
            schema_name="codex-project-native-u0-evidence",
        )
        return NativeU0Preparation(envelope, evidence, normalized)

    def prepare_owner_selected_local_file(self, path: Path, *, host_task_id: str) -> NativeU0Preparation:
        """Descriptor-safely read one exact owner-named local file into the in-memory U0 boundary."""

        if not isinstance(path, Path) or not path.is_absolute():
            raise CodexProjectNativeU0Error("one absolute owner-selected local file is required")
        extension = path.suffix.casefold()
        media_type = _MEDIA_TYPES.get(extension)
        if media_type is None:
            raise CodexProjectNativeU0Error("owner-selected file type is unsupported")
        content, identity_digest = _read_one_regular_file(path, self.router.max_material_bytes)
        material = NativeIngressMaterial(
            ingress_kind="local_file",
            material_bytes=content,
            safe_label=path.name,
            declared_media_type=media_type,
            declared_extension=extension,
            opaque_id=self.ids.new("chat_ingress"),
            host_task_id=host_task_id,
            detail_digests=(identity_digest,),
        )
        return self.prepare(material)

    def host_packet(self, preparation: NativeU0Preparation) -> dict[str, Any]:
        """Return only the selected evidence/method material the visible host needs to reason."""

        request = {
            "schema_version": "1.0",
            "method_package": METHOD_PACKAGE,
            "method_version": METHOD_VERSION,
            "evidence_sha256": preparation.evidence.evidence_sha256,
            "processing_surface": PROCESSING_SURFACE,
            "authority_level": "U0",
            "candidate_lifecycle": "inactive",
            "no_effects": ["no_save", "no_activate", "no_apply", "no_send", "no_schedule", "no_tools"],
        }
        self.schemas.require("codex-project-native-u0-request", request)
        return {
            "adapter": {"id": ADAPTER_ID, "processing_surface": PROCESSING_SURFACE},
            "request": request,
            "evidence_packet": preparation.evidence.record(),
            "citation_units": [
                {"anchor": item.anchor, "text": item.text} for item in preparation.evidence.anchors
            ],
            "disclosure": {
                "processing": "hosted_codex",
                "candidate_lifecycle": "inactive",
                "vault_next_persistence": "none",
                "u1_save": "not_invoked",
                "u2_actions": "unavailable",
            },
        }

    def validate_hosted_analysis(
        self,
        preparation: NativeU0Preparation,
        analysis: object,
    ) -> dict[str, Any]:
        """Accept only one exact cited hosted result against the frozen selected evidence."""

        preparation.evidence.verify()
        validate_analysis_payload(analysis, preparation.evidence)
        preparation.evidence.verify()
        if not isinstance(analysis, dict):
            raise CodexProjectNativeU0Error("hosted analysis is malformed")
        material = {
            "schema_version": "1.0",
            "debrief_id": self.ids.new("meeting_debrief"),
            "method_package": METHOD_PACKAGE,
            "method_version": METHOD_VERSION,
            "execution_surface": PROCESSING_SURFACE,
            "analytical_usefulness": "owner_review_pending",
            "evidence_sha256": preparation.evidence.evidence_sha256,
            "ingress_kind": preparation.ingress_envelope["ingress_kind"],
            "findings": analysis["findings"],
            "summary": analysis["summary"],
            "open_questions": analysis["open_questions"],
            "suggested_followups": analysis["suggested_followups"],
            "omissions": analysis["omissions"],
            "limitations": analysis["limitations"],
            "persistence": "ephemeral",
            "candidate_lifecycle": "inactive",
            "validation_status": "accepted",
            "vault_next_persistence": "none",
        }
        result = {
            **material,
            "result_sha256": canonical_sha256(
                {key: value for key, value in material.items() if key != "debrief_id"}
            ),
        }
        self.schemas.require("codex-project-native-u0-result", result)
        return result

    def _envelope(self, material: NativeIngressMaterial) -> dict[str, Any]:
        provenance = {
            "kind": material.ingress_kind,
            "opaque_id": material.opaque_id,
            "metadata_sha256": canonical_sha256(
                {
                    "safe_label": material.safe_label,
                    "declared_media_type": material.declared_media_type,
                    "declared_extension": material.declared_extension,
                }
            ),
            "detail_digests": list(material.detail_digests),
            "host_task_id_sha256": sha256_hex(material.host_task_id.encode("utf-8")),
        }
        envelope = {
            "schema_version": "1.0",
            "ingress_id": self.ids.new("chat_ingress"),
            "ingress_kind": material.ingress_kind,
            "safe_label": material.safe_label,
            "declared_media_type": material.declared_media_type,
            "declared_extension": material.declared_extension,
            "byte_count": len(material.material_bytes),
            "material_sha256": sha256_hex(material.material_bytes),
            "provenance": provenance,
            "processing_surface": PROCESSING_SURFACE,
            "authority_level": "U0",
            "synthetic_only": False,
        }
        self.schemas.require("codex-project-native-u0-envelope", envelope)
        return envelope


def _validate_material(material: object) -> None:
    if not isinstance(material, NativeIngressMaterial):
        raise CodexProjectNativeU0Error("current-task U0 requires a native ingress material record")
    if material.ingress_kind not in _INGRESS_KINDS:
        raise CodexProjectNativeU0Error("current-task ingress kind is unsupported")
    if material.synthetic_only is not False:
        raise CodexProjectNativeU0Error("synthetic material is not valid for the native U0 contract")
    if not isinstance(material.material_bytes, bytes) or not material.material_bytes:
        raise CodexProjectNativeU0Error("current-task material bytes are unavailable")
    if (
        not isinstance(material.safe_label, str)
        or not material.safe_label
        or len(material.safe_label) > 128
        or "/" in material.safe_label
        or "\\" in material.safe_label
        or "\x00" in material.safe_label
    ):
        raise CodexProjectNativeU0Error("current-task safe label is invalid")
    if material.declared_extension not in _MEDIA_TYPES:
        raise CodexProjectNativeU0Error("current-task declared extension is unsupported")
    if material.declared_media_type != _MEDIA_TYPES[material.declared_extension]:
        raise CodexProjectNativeU0Error("current-task declared media type is unsupported")
    if not isinstance(material.opaque_id, str) or not material.opaque_id or len(material.opaque_id) > 256:
        raise CodexProjectNativeU0Error("current-task opaque identity is invalid")
    if not isinstance(material.host_task_id, str) or not material.host_task_id:
        raise CodexProjectNativeU0Error("current-task identity is invalid")
    if len(material.detail_digests) > 8 or any(
        not isinstance(item, str) or len(item) != 64 or set(item) - set("0123456789abcdef")
        for item in material.detail_digests
    ):
        raise CodexProjectNativeU0Error("current-task provenance detail digests are invalid")


def _read_one_regular_file(path: Path, max_bytes: int) -> tuple[bytes, str]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise CodexProjectNativeU0Error("descriptor-safe local-file access is unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CodexProjectNativeU0Error("owner-selected local file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CodexProjectNativeU0Error("owner-selected local input is not a regular file")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise CodexProjectNativeU0Error("owner-selected local file exceeds the U0 byte budget")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise CodexProjectNativeU0Error("owner-selected local file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CodexProjectNativeU0Error("owner-selected local file changed during read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CodexProjectNativeU0Error("owner-selected local file changed during read")
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise CodexProjectNativeU0Error("owner-selected local file changed during read") from exc
    if not stat.S_ISREG(path_stat.st_mode) or (path_stat.st_dev, path_stat.st_ino) != (
        before.st_dev,
        before.st_ino,
    ):
        raise CodexProjectNativeU0Error("owner-selected local file changed during read")
    content = b"".join(chunks)
    identity_digest = canonical_sha256(
        {"device": before.st_dev, "inode": before.st_ino, "size": before.st_size, "mtime_ns": before.st_mtime_ns}
    )
    return content, identity_digest
