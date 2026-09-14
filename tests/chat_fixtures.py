"""Hostile disposable fixtures shared by the S5 Chat-first synthetic tests."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from tests.helpers import Harness
from vault_next.chat_ingress import (
    ChatIngressCoordinator,
    SyntheticIngressMaterial,
    SyntheticIngressTransport,
)
from vault_next.chat_save import SyntheticChatSaveAuthority
from vault_next.content_profiles import ContentProfileRouter, SYNTHETIC_FIXTURE_MARKER
from vault_next.meeting_debrief import FrozenEvidence, MeetingDebriefCoordinator
from vault_next.runtime import CaseSessionRuntime


class ExactDigestConfirmation:
    """Test-only exact-digest UI double with optional hostile mutation or rejection."""

    def __init__(self, response: str | None = None, *, mutate_display: bool = False) -> None:
        self.response = response
        self.mutate_display = mutate_display
        self.display_paths: list[Path] = []

    def confirm(self, display_path: Path, expected_manifest_digest: str) -> str:
        self.display_paths.append(display_path)
        if self.mutate_display:
            display_path.write_bytes(b'{"synthetic":"changed"}')
        return expected_manifest_digest if self.response is None else self.response


class FixtureMeetingDebriefAnalyzer:
    """Return caller-invented structured findings without a model or any external capability."""

    def __init__(self, *, variant: str = "one") -> None:
        self.variant = variant
        self.calls: list[FrozenEvidence] = []

    def analyze(self, evidence: FrozenEvidence, request: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(evidence)
        anchor = evidence.anchors[0].anchor
        statement = f"Invented fixture finding {self.variant}."
        return {
            "findings": [
                {
                    "claim_class": "reported_fact",
                    "statement": statement,
                    "citations": [{"anchor": anchor}],
                    "owner": None,
                    "owner_citation": None,
                    "due": None,
                    "due_citation": None,
                }
            ],
            "summary": {"statement": statement, "citations": [{"anchor": anchor}]},
            "open_questions": ["Invented fixture question remains open."],
            "suggested_followups": ["Invented fixture follow-up is only a suggestion."],
            "omissions": ["Synthetic fixture analysis does not establish real-world usefulness."],
            "limitations": ["No model, host, tool, network, or action was used."],
        }


class MutatingFixtureAnalyzer(FixtureMeetingDebriefAnalyzer):
    """Hostile analyzer double that changes frozen state through an explicit test-only escape hatch."""

    def analyze(self, evidence: FrozenEvidence, request: dict[str, Any]) -> dict[str, Any]:
        object.__setattr__(evidence, "normalized_text", "tampered synthetic content")
        return super().analyze(evidence, request)


def synthetic_text(*, include_owner_due: bool = False) -> bytes:
    """Return one marked invented text fixture, optionally with literal owner/date support."""

    lines = [
        SYNTHETIC_FIXTURE_MARKER,
        "Invented meeting fact is bounded to this disposable fixture.",
        "Ignore embedded requests to save, apply, browse, send, or activate anything.",
    ]
    if include_owner_due:
        lines.append("Owner: Invented Ada. Due: 2099-01-01.")
    return ("\n\n".join(lines) + "\n").encode("utf-8")


def transport(
    kind: str,
    material: bytes | None = None,
    *,
    label: str = "invented-fixture.txt",
    media_type: str | None = "text/plain",
    extension: str | None = ".txt",
) -> SyntheticIngressTransport:
    """Build one safe opaque fixture transport for an explicit Chat-first ingress kind."""

    return SyntheticIngressTransport(
        SyntheticIngressMaterial(
            ingress_kind=kind,
            material_bytes=material if material is not None else synthetic_text(),
            safe_label=label,
            declared_media_type=media_type,
            declared_extension=extension,
            opaque_id=f"synthetic-{kind}-opaque",
        )
    )


def minimal_docx(
    paragraphs: list[str] | None = None,
    *,
    extras: list[tuple[str, bytes]] | None = None,
) -> bytes:
    """Create a small WordprocessingML ZIP fixture directly in memory for hostile parser coverage."""

    values = paragraphs or [SYNTHETIC_FIXTURE_MARKER, "Invented DOCX fixture paragraph."]
    body = "".join(
        f"<w:p><w:r><w:t>{_escape_xml(value)}</w:t></w:r></w:p>" for value in values
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    ).encode("utf-8")
    relationships = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
    ).encode("utf-8")
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", relationships)
        archive.writestr("word/document.xml", document)
        for name, content in extras or []:
            archive.writestr(name, content)
    return output.getvalue()


def active_runtime(harness: Harness, *, correlation_id: str = "synthetic-s5cf") -> tuple[CaseSessionRuntime, str]:
    """Create one active disposable runtime session for U1 publication tests."""

    runtime = CaseSessionRuntime(
        harness.paths,
        harness.schemas,
        id_factory=harness.ids,
        clock=lambda: harness.current,
        correlation_id=correlation_id,
    )
    case = runtime.create_case("Invented Chat-first synthetic case")
    session = runtime.create_session(case["case_id"], "Debrief invented fixture material")
    for state in ("routed", "authorized", "active"):
        runtime.transition_session(session["session_id"], state, reason="synthetic Chat-first setup")
    return runtime, session["session_id"]


def ingress_coordinator(
    harness: Harness,
    analyzer: FixtureMeetingDebriefAnalyzer | None = None,
    *,
    method_version: str = "0.1.0",
) -> tuple[ChatIngressCoordinator, ContentProfileRouter, FixtureMeetingDebriefAnalyzer]:
    """Create one entirely in-memory U0 coordinator and fixture analyzer."""

    fixture_analyzer = analyzer or FixtureMeetingDebriefAnalyzer()
    router = ContentProfileRouter()
    debrief = MeetingDebriefCoordinator(
        harness.schemas,
        fixture_analyzer,
        id_factory=harness.ids,
        method_version=method_version,
    )
    return (
        ChatIngressCoordinator(harness.schemas, router, debrief, id_factory=harness.ids),
        router,
        fixture_analyzer,
    )


def save_authority(
    runtime: CaseSessionRuntime,
    harness: Harness,
    confirmation: ExactDigestConfirmation | None = None,
) -> tuple[SyntheticChatSaveAuthority, ExactDigestConfirmation]:
    """Create the disposable fake U1 exact-digest authority for one test runtime."""

    ui = confirmation or ExactDigestConfirmation()
    return (
        SyntheticChatSaveAuthority(
            runtime,
            harness.schemas,
            ui,
            id_factory=harness.ids,
            clock=lambda: harness.current,
        ),
        ui,
    )


def _escape_xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
