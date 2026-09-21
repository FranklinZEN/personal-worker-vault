"""Bounded, in-memory content profiles for Chat-first ingress.

The router receives already-supplied bytes. It never opens a path, resolves a link, runs a
converter, or renders an office document.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from typing import Iterable
from xml.etree import ElementTree
import zipfile

from vault_next.canonical import canonical_sha256, sha256_hex


SYNTHETIC_FIXTURE_MARKER = "VAULT_NEXT_CHAT_SYNTHETIC_FIXTURE"
_WORD_NAMESPACE = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_RELATIONSHIP_NAMESPACE = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_MAX_MATERIAL_BYTES = 1_048_576
_MAX_ZIP_ENTRIES = 128
_MAX_ZIP_TOTAL_UNCOMPRESSED = 2_097_152
_MAX_ZIP_ENTRY_UNCOMPRESSED = 524_288
_MAX_EXPANSION_RATIO = 100
_MAX_ANCHORS = 256
_MAX_ANCHOR_BYTES = 16_384


class ContentProfileError(RuntimeError):
    """The supplied ingress material cannot be safely normalized."""


@dataclass(frozen=True)
class EvidenceAnchor:
    """One exact normalized-text unit used for citations and result validation."""

    anchor: str
    ordinal: int
    text: str
    text_sha256: str

    def to_record(self) -> dict[str, object]:
        """Return the non-content locator retained in the evidence packet."""

        return {
            "anchor": self.anchor,
            "ordinal": self.ordinal,
            "text_sha256": self.text_sha256,
        }


@dataclass(frozen=True)
class NormalizedContent:
    """Immutable parser output; source text remains in-memory until an optional U1 save."""

    profile_id: str
    profile_version: str
    normalized_text: str
    normalized_text_sha256: str
    anchors: tuple[EvidenceAnchor, ...]
    omissions: tuple[dict[str, str | None], ...]

    @property
    def normalized_byte_count(self) -> int:
        """Return the UTF-8 size of the derived normalized text."""

        return len(self.normalized_text.encode("utf-8"))

    @property
    def normalized_evidence_sha256(self) -> str:
        """Bind profile, normalized bytes, anchors, and omissions without provenance."""

        return canonical_sha256(
            {
                "profile_id": self.profile_id,
                "profile_version": self.profile_version,
                "normalized_text_sha256": self.normalized_text_sha256,
                "normalized_byte_count": self.normalized_byte_count,
                "anchors": [anchor.to_record() for anchor in self.anchors],
                "omissions": list(self.omissions),
            }
        )


class ContentProfileRouter:
    """Select and execute only the registered in-memory text, Markdown, and DOCX profiles."""

    def __init__(
        self,
        *,
        max_material_bytes: int = _MAX_MATERIAL_BYTES,
        max_zip_total_uncompressed: int = _MAX_ZIP_TOTAL_UNCOMPRESSED,
        max_anchors: int = _MAX_ANCHORS,
    ) -> None:
        if max_material_bytes < 1 or max_zip_total_uncompressed < 1 or max_anchors < 1:
            raise ValueError("content profile limits must be positive")
        self.max_material_bytes = max_material_bytes
        self.max_zip_total_uncompressed = max_zip_total_uncompressed
        self.max_anchors = max_anchors

    def route(
        self,
        material: bytes,
        *,
        declared_media_type: str | None,
        declared_extension: str | None,
    ) -> NormalizedContent:
        """Normalize supplied bytes after bounded signature-first profile selection."""

        if not isinstance(material, bytes) or not material:
            raise ContentProfileError("ingress material must be nonempty bytes")
        if len(material) > self.max_material_bytes:
            raise ContentProfileError("ingress material exceeds the byte budget")
        if _looks_like_zip(material):
            return self._route_docx(material)
        if b"\x00" in material:
            raise ContentProfileError("text ingress material contains a NUL byte")
        try:
            text = material.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ContentProfileError("text ingress material is not strict UTF-8") from exc
        profile = (
            "markdown_text"
            if declared_media_type == "text/markdown"
            or (declared_extension or "").casefold() in {".md", ".markdown"}
            else "plain_text"
        )
        return _normalized(
            profile, text, _text_units(text, markdown=profile == "markdown_text"), max_anchors=self.max_anchors
        )

    def _route_docx(self, material: bytes) -> NormalizedContent:
        entries = _safe_docx_entries(
            material,
            max_total_uncompressed=self.max_zip_total_uncompressed,
        )
        document = entries.get("word/document.xml")
        if document is None:
            raise ContentProfileError("DOCX fixture has no word/document.xml")
        _require_safe_xml(document, "DOCX document XML")
        try:
            root = ElementTree.fromstring(document)
        except ElementTree.ParseError as exc:
            raise ContentProfileError("DOCX fixture document XML is malformed") from exc
        paragraphs: list[str] = []
        for paragraph in root.iter(f"{_WORD_NAMESPACE}p"):
            text = "".join(node.text or "" for node in paragraph.iter(f"{_WORD_NAMESPACE}t"))
            if text:
                paragraphs.append(text)
        if not paragraphs:
            raise ContentProfileError("DOCX fixture has no extractable paragraph text")
        units = [(f"paragraph:{index:06d}", text) for index, text in enumerate(paragraphs, start=1)]
        return _normalized(
            "docx_wordprocessingml", "\n".join(paragraphs), units, max_anchors=self.max_anchors
        )


def _looks_like_zip(material: bytes) -> bool:
    return material.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))


def _safe_docx_entries(material: bytes, *, max_total_uncompressed: int) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(BytesIO(material))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ContentProfileError("synthetic DOCX fixture is not a valid ZIP container") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_ZIP_ENTRIES:
            raise ContentProfileError("DOCX fixture entry count is outside the bounded profile")
        names: set[str] = set()
        total = 0
        for info in infos:
            _require_safe_zip_info(info, names)
            names.add(info.filename)
            total += info.file_size
            if total > max_total_uncompressed:
                raise ContentProfileError("DOCX fixture exceeds the total expansion budget")
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            raise ContentProfileError("DOCX fixture is missing required Open XML parts")
        if any(name.casefold().endswith("vbaproject.bin") for name in names):
            raise ContentProfileError("DOCX fixture macro content is unsupported")
        if any(name.startswith("word/embeddings/") for name in names):
            raise ContentProfileError("DOCX fixture embedded objects are unsupported")
        entries: dict[str, bytes] = {}
        for info in infos:
            try:
                content = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise ContentProfileError("DOCX fixture ZIP entry cannot be read safely") from exc
            if len(content) != info.file_size:
                raise ContentProfileError("DOCX fixture ZIP entry size changed during read")
            entries[info.filename] = content
        _require_safe_xml(entries["[Content_Types].xml"], "DOCX content types")
        if not any(
            b"wordprocessingml.document.main+xml" in content
            for name, content in entries.items()
            if name == "[Content_Types].xml"
        ):
            raise ContentProfileError("DOCX fixture content type is not a WordprocessingML document")
        for name, content in entries.items():
            if name.endswith(".rels"):
                _require_no_external_relationships(content)
        return entries


def _require_safe_zip_info(info: zipfile.ZipInfo, names: set[str]) -> None:
    parts = info.filename.split("/")
    if (
        not info.filename
        or info.filename.startswith("/")
        or "\\" in info.filename
        or any(part in {"", ".", ".."} for part in parts)
        or info.filename in names
    ):
        raise ContentProfileError("DOCX fixture contains an unsafe or duplicate ZIP entry")
    if info.flag_bits & 0x1:
        raise ContentProfileError("DOCX fixture encrypted ZIP entries are unsupported")
    if info.file_size < 0 or info.file_size > _MAX_ZIP_ENTRY_UNCOMPRESSED:
        raise ContentProfileError("DOCX fixture ZIP entry exceeds the uncompressed byte budget")
    if info.file_size and info.compress_size <= 0:
        raise ContentProfileError("DOCX fixture ZIP entry has an invalid compressed size")
    if info.compress_size and info.file_size > info.compress_size * _MAX_EXPANSION_RATIO:
        raise ContentProfileError("DOCX fixture ZIP entry exceeds the expansion-ratio budget")


def _require_safe_xml(content: bytes, label: str) -> None:
    lowered = content.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ContentProfileError(f"{label} declares an unsupported XML entity")


def _require_no_external_relationships(content: bytes) -> None:
    _require_safe_xml(content, "DOCX relationship XML")
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        raise ContentProfileError("DOCX relationship XML is malformed") from exc
    for relationship in root.iter(f"{_RELATIONSHIP_NAMESPACE}Relationship"):
        if relationship.attrib.get("TargetMode") == "External":
            raise ContentProfileError("DOCX fixture external relationships are unsupported")


def _text_units(text: str, *, markdown: bool) -> list[tuple[str, str]]:
    lines = text.splitlines()
    units: list[tuple[str, str]] = []
    start: int | None = None
    buffered: list[str] = []

    def finish(end_line: int) -> None:
        nonlocal start, buffered
        if start is not None and buffered:
            units.append((f"line:{start:06d}-{end_line:06d}", "\n".join(buffered)))
        start = None
        buffered = []

    for line_number, line in enumerate(lines, start=1):
        heading = markdown and line.lstrip().startswith("#") and line.lstrip().startswith("# ")
        if heading:
            finish(line_number - 1)
            units.append((f"line:{line_number:06d}-{line_number:06d}", line))
        elif line.strip():
            if start is None:
                start = line_number
            buffered.append(line)
        else:
            finish(line_number - 1)
    finish(len(lines))
    if not units and text:
        units.append(("line:000001-000001", text))
    return units


def _normalized(
    profile_id: str,
    normalized_text: str,
    units: Iterable[tuple[str, str]],
    *,
    max_anchors: int = _MAX_ANCHORS,
) -> NormalizedContent:
    anchors: list[EvidenceAnchor] = []
    omissions: list[dict[str, str | None]] = []
    for ordinal, (anchor, text) in enumerate(units, start=1):
        data = text.encode("utf-8")
        if len(data) > _MAX_ANCHOR_BYTES:
            omissions.append({"anchor": anchor, "reason": "unit_exceeds_chat_profile_budget"})
            continue
        anchors.append(EvidenceAnchor(anchor, ordinal, text, sha256_hex(data)))
        if len(anchors) > max_anchors:
            raise ContentProfileError("ingress content has too many citation units")
    if not anchors:
        raise ContentProfileError("ingress content has no bounded citation units")
    return NormalizedContent(
        profile_id=profile_id,
        profile_version="1.0",
        normalized_text=normalized_text,
        normalized_text_sha256=sha256_hex(normalized_text.encode("utf-8")),
        anchors=tuple(anchors),
        omissions=tuple(omissions),
    )
