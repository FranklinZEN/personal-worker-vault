"""Read-only real U0 operating views over one explicitly selected admitted event.

This is deliberately a production sibling of ``operating_view_query/0.1``, not an expansion of that
hostile-synthetic component.  It reads only an exact event, its event-linked artifact object, explicitly
listed generated workspace pages, and the existing event-bound FTS citation rows.  It never opens a
canonical source object or writes a bundle, workspace, receipt, event, query history, or working artifact.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.readable_projections import parse_markdown_projection_header
from vault_next.private_workspace import _verify_page


COMPONENT = "vault-next-operating-view-real-u0/0.1.0"
_EVENT = re.compile(r"^event_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INTENTS = frozenset({"continuity", "decision_dependency", "next_evidence"})
_SECTION_BY_INTENT = {
    "continuity": ("executive_spine", "reconciliation", "omissions"),
    "decision_dependency": ("decision_dependency_ledger",),
    "next_evidence": ("next_evidence", "omissions"),
}
_MARKDOWN_KIND = {
    "continuity": "work_continuity",
    "decision_dependency": "decision",
    "next_evidence": "work_preparation",
}


class RealOperatingViewError(RuntimeError):
    """The exact selected real U0 material cannot safely produce an operating view."""


@dataclass(frozen=True)
class RealOperatingViewPage:
    """One explicit generated workspace page; no directory discovery is permitted."""

    intent: Literal["continuity", "decision_dependency", "next_evidence"]
    relative_path: str


@dataclass(frozen=True)
class RealOperatingViewResult:
    """A U0-only clean view with exact event/artifact/FTS citation bindings."""

    intent: Literal["continuity", "decision_dependency", "next_evidence"]
    display_alias: str
    event_id: str
    artifact_sha256: str
    markdown: str
    evidence_companion: str
    sidecar: dict[str, object]


class RealOperatingViewReader:
    """Build one natural-request result from an explicitly bounded already-admitted publication."""

    def __init__(
        self,
        bundle_root: Path,
        *,
        event_id: str,
        artifact_sha256: str,
        pages: tuple[RealOperatingViewPage, ...],
    ) -> None:
        self.root = _open_private_root(bundle_root)
        if not _EVENT.fullmatch(event_id) or not _DIGEST.fullmatch(artifact_sha256):
            raise RealOperatingViewError("real operating-view event or artifact identifier is invalid")
        if len(pages) != 3 or {page.intent for page in pages} != _INTENTS:
            raise RealOperatingViewError("real operating-view requires exactly three explicit intent pages")
        if len({page.relative_path for page in pages}) != len(pages):
            raise RealOperatingViewError("real operating-view page list is duplicated")
        if any(not _safe_relative(page.relative_path) for page in pages):
            raise RealOperatingViewError("real operating-view page escaped the generated workspace")
        self.event_id = event_id
        self.artifact_sha256 = artifact_sha256
        self.pages = {page.intent: page for page in pages}

    def query(self, natural_request: str) -> RealOperatingViewResult:
        """Resolve one of three bounded natural requests without writes or source fallback."""

        intent = _parse_intent(natural_request)
        event = self._load_event()
        artifact = self._load_artifact(event)
        page = self._load_page(intent, artifact)
        citation_text = self._citation_catalog(artifact)
        claims = self._claims(artifact, intent)
        candidate_anchors = tuple(
            dict.fromkeys(anchor for claim in claims for anchor in claim[1] if anchor in citation_text)
        )
        available = self._available_anchors(candidate_anchors, citation_text)
        supported, unavailable_count = _supported_claims(claims, citation_text, available)
        all_anchors = tuple(dict.fromkeys(anchor for claim in supported for anchor in claim[1]))
        display_alias = page["display_alias"]
        numbers = {anchor: index for index, anchor in enumerate(all_anchors, start=1)}
        markdown = _render_markdown(intent, display_alias, supported, numbers, unavailable_count)
        companion = _render_companion(all_anchors, citation_text, numbers)
        sidecar: dict[str, object] = {
            "component": COMPONENT,
            "intent": intent,
            "event_id": self.event_id,
            "artifact_sha256": self.artifact_sha256,
            "workspace_relative_path": self.pages[intent].relative_path,
            "workspace_item_id": page["item_id"],
            "workspace_version_id": page["version_id"],
            "citations": [
                {
                    "ordinal": numbers[anchor],
                    "anchor": anchor,
                    "evidence_sha256": citation_text[anchor],
                }
                for anchor in all_anchors
            ],
            "withheld_claim_count": unavailable_count,
            "ephemeral": True,
            "no_automatic_persistence": True,
            "no_authority": ["no_u1", "no_u2", "no_s2", "no_activation", "no_current_work"],
        }
        return RealOperatingViewResult(
            intent, display_alias, self.event_id, self.artifact_sha256, markdown, companion, sidecar
        )

    def _load_event(self) -> dict[str, object]:
        path = _inside(self.root, self.root / "canonical" / "events" / f"{self.event_id}.json")
        event = _read_json(path, "real operating-view event")
        required = {
            "admission_id", "artifact_object_sha256", "candidate_package_object_sha256", "event_id",
            "manifest_digest", "publication_type", "receipt_id", "recorded_at",
            "relationship_ledger_object_sha256", "schema_version", "source_items",
        }
        if set(event) != required or event.get("event_id") != self.event_id:
            raise RealOperatingViewError("real operating-view event shape is invalid")
        if event.get("publication_type") != "chat_first_u1_multi_source_save":
            raise RealOperatingViewError("real operating-view event purpose is outside the selected wave")
        if event.get("artifact_object_sha256") != self.artifact_sha256:
            raise RealOperatingViewError("real operating-view event artifact binding changed")
        if not isinstance(event["source_items"], list) or len(event["source_items"]) != 4:
            raise RealOperatingViewError("real operating-view selected event source scope is invalid")
        return event

    def _load_artifact(self, event: dict[str, object]) -> dict[str, object]:
        del event
        path = _inside(
            self.root, self.root / "canonical" / "artifact-objects" / self.artifact_sha256
        )
        if path.is_symlink() or not path.is_file():
            raise RealOperatingViewError("real operating-view artifact is unavailable")
        material = path.read_bytes()
        if sha256_hex(material) != self.artifact_sha256:
            raise RealOperatingViewError("real operating-view artifact digest changed")
        try:
            artifact = json.loads(material)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RealOperatingViewError("real operating-view artifact is invalid") from exc
        required = {
            "artifact_kind", "citation_text", "result", "schema_version", "u0_result_sha256",
            "wave_id", "workspace_items",
        }
        if not isinstance(artifact, dict) or set(artifact) != required:
            raise RealOperatingViewError("real operating-view artifact shape is invalid")
        result = artifact["result"]
        if not isinstance(result, dict) or artifact["u0_result_sha256"] != result.get("result_sha256"):
            raise RealOperatingViewError("real operating-view result binding changed")
        material_result = {key: value for key, value in result.items() if key != "result_sha256"}
        if canonical_sha256(material_result) != result["result_sha256"]:
            raise RealOperatingViewError("real operating-view result digest changed")
        if artifact["artifact_kind"] != "work_continuity_wave" or artifact["wave_id"] != "S6-W2-C1":
            raise RealOperatingViewError("real operating-view artifact is outside the selected wave")
        if not isinstance(artifact["workspace_items"], list) or len(artifact["workspace_items"]) != 3:
            raise RealOperatingViewError("real operating-view workspace binding is invalid")
        return artifact

    def _load_page(self, intent: str, artifact: dict[str, object]) -> dict[str, object]:
        page_path = _inside(self.root, self.root / self.pages[intent].relative_path)
        if page_path.is_symlink() or not page_path.is_file():
            raise RealOperatingViewError("real operating-view generated page is unavailable")
        content = page_path.read_text(encoding="utf-8")
        if not _verify_page(content):
            raise RealOperatingViewError("real operating-view generated page requires rebuild")
        metadata = parse_markdown_projection_header(content)["metadata"]
        if metadata.get("canonical_object_sha256") != self.artifact_sha256:
            raise RealOperatingViewError("real operating-view generated page artifact binding changed")
        if f"Source event: {self.event_id}." not in content:
            raise RealOperatingViewError("real operating-view generated page event binding changed")
        matching = [
            item
            for item in artifact["workspace_items"]  # type: ignore[index]
            if isinstance(item, dict) and item.get("family") and item.get("view") == "reported"
            and _MARKDOWN_KIND[intent] == _artifact_kind_for_item(item)
        ]
        if len(matching) != 1:
            raise RealOperatingViewError("real operating-view page cannot bind one selected artifact")
        item = matching[0]
        if not isinstance(item.get("body"), str) or item["body"] not in content:
            raise RealOperatingViewError("real operating-view generated page body binding changed")
        if item.get("display_alias") not in content:
            raise RealOperatingViewError("real operating-view generated page display binding changed")
        if metadata.get("item_id") != item.get("item_id") or metadata.get("version_id") != item.get("version_id"):
            raise RealOperatingViewError("real operating-view generated page item binding changed")
        return item

    @staticmethod
    def _claims(artifact: dict[str, object], intent: str) -> tuple[tuple[str, tuple[str, ...], str], ...]:
        result = artifact["result"]
        assert isinstance(result, dict)
        values: list[tuple[str, tuple[str, ...], str]] = []
        for section in _SECTION_BY_INTENT[intent]:
            section_values = result.get(section)
            if not isinstance(section_values, list):
                raise RealOperatingViewError("real operating-view result section is unavailable")
            for value in section_values:
                if (
                    not isinstance(value, dict)
                    or not isinstance(value.get("statement"), str)
                    or not isinstance(value.get("claim_class"), str)
                    or not isinstance(value.get("citations"), list)
                    or not value["citations"]
                    or any(not isinstance(anchor, str) for anchor in value["citations"])
                ):
                    raise RealOperatingViewError("real operating-view result claim is invalid")
                values.append((value["statement"], tuple(value["citations"]), value["claim_class"]))
        if not values:
            raise RealOperatingViewError("real operating-view selected intent has no claims")
        return tuple(values)

    @staticmethod
    def _citation_catalog(artifact: dict[str, object]) -> dict[str, str]:
        raw = artifact["citation_text"]
        if not isinstance(raw, list):
            raise RealOperatingViewError("real operating-view citation catalog is invalid")
        result: dict[str, str] = {}
        for row in raw:
            if (
                not isinstance(row, list)
                or len(row) != 2
                or not isinstance(row[0], str)
                or not isinstance(row[1], str)
                or not _DIGEST.fullmatch(row[1])
                or row[0] in result
            ):
                raise RealOperatingViewError("real operating-view citation binding is invalid")
            result[row[0]] = row[1]
        return result

    def _available_anchors(self, anchors: tuple[str, ...], catalog: dict[str, str]) -> frozenset[str]:
        """Return only anchors whose one retained FTS row exactly matches the event catalog."""

        if not anchors:
            return frozenset()
        database = _inside(self.root, self.root / "derived" / "fts5" / "citations.sqlite3")
        if database.is_symlink() or not database.is_file():
            raise RealOperatingViewError("real operating-view derived citation index is unavailable")
        try:
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                rows = connection.execute(
                    "SELECT anchor, text FROM citations WHERE event_id = ? AND anchor IN ("
                    + ",".join("?" for _ in anchors)
                    + ")",
                    (self.event_id, *anchors),
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise RealOperatingViewError("real operating-view derived citation index cannot be read") from exc
        grouped: dict[str, list[str]] = {anchor: [] for anchor in anchors}
        for anchor, text in rows:
            if isinstance(anchor, str) and isinstance(text, str) and anchor in grouped:
                grouped[anchor].append(text)
        return frozenset(
            anchor
            for anchor, texts in grouped.items()
            if len(texts) == 1 and sha256_hex(texts[0].encode("utf-8")) == catalog[anchor]
        )


def _parse_intent(natural_request: str) -> Literal["continuity", "decision_dependency", "next_evidence"]:
    if not isinstance(natural_request, str) or not natural_request.strip() or len(natural_request.encode()) > 1024:
        raise RealOperatingViewError("real operating-view natural request is invalid")
    normalized = " ".join(natural_request.casefold().split())
    if "continuity" in normalized or "what changed" in normalized:
        return "continuity"
    if "decision" in normalized or "dependenc" in normalized or "unresolved" in normalized:
        return "decision_dependency"
    if "evidence" in normalized or "gather" in normalized or "prepar" in normalized:
        return "next_evidence"
    raise RealOperatingViewError("real operating-view natural request is outside the three supported intents")


def _render_markdown(
    intent: str,
    display_alias: str,
    claims: tuple[tuple[str, tuple[str, ...], str], ...],
    numbers: dict[str, int],
    unavailable_count: int,
) -> str:
    lines = [
        f"# {display_alias}",
        "",
        f"Operating view: {intent.replace('_', ' ')}.",
        "State: source-reported, proposed, conflicting, unknown, or unavailable as labelled below; "
        "no current work is adopted.",
        "",
        "## Evidence-backed view",
        "",
    ]
    if claims:
        for statement, citations, claim_class in claims:
            refs = " ".join(f"[E{numbers[anchor]}]" for anchor in citations)
            lines.append(f"- **{claim_class}:** {statement} {refs}")
    else:
        lines.append("- No claims are displayed because none has a retained exact citation binding.")
    if unavailable_count:
        lines.extend(
            [
                "",
                "## Citation availability",
                "",
                f"- {unavailable_count} claim(s) are withheld because their retained event citation "
                "binding is unavailable. No substitute evidence was inferred.",
            ]
        )
    lines.extend(
        [
            "",
            "## Scope and limits",
            "",
            "- This is a read-only U0 view of one already admitted S6-W2 publication.",
            "- It does not read an original source, save a result, adopt work, activate a candidate, "
            "or authorize an action.",
            "- Open the optional evidence companion for exact anchors and digests.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_companion(anchors: tuple[str, ...], catalog: dict[str, str], numbers: dict[str, int]) -> str:
    lines = [
        "# Evidence companion",
        "",
        "This companion binds the read-only operating view to exact event-scoped FTS evidence.",
        "",
        "| Evidence | Source anchor | Evidence digest |",
        "| --- | --- | --- |",
    ]
    for anchor in anchors:
        lines.append(f"| E{numbers[anchor]} | `{anchor}` | `{catalog[anchor]}` |")
    return "\n".join(lines) + "\n"


def _supported_claims(
    claims: tuple[tuple[str, tuple[str, ...], str], ...],
    catalog: dict[str, str],
    available: frozenset[str],
) -> tuple[tuple[tuple[str, tuple[str, ...], str], ...], int]:
    """Withhold only claims missing retained bindings; all displayed claims stay exact-citation-bound."""

    supported: list[tuple[str, tuple[str, ...], str]] = []
    unavailable = 0
    for claim in claims:
        if any(anchor not in catalog or anchor not in available for anchor in claim[1]):
            unavailable += 1
        else:
            supported.append(claim)
    return tuple(supported), unavailable


def _artifact_kind_for_item(item: dict[str, object]) -> str:
    family = item.get("family")
    alias = item.get("display_alias")
    if family == "work" and isinstance(alias, str) and "continuity" in alias.casefold():
        return "work_continuity"
    if family == "decision":
        return "decision"
    if family == "work" and isinstance(alias, str) and "next evidence" in alias.casefold():
        return "work_preparation"
    return "unsupported"


def _open_private_root(root: Path) -> Path:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RealOperatingViewError("real operating-view bundle root is unavailable")
    if root.stat().st_mode & 0o077:
        raise RealOperatingViewError("real operating-view bundle root is not owner-only")
    return root.resolve(strict=True)


def _inside(root: Path, path: Path) -> Path:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RealOperatingViewError("real operating-view path escaped its private root") from exc
    return resolved


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and path.parts[:1] == ("workspace",)
        and ".." not in path.parts
        and "\\" not in value
        and "\x00" not in value
    )


def _read_json(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise RealOperatingViewError(f"{label} is unavailable")
    try:
        material = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RealOperatingViewError(f"{label} is invalid") from exc
    if not isinstance(material, dict):
        raise RealOperatingViewError(f"{label} shape is invalid")
    return material
