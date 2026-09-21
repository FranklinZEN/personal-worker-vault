"""S6-W1 bounded meeting-family orchestration over one frozen meeting source.

The visible host supplies analytical content. This module reads no ambient context, invokes no model
or network capability, and grants no effect authority. It validates one exact E1/M1/M2 selection and
composes the existing private U1 admission packet without changing publication or recovery semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.codex_project_native import NativeU0Preparation
from vault_next.content_profiles import EvidenceAnchor
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.private_admission import PrivateAdmissionInput, PrivateAdmissionPublisher
from vault_next.private_workspace import PrivateWorkspaceItem, build_u1_manifest
from vault_next.records import SchemaRegistry


COMPONENT_ID = "vault-next-meeting-family-wave/0.1.0"
WAVE_ID = "S6-W1-C1"
_METHOD_ROLES = {"M1": "meeting-prep", "M2": "meeting-self-review"}
_SECTIONS = {
    "executive_spine": {
        "reported_fact", "reported_decision", "proposal", "commitment", "risk", "conflict", "unknown"
    },
    "decisions": {"reported_decision"},
    "proposals": {"proposal"},
    "dissent": {"conflict"},
    "commitments": {"commitment"},
    "rationale_tradeoffs": {"reported_fact", "conflict"},
    "dependencies": {"reported_fact", "risk", "unknown"},
    "risks": {"risk"},
    "omissions": {"unknown", "unavailable"},
    "open_questions": {"unknown", "unavailable"},
    "continuity": {"proposal", "unknown", "unavailable"},
    "next_meeting_preparation": {"proposal", "unknown"},
    "self_review": {"reported_fact", "proposal", "unknown", "unavailable"},
}
_NO_EFFECTS = (
    "no_activation", "no_promotion", "no_current_work", "no_u2", "no_s2_apply", "no_send",
    "no_connector", "no_network", "no_model_call_by_vault_next",
)


class MeetingWorkflowError(RuntimeError):
    """The bounded S6-W1 selection or result violated its contract."""


@dataclass(frozen=True)
class MeetingMethodSource:
    role: str
    method_name: str
    method_version: str
    source_locator: str
    safe_label: str
    source_bytes: bytes
    portable_core: tuple[str, ...]


@dataclass(frozen=True)
class MeetingWave:
    result: dict[str, Any]
    packet: PrivateAdmissionInput
    selected_scope: dict[str, Any]


class S6MeetingWorkflowCoordinator:
    """Build one complete inactive meeting-family U0/U1 wave."""

    def __init__(self, schemas: SchemaRegistry, *, id_factory: ULIDFactory = DEFAULT_FACTORY) -> None:
        self.schemas = schemas
        self.ids = id_factory

    def prepare_wave(
        self,
        *,
        preparation: NativeU0Preparation,
        source_bytes: bytes,
        source_locator: str,
        methods: tuple[MeetingMethodSource, ...],
        hosted_result: object,
        bundle_id: str,
        expires_at: datetime,
        prior_artifact_version_id: str | None = None,
    ) -> MeetingWave:
        preparation.evidence.verify()
        if sha256_hex(source_bytes) != preparation.ingress_envelope["material_sha256"]:
            raise MeetingWorkflowError("S6-W1 E1 changed after its exact-source preflight")
        ordered_methods = self._methods(methods)
        result = self._result(preparation, hosted_result, ordered_methods)
        candidate = self._candidate_package(ordered_methods)
        source_version_id = self.ids.new("source_version")
        relationships = self._relationships(
            source_version_id, result, candidate, prior_artifact_version_id
        )
        citation_text = tuple((anchor.anchor, anchor.text) for anchor in preparation.evidence.anchors)
        items = self._workspace_items(result, candidate)
        artifact = {
            "schema_version": "1.0",
            "artifact_kind": "meeting_family_wave",
            "wave_id": WAVE_ID,
            "u0_result_sha256": result["result_sha256"],
            "result": result,
            "citation_text": [list(row) for row in citation_text],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item) for item in items],
        }
        scope = {
            "wave_id": WAVE_ID,
            "selected_inputs": [
                {
                    "role": "E1", "source_locator": source_locator,
                    "safe_label": preparation.ingress_envelope["safe_label"],
                    "content_sha256": sha256_hex(source_bytes),
                },
                *[
                    {
                        "role": method.role, "source_locator": method.source_locator,
                        "safe_label": method.safe_label, "content_sha256": sha256_hex(method.source_bytes),
                    }
                    for method in ordered_methods
                ],
            ],
            "excluded_inputs": ["E2-E8", "outbound_draft", "ambient_context", "parent_directory_scan"],
        }
        manifest = build_u1_manifest(
            ids=self.ids,
            expires_at=expires_at,
            bundle_id=bundle_id,
            ingress_envelope_sha256=canonical_sha256(preparation.ingress_envelope),
            source_sha256=sha256_hex(source_bytes), source_size=len(source_bytes),
            u0_result_sha256=result["result_sha256"], artifact_sha256=canonical_sha256(artifact),
            candidate_package_sha256=canonical_sha256(candidate),
            relationship_ledger_sha256=canonical_sha256(relationships),
            profile_id=preparation.normalized.profile_id,
            safe_label=preparation.ingress_envelope["safe_label"],
            citations=tuple(anchor for anchor, _text in citation_text),
            schemas=self.schemas, wave_scope=scope,
        )
        packet = PrivateAdmissionInput(
            manifest=manifest, source_bytes=source_bytes,
            source_version={
                "source_version_id": source_version_id,
                "content_sha256": sha256_hex(source_bytes), "byte_count": len(source_bytes),
                "profile_id": preparation.normalized.profile_id,
                "provenance_sha256": canonical_sha256(preparation.ingress_envelope["provenance"]),
            },
            artifact=artifact, candidate_package=candidate,
            relationship_assertions=tuple(relationships), citation_text=citation_text,
            workspace_items=items,
        )
        return MeetingWave(result=result, packet=packet, selected_scope=scope)

    def _methods(self, methods: tuple[MeetingMethodSource, ...]) -> tuple[MeetingMethodSource, ...]:
        if len(methods) != 2 or {method.role for method in methods} != set(_METHOD_ROLES):
            raise MeetingWorkflowError("S6-W1 requires exactly M1 and M2; no ambient method is allowed")
        ordered = tuple(sorted(methods, key=lambda method: method.role))
        for method in ordered:
            if (
                method.method_name != _METHOD_ROLES[method.role]
                or not method.method_version.startswith("0.")
                or not method.source_locator.startswith("/")
                or not method.safe_label.endswith(".md")
                or not isinstance(method.source_bytes, bytes) or not method.source_bytes
                or len(method.source_bytes) > 262_144
                or not method.portable_core or len(set(method.portable_core)) != len(method.portable_core)
            ):
                raise MeetingWorkflowError("S6-W1 method selection is invalid")
            try:
                method.source_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise MeetingWorkflowError("S6-W1 method source must be exact UTF-8 Markdown") from exc
        return ordered

    def _candidate_package(self, methods: tuple[MeetingMethodSource, ...]) -> dict[str, Any]:
        members = [
            {
                "candidate_id": self.ids.new("skill_candidate"), "method_name": method.method_name,
                "method_version": method.method_version, "safe_label": method.safe_label,
                "method_source_sha256": sha256_hex(method.source_bytes),
                "method_source_markdown": method.source_bytes.decode("utf-8"),
                "portable_core": list(method.portable_core), "lifecycle": "inactive",
            }
            for method in methods
        ]
        combined = canonical_sha256([
            {"method_name": item["method_name"], "source_sha256": item["method_source_sha256"]}
            for item in members
        ])
        package = {
            "schema_version": "1.0", "candidate_id": self.ids.new("skill_candidate"),
            "family": "meeting_workflow", "package_version": "1.1",
            "ingress_profiles": ["plain_text", "markdown_text", "docx_wordprocessingml"],
            "required_sections": ["granular_debrief", "continuity", "next_meeting_preparation", "self_review"],
            "prohibitions": list(_NO_EFFECTS), "method_source_sha256": combined,
            "method_source_markdown": "\n\n".join(item["method_source_markdown"] for item in members),
            "members": members, "lifecycle": "inactive",
        }
        self.schemas.require("method-candidate-package", package)
        return package

    def _result(
        self, preparation: NativeU0Preparation, raw: object, methods: tuple[MeetingMethodSource, ...]
    ) -> dict[str, Any]:
        _validate_hosted_result(raw, preparation.evidence.anchors)
        assert isinstance(raw, dict)
        material = {
            "schema_version": "1.0", "component": COMPONENT_ID, "wave_id": WAVE_ID,
            "meeting_id": self.ids.new("meeting_debrief"),
            "evidence_sha256": preparation.evidence.evidence_sha256,
            "method_versions": {
                "meeting-debrief": "0.3.0",
                **{method.method_name: method.method_version for method in methods},
            },
            **raw, "candidate_lifecycle": "inactive", "persistence": "ephemeral_pending_u1",
            "no_effects": list(_NO_EFFECTS),
        }
        return {**material, "result_sha256": canonical_sha256(material)}

    def _relationships(
        self,
        source_version_id: str,
        result: dict[str, Any],
        candidate: dict[str, Any],
        prior_artifact_version_id: str | None,
    ) -> list[dict[str, Any]]:
        meeting_id = result["meeting_id"]
        anchor = result["executive_spine"][0]["citations"][0]["anchor"]
        prep_id, review_id = f"{meeting_id}:preparation", f"{meeting_id}:self-review"
        relationships = [
            self._relation(source_version_id, meeting_id, "debriefs", anchor, "reported"),
            self._relation(meeting_id, prep_id, "prepares_for", anchor, "inferred"),
            self._relation(candidate["members"][0]["candidate_id"], prep_id, "derived_from", anchor, "reported"),
            self._relation(candidate["members"][1]["candidate_id"], review_id, "self_reviews", anchor, "reported"),
            self._relation(review_id, meeting_id, "about_meeting", anchor, "inferred"),
        ]
        if prior_artifact_version_id is not None:
            if not prior_artifact_version_id or "/" in prior_artifact_version_id:
                raise MeetingWorkflowError("S6-W1 prior admitted anchor is invalid")
            relationships.append(
                self._relation(
                    prior_artifact_version_id, meeting_id, "supports", anchor, "reported"
                )
            )
        return relationships

    def _relation(self, origin: str, target: str, kind: str, anchor: str, state: str) -> dict[str, Any]:
        relation = {
            "assertion_id": self.ids.new("relationship_ledger"), "origin_version_id": origin,
            "target_version_id": target, "type": kind, "source_anchor": anchor, "state": state,
        }
        self.schemas.require("relationship-assertion", relation)
        return relation

    def _workspace_items(
        self, result: dict[str, Any], candidate: dict[str, Any]
    ) -> tuple[PrivateWorkspaceItem, ...]:
        all_anchors = tuple(dict.fromkeys(_anchors_from_result(result)))
        meeting_id = result["meeting_id"]
        items = [
            PrivateWorkspaceItem(
                item_id=meeting_id, version_id=result["result_sha256"], family="meeting", view="debriefs",
                status="reported", display_alias="S6 W1 Meeting Debrief", canonical_object_sha256="0" * 64,
                admission_event_id="event-pending", body=_render_result(result), citations=all_anchors,
                candidate_inactive=True,
            ),
            PrivateWorkspaceItem(
                item_id=f"{meeting_id}:continuity", version_id=result["result_sha256"], family="work",
                view="reported", status="historical", display_alias="S6 W1 Provisional Continuity",
                canonical_object_sha256="0" * 64, admission_event_id="event-pending",
                body=_render_sections(result, ("continuity",)),
                citations=tuple(_anchors_from_sections(result, ("continuity",))),
            ),
            PrivateWorkspaceItem(
                item_id=f"{meeting_id}:preparation", version_id=result["result_sha256"], family="meeting",
                view="preparations", status="inactive", display_alias="S6 W1 Next Meeting Preparation",
                canonical_object_sha256="0" * 64, admission_event_id="event-pending",
                body=_render_sections(result, ("next_meeting_preparation", "self_review")),
                citations=tuple(_anchors_from_sections(result, ("next_meeting_preparation", "self_review"))),
                candidate_inactive=True,
            ),
        ]
        for member in candidate["members"]:
            items.append(PrivateWorkspaceItem(
                item_id=member["candidate_id"], version_id=member["method_version"], family="skill",
                view="package", status="inactive", display_alias=member["method_name"],
                canonical_object_sha256="0" * 64, admission_event_id="event-pending",
                body="\n".join((
                    f"Method: {member['method_name']}/{member['method_version']}",
                    f"Source digest: {member['method_source_sha256']}", "Portable core:",
                    *(f"- {line}" for line in member["portable_core"]),
                )), citations=(), candidate_inactive=True,
            ))
        return tuple(items)


def _validate_hosted_result(raw: object, anchors: tuple[EvidenceAnchor, ...]) -> None:
    required = {"executive_spine", "topics", *(_SECTIONS.keys() - {"executive_spine"})}
    if not isinstance(raw, dict) or set(raw) != required:
        raise MeetingWorkflowError("S6-W1 hosted result shape is invalid")
    by_anchor = {anchor.anchor: anchor.text for anchor in anchors}
    if not 1 <= len(raw["executive_spine"]) <= 12 or not 1 <= len(raw["topics"]) <= 24:
        raise MeetingWorkflowError("S6-W1 requires a bounded executive spine and topic layer")
    for section, allowed in _SECTIONS.items():
        values = raw[section]
        if not isinstance(values, list) or len(values) > 128:
            raise MeetingWorkflowError(f"S6-W1 {section} is outside the bounded contract")
        for value in values:
            _validate_assertion(value, by_anchor, allowed, section)
    for topic in raw["topics"]:
        if not isinstance(topic, dict) or set(topic) != {"title", "items"}:
            raise MeetingWorkflowError("S6-W1 topic shape is invalid")
        _bounded_text(topic["title"], "topic title")
        if not isinstance(topic["items"], list) or not topic["items"] or len(topic["items"]) > 32:
            raise MeetingWorkflowError("S6-W1 topic items are invalid")
        for item in topic["items"]:
            _validate_assertion(item, by_anchor, _SECTIONS["executive_spine"] | {"unavailable"}, "topic")


def _validate_assertion(value: object, anchors: dict[str, str], allowed: set[str], label: str) -> None:
    keys = {"claim_class", "statement", "citations", "owner", "owner_citation", "due", "due_citation"}
    if not isinstance(value, dict) or set(value) != keys or value["claim_class"] not in allowed:
        raise MeetingWorkflowError(f"S6-W1 {label} assertion is invalid")
    _bounded_text(value["statement"], f"{label} statement")
    citations = value["citations"]
    if not isinstance(citations, list) or not citations or len(citations) > 16:
        raise MeetingWorkflowError(f"S6-W1 {label} citations are invalid")
    selected: set[str] = set()
    for citation in citations:
        if not isinstance(citation, dict) or set(citation) != {"anchor"}:
            raise MeetingWorkflowError(f"S6-W1 {label} citation shape is invalid")
        anchor = citation["anchor"]
        if anchor not in anchors or anchor in selected:
            raise MeetingWorkflowError(f"S6-W1 {label} citation is unavailable")
        selected.add(anchor)
    for field, citation_field in (("owner", "owner_citation"), ("due", "due_citation")):
        field_value, citation = value[field], value[citation_field]
        if (field_value is None) != (citation is None):
            raise MeetingWorkflowError(f"S6-W1 {field} requires an exact citation")
        if field_value is not None:
            _bounded_text(field_value, field)
            if citation not in selected or field_value.casefold() not in anchors[citation].casefold():
                raise MeetingWorkflowError(f"S6-W1 {field} is not literal source evidence")


def _bounded_text(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 4096:
        raise MeetingWorkflowError(f"S6-W1 {label} is invalid")


def _anchors_from_result(result: dict[str, Any]) -> list[str]:
    return _anchors_from_sections(result, tuple(_SECTIONS)) + [
        citation["anchor"] for topic in result["topics"] for item in topic["items"]
        for citation in item["citations"]
    ]


def _anchors_from_sections(result: dict[str, Any], sections: tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(
        citation["anchor"] for section in sections for item in result[section]
        for citation in item["citations"]
    ))


def _render_assertions(values: list[dict[str, Any]]) -> str:
    return "\n".join(
        f"- [{value['claim_class']}] {value['statement']} "
        f"({', '.join(citation['anchor'] for citation in value['citations'])})"
        for value in values
    ) or "- None reported."


def _render_sections(result: dict[str, Any], sections: tuple[str, ...]) -> str:
    parts: list[str] = []
    for section in sections:
        parts.extend((f"## {section.replace('_', ' ').title()}", "", _render_assertions(result[section]), ""))
    return "\n".join(parts).rstrip()


def _render_result(result: dict[str, Any]) -> str:
    sections = (
        "executive_spine", "decisions", "proposals", "dissent", "commitments",
        "rationale_tradeoffs", "dependencies", "risks", "omissions", "open_questions",
    )
    parts = [_render_sections(result, sections), "", "## Topic-by-topic evidence", ""]
    for topic in result["topics"]:
        parts.extend((f"### {topic['title']}", "", _render_assertions(topic["items"]), ""))
    return "\n".join(parts).rstrip()
