"""Adapter-independent S6-W2 validation and publication-packet assembly.

The host supplies exactly four pre-read Markdown sources and visible reasoning.  This module never
opens a path, invokes a model, or persists material.  It labels every conclusion as source-reported,
proposed, conflicting, completed, unknown, or unavailable and composes the multi-source U1 packet only
from selected working-artifact revisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from vault_next.canonical import canonical_sha256, sha256_hex
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.multi_source_admission import (
    MultiSourceAdmissionInput,
    MultiSourceItem,
    build_multi_source_u1_manifest,
)
from vault_next.private_admission import PrivateAdmissionPublisher
from vault_next.records import SchemaRegistry
from vault_next.working_artifact import WorkingArtifactCoordinator, WorkingArtifactSelection


COMPONENT = "vault-next-work-continuity-wave/0.1.0"
WAVE_ID = "S6-W2-C1"
_MAX_WORK_CONTINUITY_ANCHORS = 2048
_ROLES = ("M1", "W1", "W2", "W3")
_NO_EFFECTS = (
    "no_activation", "no_promotion", "no_current_work", "no_u2", "no_s2_apply", "no_send",
    "no_connector", "no_network", "no_model_call_by_vault_next",
)
_SECTIONS = {
    "executive_spine": {"reported", "completed", "conflicting", "unknown", "unavailable"},
    "reconciliation": {"reported", "proposed", "completed", "conflicting", "unknown", "unavailable"},
    "decision_dependency_ledger": {"reported", "conflicting", "unknown", "unavailable"},
    "next_evidence": {"proposed", "unknown", "unavailable"},
    "omissions": {"unknown", "unavailable"},
}


class WorkContinuityError(RuntimeError):
    """The bounded work-continuity source set or hosted result is not admissible."""


@dataclass(frozen=True)
class WorkContinuityWave:
    result: dict[str, Any]
    citation_catalog: dict[str, str]
    provenance: tuple[dict[str, str], ...]
    candidate_package: dict[str, Any]


class S6WorkContinuityCoordinator:
    """Validate an inactive state-check U0 outcome and compose its later U1 packet."""

    def __init__(self, schemas: SchemaRegistry, *, id_factory: ULIDFactory = DEFAULT_FACTORY) -> None:
        self.schemas = schemas
        self.ids = id_factory

    def prepare_u0(
        self,
        *,
        source_items: tuple[MultiSourceItem, ...],
        hosted_result: object,
        portable_core: tuple[str, ...],
    ) -> WorkContinuityWave:
        """Freeze a caller-supplied, cited U0 result; it performs no source or durable I/O."""

        sources = self._sources(source_items)
        catalog, provenance = self._evidence(sources)
        self._validate_result(hosted_result, catalog)
        candidate = self._candidate(sources[0], portable_core)
        assert isinstance(hosted_result, dict)
        material = {
            "schema_version": "1.0", "component": COMPONENT, "wave_id": WAVE_ID,
            "continuity_id": self.ids.new("work_item"), "source_set_sha256": canonical_sha256(
                [self._source_summary(item) for item in sources]
            ),
            "candidate_lifecycle": "inactive", "persistence": "ephemeral_pending_u1",
            "no_effects": list(_NO_EFFECTS), **hosted_result,
        }
        result = {**material, "result_sha256": canonical_sha256(material)}
        return WorkContinuityWave(result, catalog, provenance, candidate)

    def build_packet(
        self,
        *,
        wave: WorkContinuityWave,
        source_items: tuple[MultiSourceItem, ...],
        selections: tuple[WorkingArtifactSelection, ...],
        coordinator: WorkingArtifactCoordinator,
        bundle_id: str,
        expires_at: datetime,
    ) -> MultiSourceAdmissionInput:
        """Bind three exact U0 review revisions into one later multi-source save proposal."""

        sources = self._sources(source_items)
        if len(selections) != 3:
            raise WorkContinuityError("S6-W2 requires exactly three selected working artifacts")
        expected = {"work_continuity", "decision", "work_preparation"}
        if {selection.record["artifact_kind"] for selection in selections} != expected:
            raise WorkContinuityError("S6-W2 selected working artifacts are incomplete")
        workspace_items = tuple(coordinator.workspace_item(selection) for selection in selections)
        all_citations = tuple(
            dict.fromkeys(anchor for selection in selections for anchor in selection.record["citations"])
        )
        if set(all_citations) - set(wave.citation_catalog):
            raise WorkContinuityError("S6-W2 selected artifact citation escaped the source packet")
        anchor = all_citations[0]
        relationships = [
            self._relation(
                sources[1].source_version["source_version_id"],
                wave.result["continuity_id"],
                "about_initiative",
                anchor,
            ),
            self._relation(
                sources[2].source_version["source_version_id"],
                wave.result["continuity_id"],
                "supports",
                anchor,
            ),
            self._relation(
                sources[3].source_version["source_version_id"],
                wave.result["continuity_id"],
                "reports_decision",
                anchor,
            ),
            self._relation(
                wave.candidate_package["candidate_id"],
                wave.result["continuity_id"],
                "derived_from",
                anchor,
            ),
        ]
        citation_text = tuple((anchor, wave.citation_catalog[anchor]) for anchor in all_citations)
        artifact = {
            "schema_version": "1.0", "artifact_kind": "work_continuity_wave", "wave_id": WAVE_ID,
            "u0_result_sha256": wave.result["result_sha256"], "result": wave.result,
            "citation_text": [list(row) for row in citation_text],
            "workspace_items": [PrivateAdmissionPublisher._item_record(item) for item in workspace_items],
        }
        manifest = build_multi_source_u1_manifest(
            ids=self.ids, expires_at=expires_at, bundle_id=bundle_id, source_items=sources,
            u0_result_sha256=wave.result["result_sha256"], artifact_sha256=canonical_sha256(artifact),
            candidate_package_sha256=canonical_sha256(wave.candidate_package),
            relationship_ledger_sha256=canonical_sha256(relationships), citations=all_citations,
            schemas=self.schemas,
        )
        return MultiSourceAdmissionInput(
            manifest=manifest, source_items=sources, artifact=artifact,
            candidate_package=wave.candidate_package, relationship_assertions=tuple(relationships),
            citation_text=citation_text, workspace_items=workspace_items,
        )

    def _sources(self, items: tuple[MultiSourceItem, ...]) -> tuple[MultiSourceItem, ...]:
        if len(items) != 4 or tuple(item.role for item in items) != _ROLES:
            raise WorkContinuityError("S6-W2 requires exact ordered M1/W1/W2/W3 sources")
        for item in items:
            version = item.source_version
            if (
                not item.source_locator.startswith("/") or not item.safe_label.endswith(".md")
                or not isinstance(item.source_bytes, bytes) or not item.source_bytes
                or sha256_hex(item.source_bytes) != version.get("content_sha256")
                or len(item.source_bytes) != version.get("byte_count")
                or version.get("profile_id") != "markdown_text"
            ):
                raise WorkContinuityError("S6-W2 source binding is invalid")
        return items

    def _evidence(self, items: tuple[MultiSourceItem, ...]) -> tuple[dict[str, str], tuple[dict[str, str], ...]]:
        from vault_next.content_profiles import ContentProfileRouter

        catalog: dict[str, str] = {}
        provenance: list[dict[str, str]] = []
        for item in items:
            # A bounded work packet may contain a long, selected Markdown decision record. The
            # general ingress default remains 256 anchors; this explicit four-source coordinator
            # permits 2,048 exact line-level anchors rather than dropping a source or citation.
            normalized = ContentProfileRouter(max_anchors=_MAX_WORK_CONTINUITY_ANCHORS).route(
                item.source_bytes, declared_media_type="text/markdown", declared_extension=".md"
            )
            for evidence in normalized.anchors:
                catalog[f"{item.role}:{evidence.anchor}"] = evidence.text_sha256
            provenance.append({
                "ref": item.source_version["source_version_id"],
                "digest": item.source_version["content_sha256"],
            })
        if not catalog:
            raise WorkContinuityError("S6-W2 source packet has no citable evidence")
        return catalog, tuple(provenance)

    def _candidate(self, method: MultiSourceItem, portable_core: tuple[str, ...]) -> dict[str, Any]:
        if not portable_core or len(portable_core) != len(set(portable_core)):
            raise WorkContinuityError("S6-W2 state-check portable core is invalid")
        try:
            markdown = method.source_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise WorkContinuityError("S6-W2 M1 must be strict UTF-8 Markdown") from exc
        package = {
            "schema_version": "1.0", "candidate_id": self.ids.new("skill_candidate"),
            "family": "work_continuity", "method_name": "state-check", "method_version": "0.1.0",
            "method_source_sha256": sha256_hex(method.source_bytes), "method_source_markdown": markdown,
            "portable_core": list(portable_core), "prohibitions": list(_NO_EFFECTS), "lifecycle": "inactive",
        }
        self.schemas.require("work-continuity-candidate-package", package)
        return package

    def _validate_result(self, raw: object, catalog: dict[str, str]) -> None:
        if not isinstance(raw, dict) or set(raw) != set(_SECTIONS):
            raise WorkContinuityError("S6-W2 hosted result shape is invalid")
        if not raw["executive_spine"] or len(raw["executive_spine"]) > 12:
            raise WorkContinuityError("S6-W2 executive spine is outside its bound")
        for section, allowed in _SECTIONS.items():
            values = raw[section]
            if not isinstance(values, list) or len(values) > 96:
                raise WorkContinuityError("S6-W2 result section is outside its bound")
            for assertion in values:
                self._assertion(assertion, catalog, allowed)

    @staticmethod
    def _assertion(value: object, catalog: dict[str, str], allowed: set[str]) -> None:
        required = {"claim_class", "statement", "citations", "owner", "due"}
        if not isinstance(value, dict) or set(value) != required or value["claim_class"] not in allowed:
            raise WorkContinuityError("S6-W2 assertion is invalid")
        if (
            not isinstance(value["statement"], str)
            or not value["statement"].strip()
            or len(value["statement"].encode()) > 4096
        ):
            raise WorkContinuityError("S6-W2 assertion statement is invalid")
        citations = value["citations"]
        if not isinstance(citations, list) or not citations or len(citations) != len(set(citations)):
            raise WorkContinuityError("S6-W2 assertion citations are invalid")
        if any(not isinstance(anchor, str) or anchor not in catalog for anchor in citations):
            raise WorkContinuityError("S6-W2 assertion citation is unavailable")
        for field in ("owner", "due"):
            if value[field] is not None and (not isinstance(value[field], str) or len(value[field]) > 240):
                raise WorkContinuityError("S6-W2 assertion owner/due is invalid")

    def _relation(self, origin: str, target: str, relation_type: str, anchor: str) -> dict[str, Any]:
        record = {
            "assertion_id": self.ids.new("relationship_ledger"), "origin_version_id": origin,
            "target_version_id": target, "type": relation_type, "source_anchor": anchor, "state": "reported",
        }
        self.schemas.require("relationship-assertion", record)
        return record

    @staticmethod
    def _source_summary(item: MultiSourceItem) -> dict[str, str]:
        return {
            "role": item.role, "source_version_id": item.source_version["source_version_id"],
            "content_sha256": item.source_version["content_sha256"],
        }
