"""Fixture-analyzer boundary for the synthetic Chat-first Meeting Debrief workflow."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.content_profiles import EvidenceAnchor, NormalizedContent
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.records import SchemaRegistry


_CLAIM_CLASSES = frozenset(
    {
        "reported_fact",
        "reported_decision",
        "proposal",
        "commitment",
        "risk",
        "conflict",
        "unknown",
        "unavailable",
    }
)
_NO_EFFECTS = ("no_save", "no_activate", "no_apply", "no_send", "no_schedule", "no_tools")


class MeetingDebriefError(RuntimeError):
    """The fixture analysis is unbound, malformed, or attempts to cross its authority fence."""


@dataclass(frozen=True)
class FrozenEvidence:
    """The sole in-memory analytical input; its record retains locators but no source text."""

    record_bytes: bytes
    normalized_text: str
    anchors: tuple[EvidenceAnchor, ...]
    evidence_sha256: str

    def record(self) -> dict[str, Any]:
        """Return an isolated parsed evidence record for callers that need its public shape."""

        value = json.loads(self.record_bytes)
        if not isinstance(value, dict):
            raise MeetingDebriefError("frozen evidence record is malformed")
        return value

    def verify(self) -> None:
        """Recompute immutable bindings before and after calling an injected analyzer."""

        record = self.record()
        if canonical_bytes(record) != self.record_bytes:
            raise MeetingDebriefError("frozen evidence record is not canonical")
        expected = canonical_sha256(
            {
                "profile_id": record["profile_id"],
                "profile_version": record["profile_version"],
                "normalized_text_sha256": sha256_hex(self.normalized_text.encode("utf-8")),
                "normalized_byte_count": len(self.normalized_text.encode("utf-8")),
                "anchors": [anchor.to_record() for anchor in self.anchors],
                "omissions": record["omissions"],
            }
        )
        if expected != self.evidence_sha256 or record["normalized_evidence_sha256"] != expected:
            raise MeetingDebriefError("frozen evidence binding changed")
        if record["normalized_text_sha256"] != sha256_hex(self.normalized_text.encode("utf-8")):
            raise MeetingDebriefError("frozen evidence text changed")


class MeetingDebriefAnalyzer(Protocol):
    """An injected analyzer contract with no tool, host, model, or filesystem capability."""

    def analyze(self, evidence: FrozenEvidence, request: dict[str, Any]) -> dict[str, Any]: ...


def freeze_evidence(
    schemas: SchemaRegistry,
    envelope: dict[str, Any],
    normalized: NormalizedContent,
    *,
    schema_name: str = "chat-evidence-packet",
) -> FrozenEvidence:
    """Create canonical evidence from a validated ingress envelope under its exact contract."""

    record = {
        "schema_version": "1.0",
        "ingress_id": envelope["ingress_id"],
        "profile_id": normalized.profile_id,
        "profile_version": normalized.profile_version,
        "material_sha256": envelope["material_sha256"],
        "normalized_text_sha256": normalized.normalized_text_sha256,
        "normalized_byte_count": normalized.normalized_byte_count,
        "anchors": [anchor.to_record() for anchor in normalized.anchors],
        "omissions": list(normalized.omissions),
        "provenance_sha256": canonical_sha256(envelope["provenance"]),
        "normalized_evidence_sha256": normalized.normalized_evidence_sha256,
    }
    schemas.require(schema_name, record)
    frozen = FrozenEvidence(
        record_bytes=canonical_bytes(record),
        normalized_text=normalized.normalized_text,
        anchors=normalized.anchors,
        evidence_sha256=normalized.normalized_evidence_sha256,
    )
    frozen.verify()
    return frozen


class MeetingDebriefCoordinator:
    """Validate an attributable synthetic debrief without granting the analyzer authority."""

    def __init__(
        self,
        schemas: SchemaRegistry,
        analyzer: MeetingDebriefAnalyzer,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        method_version: str = "0.1.0",
    ) -> None:
        if not method_version.startswith("0.1.") or not method_version.removeprefix("0.1.").isdigit():
            raise ValueError("synthetic Meeting Debrief method version is invalid")
        self.schemas = schemas
        self.analyzer = analyzer
        self.ids = id_factory
        self.method_version = method_version

    def run(self, evidence: FrozenEvidence) -> dict[str, Any]:
        """Produce one cited U0 debrief from an immutable packet and a fixture analyzer result."""

        evidence.verify()
        request = {
            "schema_version": "1.0",
            "method_package": "meeting-debrief",
            "method_version": self.method_version,
            "evidence_sha256": evidence.evidence_sha256,
            "requested_sections": ["summary", "findings", "open_questions", "followups"],
            "disclosure_surface": "synthetic_fixture",
            "no_effects": list(_NO_EFFECTS),
        }
        self.schemas.require("meeting-debrief-request", request)
        raw = self.analyzer.analyze(evidence, request)
        evidence.verify()
        validate_analysis_payload(raw, evidence)
        material = {
            "schema_version": "1.0",
            "debrief_id": self.ids.new("meeting_debrief"),
            "method_package": "meeting-debrief",
            "method_version": self.method_version,
            "execution_surface": "synthetic_fixture",
            "analytical_usefulness": "synthetic_mechanics_only",
            "evidence_sha256": evidence.evidence_sha256,
            "findings": raw["findings"],
            "summary": raw["summary"],
            "open_questions": raw["open_questions"],
            "suggested_followups": raw["suggested_followups"],
            "omissions": raw["omissions"],
            "limitations": raw["limitations"],
            "persistence": "ephemeral",
            "candidate_lifecycle": "inactive",
        }
        result = {
            **material,
            "result_sha256": canonical_sha256(
                {key: value for key, value in material.items() if key != "debrief_id"}
            ),
        }
        self.schemas.require("meeting-debrief-result", result)
        return result


def verify_result_bindings(result: dict[str, Any], evidence: FrozenEvidence) -> None:
    """Revalidate one saved result against frozen evidence during U1 restart recovery."""

    expected_keys = {
        "schema_version",
        "debrief_id",
        "method_package",
        "method_version",
        "execution_surface",
        "analytical_usefulness",
        "evidence_sha256",
        "findings",
        "summary",
        "open_questions",
        "suggested_followups",
        "omissions",
        "limitations",
        "persistence",
        "candidate_lifecycle",
        "result_sha256",
    }
    if set(result) != expected_keys or result["evidence_sha256"] != evidence.evidence_sha256:
        raise MeetingDebriefError("saved Meeting Debrief result is not bound to its evidence")
    material = {
        key: value
        for key, value in result.items()
        if key not in {"debrief_id", "result_sha256"}
    }
    if result["result_sha256"] != canonical_sha256(material):
        raise MeetingDebriefError("saved Meeting Debrief result digest is invalid")
    validate_analysis_payload(
        {
            "findings": result["findings"],
            "summary": result["summary"],
            "open_questions": result["open_questions"],
            "suggested_followups": result["suggested_followups"],
            "omissions": result["omissions"],
            "limitations": result["limitations"],
        },
        evidence,
    )


def validate_analysis_payload(raw: object, evidence: FrozenEvidence) -> None:
    if not isinstance(raw, dict) or set(raw) != {
        "findings",
        "summary",
        "open_questions",
        "suggested_followups",
        "omissions",
        "limitations",
    }:
        raise MeetingDebriefError("fixture analyzer payload has an unsupported shape")
    anchors = {item.anchor: item for item in evidence.anchors}
    findings = raw["findings"]
    if not isinstance(findings, list) or len(findings) > 32:
        raise MeetingDebriefError("fixture analyzer findings exceed the bounded result contract")
    for finding in findings:
        _validate_finding(finding, anchors)
    _validate_statement(raw["summary"], anchors, "summary")
    for key in ("open_questions", "suggested_followups", "omissions", "limitations"):
        _bounded_strings(raw[key], key)


def _validate_finding(finding: object, anchors: dict[str, EvidenceAnchor]) -> None:
    required = {"claim_class", "statement", "citations", "owner", "owner_citation", "due", "due_citation"}
    if not isinstance(finding, dict) or set(finding) != required:
        raise MeetingDebriefError("fixture finding has an unsupported shape")
    if finding["claim_class"] not in _CLAIM_CLASSES:
        raise MeetingDebriefError("fixture finding has an unsupported claim class")
    _bounded_string(finding["statement"], "finding statement")
    citations = _validate_citations(finding["citations"], anchors, "finding")
    for value_name, citation_name in (("owner", "owner_citation"), ("due", "due_citation")):
        value = finding[value_name]
        citation = finding[citation_name]
        if (value is None) != (citation is None):
            raise MeetingDebriefError("fixture owner or due value lacks an exact citation")
        if value is not None:
            _bounded_string(value, value_name)
            if not isinstance(citation, str) or citation not in citations or citation not in anchors:
                raise MeetingDebriefError("fixture owner or due citation is unavailable")
            if value.casefold() not in anchors[citation].text.casefold():
                raise MeetingDebriefError("fixture owner or due value is not supported by its citation")


def _validate_statement(
    value: object,
    anchors: dict[str, EvidenceAnchor],
    label: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {"statement", "citations"}:
        raise MeetingDebriefError(f"fixture {label} has an unsupported shape")
    _bounded_string(value["statement"], label)
    _validate_citations(value["citations"], anchors, label)


def _validate_citations(
    value: object,
    anchors: dict[str, EvidenceAnchor],
    label: str,
) -> set[str]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise MeetingDebriefError(f"fixture {label} citations are invalid")
    selected: set[str] = set()
    for citation in value:
        if not isinstance(citation, dict) or set(citation) != {"anchor"}:
            raise MeetingDebriefError(f"fixture {label} citation has an unsupported shape")
        anchor = citation["anchor"]
        if not isinstance(anchor, str) or anchor not in anchors or anchor in selected:
            raise MeetingDebriefError(f"fixture {label} citation is unavailable")
        selected.add(anchor)
    return selected


def _bounded_strings(value: object, label: str) -> None:
    if not isinstance(value, list) or len(value) > 32:
        raise MeetingDebriefError(f"fixture {label} list is invalid")
    for item in value:
        _bounded_string(item, label)


def _bounded_string(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 2_048:
        raise MeetingDebriefError(f"fixture {label} is not a bounded nonempty string")


def _contract_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
