"""Tool-less semantic-review packets and immutable result handling for Phase 5.

The reviewer is deliberately a pure function over a supplied packet.  It receives no runtime,
ledger, filesystem, network, policy engine, or owner-decision capability.  The coordinator is the
separate trusted boundary that may persist the returned record and append a runtime-attributed
completion event.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Protocol

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.paths import RuntimePaths
from vault_next.records import SCHEMA_VERSION, SchemaRegistry, aware_utc_now, timestamp


REVIEWABLE_SENSITIVITY = frozenset({"none"})
MAX_PRIMARY_QUESTION_BYTES = 4 * 1024
MAX_TARGET_EVENT_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_CONTEXT_RECORD_BYTES = 8 * 1024
MAX_CONTEXT_RECORDS = 32
MAX_EVIDENCE_BYTES = 16 * 1024
MAX_EVIDENCE_RECORDS = 16
MAX_EVIDENCE_TOTAL_BYTES = 128 * 1024
CONTEXT_EVENT_TYPES = frozenset(
    {
        "claim.recorded",
        "assumption.recorded",
        "assumption.revised",
        "alternative.recorded",
        "alternative.disposition_changed",
        "disagreement.recorded",
        "disagreement.resolved",
        "recommendation.issued",
        "recommendation.revised",
        "owner_input.recorded",
        "artifact.feedback_recorded",
    }
)


class ReviewerUnavailable(Exception):
    """A reviewer could not produce an assessment; this never means review passed."""


class ToollessSemanticReviewer(Protocol):
    """Pure packet-in, result-details-out interface with no tools or storage capability."""

    reviewer_id: str
    reviewer_version: str

    def review(self, packet: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
        """Return ``(status, reason, findings)`` for this exact read-only packet."""


@dataclass(frozen=True)
class ReviewTarget:
    """An immutable session object eligible for semantic review."""

    target_type: str
    target_ref: str
    target_sha256: str
    source_event_id: str
    source_event: dict[str, Any]


@dataclass(frozen=True)
class ReviewAttempt:
    """The packet/result pair returned by one non-authoritative review attempt."""

    packet: dict[str, Any]
    packet_sha256: str
    result: dict[str, Any]
    result_sha256: str


class ReviewRepository:
    """Persist immutable review artefacts separately from canonical semantic history."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry):
        self.paths = paths
        self.schemas = schemas

    def write_packet(self, packet: dict[str, Any]) -> tuple[Path, str]:
        self.schemas.require("review-packet", packet)
        _require_new_packet_contract(packet)
        digest = canonical_sha256(packet)
        return self._write_immutable("packets", packet["packet_id"], packet), digest

    def write_result(self, review_id: str, result: dict[str, Any]) -> tuple[Path, str]:
        self.schemas.require("review-result", result)
        digest = canonical_sha256(result)
        return self._write_immutable("results", f"{review_id}-{result['attempt']}", result), digest

    def write_waiver(self, waiver: dict[str, Any]) -> tuple[Path, str]:
        self.schemas.require("review-waiver", waiver)
        digest = canonical_sha256(waiver)
        return self._write_immutable("waivers", waiver["waiver_id"], waiver), digest

    def read_packet(self, review_id: str) -> dict[str, Any]:
        return self._read("packets", review_id, "review-packet")

    def read_result(self, review_id: str, attempt: int) -> dict[str, Any]:
        return self._read("results", f"{review_id}-{attempt}", "review-result")

    def read_verified_artifact(self, version: dict[str, Any]) -> bytes:
        """Return an immutable artifact only after recorded hash and size verification."""

        path = self.paths.ensure_runtime_write_target(
            self.paths.artifact_root / "objects" / version["object_ref"]
        )
        content = path.read_bytes()
        if (
            len(content) != version["byte_count"]
            or sha256_hex(content) != version["content_sha256"]
        ):
            raise ValueError("artifact object does not match recorded version")
        return content

    def read_verified_evidence(self, metadata: dict[str, Any]) -> bytes:
        """Return an immutable evidence object only after metadata binding verification."""

        path = self.paths.ensure_runtime_write_target(
            self.paths.evidence_root / "objects" / metadata["object_ref"]
        )
        content = path.read_bytes()
        if (
            len(content) != metadata["byte_count"]
            or sha256_hex(content) != metadata["content_sha256"]
        ):
            raise ValueError("evidence object does not match recorded metadata")
        return content

    def _read(self, category: str, stem: str, schema: str) -> dict[str, Any]:
        path = self.paths.review_root / category / f"{stem}.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(
                [Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), type(exc).__name__)]
            ) from exc
        self.schemas.require(schema, value)
        if canonical_bytes(value) + b"\n" != path.read_bytes():
            raise ValidationError(
                [Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), "review record is not canonical")]
            )
        return value

    def _write_immutable(self, category: str, stem: str, value: dict[str, Any]) -> Path:
        root = self.paths.ensure_runtime_write_target(self.paths.review_root / category)
        root.mkdir(parents=True, exist_ok=True)
        path = self.paths.ensure_runtime_write_target(root / f"{stem}.json")
        content = canonical_bytes(value) + b"\n"
        if path.exists():
            if path.read_bytes() == content:
                return path
            raise ValidationError(
                [Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), "immutable review record differs")]
            )
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        try:
            temporary.write_bytes(content)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        if path.read_bytes() != content:
            raise ValidationError(
                [Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), "post-write verification failed")]
            )
        return path


def resolve_review_target(
    events: list[dict[str, Any]], session_id: str, target_type: str, target_ref: str
) -> ReviewTarget:
    """Resolve a supported target to an exact content/event digest before review."""

    for event in reversed(events):
        if event.get("session_id") != session_id:
            continue
        payload = event["payload"]
        if (
            target_type == "recommendation"
            and event["event_type"] in {"recommendation.issued", "recommendation.revised"}
            and payload.get("recommendation_id") == target_ref
        ):
            return ReviewTarget(
                target_type,
                target_ref,
                event["integrity"]["event_sha256"],
                event["event_id"],
                event,
            )
        if (
            target_type == "checkpoint"
            and event["event_type"] == "checkpoint.recorded"
            and payload.get("checkpoint_id") == target_ref
        ):
            return ReviewTarget(
                target_type,
                target_ref,
                event["integrity"]["event_sha256"],
                event["event_id"],
                event,
            )
        if (
            target_type == "artifact_version"
            and event["event_type"] == "artifact.version_created"
            and payload.get("version", {}).get("version_id") == target_ref
        ):
            return ReviewTarget(
                target_type,
                target_ref,
                payload["version"]["content_sha256"],
                event["event_id"],
                event,
            )
    raise ValidationError(
        [Issue(ErrorCode.EVENT_REFERENCE_MISSING, "$target_ref", "review target is absent from session")]
    )


def build_review_packet(
    events: list[dict[str, Any]],
    *,
    review_id: str,
    session_id: str,
    target_type: str,
    target_ref: str,
    schemas: SchemaRegistry,
    created_at: datetime | None = None,
    rubric_id: str = "semantic-coherence-v1",
    artifact_loader: Callable[[dict[str, Any]], bytes] | None = None,
    evidence_loader: Callable[[dict[str, Any]], bytes] | None = None,
) -> dict[str, Any]:
    """Build a fixed packet and withhold all substantive material above synthetic-safe sensitivity."""

    session_events = [event for event in events if event.get("session_id") == session_id]
    if not session_events:
        raise ValidationError(
            [Issue(ErrorCode.SESSION_REFERENCE_MISSING, "$session_id", "session has no canonical events")]
        )
    target = resolve_review_target(events, session_id, target_type, target_ref)
    labels = sorted({event["sensitivity"] for event in session_events})
    reviewable = set(labels).issubset(REVIEWABLE_SENSITIVITY)
    omissions: list[dict[str, str]] = []
    if reviewable:
        question = _bounded_question(session_events, omissions)
        target_content = _target_content(target, omissions, artifact_loader)
        context_records = _context_records(session_events, target.source_event_id, omissions)
        evidence = _evidence_records(session_events, omissions, evidence_loader)
    else:
        question = "Withheld by sensitivity policy."
        target_content = _omitted_target_content(target, "withheld")
        context_records = []
        evidence = []
        omissions.append(
            {
                "category": "sensitivity",
                "ref": session_id,
                "reason": "session contains material above synthetic-safe sensitivity",
            }
        )
    subject: dict[str, Any] = {
        "primary_question": question,
        "target_type": target.target_type,
        "target_ref": target.target_ref,
        "target_sha256": target.target_sha256,
        "recommendations": [],
        "assumptions": [],
        "alternatives": [],
        "target_content": target_content,
        "context_records": context_records,
        "evidence": evidence,
    }
    packet = {
        "schema_version": SCHEMA_VERSION,
        "packet_id": review_id,
        "review_kind": "semantic_coherence",
        "rubric_id": rubric_id,
        "created_at": timestamp(created_at or aware_utc_now()),
        "case_id": session_events[0]["case_id"],
        "session_id": session_id,
        "subject": subject,
        "source_event_ids": [event["event_id"] for event in session_events],
        "source_watermark": session_events[-1]["integrity"]["event_sha256"],
        "sensitivity": {
            "labels": labels,
            "reviewable": reviewable,
            "withheld_source_event_ids": [] if reviewable else [event["event_id"] for event in session_events],
        },
        "reviewability": {
            "complete": reviewable and not omissions,
            "omissions": omissions,
        },
        "policy": {
            "tools_available": False,
            "write_authority": False,
            "approval_authority": False,
            "decision_authority": False,
        },
    }
    schemas.require("review-packet", packet)
    _require_new_packet_contract(packet)
    return packet


class SemanticReviewCoordinator:
    """Run pure reviewers and persist their results without granting reviewer authority."""

    def __init__(
        self,
        repository: ReviewRepository,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
    ) -> None:
        self.repository = repository
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock

    def create_packet(
        self,
        events: list[dict[str, Any]],
        *,
        session_id: str,
        target_type: str,
        target_ref: str,
    ) -> tuple[dict[str, Any], str]:
        packet = build_review_packet(
            events,
            review_id=self.ids.new("review"),
            session_id=session_id,
            target_type=target_type,
            target_ref=target_ref,
            schemas=self.schemas,
            created_at=self.clock(),
            artifact_loader=self.repository.read_verified_artifact,
            evidence_loader=self.repository.read_verified_evidence,
        )
        _, digest = self.repository.write_packet(packet)
        return packet, digest

    def run(
        self,
        packet: dict[str, Any],
        packet_sha256: str,
        reviewer: ToollessSemanticReviewer,
        *,
        attempt: int,
    ) -> ReviewAttempt:
        """Call the pure reviewer; convert unavailability to a non-passing immutable result."""

        self.schemas.require("review-packet", packet)
        target_sha256 = packet["subject"]["target_sha256"]
        if not _packet_is_complete(packet):
            status, reason, findings = (
                "unavailable",
                "review packet is incomplete or withheld",
                [],
            )
        else:
            try:
                status, reason, findings = reviewer.review(packet)
            except ReviewerUnavailable:
                status, reason, findings = "unavailable", "reviewer unavailable", []
        result = {
            "schema_version": SCHEMA_VERSION,
            "result_id": self.ids.new("review_result"),
            "attempt": attempt,
            "packet_sha256": packet_sha256,
            "target_sha256": target_sha256,
            "reviewer": {"id": reviewer.reviewer_id, "version": reviewer.reviewer_version},
            "reviewed_at": timestamp(self.clock()),
            "status": status,
            "reason": reason,
            "findings": findings,
        }
        self.schemas.require("review-result", result)
        _validate_result_semantics(packet, result)
        _, result_sha256 = self.repository.write_result(packet["packet_id"], result)
        return ReviewAttempt(packet, packet_sha256, result, result_sha256)

    def waive(
        self,
        *,
        review_id: str,
        target_sha256: str,
        result_sha256: str,
        finding_ids: list[str],
        reason: str,
        owner_id: str = "owner",
    ) -> tuple[dict[str, Any], str]:
        waiver = {
            "schema_version": SCHEMA_VERSION,
            "waiver_id": self.ids.new("waiver"),
            "review_id": review_id,
            "target_sha256": target_sha256,
            "result_sha256": result_sha256,
            "finding_ids": list(dict.fromkeys(finding_ids)),
            "owner_id": owner_id,
            "reason": reason,
            "explicit_confirmation": True,
            "waived_at": timestamp(self.clock()),
        }
        _, digest = self.repository.write_waiver(waiver)
        return waiver, digest


class SemanticReviewWorkflow:
    """Coordinate packet persistence and runtime state without granting the reviewer any power."""

    def __init__(self, coordinator: SemanticReviewCoordinator, runtime: Any):
        self.coordinator = coordinator
        self.runtime = runtime

    def request(
        self, session_id: str, *, target_type: str, target_ref: str
    ) -> tuple[dict[str, Any], str]:
        """Create a packet and mark the active session review-pending before invocation."""

        packet, packet_sha256 = self.coordinator.create_packet(
            self.runtime.semantic.read_all(),
            session_id=session_id,
            target_type=target_type,
            target_ref=target_ref,
        )
        subject = packet["subject"]
        self.runtime.request_semantic_review(
            session_id,
            review_id=packet["packet_id"],
            packet_sha256=packet_sha256,
            target_type=subject["target_type"],
            target_ref=subject["target_ref"],
            target_sha256=subject["target_sha256"],
        )
        return packet, packet_sha256

    def run(
        self,
        session_id: str,
        packet: dict[str, Any],
        packet_sha256: str,
        reviewer: ToollessSemanticReviewer,
        *,
        attempt: int,
    ) -> ReviewAttempt:
        """Persist an attempt and block only high findings or unavailability, never draft capture."""

        review = self.coordinator.run(packet, packet_sha256, reviewer, attempt=attempt)
        self.runtime.record_semantic_review_completion(
            session_id,
            review_id=packet["packet_id"],
            attempt=attempt,
            packet_sha256=packet_sha256,
            result_sha256=review.result_sha256,
            target_sha256=packet["subject"]["target_sha256"],
            status=review.result["status"],
        )
        high_finding = any(finding["severity"] == "high" for finding in review.result["findings"])
        if review.result["status"] == "unavailable" or high_finding:
            self.runtime.transition_session(
                session_id,
                "blocked",
                reason="semantic review unavailable or has high-severity findings",
            )
        return review


def _primary_question(events: list[dict[str, Any]]) -> str:
    question = next((event for event in events if event["event_type"] == "question.recorded"), None)
    if question is not None:
        return str(question["payload"]["question"])
    created = next((event for event in events if event["event_type"] == "session.created"), None)
    if created is not None:
        return str(created["payload"]["manifest"]["primary_question"])
    return "No separately recorded question."


def _records(events: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [
        {"event_id": event["event_id"], "event_type": event["event_type"], "payload": event["payload"]}
        for event in events
        if event["event_type"].startswith(prefix + ".")
    ]


def _bounded_question(events: list[dict[str, Any]], omissions: list[dict[str, str]]) -> str:
    question = _primary_question(events)
    if len(question.encode("utf-8")) <= MAX_PRIMARY_QUESTION_BYTES:
        return question
    omissions.append(
        {
            "category": "primary_question",
            "ref": events[0]["session_id"],
            "reason": f"question exceeds {MAX_PRIMARY_QUESTION_BYTES} byte limit",
        }
    )
    return "Primary question omitted because it exceeds the packet limit."


def _target_content(
    target: ReviewTarget,
    omissions: list[dict[str, str]],
    artifact_loader: Callable[[dict[str, Any]], bytes] | None,
) -> dict[str, Any]:
    if target.target_type != "artifact_version":
        payload = target.source_event["payload"]
        try:
            content = canonical_bytes(payload)
        except ValidationError:
            return _target_omission(target, omissions, "target event payload is not canonical")
        if len(content) > MAX_TARGET_EVENT_BYTES:
            return _target_omission(
                target, omissions, f"target payload exceeds {MAX_TARGET_EVENT_BYTES} byte limit"
            )
        if canonical_sha256(payload) != target.source_event["integrity"]["payload_sha256"]:
            return _target_omission(target, omissions, "target event payload hash does not match")
        return {
            "status": "present",
            "representation": "event_payload",
            "source_event_id": target.source_event_id,
            "content_sha256": target.source_event["integrity"]["payload_sha256"],
            "byte_count": len(content),
            "content": payload,
            "text": None,
        }

    version = target.source_event["payload"]["version"]
    if version["byte_count"] > MAX_ARTIFACT_BYTES:
        return _target_omission(
            target, omissions, f"artifact exceeds {MAX_ARTIFACT_BYTES} byte limit"
        )
    if artifact_loader is None:
        return _target_omission(target, omissions, "trusted artifact loader is unavailable")
    try:
        content = artifact_loader(version)
        text = content.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError, KeyError):
        return _target_omission(target, omissions, "artifact is unavailable, invalid, or not UTF-8")
    if len(content) != version["byte_count"] or sha256_hex(content) != target.target_sha256:
        return _target_omission(target, omissions, "artifact hash or byte count does not match")
    return {
        "status": "present",
        "representation": "artifact_text",
        "source_event_id": target.source_event_id,
        "content_sha256": target.target_sha256,
        "byte_count": len(content),
        "content": None,
        "text": text,
    }


def _target_omission(
    target: ReviewTarget, omissions: list[dict[str, str]], reason: str
) -> dict[str, Any]:
    omissions.append({"category": "target_content", "ref": target.target_ref, "reason": reason})
    return _omitted_target_content(target, "omitted")


def _omitted_target_content(target: ReviewTarget, status: str) -> dict[str, Any]:
    return {
        "status": status,
        "representation": "none",
        "source_event_id": target.source_event_id,
        "content_sha256": None,
        "byte_count": None,
        "content": None,
        "text": None,
    }


def _context_records(
    events: list[dict[str, Any]], target_event_id: str, omissions: list[dict[str, str]]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for event in events:
        if event["event_id"] == target_event_id or event["event_type"] not in CONTEXT_EVENT_TYPES:
            continue
        if len(records) >= MAX_CONTEXT_RECORDS:
            omissions.append(
                {
                    "category": "context_records",
                    "ref": event["event_id"],
                    "reason": f"context exceeds {MAX_CONTEXT_RECORDS} record limit",
                }
            )
            break
        payload = event["payload"]
        try:
            encoded = canonical_bytes(payload)
        except ValidationError:
            omissions.append(
                {
                    "category": "context_records",
                    "ref": event["event_id"],
                    "reason": "context payload is not canonical",
                }
            )
            continue
        if len(encoded) > MAX_CONTEXT_RECORD_BYTES:
            omissions.append(
                {
                    "category": "context_records",
                    "ref": event["event_id"],
                    "reason": f"context payload exceeds {MAX_CONTEXT_RECORD_BYTES} byte limit",
                }
            )
            continue
        expected = event["integrity"].get("payload_sha256")
        if canonical_sha256(payload) != expected:
            omissions.append(
                {
                    "category": "context_records",
                    "ref": event["event_id"],
                    "reason": "context payload hash does not match",
                }
            )
            continue
        records.append(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "payload": payload,
                "payload_sha256": expected,
                "byte_count": len(encoded),
            }
        )
    return records


def _evidence_records(
    events: list[dict[str, Any]],
    omissions: list[dict[str, str]],
    evidence_loader: Callable[[dict[str, Any]], bytes] | None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    total_bytes = 0
    for event in events:
        if event["event_type"] != "evidence.registered":
            continue
        metadata = event["payload"].get("metadata", {})
        evidence_id = str(metadata.get("evidence_id", event["event_id"]))
        expected_size = metadata.get("byte_count")
        if len(evidence) >= MAX_EVIDENCE_RECORDS:
            omissions.append(
                {
                    "category": "evidence",
                    "ref": evidence_id,
                    "reason": f"evidence exceeds {MAX_EVIDENCE_RECORDS} record limit",
                }
            )
            continue
        if not isinstance(expected_size, int) or expected_size < 0:
            omissions.append(
                {"category": "evidence", "ref": evidence_id, "reason": "invalid evidence byte count"}
            )
            continue
        if expected_size > MAX_EVIDENCE_BYTES or total_bytes + expected_size > MAX_EVIDENCE_TOTAL_BYTES:
            omissions.append(
                {
                    "category": "evidence",
                    "ref": evidence_id,
                    "reason": "evidence exceeds packet byte limit",
                }
            )
            continue
        if evidence_loader is None:
            omissions.append(
                {"category": "evidence", "ref": evidence_id, "reason": "trusted evidence loader is unavailable"}
            )
            continue
        try:
            content = evidence_loader(metadata)
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError, KeyError):
            omissions.append(
                {"category": "evidence", "ref": evidence_id, "reason": "evidence is unavailable, invalid, or not UTF-8"}
            )
            continue
        if len(content) != expected_size or sha256_hex(content) != metadata.get("content_sha256"):
            omissions.append(
                {"category": "evidence", "ref": evidence_id, "reason": "evidence hash or byte count does not match"}
            )
            continue
        total_bytes += len(content)
        evidence.append(
            {
                "evidence_id": evidence_id,
                "source_event_id": event["event_id"],
                "content_type": str(metadata.get("content_type", "application/octet-stream")),
                "content_sha256": metadata["content_sha256"],
                "byte_count": len(content),
                "text": text,
            }
        )
    return evidence


def _packet_is_complete(packet: dict[str, Any]) -> bool:
    reviewability = packet.get("reviewability")
    return (
        isinstance(reviewability, dict)
        and reviewability.get("complete") is True
        and reviewability.get("omissions") == []
        and packet["sensitivity"]["reviewable"] is True
    )


def _require_new_packet_contract(packet: dict[str, Any]) -> None:
    reviewability = packet.get("reviewability")
    issues: list[Issue] = []
    if not isinstance(reviewability, dict):
        issues.append(Issue(ErrorCode.REVIEW_RESULT_INVALID, "$reviewability", "bounded packet contract missing"))
    else:
        omissions = reviewability.get("omissions")
        complete = reviewability.get("complete")
        expected_complete = packet["sensitivity"]["reviewable"] and omissions == []
        if complete is not expected_complete:
            issues.append(
                Issue(ErrorCode.REVIEW_RESULT_INVALID, "$reviewability", "completeness does not match omissions")
            )
        target = packet["subject"].get("target_content")
        if not isinstance(target, dict):
            issues.append(Issue(ErrorCode.REVIEW_RESULT_INVALID, "$subject/target_content", "target content missing"))
        elif complete and target.get("status") != "present":
            issues.append(
                Issue(ErrorCode.REVIEW_RESULT_INVALID, "$subject/target_content", "complete packet omits target")
            )
    if issues:
        raise ValidationError(issues)


def _validate_result_semantics(packet: dict[str, Any], result: dict[str, Any]) -> None:
    issues: list[Issue] = []
    if result["packet_sha256"] != canonical_sha256(packet):
        issues.append(Issue(ErrorCode.REVIEW_RESULT_INVALID, "$packet_sha256", "result does not bind packet"))
    if result["target_sha256"] != packet["subject"]["target_sha256"]:
        issues.append(Issue(ErrorCode.REVIEW_TARGET_STALE, "$target_sha256", "result does not bind exact target"))
    if result["status"] == "pass" and result["findings"]:
        issues.append(Issue(ErrorCode.REVIEW_RESULT_INVALID, "$findings", "passing result cannot contain findings"))
    if result["status"] == "findings" and not result["findings"]:
        issues.append(Issue(ErrorCode.REVIEW_RESULT_INVALID, "$findings", "finding result requires findings"))
    if result["status"] == "pass" and not _packet_is_complete(packet):
        issues.append(
            Issue(ErrorCode.REVIEW_RESULT_INVALID, "$status", "incomplete packet cannot pass review")
        )
    packet_sources = set(packet["source_event_ids"])
    for finding in result["findings"]:
        if not set(finding["source_event_ids"]).issubset(packet_sources):
            issues.append(
                Issue(
                    ErrorCode.REVIEW_RESULT_INVALID,
                    "$findings/source_event_ids",
                    "finding references packet-external source",
                )
            )
    if issues:
        raise ValidationError(issues)
