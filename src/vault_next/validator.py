"""Repository-wide deterministic validation across ledgers and projections."""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next import __version__
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ledger import OperationalLedger, SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.packages import PackageRegistry
from vault_next.projection import build_session_trace, verify_projection
from vault_next.readable_projections import (
    parse_markdown_projection_header,
    rebuild_markdown_projection,
    verify_markdown_projection,
)
from vault_next.records import SCHEMA_VERSION, SchemaRegistry


@dataclass(frozen=True)
class ValidationReport:
    """Versioned deterministic validation evidence."""

    issues: tuple[Issue, ...]
    semantic_event_count: int
    operational_record_count: int
    projection_count: int
    semantic_fixture_hash: str
    operational_fixture_hash: str

    @property
    def passed(self) -> bool:
        return not self.issues

    def to_record(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "issues": [issue.__dict__ for issue in self.issues],
            "operational_fixture_hash": self.operational_fixture_hash,
            "operational_record_count": self.operational_record_count,
            "projection_count": self.projection_count,
            "runtime": platform.python_version(),
            "schema_version": SCHEMA_VERSION,
            "semantic_event_count": self.semantic_event_count,
            "semantic_fixture_hash": self.semantic_fixture_hash,
            "tool_version": __version__,
        }


class KernelValidator:
    """Validate canonical stores, cross-store references, and generated traces."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry):
        self.paths = paths
        self.schemas = schemas
        self.semantic = SemanticLedger(paths, schemas)
        self.operational = OperationalLedger(paths, schemas)

    def validate(self) -> ValidationReport:
        issues = list(self.semantic.validate_all())
        issues.extend(self.operational.validate_all())
        issues.extend(PackageRegistry(self.paths, self.schemas).validate())
        events: list[dict[str, Any]] = []
        operations: list[dict[str, Any]] = []
        if not issues:
            events = self.semantic.read_all()
            operations = self.operational.read_all()
            issues.extend(self._cross_reference_issues(events, operations))
            projection_count, projection_issues = self._projection_issues(events)
            issues.extend(projection_issues)
            issues.extend(self._review_issues(events))
            issues.extend(self._evaluation_issues())
        else:
            projection_count = 0
        return ValidationReport(
            tuple(sorted(issues)),
            len(events),
            len(operations),
            projection_count,
            canonical_sha256(events),
            canonical_sha256(operations),
        )

    def _review_issues(self, events: list[dict[str, Any]]) -> list[Issue]:
        """Verify immutable P5 review records and their exact canonical-event bindings."""

        issues: list[Issue] = []
        packets: dict[str, tuple[dict[str, Any], str]] = {}
        requests = {
            event["payload"].get("review_id"): event
            for event in events
            if event["event_type"] == "review.requested"
        }
        packet_root = self.paths.review_root / "packets"
        for path in sorted(packet_root.glob("*.json")) if packet_root.exists() else []:
            try:
                raw = path.read_bytes()
                packet = json.loads(raw)
                if canonical_bytes(packet) + b"\n" != raw:
                    raise ValueError("review packet is not canonical JSON")
                self.schemas.require("review-packet", packet)
                packet_sha256 = canonical_sha256(packet)
                request = requests[packet["packet_id"]]
                prior_session_events = [
                    event
                    for event in events[: events.index(request)]
                    if event.get("session_id") == packet["session_id"]
                ]
                expected_sources = [event["event_id"] for event in prior_session_events]
                if (
                    request["payload"].get("packet_sha256") != packet_sha256
                    or request["payload"].get("target_type") != packet["subject"]["target_type"]
                    or request["payload"].get("target_ref") != packet["subject"]["target_ref"]
                    or request["payload"].get("target_sha256") != packet["subject"]["target_sha256"]
                    or packet["source_event_ids"] != expected_sources
                    or packet["source_watermark"]
                    != prior_session_events[-1]["integrity"]["event_sha256"]
                ):
                    raise ValueError("review packet differs from its exact request/source watermark")
                packets[packet["packet_id"]] = (packet, packet_sha256)
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), f"review packet failed: {type(exc).__name__}")
                )
        completion_by_result = {
            event["payload"].get("result_sha256"): event
            for event in events
            if event["event_type"] == "review.completed"
        }
        results_by_sha256: dict[str, dict[str, Any]] = {}
        result_root = self.paths.review_root / "results"
        for path in sorted(result_root.glob("*.json")) if result_root.exists() else []:
            try:
                raw = path.read_bytes()
                result = json.loads(raw)
                if canonical_bytes(result) + b"\n" != raw:
                    raise ValueError("review result is not canonical JSON")
                self.schemas.require("review-result", result)
                review_id = path.stem.rsplit("-", 1)[0]
                packet, packet_sha256 = packets[review_id]
                result_sha256 = canonical_sha256(result)
                results_by_sha256[result_sha256] = result
                completion = completion_by_result[result_sha256]
                if (
                    result["packet_sha256"] != packet_sha256
                    or result["target_sha256"] != packet["subject"]["target_sha256"]
                    or completion["payload"].get("review_id") != review_id
                    or completion["payload"].get("status") != result["status"]
                ):
                    raise ValueError("review result differs from packet or completion event")
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), f"review result failed: {type(exc).__name__}")
                )
        waiver_root = self.paths.review_root / "waivers"
        waiver_events = [event for event in events if event["event_type"] == "review.waived"]
        for path in sorted(waiver_root.glob("*.json")) if waiver_root.exists() else []:
            try:
                raw = path.read_bytes()
                waiver = json.loads(raw)
                if canonical_bytes(waiver) + b"\n" != raw:
                    raise ValueError("review waiver is not canonical JSON")
                self.schemas.require("review-waiver", waiver)
                result = results_by_sha256[waiver["result_sha256"]]
                event = next(
                    item
                    for item in waiver_events
                    if item["payload"].get("waiver_id") == waiver["waiver_id"]
                )
                if (
                    waiver["review_id"] != event["payload"].get("review_id")
                    or waiver["target_sha256"] != result["target_sha256"]
                    or not set(waiver["finding_ids"])
                    .issubset({finding["finding_id"] for finding in result["findings"]})
                ):
                    raise ValueError("review waiver differs from exact finding result")
            except (KeyError, StopIteration, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), f"review waiver failed: {type(exc).__name__}")
                )
        return issues

    def _evaluation_issues(self) -> list[Issue]:
        """Verify P5 regression reports and baselines are canonical and review-bound."""

        issues: list[Issue] = []
        result_hashes: set[str] = set()
        result_root = self.paths.review_root / "results"
        for path in sorted(result_root.glob("*.json")) if result_root.exists() else []:
            try:
                result_hashes.add(canonical_sha256(json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError):
                continue
        runs: set[str] = set()
        run_root = self.paths.evaluation_root / "runs"
        for path in sorted(run_root.glob("*.json")) if run_root.exists() else []:
            try:
                raw = path.read_bytes()
                run = json.loads(raw)
                if canonical_bytes(run) + b"\n" != raw:
                    raise ValueError("evaluation run is not canonical JSON")
                self.schemas.require("evaluation-run", run)
                zeroed = dict(run)
                zeroed["run_sha256"] = "0" * 64
                if run["run_sha256"] != canonical_sha256(zeroed):
                    raise ValueError("evaluation run self digest differs")
                runs.add(canonical_sha256(run))
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(ErrorCode.REVIEW_RESULT_INVALID, str(path), f"evaluation run failed: {type(exc).__name__}")
                )
        baseline_root = self.paths.evaluation_root / "baselines"
        for path in sorted(baseline_root.glob("*.json")) if baseline_root.exists() else []:
            try:
                raw = path.read_bytes()
                baseline = json.loads(raw)
                if canonical_bytes(baseline) + b"\n" != raw:
                    raise ValueError("evaluation baseline is not canonical JSON")
                self.schemas.require("evaluation-baseline", baseline)
                zeroed = dict(baseline)
                zeroed["baseline_sha256"] = "0" * 64
                if baseline["baseline_sha256"] != canonical_sha256(zeroed):
                    raise ValueError("evaluation baseline self digest differs")
                if (
                    baseline["run_sha256"] not in runs
                    or baseline["reviewed_change_record_sha256"] not in result_hashes
                ):
                    raise ValueError("baseline lacks stored run or reviewed change record")
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.REVIEW_RESULT_INVALID,
                        str(path),
                        f"evaluation baseline failed: {type(exc).__name__}",
                    )
                )
        return issues

    @staticmethod
    def _cross_reference_issues(
        events: list[dict[str, Any]],
        operations: list[dict[str, Any]],
    ) -> list[Issue]:
        issues: list[Issue] = []
        event_ids = {event["event_id"] for event in events}
        case_ids = {
            event["case_id"] for event in events if event["event_type"] == "case.created"
        }
        session_ids = {
            event["session_id"]
            for event in events
            if event["event_type"] in {"session.started", "session.created"}
        }
        for operation in operations:
            operation_id = operation["operation_id"]
            if operation["case_id"] is not None and operation["case_id"] not in case_ids:
                issues.append(
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        f"$operations/{operation_id}/case_id",
                        "operational record references an unknown case",
                    )
                )
            if operation["session_id"] is not None and operation["session_id"] not in session_ids:
                issues.append(
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        f"$operations/{operation_id}/session_id",
                        "operational record references an unknown session",
                    )
                )
            for event_id in operation["semantic_event_refs"]:
                if event_id not in event_ids:
                    issues.append(
                        Issue(
                            ErrorCode.EVENT_REFERENCE_MISSING,
                            f"$operations/{operation_id}/semantic_event_refs",
                            "operational record references an unknown semantic event",
                        )
                    )
        return issues

    def _projection_issues(self, events: list[dict[str, Any]]) -> tuple[int, list[Issue]]:
        issues: list[Issue] = []
        projection_dir = self.paths.projection_root / "sessions"
        paths = sorted(projection_dir.glob("*.json")) if projection_dir.exists() else []
        for path in paths:
            try:
                raw = path.read_bytes()
                projection = json.loads(raw)
                if canonical_bytes(projection) + b"\n" != raw:
                    raise ValueError("projection is not canonical JSON")
                self.schemas.require("projection-metadata", projection["metadata"])
                if not verify_projection(projection):
                    raise ValueError("projection content digest does not match")
                expected = build_session_trace(events, projection["session_id"], self.schemas)
                if canonical_bytes(expected) != canonical_bytes(projection):
                    raise ValueError("projection differs from clean rebuild")
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.PROJECTION_TAMPERED,
                        str(path),
                        f"generated projection validation failed: {type(exc).__name__}",
                    )
                )
        markdown_root = self.paths.projection_root
        markdown_paths = (
            sorted(markdown_root.rglob("*.md")) if markdown_root.exists() else []
        )
        for path in markdown_paths:
            try:
                raw = path.read_bytes()
                content = raw.decode("utf-8")
                if not verify_markdown_projection(content):
                    raise ValueError("Markdown projection content digest does not match")
                envelope = parse_markdown_projection_header(content)
                self.schemas.require("projection-metadata", envelope["metadata"])
                expected = rebuild_markdown_projection(events, content, self.schemas)
                expected_path = self.paths.projection_root / expected.relative_path
                if path.resolve() != expected_path.resolve():
                    raise ValueError("Markdown projection path does not match its parameters")
                if expected.content.encode("utf-8") != raw:
                    raise ValueError("Markdown projection differs from clean rebuild")
            except (
                KeyError,
                TypeError,
                UnicodeDecodeError,
                ValueError,
                json.JSONDecodeError,
                ValidationError,
            ) as exc:
                issues.append(
                    Issue(
                        ErrorCode.PROJECTION_TAMPERED,
                        str(path),
                        f"generated Markdown projection validation failed: {type(exc).__name__}",
                    )
                )
        context_dir = self.paths.projection_root / "context"
        context_paths = sorted(context_dir.glob("*.json")) if context_dir.exists() else []
        event_ids = {event["event_id"] for event in events}
        evidence_events = {
            event["payload"]["metadata"]["evidence_id"]: event
            for event in events
            if event["event_type"] == "evidence.registered"
        }
        from vault_next.lifecycle import fold_session_states

        session_states, lifecycle_issues = fold_session_states(events)
        issues.extend(lifecycle_issues)
        for path in context_paths:
            try:
                raw = path.read_bytes()
                report = json.loads(raw)
                if canonical_bytes(report) + b"\n" != raw:
                    raise ValueError("context provenance report is not canonical JSON")
                self.schemas.require("context-provenance-report", report)
                state = session_states[report["session_id"]]
                if state.manifest_sha256 != report["manifest_sha256"]:
                    raise ValueError("context report does not use the current manifest")
                allowed = {item["ref"] for item in state.manifest["authorized_context"]}
                if not set(report["loaded_refs"]).issubset(allowed):
                    raise ValueError("context report contains unauthorized references")
                if not set(report["source_event_ids"]).issubset(event_ids):
                    raise ValueError("context report references unknown source events")
            except (KeyError, ValueError, json.JSONDecodeError, ValidationError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.PROJECTION_TAMPERED,
                        str(path),
                        f"context projection validation failed: {type(exc).__name__}",
                    )
                )
        for evidence_id, event in evidence_events.items():
            metadata = event["payload"]["metadata"]
            try:
                object_path = self.paths.ensure_runtime_write_target(
                    self.paths.evidence_root / "objects" / metadata["object_ref"]
                )
                content = object_path.read_bytes()
                if (
                    sha256_hex(content) != metadata["content_sha256"]
                    or len(content) != metadata["byte_count"]
                ):
                    raise ValueError("evidence hash or size mismatch")
            except (OSError, ValueError, ValidationError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.EVIDENCE_OBJECT_INVALID,
                        metadata["object_ref"],
                        f"evidence validation failed: {type(exc).__name__}",
                    )
                )
        objects_root = self.paths.evidence_root / "objects" / "sha256"
        registered_hashes = {
            event["payload"]["metadata"]["content_sha256"]
            for event in evidence_events.values()
        }
        if objects_root.exists():
            for object_path in sorted(path for path in objects_root.glob("*/*") if path.is_file()):
                if object_path.name not in registered_hashes:
                    issues.append(
                        Issue(
                            ErrorCode.EVIDENCE_OBJECT_INVALID,
                            str(object_path),
                            "orphan synthetic evidence object has no canonical registration event",
                        )
                    )
        artifact_versions = [
            event["payload"]["version"]
            for event in events
            if event["event_type"] == "artifact.version_created"
        ]
        artifact_hashes = {version["content_sha256"] for version in artifact_versions}
        for version in artifact_versions:
            try:
                object_path = self.paths.ensure_runtime_write_target(
                    self.paths.artifact_root / "objects" / version["object_ref"]
                )
                content = object_path.read_bytes()
                if (
                    sha256_hex(content) != version["content_sha256"]
                    or len(content) != version["byte_count"]
                ):
                    raise ValueError("artifact hash or size mismatch")
            except (OSError, ValueError, ValidationError) as exc:
                issues.append(
                    Issue(
                        ErrorCode.ARTIFACT_REFERENCE_INVALID,
                        version["object_ref"],
                        f"artifact validation failed: {type(exc).__name__}",
                    )
                )
        artifact_objects = self.paths.artifact_root / "objects" / "sha256"
        if artifact_objects.exists():
            for object_path in sorted(
                path for path in artifact_objects.glob("*/*") if path.is_file()
            ):
                if object_path.name not in artifact_hashes:
                    issues.append(
                        Issue(
                            ErrorCode.ARTIFACT_REFERENCE_INVALID,
                            str(object_path),
                            "orphan working-artifact object has no canonical version event",
                        )
                    )
        return len(paths) + len(context_paths) + len(markdown_paths), issues
