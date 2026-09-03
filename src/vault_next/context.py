"""Explicit, manifest-authorized Phase 2 context loading and provenance."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.lifecycle import fold_session_states
from vault_next.ledger import SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry


@dataclass(frozen=True)
class LoadedContext:
    items: tuple[dict[str, Any], ...]
    report: dict[str, Any]
    report_path: Path


class ExplicitContextLoader:
    """Load no ambient context: every requested reference must be allowlisted."""

    def __init__(self, paths: RuntimePaths, schemas: SchemaRegistry) -> None:
        self.paths = paths
        self.schemas = schemas

    def load(
        self,
        *,
        session_id: str,
        requested_refs: list[str],
        events: list[dict[str, Any]],
    ) -> LoadedContext:
        states, fold_issues = fold_session_states(events)
        if fold_issues:
            raise ValidationError(fold_issues)
        state = states.get(session_id)
        if state is None or state.manifest is None or state.manifest_sha256 is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        "$session_id",
                        "session has no Phase 2 manifest",
                    )
                ]
            )
        manifest = state.manifest
        authorizations = {item["ref"]: item for item in manifest["authorized_context"]}
        unauthorized = sorted(set(requested_refs) - set(authorizations))
        if unauthorized:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.CONTEXT_AUTHORIZATION_DENIED,
                        "$requested_refs",
                        f"context references are not authorized: {', '.join(unauthorized)}",
                    )
                ]
            )
        event_index = {event["event_id"]: event for event in events}
        evidence_index = {
            event["payload"]["metadata"]["evidence_id"]: event
            for event in events
            if event["event_type"] == "evidence.registered"
        }
        loaded: list[dict[str, Any]] = []
        source_event_ids: list[str] = []
        observed_labels: set[str] = set()
        for ref in requested_refs:
            authorization = authorizations[ref]
            if ref.startswith("event_"):
                event = event_index.get(ref)
                if event is None or event["case_id"] != state.case_id:
                    raise self._denied(ref, "event is missing or belongs to another case")
                labels = {event["sensitivity"]}
                loaded.append({"ref": ref, "kind": "event", "value": event})
                source_event_ids.append(event["event_id"])
            elif ref.startswith("evidence_sha256_"):
                event = evidence_index.get(ref)
                if event is None or event["case_id"] != state.case_id:
                    raise self._denied(ref, "evidence is missing or belongs to another case")
                metadata = event["payload"]["metadata"]
                object_path = self.paths.ensure_runtime_write_target(
                    self.paths.evidence_root / "objects" / metadata["object_ref"]
                )
                try:
                    data = object_path.read_bytes()
                except OSError:
                    raise self._denied(ref, "evidence object is unavailable") from None
                if (
                    sha256_hex(data) != metadata["content_sha256"]
                    or len(data) != metadata["byte_count"]
                ):
                    raise ValidationError(
                        [
                            Issue(
                                ErrorCode.EVIDENCE_OBJECT_INVALID,
                                ref,
                                "evidence content hash or size mismatch",
                            )
                        ]
                    )
                labels = set(metadata["sensitivity_labels"])
                loaded.append(
                    {
                        "ref": ref,
                        "kind": "evidence",
                        "metadata": metadata,
                        "content_bytes": data,
                    }
                )
                source_event_ids.append(event["event_id"])
            else:
                raise self._denied(ref, "unsupported context reference type")
            if not labels.issubset(set(authorization["sensitivity_labels"])):
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.CONTEXT_SENSITIVITY_EXCEEDED,
                            ref,
                            "source sensitivity exceeds reference authorization",
                        )
                    ]
                )
            observed_labels.update(labels)
        if not observed_labels.issubset(set(manifest["sensitivity_labels"])):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.CONTEXT_SENSITIVITY_EXCEEDED,
                        "$manifest/sensitivity_labels",
                        "loaded context exceeds session sensitivity",
                    )
                ]
            )
        report = {
            "schema_version": "1.0",
            "case_id": state.case_id,
            "session_id": session_id,
            "manifest_version": manifest["manifest_version"],
            "manifest_sha256": state.manifest_sha256,
            "loaded_refs": list(dict.fromkeys(requested_refs)),
            "rejected_refs": [],
            "sensitivity_labels": sorted(observed_labels),
            "source_event_ids": list(dict.fromkeys(source_event_ids)),
        }
        self.schemas.require("context-provenance-report", report)
        path = self._write_report(report)
        return LoadedContext(tuple(loaded), report, path)

    def load_from_repository(
        self, *, session_id: str, requested_refs: list[str]
    ) -> LoadedContext:
        """Reconstruct context solely from canonical repository state."""

        events = SemanticLedger(self.paths, self.schemas).read_all()
        return self.load(session_id=session_id, requested_refs=requested_refs, events=events)

    def _write_report(self, report: dict[str, Any]) -> Path:
        directory = self.paths.ensure_runtime_write_target(self.paths.projection_root / "context")
        directory.mkdir(parents=True, exist_ok=True)
        path = self.paths.ensure_runtime_write_target(directory / f"{report['session_id']}.json")
        data = canonical_bytes(report) + b"\n"
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            if os.write(descriptor, data) != len(data):
                raise OSError("short context report write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        return path

    @staticmethod
    def _denied(ref: str, reason: str) -> ValidationError:
        return ValidationError([Issue(ErrorCode.CONTEXT_AUTHORIZATION_DENIED, ref, reason)])
