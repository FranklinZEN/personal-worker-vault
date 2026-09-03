"""Deterministic Phase 1 session trace projection and tamper handling."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next import __version__
from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.errors import ErrorCode, Issue
from vault_next.paths import RuntimePaths
from vault_next.records import SCHEMA_VERSION, SchemaRegistry
from vault_next.lifecycle import fold_decisions
from vault_next.state import (
    fold_artifact_state,
    fold_interaction_state,
    fold_reasoning_state,
    fold_work_items,
)


@dataclass(frozen=True)
class ProjectionWriteResult:
    path: Path
    projection_sha256: str
    findings: tuple[Issue, ...] = ()
    quarantined_path: Path | None = None


def build_session_trace(
    events: list[dict[str, Any]],
    session_id: str,
    schemas: SchemaRegistry,
) -> dict[str, Any]:
    """Fold validated events into a deterministic, non-authoritative session trace."""

    session_events = [item for item in events if item.get("session_id") == session_id]
    if not session_events:
        raise ValueError(f"no events found for session: {session_id}")
    case_id = session_events[0]["case_id"]
    selected = [
        item
        for item in events
        if item.get("session_id") == session_id
        or (item["event_type"] == "case.created" and item["case_id"] == case_id)
    ]
    # ``events`` is already canonical ledger order; timestamps are data, not an ordering override.
    corrections: dict[str, list[dict[str, Any]]] = {}
    for event in selected:
        if event["event_type"] == "event.correction_recorded":
            target = event["payload"].get("corrects_event_id")
            if isinstance(target, str):
                corrections.setdefault(target, []).append(event)

    event_trace: list[dict[str, Any]] = []
    recommendations: list[str] = []
    owner_decisions: list[str] = []
    actions: list[str] = []
    disposition = "open"
    for event in selected:
        effective_values: dict[str, Any] = {}
        for correction in corrections.get(event["event_id"], []):
            effective_values.update(correction["payload"].get("corrected_values", {}))
        event_trace.append(
            {
                "actor_type": event["actor"]["type"],
                "effective_values": effective_values,
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "recorded_at": event["recorded_at"],
                "subject_refs": event["subject_refs"],
            }
        )
        if event["event_type"] == "recommendation.issued":
            recommendations.extend(event["subject_refs"])
        elif event["event_type"] == "owner_decision.recorded":
            owner_decisions.extend(event["subject_refs"])
        elif event["event_type"] == "action.proposed":
            actions.extend(event["subject_refs"])
        elif event["event_type"] == "session.closed":
            disposition = event["payload"]["disposition"]

    metadata = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": __version__,
        "source_event_ids": [item["event_id"] for item in selected],
        "source_watermark": selected[-1]["integrity"]["event_sha256"],
        "generated_at": selected[-1]["recorded_at"],
        "projection_sha256": "0" * 64,
        "do_not_edit": True,
    }
    projection = {
        "metadata": metadata,
        "case_id": case_id,
        "session_id": session_id,
        "disposition": disposition,
        "recommendation_refs": recommendations,
        "owner_decision_refs": owner_decisions,
        "action_refs": actions,
        "event_trace": event_trace,
        "current_reasoning_state": fold_reasoning_state(events, session_id),
        "interaction_state": fold_interaction_state(events, session_id),
        "artifact_state": fold_artifact_state(events, case_id=case_id),
        "work_item_state": fold_work_items(events, case_id=case_id),
        "decision_state": {
            decision_id: {
                "current": state.current,
                "decision": state.decision,
                "last_event_id": state.last_event_id,
                "revision": state.revision,
                "session_id": state.session_id,
                "superseded_by": state.superseded_by,
            }
            for decision_id, state in sorted(fold_decisions(events)[0].items())
            if state.case_id == case_id
        },
    }
    metadata["projection_sha256"] = _projection_hash(projection)
    schemas.require("projection-metadata", metadata)
    return projection


def verify_projection(projection: dict[str, Any]) -> bool:
    """Verify the projection's self-excluding content digest."""

    return projection.get("metadata", {}).get("projection_sha256") == _projection_hash(projection)


def write_session_trace(
    projection: dict[str, Any],
    paths: RuntimePaths,
) -> ProjectionWriteResult:
    """Write a replaceable projection and quarantine any unexplained prior bytes."""

    if not verify_projection(projection):
        raise ValueError("projection digest is invalid")
    output_dir = paths.ensure_runtime_write_target(paths.projection_root / "sessions")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = paths.ensure_runtime_write_target(output_dir / f"{projection['session_id']}.json")
    expected = canonical_bytes(projection) + b"\n"
    findings: list[Issue] = []
    quarantined_path: Path | None = None
    if output_path.exists() and output_path.read_bytes() != expected:
        old = output_path.read_bytes()
        digest = sha256_hex(old)
        quarantine_dir = paths.ensure_runtime_write_target(paths.quarantine_root / "projections")
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantined_path = paths.ensure_runtime_write_target(
            quarantine_dir / f"{output_path.stem}-{digest}.json"
        )
        if not quarantined_path.exists():
            _atomic_write(quarantined_path, old)
        findings.append(
            Issue(
                ErrorCode.PROJECTION_TAMPERED,
                str(output_path),
                "existing generated projection differed from canonical rebuild",
            )
        )
    _atomic_write(output_path, expected)
    return ProjectionWriteResult(
        output_path,
        projection["metadata"]["projection_sha256"],
        tuple(findings),
        quarantined_path,
    )


def _projection_hash(projection: dict[str, Any]) -> str:
    material = copy.deepcopy(projection)
    material.setdefault("metadata", {})["projection_sha256"] = "0" * 64
    return canonical_sha256(material)


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        written = os.write(descriptor, data)
        if written != len(data):
            raise OSError(f"short projection write: {written}/{len(data)}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
