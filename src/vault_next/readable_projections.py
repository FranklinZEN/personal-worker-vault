"""Deterministic, provenance-labelled Markdown projections for Phase 4."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next import __version__
from vault_next.canonical import canonical_bytes, sha256_hex
from vault_next.errors import ErrorCode, Issue
from vault_next.lifecycle import fold_case_states, fold_decisions, fold_session_states
from vault_next.paths import RuntimePaths
from vault_next.projection import ProjectionWriteResult
from vault_next.records import SCHEMA_VERSION, SchemaRegistry
from vault_next.state import build_current_work_state, fold_artifact_state


HEADER_PREFIX = "<!-- vault-next-generated "
HEADER_SUFFIX = " -->\n"
_ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class MarkdownProjection:
    """A replaceable, fully-derived Markdown view and its reconstruction parameters."""

    kind: str
    parameters: dict[str, str]
    metadata: dict[str, Any]
    content: str

    @property
    def relative_path(self) -> Path:
        if self.kind == "decision_memo":
            return Path("decision-memos") / f"{self.parameters['case_id']}.md"
        if self.kind == "case_journal":
            return Path("cases") / f"{self.parameters['case_id']}.md"
        if self.kind == "artifact_history":
            return Path("artifacts") / f"{self.parameters['artifact_id']}.md"
        if self.kind == "current_work":
            return Path("work") / (
                f"today-{self.parameters['as_of_date']}-{_safe_path_part(self.parameters['time_zone'])}.md"
            )
        raise ValueError(f"unsupported Markdown projection kind: {self.kind}")


def build_decision_memo(
    events: list[dict[str, Any]], case_id: str, schemas: SchemaRegistry
) -> MarkdownProjection:
    """Render an inspectable decision memo without inferring owner intent."""

    selected = _case_events(events, case_id)
    question = _primary_question(selected)
    decision_states, _ = fold_decisions(events)
    case_decisions = [state for state in decision_states.values() if state.case_id == case_id]
    body = [
        f"# Decision memo: {_case_title(selected, case_id)}",
        "",
        "## Purpose and authority boundary",
        "",
        "This generated memo reconstructs canonical records. It is not an owner decision, approval,"
        " or action authorization.",
        "",
        "## Original question",
        "",
        _claim(question[0], question[1]),
        "",
        "## Accepted frame",
        "",
        *_derived_absence_or_items(
            selected,
            {"question.reframed", "question.clarified"},
            "No separate accepted frame was explicitly recorded.",
            lambda event: event["payload"].get("question") or event["payload"].get("summary", ""),
        ),
        "",
        "## Material changes",
        "",
        *_event_bullets(
            selected,
            {
                "question.clarified",
                "question.reframed",
                "recommendation.issued",
                "recommendation.revised",
                "recommendation.withdrawn",
                "recommendation.upheld",
                "review.finding_recorded",
                "event.correction_recorded",
            },
        ),
        "",
        "## Evidence and limitations",
        "",
        *_evidence_bullets(selected),
        "",
        "## Assumptions and alternatives",
        "",
        *_event_bullets(
            selected,
            {
                "assumption.recorded",
                "assumption.revised",
                "alternative.recorded",
                "alternative.disposition_changed",
                "disagreement.recorded",
                "disagreement.resolved",
            },
        ),
        "",
        "## Recommendation history",
        "",
        *_event_bullets(
            selected,
            {
                "recommendation.issued",
                "recommendation.revised",
                "recommendation.withdrawn",
                "recommendation.upheld",
            },
        ),
        "",
        "## Owner decision history and current disposition",
        "",
        *_decision_bullets(selected, case_decisions),
        "",
        "## Current outcome assessment",
        "",
        *_outcome_bullets(selected),
        "",
        "## Provenance",
        "",
        *_provenance_lines(selected),
    ]
    return _build_projection(
        "decision_memo", {"case_id": case_id}, selected, "\n".join(body) + "\n", schemas
    )


def build_case_journal(
    events: list[dict[str, Any]], case_id: str, schemas: SchemaRegistry
) -> MarkdownProjection:
    """Render a chronological case journey with interaction and correction markers."""

    selected = _case_events(events, case_id)
    case_states, _ = fold_case_states(events)
    session_states, _ = fold_session_states(events)
    body = [
        f"# Case journal: {_case_title(selected, case_id)}",
        "",
        "## Current derived state",
        "",
        _claim(
            f"Case status: {case_states[case_id].status}.", case_states[case_id].last_event_id
        ),
        _claim(
            "Sessions: "
            + ", ".join(
                f"{state.session_id} ({state.status})"
                for state in sorted(
                    (state for state in session_states.values() if state.case_id == case_id),
                    key=lambda state: state.session_id,
                )
            )
            + ".",
            selected[-1]["event_id"],
        ),
        "",
        "## Interaction journey and continuity",
        "",
        *_event_bullets(
            selected,
            {
                "interaction.started",
                "interaction.mode_changed",
                "owner_input.recorded",
                "checkpoint.recorded",
                "session.closed",
                "session.created",
                "session.started",
            },
        ),
        "",
        "## Chronological event journal",
        "",
        "| Recorded at | Actor | Event | Canonical summary | Source |",
        "| --- | --- | --- | --- | --- |",
    ]
    for event in selected:
        body.append(
            "| "
            + " | ".join(
                (
                    _cell(event["recorded_at"]),
                    _cell(event["actor"]["type"]),
                    _cell(event["event_type"]),
                    _cell(_event_summary(event)),
                    _cell(event["event_id"]),
                )
            )
            + " |"
        )
    body.extend(["", "## Provenance", "", *_provenance_lines(selected)])
    return _build_projection(
        "case_journal", {"case_id": case_id}, selected, "\n".join(body) + "\n", schemas
    )


def build_artifact_history(
    events: list[dict[str, Any]], artifact_id: str, schemas: SchemaRegistry
) -> MarkdownProjection:
    """Render immutable artifact lineage, feedback disposition, and exact acceptance."""

    artifacts = fold_artifact_state(events)
    if artifact_id not in artifacts:
        raise ValueError(f"unknown artifact: {artifact_id}")
    artifact = artifacts[artifact_id]
    selected = [
        event
        for event in events
        if event.get("case_id") == next(iter(artifact["versions"].values()))["case_id"]
        and (
            artifact_id in event.get("subject_refs", [])
            or event["event_type"] in {"case.created", "session.created", "session.started"}
        )
    ]
    versions = sorted(
        artifact["versions"].values(), key=lambda item: item["version_number"]
    )
    body = [
        f"# Working-artifact history: {artifact_id}",
        "",
        "This generated history identifies immutable versions and does not make any version an owner"
        " decision or external approval.",
        "",
        "## Version lineage",
        "",
        "| Version | Status | Content digest | Parent | Change summary | Source event |",
        "| --- | --- | --- | --- | --- |",
    ]
    for version in versions:
        body.append(
            "| "
            + " | ".join(
                (
                    str(version["version_number"]),
                    _cell(version["status"]),
                    _cell(version["content_sha256"]),
                    _cell(version["prior_version_id"] or "—"),
                    _cell(version["change_summary"]),
                    _cell(version["event_id"]),
                )
            )
            + " |"
        )
    body.extend(["", "## Feedback and review state", ""])
    if artifact["feedback"]:
        for feedback in sorted(artifact["feedback"].values(), key=lambda item: item["feedback_id"]):
            disposition = feedback.get("disposition", "open")
            addressed = feedback.get("addressed_by_version_id", "not yet addressed")
            body.append(
                _claim(
                    f"Feedback on {feedback['version_id']}: {feedback['feedback']} "
                    f"(state: {disposition}; {addressed}).",
                    feedback["event_id"],
                )
            )
    else:
        body.append("- Derived absence: no feedback is recorded for this artifact.")
    body.extend(["", "## Exact acceptance", ""])
    accepted_id = artifact["accepted_version_id"]
    if accepted_id is None:
        body.append("- Derived absence: no artifact version is explicitly accepted.")
    else:
        accepted = artifact["versions"][accepted_id]
        body.append(
            _claim(
                f"Accepted version: {accepted_id} with exact digest {accepted['content_sha256']}.",
                accepted["accepted_event_id"],
            )
        )
    body.extend(["", "## Version comparison", ""])
    for prior, current in zip(versions, versions[1:]):
        body.append(
            _claim(
                f"Version {prior['version_number']} → {current['version_number']}: "
                f"{current['change_summary']} (digest {prior['content_sha256']} → {current['content_sha256']}).",
                current["event_id"],
            )
        )
    if len(versions) == 1:
        body.append("- Derived absence: no later immutable version exists for comparison.")
    body.extend(["", "## Provenance", "", *_provenance_lines(selected)])
    return _build_projection(
        "artifact_history", {"artifact_id": artifact_id}, selected, "\n".join(body) + "\n", schemas
    )


def build_current_work_view(
    events: list[dict[str, Any]],
    *,
    as_of_date: str,
    time_zone: str,
    schemas: SchemaRegistry,
) -> MarkdownProjection:
    """Render the non-mutating repository-local today view."""

    state = build_current_work_state(events, as_of_date=as_of_date, time_zone=time_zone)
    selected = list(events)
    acceptance_event_ids = {
        (event["payload"]["artifact_id"], event["payload"]["version_id"]): event["event_id"]
        for event in events
        if event["event_type"] == "artifact.accepted"
    }
    body = [
        f"# Current work — {as_of_date} ({time_zone})",
        "",
        "This generated view is derived from canonical events and does not create, commit, complete, or modify work.",
        "",
        "## Due or review-needed",
        "",
        _claim(
            "Due or overdue work IDs: " + _or_none(state["due_or_overdue_ids"]) + ".",
            state["source_event_ids"][-1] if state["source_event_ids"] else "GENESIS",
        ),
        _claim(
            "Review-due work IDs: " + _or_none(state["review_due_ids"]) + ".",
            state["source_event_ids"][-1] if state["source_event_ids"] else "GENESIS",
        ),
        "",
        "## Owner-committed work",
        "",
        *_work_bullets(state["committed_work_items"]),
        "",
        "## Proposed work — not committed",
        "",
        *_work_bullets(state["proposed_work_items"]),
        "",
        "## Blockers and active sessions",
        "",
        *_blocker_bullets(state["active_work_items"]),
        _claim(
            "Active cases: " + _or_none(state["active_case_ids"]) + ".",
            state["source_event_ids"][-1] if state["source_event_ids"] else "GENESIS",
        ),
        _claim(
            "Active sessions: " + _or_none(state["active_session_ids"]) + ".",
            state["source_event_ids"][-1] if state["source_event_ids"] else "GENESIS",
        ),
        "",
        "## Accepted artifacts awaiting an explicit next step",
        "",
        *_accepted_artifact_bullets(
            state["accepted_artifacts"],
            state["committed_work_items"],
            acceptance_event_ids,
        ),
        "",
        "## Provenance",
        "",
        *_provenance_lines(selected),
    ]
    return _build_projection(
        "current_work",
        {"as_of_date": as_of_date, "time_zone": time_zone},
        selected,
        "\n".join(body) + "\n",
        schemas,
    )


def write_markdown_projection(
    projection: MarkdownProjection, paths: RuntimePaths
) -> ProjectionWriteResult:
    """Write a Markdown projection and quarantine an unexplained previous rendering."""

    if not verify_markdown_projection(projection.content):
        raise ValueError("Markdown projection digest is invalid")
    output_path = paths.ensure_runtime_write_target(paths.projection_root / projection.relative_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    expected = projection.content.encode("utf-8")
    findings: list[Issue] = []
    quarantined_path: Path | None = None
    if output_path.exists() and output_path.read_bytes() != expected:
        old = output_path.read_bytes()
        digest = sha256_hex(old)
        quarantine_dir = paths.ensure_runtime_write_target(paths.quarantine_root / "projections")
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantined_path = paths.ensure_runtime_write_target(
            quarantine_dir / f"{output_path.stem}-{digest}.md"
        )
        if not quarantined_path.exists():
            _atomic_write(quarantined_path, old)
        findings.append(
            Issue(
                ErrorCode.PROJECTION_TAMPERED,
                str(output_path),
                "existing generated Markdown projection differed from canonical rebuild",
            )
        )
    _atomic_write(output_path, expected)
    return ProjectionWriteResult(
        output_path,
        projection.metadata["projection_sha256"],
        tuple(findings),
        quarantined_path,
    )


def verify_markdown_projection(content: str) -> bool:
    """Verify self-excluding projection metadata embedded in the generated header."""

    try:
        envelope = parse_markdown_projection_header(content)
        metadata = copy.deepcopy(envelope["metadata"])
        expected = metadata["projection_sha256"]
        metadata["projection_sha256"] = _ZERO_HASH
        material = _render_markdown(envelope["kind"], envelope["parameters"], metadata, _markdown_body(content))
        return expected == sha256_hex(material.encode("utf-8"))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def parse_markdown_projection_header(content: str) -> dict[str, Any]:
    """Return the canonical metadata envelope from a generated Markdown document."""

    first, _, _ = content.partition("\n")
    if not first.startswith(HEADER_PREFIX) or not first.endswith(HEADER_SUFFIX.strip()):
        raise ValueError("missing generated Markdown metadata header")
    return json.loads(first[len(HEADER_PREFIX) : -len(HEADER_SUFFIX.strip())])


def rebuild_markdown_projection(
    events: list[dict[str, Any]], content: str, schemas: SchemaRegistry
) -> MarkdownProjection:
    """Rebuild one parsed Markdown projection from canonical records only."""

    envelope = parse_markdown_projection_header(content)
    metadata = envelope["metadata"]
    schemas.require("projection-metadata", metadata)
    kind = envelope["kind"]
    parameters = envelope["parameters"]
    if kind == "decision_memo":
        return build_decision_memo(events, parameters["case_id"], schemas)
    if kind == "case_journal":
        return build_case_journal(events, parameters["case_id"], schemas)
    if kind == "artifact_history":
        return build_artifact_history(events, parameters["artifact_id"], schemas)
    if kind == "current_work":
        return build_current_work_view(
            events,
            as_of_date=parameters["as_of_date"],
            time_zone=parameters["time_zone"],
            schemas=schemas,
        )
    raise ValueError(f"unsupported generated Markdown kind: {kind}")


def _build_projection(
    kind: str,
    parameters: dict[str, str],
    selected: list[dict[str, Any]],
    body: str,
    schemas: SchemaRegistry,
) -> MarkdownProjection:
    if not selected:
        raise ValueError("a generated projection needs at least one source event")
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": __version__,
        "source_event_ids": [event["event_id"] for event in selected],
        "source_watermark": selected[-1]["integrity"]["event_sha256"],
        "generated_at": selected[-1]["recorded_at"],
        "projection_sha256": _ZERO_HASH,
        "do_not_edit": True,
    }
    schemas.require("projection-metadata", metadata)
    zeroed = _render_markdown(kind, parameters, metadata, body)
    metadata["projection_sha256"] = sha256_hex(zeroed.encode("utf-8"))
    schemas.require("projection-metadata", metadata)
    return MarkdownProjection(kind, dict(parameters), metadata, _render_markdown(kind, parameters, metadata, body))


def _render_markdown(kind: str, parameters: dict[str, str], metadata: dict[str, Any], body: str) -> str:
    envelope = {"kind": kind, "metadata": metadata, "parameters": parameters}
    return HEADER_PREFIX + canonical_bytes(envelope).decode("utf-8") + HEADER_SUFFIX + body


def _markdown_body(content: str) -> str:
    _, separator, body = content.partition("\n")
    if not separator:
        raise ValueError("generated Markdown document has no body")
    return body


def _case_events(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    selected = [event for event in events if event.get("case_id") == case_id]
    if not selected:
        raise ValueError(f"unknown case: {case_id}")
    return selected


def _case_title(events: list[dict[str, Any]], case_id: str) -> str:
    created = next(event for event in events if event["event_type"] == "case.created")
    return str(created["payload"].get("title", case_id))


def _primary_question(events: list[dict[str, Any]]) -> tuple[str, str]:
    question_event = next((event for event in events if event["event_type"] == "question.recorded"), None)
    if question_event is not None:
        return str(question_event["payload"]["question"]), question_event["event_id"]
    session = next(
        (event for event in events if event["event_type"] in {"session.created", "session.started"}),
        None,
    )
    if session is None:
        return "Derived absence: no primary question was recorded.", events[0]["event_id"]
    manifest = session["payload"].get("manifest", {})
    question = manifest.get(
        "primary_question", "Derived absence: no primary question was recorded."
    )
    return str(question), session["event_id"]


def _event_bullets(events: list[dict[str, Any]], event_types: set[str]) -> list[str]:
    matches = [event for event in events if event["event_type"] in event_types]
    if not matches:
        return ["- Derived absence: no matching canonical records were found."]
    return [_claim(_event_summary(event), event["event_id"]) for event in matches]


def _evidence_bullets(events: list[dict[str, Any]]) -> list[str]:
    matches = [event for event in events if event["event_type"] == "evidence.registered"]
    if not matches:
        return ["- Derived absence: no evidence registration is recorded."]
    lines = []
    for event in matches:
        metadata = event["payload"]["metadata"]
        lines.append(
            _claim(
                f"Evidence {metadata['evidence_id']}: {metadata['original_display_name']} "
                f"(digest {metadata['content_sha256']}; sensitivity "
                f"{', '.join(metadata['sensitivity_labels'])}).",
                event["event_id"],
            )
        )
    return lines


def _decision_bullets(
    events: list[dict[str, Any]], decisions: list[Any]
) -> list[str]:
    if not decisions:
        return ["- Derived absence: no explicit owner decision is recorded; recommendations remain non-authoritative."]
    lines = []
    for state in sorted(decisions, key=lambda item: item.decision_id):
        history = [
            event
            for event in events
            if event["event_type"] in {"owner_decision.recorded", "owner_decision.revised"}
            and event["payload"].get("decision_id") == state.decision_id
        ]
        for event in history:
            payload = event["payload"]
            if event["event_type"] == "owner_decision.recorded":
                lines.append(
                    _claim(
                        f"Historical owner decision {state.decision_id} (recorded): "
                        f"{payload.get('decision') or 'not stated'}.",
                        event["event_id"],
                    )
                )
            else:
                lines.append(
                    _claim(
                        f"Historical owner decision {state.decision_id} (revision): "
                        f"{payload.get('decision') or 'not stated'}. Reason: "
                        f"{payload.get('reason') or 'not stated'}.",
                        event["event_id"],
                    )
                )
        status = "current" if state.current else f"superseded by {state.superseded_by}"
        lines.append(
            _claim(
                f"Owner decision {state.decision_id} (revision {state.revision}, {status}): "
                f"{state.decision or 'not stated'}. This is the current derived disposition; "
                "rationale/costs are not stated.",
                state.last_event_id,
            )
        )
    return lines


def _outcome_bullets(events: list[dict[str, Any]]) -> list[str]:
    assessments = [event for event in events if event["event_type"] == "outcome.assessed"]
    if not assessments:
        return ["- Derived absence: no later outcome assessment is recorded."]
    return [
        _claim(
            f"Outcome for {event['payload']['decision_id']}: "
            f"result quality {event['payload']['result_quality']}; process quality "
            f"{event['payload']['process_quality']}; prediction assessment "
            f"{event['payload']['prediction_assessment']}; competing explanation "
            f"{event['payload']['competing_explanation']}; attribution confidence "
            f"{event['payload']['attribution_confidence']}; matured at "
            f"{event['payload']['matured_at']}; evidence "
            f"{', '.join(event['payload']['evidence_refs'])}.",
            event["event_id"],
        )
        for event in assessments
    ]


def _derived_absence_or_items(
    events: list[dict[str, Any]],
    event_types: set[str],
    absence: str,
    text: Any,
) -> list[str]:
    matches = [event for event in events if event["event_type"] in event_types]
    if not matches:
        return ["- Derived absence: " + absence]
    return [_claim(str(text(event)), event["event_id"]) for event in matches]


def _work_bullets(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["- Derived absence: none."]
    return [
        _claim(
            f"{item['work_item_id']}: {item['statement']} (status: {item['status']}; "
            f"due: {item.get('due_on') or 'not set'}; review: {item.get('next_review_on') or 'not set'}).",
            item["last_event_id"],
        )
        for item in items
    ]


def _blocker_bullets(items: list[dict[str, Any]]) -> list[str]:
    blocked = [item for item in items if item.get("blocker")]
    if not blocked:
        return ["- Derived absence: no explicit blocker is recorded."]
    return [
        _claim(
            f"{item['work_item_id']} blocker: {item['blocker']}.", item["last_event_id"]
        )
        for item in blocked
    ]


def _accepted_artifact_bullets(
    artifacts: list[dict[str, Any]],
    committed_items: list[dict[str, Any]],
    acceptance_event_ids: dict[tuple[str, str], str],
) -> list[str]:
    if not artifacts:
        return ["- Derived absence: no accepted artifact is recorded."]
    committed_cases = {item["case_id"] for item in committed_items}
    return [
        _claim(
            f"{artifact['artifact_id']} version {artifact['version_id']} (digest {artifact['content_sha256']}) "
            + (
                "has a committed case follow-up."
                if artifact["case_id"] in committed_cases
                else "has no committed next step."
            ),
            acceptance_event_ids[(artifact["artifact_id"], artifact["version_id"])],
        )
        for artifact in artifacts
    ]


def _provenance_lines(events: list[dict[str, Any]]) -> list[str]:
    return [
        "- Generated from canonical source events: " + ", ".join(event["event_id"] for event in events) + ".",
        "- Source watermark: " + events[-1]["integrity"]["event_sha256"] + ".",
        "- Generated output is replaceable; direct edits are detected and quarantined on rebuild.",
    ]


def _event_summary(event: dict[str, Any]) -> str:
    payload = event["payload"]
    event_type = event["event_type"]
    if event_type in {"case.created", "session.created", "session.started"}:
        return payload.get("title") or payload.get("manifest", {}).get("primary_question", event_type)
    if event_type == "question.recorded":
        return payload["question"]
    if event_type.startswith("recommendation."):
        return payload.get("summary") or payload.get("reason", event_type)
    if event_type.startswith("owner_decision."):
        return payload.get("decision") or payload.get("reason", event_type)
    if event_type == "checkpoint.recorded":
        return payload["summary"]
    if event_type == "owner_input.recorded":
        return payload["statement"]
    if event_type == "interaction.started":
        return "Interaction started in " + payload["contract"]["mode"] + " mode"
    if event_type == "interaction.mode_changed":
        return "Interaction changed to " + payload["new_contract"]["mode"] + " mode"
    if event_type == "artifact.version_created":
        version = payload["version"]
        return f"Artifact version {version['version_number']}: {version['change_summary']}"
    if event_type == "artifact.feedback_recorded":
        return payload["feedback"]
    if event_type == "artifact.accepted":
        return "Exact artifact version accepted for " + payload["purpose"]
    if event_type == "work_item.recorded":
        return payload["statement"]
    if event_type == "work_item.status_changed":
        return f"Work item changed to {payload['to_status']}: {payload['reason']}"
    if event_type == "outcome.assessed":
        return (
            f"Outcome assessed: result {payload['result_quality']}; "
            f"process {payload['process_quality']}"
        )
    if event_type == "event.correction_recorded":
        return (
            "Correction for "
            + payload["corrects_event_id"]
            + ": "
            + json.dumps(payload["corrected_values"], sort_keys=True)
        )
    return event_type


def _claim(text: str, event_id: str) -> str:
    if event_id == "GENESIS":
        return "- " + text + " _(derived from an empty canonical store)_"
    return "- " + text + f" _(source: {event_id})_"


def _or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _safe_path_part(value: str) -> str:
    return value.replace("/", "-").replace(" ", "-")


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
