"""Pure deterministic Phase 2 state folds for cases, sessions, and decisions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue

CASE_TRANSITIONS = {
    "open": frozenset({"dormant", "closed"}),
    "dormant": frozenset({"open", "closed"}),
    "closed": frozenset({"reopened"}),
    "reopened": frozenset({"open", "dormant", "closed"}),
}

SESSION_TRANSITIONS = {
    "draft": frozenset({"routed", "abandoned"}),
    "routed": frozenset({"authorized", "abandoned"}),
    "authorized": frozenset({"active", "blocked", "abandoned"}),
    "active": frozenset({"review_pending", "blocked", "closed", "abandoned"}),
    "review_pending": frozenset({"closed", "blocked", "abandoned"}),
    "blocked": frozenset({"active", "closed", "abandoned"}),
}


@dataclass(frozen=True)
class CaseState:
    case_id: str
    status: str
    manifest: dict[str, Any] | None
    manifest_sha256: str | None
    last_event_id: str


@dataclass(frozen=True)
class SessionState:
    case_id: str
    session_id: str
    status: str
    manifest: dict[str, Any] | None
    manifest_sha256: str | None
    last_event_id: str
    frozen: bool = False


@dataclass(frozen=True)
class DecisionState:
    decision_id: str
    case_id: str
    session_id: str
    decision: str | None
    revision: int
    current: bool
    superseded_by: str | None
    last_event_id: str


def fold_case_states(events: list[dict[str, Any]]) -> tuple[dict[str, CaseState], tuple[Issue, ...]]:
    states: dict[str, CaseState] = {}
    issues: list[Issue] = []
    for event in events:
        event_type = event.get("event_type")
        case_id = event.get("case_id")
        payload = event.get("payload", {})
        if event_type == "case.created":
            if case_id in states:
                continue
            manifest = payload.get("manifest")
            states[case_id] = CaseState(
                case_id, "open", manifest, payload.get("manifest_sha256"), event["event_id"]
            )
        elif event_type == "case.status_changed" and case_id in states:
            prior = states[case_id]
            source = payload.get("from_status")
            target = payload.get("to_status")
            if source != prior.status or target not in CASE_TRANSITIONS.get(prior.status, ()):
                issues.append(
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        f"$events/{event['event_id']}/payload/to_status",
                        f"invalid case transition: {prior.status} -> {target}",
                    )
                )
                continue
            states[case_id] = replace(prior, status=target, last_event_id=event["event_id"])
    return states, tuple(sorted(issues))


def fold_session_states(
    events: list[dict[str, Any]],
) -> tuple[dict[str, SessionState], tuple[Issue, ...]]:
    states: dict[str, SessionState] = {}
    issues: list[Issue] = []
    snapshot_types = {
        "session.created",
        "session.started",
        "session.status_changed",
        "session.scope_changed",
        "session.blocked",
        "session.closed",
    }
    for event in events:
        event_type = event.get("event_type")
        if event_type not in snapshot_types:
            continue
        session_id = event.get("session_id")
        if session_id is None:
            continue
        payload = event.get("payload", {})
        manifest = payload.get("manifest") or payload.get("frozen_manifest")
        digest = payload.get("manifest_sha256") or payload.get("frozen_manifest_sha256")
        if event_type in {"session.created", "session.started"}:
            if session_id in states:
                continue
            status = manifest.get("status") if isinstance(manifest, dict) else "active"
            states[session_id] = SessionState(
                event["case_id"], session_id, status, manifest, digest, event["event_id"],
                status in {"closed", "abandoned"},
            )
            continue
        if session_id not in states:
            continue
        prior = states[session_id]
        if prior.frozen:
            issues.append(
                Issue(
                    ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                    f"$events/{event['event_id']}",
                    "terminal session is frozen; resume requires a new session",
                )
            )
            continue
        source = payload.get("from_status", prior.status)
        if event_type == "session.scope_changed":
            target = prior.status
        elif event_type == "session.blocked":
            target = "blocked"
        elif event_type == "session.closed":
            target = "abandoned" if payload.get("disposition") == "abandoned" else "closed"
        else:
            target = payload.get("to_status")
        if event_type != "session.scope_changed" and (
            source != prior.status or target not in SESSION_TRANSITIONS.get(prior.status, ())
        ):
            issues.append(
                Issue(
                    ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                    f"$events/{event['event_id']}/payload/to_status",
                    f"invalid session transition: {prior.status} -> {target}",
                )
            )
            continue
        if isinstance(manifest, dict) and manifest.get("status") != target:
            issues.append(
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    f"$events/{event['event_id']}/payload/manifest/status",
                    "manifest status does not match lifecycle event",
                )
            )
            continue
        states[session_id] = SessionState(
            prior.case_id, session_id, target, manifest or prior.manifest, digest or prior.manifest_sha256,
            event["event_id"], target in {"closed", "abandoned"},
        )
    return states, tuple(sorted(issues))


def fold_decisions(
    events: list[dict[str, Any]],
) -> tuple[dict[str, DecisionState], tuple[Issue, ...]]:
    states: dict[str, DecisionState] = {}
    issues: list[Issue] = []
    for event in events:
        event_type = event.get("event_type")
        payload = event.get("payload", {})
        if event_type == "owner_decision.recorded":
            decision_id = payload.get("decision_id") or next(
                (ref for ref in event.get("subject_refs", []) if ref.startswith("decision_")), None
            )
            if decision_id and decision_id not in states:
                states[decision_id] = DecisionState(
                    decision_id, event["case_id"], event["session_id"], payload.get("decision"),
                    1, True, None, event["event_id"],
                )
        elif event_type == "owner_decision.revised":
            decision_id = payload.get("decision_id")
            if decision_id in states:
                prior = states[decision_id]
                states[decision_id] = replace(
                    prior,
                    decision=payload.get("decision", prior.decision),
                    revision=prior.revision + 1,
                    session_id=event["session_id"],
                    last_event_id=event["event_id"],
                )
        elif event_type == "owner_decision.superseded":
            decision_id = payload.get("decision_id")
            replacement = payload.get("superseded_by_decision_id")
            if decision_id in states and replacement in states:
                cursor = replacement
                seen = {decision_id}
                cycle = False
                while cursor in states and states[cursor].superseded_by is not None:
                    if cursor in seen:
                        cycle = True
                        break
                    seen.add(cursor)
                    cursor = states[cursor].superseded_by
                if cursor == decision_id:
                    cycle = True
                if cycle:
                    issues.append(
                        Issue(
                            ErrorCode.DECISION_SUPERSESSION_CYCLE,
                            f"$events/{event['event_id']}/payload/superseded_by_decision_id",
                            "decision supersession would create a cycle",
                        )
                    )
                else:
                    states[decision_id] = replace(
                        states[decision_id], current=False, superseded_by=replacement,
                        last_event_id=event["event_id"],
                    )
    return states, tuple(sorted(issues))


def manifest_issues(
    manifest: dict[str, Any], digest: str | None, *, path: str
) -> list[Issue]:
    issues: list[Issue] = []
    if digest != canonical_sha256(manifest):
        issues.append(Issue(ErrorCode.MANIFEST_HASH_MISMATCH, path, "manifest digest mismatch"))
    return issues
