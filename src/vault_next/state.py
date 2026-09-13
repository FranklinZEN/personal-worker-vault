"""Deterministic folds for Phase 2 reasoning objects."""

from __future__ import annotations

from datetime import date
from typing import Any
from zoneinfo import ZoneInfo

from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.lifecycle import fold_case_states, fold_session_states


def fold_reasoning_state(events: list[dict[str, Any]], session_id: str) -> dict[str, Any]:
    """Return current assumptions, alternatives, disagreements, and recommendations."""

    assumptions: dict[str, dict[str, Any]] = {}
    alternatives: dict[str, dict[str, Any]] = {}
    disagreements: dict[str, dict[str, Any]] = {}
    recommendations: dict[str, dict[str, Any]] = {}
    contributions: dict[str, dict[str, Any]] = {}
    framework_stages: list[dict[str, Any]] = []
    review_findings: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("session_id") != session_id:
            continue
        event_type = event["event_type"]
        payload = event["payload"]
        if event_type in {"assumption.recorded", "assumption.revised"}:
            assumptions[payload["assumption_id"]] = {
                **payload,
                "last_event_id": event["event_id"],
            }
        elif event_type == "alternative.recorded":
            alternatives[payload["alternative_id"]] = {
                **payload,
                "last_event_id": event["event_id"],
            }
        elif (
            event_type == "alternative.disposition_changed"
            and payload["alternative_id"] in alternatives
        ):
            alternatives[payload["alternative_id"]].update(
                {
                    "disposition": payload["disposition"],
                    "reason": payload["reason"],
                    "last_event_id": event["event_id"],
                }
            )
        elif event_type == "disagreement.recorded":
            disagreements[payload["disagreement_id"]] = {
                **payload,
                "last_event_id": event["event_id"],
            }
        elif (
            event_type == "disagreement.resolved"
            and payload["disagreement_id"] in disagreements
        ):
            disagreements[payload["disagreement_id"]].update(
                {
                    "status": "resolved",
                    "resolution": payload["resolution"],
                    "last_event_id": event["event_id"],
                }
            )
        elif event_type == "recommendation.issued":
            recommendation_id = payload.get("recommendation_id") or next(
                (
                    ref
                    for ref in event["subject_refs"]
                    if ref.startswith("recommendation_")
                ),
                event["event_id"],
            )
            recommendations[recommendation_id] = {
                **payload,
                "status": "current",
                "last_event_id": event["event_id"],
            }
        elif (
            event_type == "recommendation.revised"
            and payload["recommendation_id"] in recommendations
        ):
            recommendations[payload["recommendation_id"]].update(
                {**payload, "status": "current", "last_event_id": event["event_id"]}
            )
        elif (
            event_type == "recommendation.withdrawn"
            and payload["recommendation_id"] in recommendations
        ):
            recommendations[payload["recommendation_id"]].update(
                {
                    "status": "withdrawn",
                    "reason": payload["reason"],
                    "last_event_id": event["event_id"],
                }
            )
        elif event_type == "recommendation.upheld":
            recommendation_id = payload["recommendation_id"]
            if recommendation_id in recommendations:
                recommendations[recommendation_id].update(
                    {
                        "status": "upheld",
                        "uphold_reason": payload["reason"],
                        "last_event_id": event["event_id"],
                    }
                )
        elif event_type == "contribution.recorded":
            contributions[payload["contribution_id"]] = {
                **payload,
                "actor": event["actor"],
                "last_event_id": event["event_id"],
            }
        elif event_type == "framework.stage_recorded":
            framework_stages.append({**payload, "event_id": event["event_id"]})
        elif event_type == "review.finding_recorded":
            review_findings[payload["finding_id"]] = {
                **payload,
                "last_event_id": event["event_id"],
            }
    return {
        "assumptions": assumptions,
        "alternatives": alternatives,
        "disagreements": disagreements,
        "recommendations": recommendations,
        "contributions": contributions,
        "framework_stages": framework_stages,
        "review_findings": review_findings,
    }


def fold_interaction_state(events: list[dict[str, Any]], session_id: str) -> dict[str, Any]:
    """Return the current interaction contract and resumable material records."""

    contract: dict[str, Any] | None = None
    contract_sha256: str | None = None
    started_event_id: str | None = None
    mode_changes: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []
    owner_inputs: list[dict[str, Any]] = []
    for event in events:
        if event.get("session_id") != session_id:
            continue
        payload = event["payload"]
        if event["event_type"] == "interaction.started":
            contract = payload["contract"]
            contract_sha256 = payload["contract_sha256"]
            started_event_id = event["event_id"]
        elif event["event_type"] == "interaction.mode_changed":
            contract = payload["new_contract"]
            contract_sha256 = payload["new_contract_sha256"]
            mode_changes.append({**payload, "event_id": event["event_id"]})
        elif event["event_type"] == "checkpoint.recorded":
            checkpoints.append({**payload, "event_id": event["event_id"]})
        elif event["event_type"] == "owner_input.recorded":
            owner_inputs.append(
                {**payload, "actor": event["actor"], "event_id": event["event_id"]}
            )
    return {
        "contract": contract,
        "contract_sha256": contract_sha256,
        "started_event_id": started_event_id,
        "mode_changes": mode_changes,
        "checkpoints": checkpoints,
        "owner_inputs": owner_inputs,
    }


def fold_artifact_state(
    events: list[dict[str, Any]], *, case_id: str | None = None
) -> dict[str, dict[str, Any]]:
    """Fold immutable artifact versions, feedback, acceptance, and withdrawal."""

    artifacts: dict[str, dict[str, Any]] = {}
    for event in events:
        if case_id is not None and event.get("case_id") != case_id:
            continue
        event_type = event["event_type"]
        payload = event["payload"]
        if event_type == "artifact.version_created":
            version = payload["version"]
            artifact = artifacts.setdefault(
                version["artifact_id"],
                {
                    "artifact_id": version["artifact_id"],
                    "versions": {},
                    "feedback": {},
                    "current_version_id": None,
                    "accepted_version_id": None,
                },
            )
            artifact["versions"][version["version_id"]] = {
                **version,
                "case_id": event["case_id"],
                "session_id": event["session_id"],
                "event_id": event["event_id"],
            }
            artifact["current_version_id"] = version["version_id"]
            for feedback_id in version["addressed_feedback_ids"]:
                if feedback_id in artifact["feedback"]:
                    artifact["feedback"][feedback_id]["disposition"] = "addressed"
                    artifact["feedback"][feedback_id]["addressed_by_version_id"] = version[
                        "version_id"
                    ]
        elif event_type == "artifact.feedback_recorded":
            artifact = artifacts.get(payload["artifact_id"])
            if artifact is not None:
                artifact["feedback"][payload["feedback_id"]] = {
                    **payload,
                    "actor": event["actor"],
                    "event_id": event["event_id"],
                }
        elif event_type == "artifact.accepted":
            artifact = artifacts.get(payload["artifact_id"])
            if artifact is not None and payload["version_id"] in artifact["versions"]:
                prior_accepted = artifact["accepted_version_id"]
                if prior_accepted is not None:
                    artifact["versions"][prior_accepted]["status"] = "superseded"
                artifact["versions"][payload["version_id"]]["status"] = "accepted"
                artifact["versions"][payload["version_id"]]["accepted_event_id"] = event[
                    "event_id"
                ]
                artifact["accepted_version_id"] = payload["version_id"]
        elif event_type == "artifact.withdrawn":
            artifact = artifacts.get(payload["artifact_id"])
            if artifact is not None and payload["version_id"] in artifact["versions"]:
                artifact["versions"][payload["version_id"]]["status"] = "withdrawn"
                artifact["versions"][payload["version_id"]]["withdrawn_event_id"] = event[
                    "event_id"
                ]
                if artifact["accepted_version_id"] == payload["version_id"]:
                    artifact["accepted_version_id"] = None
    return artifacts


def fold_work_items(
    events: list[dict[str, Any]], *, case_id: str | None = None
) -> dict[str, dict[str, Any]]:
    """Return current repository-local work items from explicit semantic events."""

    items: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["event_type"] == "work_transaction.committed":
            for operation in event["payload"]["transaction_manifest"]["operations"]:
                if case_id is not None and operation["case_id"] != case_id:
                    continue
                work_item_id = operation["work_item_id"]
                next_state = operation["next_state"]
                if operation["operation"] == "record":
                    items[work_item_id] = {
                        **next_state,
                        "work_item_id": work_item_id,
                        "revision": 1,
                        "case_id": operation["case_id"],
                        "session_id": operation["session_id"],
                        "created_event_id": event["event_id"],
                        "last_event_id": event["event_id"],
                    }
                elif work_item_id in items:
                    items[work_item_id].update(
                        {
                            **next_state,
                            "revision": operation["expected_revision"] + 1,
                            "last_event_id": event["event_id"],
                        }
                    )
            continue
        if case_id is not None and event.get("case_id") != case_id:
            continue
        payload = event["payload"]
        if event["event_type"] == "work_item.recorded":
            items[payload["work_item_id"]] = {
                **payload,
                "revision": 1,
                "case_id": event["case_id"],
                "session_id": event["session_id"],
                "created_event_id": event["event_id"],
                "last_event_id": event["event_id"],
            }
        elif (
            event["event_type"] == "work_item.status_changed"
            and payload["work_item_id"] in items
        ):
            items[payload["work_item_id"]].update(
                {
                    "status": payload["to_status"],
                    "priority": payload["priority"],
                    "due_on": payload["due_on"],
                    "next_review_on": payload["next_review_on"],
                    "blocker": payload["blocker"],
                    "revision": items[payload["work_item_id"]].get("revision", 1) + 1,
                    "last_event_id": event["event_id"],
                }
            )
        elif event["event_type"] == "work_batch.committed":
            for operation in payload["proposal"]["operations"]:
                work_item_id = operation["work_item_id"]
                next_state = operation["next_state"]
                if operation["operation"] == "record":
                    items[work_item_id] = {
                        **next_state,
                        "work_item_id": work_item_id,
                        "revision": 1,
                        "case_id": event["case_id"],
                        "session_id": event["session_id"],
                        "created_event_id": event["event_id"],
                        "last_event_id": event["event_id"],
                    }
                elif work_item_id in items:
                    items[work_item_id].update(
                        {
                            **next_state,
                            "revision": operation["expected_revision"] + 1,
                            "last_event_id": event["event_id"],
                        }
                    )
    return items


def build_current_work_view(
    events: list[dict[str, Any]],
    *,
    as_of_date: str,
    time_zone: str,
    minimum_watermark: str | None = None,
) -> dict[str, Any]:
    """Return a current-work view only when it includes a requested committed watermark."""

    watermarks = [event["integrity"]["event_sha256"] for event in events]
    if minimum_watermark is not None and minimum_watermark not in watermarks:
        raise ValidationError(
            [
                Issue(
                    ErrorCode.WORK_BATCH_WATERMARK_STALE,
                    "$/minimum_watermark",
                    "current-work query does not include the committed watermark",
                )
            ]
        )
    return {
        "state": build_current_work_state(
            events, as_of_date=as_of_date, time_zone=time_zone
        ),
        "committed_watermark": watermarks[-1] if watermarks else "GENESIS",
    }


def build_current_work_state(
    events: list[dict[str, Any]], *, as_of_date: str, time_zone: str
) -> dict[str, Any]:
    """Build the deterministic P3A read model that later P4 views will render."""

    date.fromisoformat(as_of_date)
    ZoneInfo(time_zone)
    items = fold_work_items(events)
    active_statuses = {"proposed", "open", "in_progress", "waiting"}
    active = [item for item in items.values() if item["status"] in active_statuses]
    proposed = [item for item in active if item["status"] == "proposed"]
    committed = [item for item in active if item["status"] != "proposed"]
    terminal = [item for item in items.values() if item["status"] not in active_statuses]
    due = [
        item["work_item_id"]
        for item in active
        if item.get("due_on") is not None and item["due_on"] <= as_of_date
    ]
    reviews = [
        item["work_item_id"]
        for item in active
        if item.get("next_review_on") is not None
        and item["next_review_on"] <= as_of_date
    ]
    case_states, _ = fold_case_states(events)
    session_states, _ = fold_session_states(events)
    artifacts = fold_artifact_state(events)
    accepted_artifacts = []
    for artifact in artifacts.values():
        accepted_id = artifact["accepted_version_id"]
        if accepted_id is not None:
            accepted = artifact["versions"][accepted_id]
            accepted_artifacts.append(
                {
                    "artifact_id": artifact["artifact_id"],
                    "version_id": accepted_id,
                    "content_sha256": accepted["content_sha256"],
                    "purpose": accepted["purpose"],
                    "case_id": accepted["case_id"],
                    "session_id": accepted["session_id"],
                }
            )
    return {
        "schema_version": "1.0",
        "as_of_date": as_of_date,
        "time_zone": time_zone,
        "active_work_items": sorted(active, key=lambda item: item["work_item_id"]),
        "proposed_work_items": sorted(
            proposed, key=lambda item: item["work_item_id"]
        ),
        "committed_work_items": sorted(
            committed, key=lambda item: item["work_item_id"]
        ),
        "terminal_work_items": sorted(terminal, key=lambda item: item["work_item_id"]),
        "active_case_ids": sorted(
            case_id
            for case_id, state in case_states.items()
            if state.status in {"open", "reopened"}
        ),
        "active_session_ids": sorted(
            session_id
            for session_id, state in session_states.items()
            if not state.frozen
        ),
        "accepted_artifacts": sorted(
            accepted_artifacts, key=lambda item: item["artifact_id"]
        ),
        "due_or_overdue_ids": sorted(due),
        "review_due_ids": sorted(reviews),
        "source_event_ids": [event["event_id"] for event in events],
        "source_watermark": (
            events[-1]["integrity"]["event_sha256"] if events else None
        ),
    }
