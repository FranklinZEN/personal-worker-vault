"""S2-A structured, adapter-independent status, history, and pending-update core.

This module deliberately reads only the semantic ledger and returns an ephemeral proposal.  It has
no host, connector, model, receipt, policy, or commit dependency; S2-B remains the only place an
apply route could be considered.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from vault_next.canonical import canonical_sha256
from vault_next.contracts import (
    finalize_work_change_proposal,
    require_request_envelope,
    require_result_envelope,
    require_work_change_proposal,
)
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.records import SchemaRegistry
from vault_next.runtime import CaseSessionRuntime
from vault_next.state import build_current_work_view, fold_work_items


FUNCTION_HISTORICAL_DIFF = "function_historical_diff"
FUNCTION_STATUS = "function_status"
FUNCTION_UPDATE = "function_update"
MAX_STATUS_ITEMS = 50
MAX_HISTORICAL_CHANGES = 200


class S2Unavailable(Exception):
    """A requested read/propose function lacks an actual, declared prerequisite."""


class StatusUpdateCoordinator:
    """Execute structured S2-A requests without appending any canonical event."""

    def __init__(self, runtime: CaseSessionRuntime, schemas: SchemaRegistry) -> None:
        self.runtime = runtime
        self.schemas = schemas

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return only committed observations and, when requested, one ephemeral proposal."""

        self._require_request(request)
        envelope = request["request"]
        events = self.runtime.semantic.read_all()
        statuses: dict[str, str] = {}
        limits: list[str] = []
        status_view: dict[str, Any] | None = None
        historical_diff: dict[str, Any] | None = None
        pending_work_proposal: dict[str, Any] | None = None

        if request["status_query"] is not None:
            try:
                status_view = self._status_view(events, request["status_query"])
                statuses[FUNCTION_STATUS] = "complete"
            except S2Unavailable as exc:
                statuses[FUNCTION_STATUS] = "unavailable"
                limits.append(str(exc))

        if request["historical_diff_query"] is not None:
            try:
                historical_diff = self._historical_diff(events, request["historical_diff_query"])
                statuses[FUNCTION_HISTORICAL_DIFF] = "complete"
            except S2Unavailable as exc:
                statuses[FUNCTION_HISTORICAL_DIFF] = "unavailable"
                limits.append(str(exc))

        if request["pending_update"] is not None:
            try:
                pending_work_proposal = self._pending_work_proposal(
                    events, envelope, request["pending_update"]
                )
                statuses[FUNCTION_UPDATE] = "pending"
            except S2Unavailable as exc:
                statuses[FUNCTION_UPDATE] = "unavailable"
                limits.append(str(exc))

        function_results = [
            {"function_id": function_id, "status": statuses[function_id]}
            for function_id in envelope["function_ids"]
        ]
        result_status = _result_status(function_results)
        pending_refs = (
            [f"pending:{pending_work_proposal['pending_digest']}"]
            if pending_work_proposal is not None
            else []
        )
        result = {
            "schema_version": "1.0",
            "request_id": envelope["request_id"],
            "status": result_status,
            "function_results": function_results,
            "receipt_ref": None,
            "committed_watermark": None,
            "pending_refs": pending_refs,
            "sources": ["semantic-ledger"] if statuses else [],
            "limits": sorted(set(limits)),
            "continuation_ref": None,
        }
        require_result_envelope(result, self.schemas, request=envelope)
        response = {
            "schema_version": "1.0",
            "result": result,
            "status_view": status_view,
            "historical_diff": historical_diff,
            "pending_work_proposal": pending_work_proposal,
        }
        self.schemas.require("s2-read-propose-result", response)
        return response

    def _require_request(self, request: dict[str, Any]) -> None:
        self.schemas.require("s2-read-propose-request", request)
        envelope = request["request"]
        if not isinstance(envelope, dict):
            raise _contract_error("$/request", "request envelope must be an object")
        require_request_envelope(envelope, self.schemas)
        if envelope["mode"] == "apply":
            raise _contract_error("$/request/mode", "S2-A never exposes an apply operation")

        declared: set[str] = set()
        scopes: list[set[str]] = []
        if request["status_query"] is not None:
            query = request["status_query"]
            if not isinstance(query, dict):
                raise _contract_error("$/status_query", "status query must be an object")
            self.schemas.require("status-query", query)
            _require_query_date_and_zone(query, "$/status_query")
            declared.add(FUNCTION_STATUS)
            scopes.append(set(query["case_scope"]))
        if request["historical_diff_query"] is not None:
            query = request["historical_diff_query"]
            if not isinstance(query, dict):
                raise _contract_error(
                    "$/historical_diff_query", "historical-diff query must be an object"
                )
            self.schemas.require("historical-diff-query", query)
            _require_query_date_and_zone(query, "$/historical_diff_query")
            declared.add(FUNCTION_HISTORICAL_DIFF)
            scopes.append(set(query["case_scope"]))
        if request["pending_update"] is not None:
            pending = request["pending_update"]
            if not isinstance(pending, dict):
                raise _contract_error("$/pending_update", "pending update must be an object")
            self.schemas.require("pending-work-update", pending)
            _parse_aware_timestamp(pending["expires_at"], "$/pending_update/expires_at")
            declared.add(FUNCTION_UPDATE)
            if pending["case_id"] not in envelope["target_refs"]:
                raise _contract_error(
                    "$/pending_update/case_id",
                    "pending update case must be an explicitly declared request target",
                )

        if not declared:
            raise _contract_error("$", "S2-A request must name at least one supported function")
        if set(envelope["function_ids"]) != declared:
            raise _contract_error(
                "$/request/function_ids", "function IDs must exactly match supplied S2-A inputs"
            )
        expected_mode = "propose" if FUNCTION_UPDATE in declared else "read"
        if envelope["mode"] != expected_mode:
            raise _contract_error(
                "$/request/mode", f"S2-A {expected_mode} requests require that exact mode"
            )
        for scope in scopes:
            if not scope.issubset(envelope["target_refs"]):
                raise _contract_error(
                    "$/request/target_refs", "every queried case must be an explicitly declared target"
                )
        if len(scopes) == 2 and scopes[0] != scopes[1]:
            raise _contract_error(
                "$/case_scope", "combined status and historical diff require one exact case scope"
            )
        if scopes and request["pending_update"] is not None and request["pending_update"]["case_id"] not in scopes[0]:
            raise _contract_error(
                "$/pending_update/case_id",
                "combined pending update must remain within the displayed query scope",
            )

    def _status_view(self, events: list[dict[str, Any]], query: dict[str, Any]) -> dict[str, Any]:
        scoped_events = self._scoped_events(events, query["case_scope"])
        current = build_current_work_view(
            scoped_events,
            as_of_date=query["as_of_date"],
            time_zone=query["time_zone"],
        )
        active_items = [
            _work_item_snapshot(item) for item in current["state"]["active_work_items"]
        ]
        if len(active_items) > MAX_STATUS_ITEMS:
            raise S2Unavailable(
                f"status has {len(active_items)} active items; limit is {MAX_STATUS_ITEMS} without truncation"
            )
        displayed_view = _displayed_work_view(
            case_scope=query["case_scope"],
            as_of_date=query["as_of_date"],
            time_zone=query["time_zone"],
            source_watermark=current["committed_watermark"],
            items=active_items,
        )
        self.schemas.require("displayed-work-view", displayed_view)
        rendered = {
            "schema_version": "1.0",
            "scope_case_ids": sorted(query["case_scope"]),
            "as_of_date": query["as_of_date"],
            "time_zone": query["time_zone"],
            "committed_watermark": current["committed_watermark"],
            "active_items": active_items,
            "due_or_overdue_ids": current["state"]["due_or_overdue_ids"],
            "review_due_ids": current["state"]["review_due_ids"],
            "displayed_view": displayed_view,
        }
        self.schemas.require("status-view", rendered)
        return rendered

    def _historical_diff(
        self, events: list[dict[str, Any]], query: dict[str, Any]
    ) -> dict[str, Any]:
        scoped_events = self._scoped_events(events, query["case_scope"])
        baseline_watermark, baseline_events = _resolve_baseline(
            scoped_events, query["baseline"], query["time_zone"]
        )
        before = fold_work_items(baseline_events)
        after = fold_work_items(scoped_events)
        changes = _historical_changes(before, after)
        if len(changes) > MAX_HISTORICAL_CHANGES:
            raise S2Unavailable(
                "historical difference has "
                f"{len(changes)} changes; limit is {MAX_HISTORICAL_CHANGES} without truncation"
            )
        result = {
            "schema_version": "1.0",
            "scope_case_ids": sorted(query["case_scope"]),
            "time_zone": query["time_zone"],
            "baseline_watermark": baseline_watermark,
            "current_watermark": _watermark(scoped_events),
            "changes": changes,
        }
        self.schemas.require("historical-work-diff", result)
        return result

    def _pending_work_proposal(
        self, events: list[dict[str, Any]], envelope: dict[str, Any], pending: dict[str, Any]
    ) -> dict[str, Any]:
        now = self.runtime.clock()
        expires_at = _parse_aware_timestamp(pending["expires_at"], "$/pending_update/expires_at")
        if expires_at <= now.astimezone(UTC):
            raise _contract_error("$/pending_update/expires_at", "pending update is already expired")
        if _idempotency_is_committed(events, envelope["idempotency_key"]):
            raise _contract_error(
                "$/request/idempotency_key",
                "idempotency key is already bound to a committed work batch",
            )

        case_id = pending["case_id"]
        self._scoped_events(events, [case_id])
        items = fold_work_items(events, case_id=case_id)
        item, selection_binding = self._resolve_selection(events, envelope, pending, items)
        if pending["expected_revision"] != item["revision"]:
            raise _contract_error(
                "$/pending_update/expected_revision",
                "pending update expected revision does not match current committed work state",
            )
        proposal = finalize_work_change_proposal(
            {
                "schema_version": "1.0",
                "batch_id": _batch_id_for_request(envelope["request_id"]),
                "request_id": envelope["request_id"],
                "idempotency_key": envelope["idempotency_key"],
                "case_id": case_id,
                "operations": [
                    {
                        "work_item_id": item["work_item_id"],
                        "expected_revision": item["revision"],
                        "operation": "status_change",
                        "next_state": pending["next_state"],
                    }
                ],
                "proposal_digest": "",
                "expires_at": pending["expires_at"],
            }
        )
        require_work_change_proposal(proposal, self.schemas)
        pending_record = {
            "schema_version": "1.0",
            "selection_binding": selection_binding,
            "work_change_proposal": proposal,
            "pending_digest": "",
        }
        pending_record["pending_digest"] = canonical_sha256(
            {key: value for key, value in pending_record.items() if key != "pending_digest"}
        )
        self.schemas.require("pending-work-proposal", pending_record)
        return pending_record

    def _resolve_selection(
        self,
        events: list[dict[str, Any]],
        envelope: dict[str, Any],
        pending: dict[str, Any],
        items: dict[str, dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        selection = pending["selection"]
        if not isinstance(selection, dict):
            raise _contract_error("$/pending_update/selection", "selection must be an object")
        kind = selection.get("kind")
        if kind == "direct_work_item":
            _require_exact_keys(
                selection,
                {"kind", "work_item_id"},
                "$/pending_update/selection",
            )
            work_item_id = selection.get("work_item_id")
            if not isinstance(work_item_id, str) or work_item_id not in items:
                raise S2Unavailable("selected work item is unavailable in the declared case")
            item = items[work_item_id]
            return item, {
                "kind": "direct_work_item",
                "case_id": item["case_id"],
                "work_item_id": item["work_item_id"],
                "revision": item["revision"],
                "source_watermark": _watermark(self._scoped_events(events, [item["case_id"]])),
            }
        if kind != "displayed_ordinal":
            raise _contract_error(
                "$/pending_update/selection/kind",
                "selection kind must be direct_work_item or displayed_ordinal",
            )
        _require_exact_keys(
            selection,
            {"kind", "ordinal", "displayed_view"},
            "$/pending_update/selection",
        )
        ordinal = selection.get("ordinal")
        displayed_view = selection.get("displayed_view")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
            raise _contract_error("$/pending_update/selection/ordinal", "ordinal must be positive")
        if not isinstance(displayed_view, dict):
            raise _contract_error(
                "$/pending_update/selection/displayed_view", "displayed view must be an object"
            )
        self.schemas.require("displayed-work-view", displayed_view)
        if not set(displayed_view["scope_case_ids"]).issubset(envelope["target_refs"]):
            raise _contract_error(
                "$/pending_update/selection/displayed_view/scope_case_ids",
                "displayed view scope must remain within declared request targets",
            )
        if pending["case_id"] not in displayed_view["scope_case_ids"]:
            raise _contract_error(
                "$/pending_update/case_id", "pending update case is absent from displayed view scope"
            )
        _require_query_date_and_zone(displayed_view, "$/pending_update/selection/displayed_view")
        expected = self._status_view(
            events,
            {
                "schema_version": "1.0",
                "case_scope": displayed_view["scope_case_ids"],
                "as_of_date": displayed_view["as_of_date"],
                "time_zone": displayed_view["time_zone"],
            },
        )["displayed_view"]
        if displayed_view != expected:
            raise _contract_error(
                "$/pending_update/selection/displayed_view",
                "displayed view is stale, malformed, or does not bind the current exact view",
            )
        selected = next(
            (item for item in displayed_view["items"] if item["ordinal"] == ordinal), None
        )
        if selected is None or selected["case_id"] != pending["case_id"]:
            raise S2Unavailable("displayed ordinal does not resolve to an item in the declared case")
        item = items.get(selected["work_item_id"])
        if item is None or item["revision"] != selected["revision"]:
            raise _contract_error(
                "$/pending_update/selection/displayed_view", "selected item revision is no longer current"
            )
        return item, {"kind": "displayed_ordinal", "displayed_view": displayed_view, "ordinal": ordinal}

    def _scoped_events(
        self, events: list[dict[str, Any]], case_scope: list[str]
    ) -> list[dict[str, Any]]:
        if not case_scope:
            raise S2Unavailable("case scope is required")
        available = {
            event["case_id"] for event in events if event["event_type"] == "case.created"
        }
        missing = sorted(set(case_scope) - available)
        if missing:
            raise S2Unavailable("declared case scope is unavailable")
        selected = [event for event in events if event["case_id"] in set(case_scope)]
        if not selected:
            raise S2Unavailable("declared case scope has no committed events")
        return selected


def _displayed_work_view(
    *,
    case_scope: list[str],
    as_of_date: str,
    time_zone: str,
    source_watermark: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    view = {
        "schema_version": "1.0",
        "scope_case_ids": sorted(case_scope),
        "as_of_date": as_of_date,
        "time_zone": time_zone,
        "source_watermark": source_watermark,
        "items": [
            {
                "ordinal": index,
                "work_item_id": item["work_item_id"],
                "case_id": item["case_id"],
                "revision": item["revision"],
            }
            for index, item in enumerate(items, start=1)
        ],
        "view_digest": "",
    }
    view["view_digest"] = canonical_sha256(
        {key: value for key, value in view.items() if key != "view_digest"}
    )
    return view


def _resolve_baseline(
    events: list[dict[str, Any]], baseline: Any, time_zone: str
) -> tuple[str, list[dict[str, Any]]]:
    if baseline is None:
        raise S2Unavailable("historical baseline is required")
    if not isinstance(baseline, dict):
        raise _contract_error("$/historical_diff_query/baseline", "baseline must be an object")
    kind = baseline.get("kind")
    if kind == "watermark":
        _require_exact_keys(
            baseline,
            {"kind", "watermark"},
            "$/historical_diff_query/baseline",
        )
        watermark = baseline.get("watermark")
        if not isinstance(watermark, str):
            raise _contract_error("$/historical_diff_query/baseline/watermark", "watermark is required")
        for index, event in enumerate(events):
            if event["integrity"]["event_sha256"] == watermark:
                return watermark, events[: index + 1]
        raise S2Unavailable("historical baseline watermark is unavailable in the declared scope")
    if kind != "end_of_local_date":
        raise _contract_error(
            "$/historical_diff_query/baseline/kind",
            "baseline kind must be watermark or end_of_local_date",
        )
    _require_exact_keys(
        baseline,
        {"kind", "as_of_date"},
        "$/historical_diff_query/baseline",
    )
    date_value = baseline.get("as_of_date")
    if not isinstance(date_value, str):
        raise _contract_error("$/historical_diff_query/baseline/as_of_date", "baseline date is required")
    try:
        local_end = datetime.combine(
            datetime.fromisoformat(date_value).date() + timedelta(days=1),
            time.min,
            tzinfo=ZoneInfo(time_zone),
        ).astimezone(UTC)
    except ValueError as exc:
        raise _contract_error(
            "$/historical_diff_query/baseline/as_of_date", "baseline date must be ISO-8601"
        ) from exc
    prior = [
        event
        for event in events
        if _parse_aware_timestamp(event["recorded_at"], "$/recorded_at") < local_end
    ]
    return (_watermark(prior), prior)


def _historical_changes(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for work_item_id in sorted(set(before) | set(after)):
        previous = _work_item_snapshot(before[work_item_id]) if work_item_id in before else None
        current = _work_item_snapshot(after[work_item_id]) if work_item_id in after else None
        if previous == current:
            continue
        changes.append(
            {
                "kind": "added" if previous is None else "removed" if current is None else "changed",
                "work_item_id": work_item_id,
                "before": previous,
                "after": current,
            }
        )
    return changes


def _work_item_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "work_item_id": item["work_item_id"],
        "case_id": item["case_id"],
        "revision": item["revision"],
        "statement": item["statement"],
        "status": item["status"],
        "source_kind": item["source_kind"],
        "priority": item["priority"],
        "due_on": item["due_on"],
        "next_review_on": item["next_review_on"],
        "blocker": item["blocker"],
    }


def _watermark(events: list[dict[str, Any]]) -> str:
    return events[-1]["integrity"]["event_sha256"] if events else "GENESIS"


def _idempotency_is_committed(events: list[dict[str, Any]], idempotency_key: str) -> bool:
    return any(
        event["event_type"] in {"work_batch.committed", "work_transaction.committed"}
        and event["payload"]["idempotency_key"] == idempotency_key
        for event in events
    )


def _batch_id_for_request(request_id: str) -> str:
    if not request_id.startswith("request_"):
        raise _contract_error("$/request/request_id", "request ID cannot form a work batch ID")
    return f"work_batch_{request_id.removeprefix('request_')}"


def _result_status(function_results: list[dict[str, str]]) -> str:
    statuses = {item["status"] for item in function_results}
    if "pending" in statuses:
        return "pending"
    if statuses == {"complete"}:
        return "complete"
    return "unavailable"


def _require_query_date_and_zone(query: dict[str, Any], path: str) -> None:
    try:
        datetime.fromisoformat(query["as_of_date"]).date()
        ZoneInfo(query["time_zone"])
    except (TypeError, ValueError, ZoneInfoNotFoundError) as exc:
        raise _contract_error(path, "query requires a valid ISO date and IANA time zone") from exc


def _parse_aware_timestamp(value: str, path: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise _contract_error(path, "timestamp must be ISO-8601 and timezone-aware") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _contract_error(path, "timestamp must be timezone-aware")
    return parsed


def _require_exact_keys(record: dict[str, Any], expected: set[str], path: str) -> None:
    if set(record) != expected:
        raise _contract_error(path, "object fields do not match the exact supported contract")


def _contract_error(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
