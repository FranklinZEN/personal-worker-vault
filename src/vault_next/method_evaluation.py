"""S4-A synthetic method coverage and candidate-only evaluation.

This module is deliberately data-only.  It evaluates caller-supplied invented cards against
caller-supplied criteria, and it never reads sources, invokes a model, selects a host, or promotes
knowledge.  Its only durable effects are the existing package lifecycle's candidate/evaluation/
review records in a disposable runtime.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.packages import PackageRegistry
from vault_next.records import timestamp


_INVENTORY_STATES = frozenset(
    {
        "implemented_baseline",
        "candidate_pending",
        "unassessed_legacy_surrogate",
        "out_of_scope_synthetic",
    }
)
_CARD_STATES = frozenset({"current", "stale", "contradictory"})
_CANDIDATE_ID = "skill_evidence_mapping"
_CANDIDATE_VERSION = "0.1.0"


class SyntheticMethodEvaluationCoordinator:
    """Reconcile an invented coverage inventory and evaluate one candidate method."""

    def __init__(self, registry: PackageRegistry) -> None:
        self.registry = registry

    def assess_inventory(self, inventory: dict[str, object]) -> dict[str, object]:
        """Return a deterministic, complete report without a lifecycle write."""

        entries = _require_inventory(inventory)
        grouped: dict[str, list[str]] = defaultdict(list)
        for entry in entries:
            grouped[entry["state"]].append(entry["entry_id"])
        report = {
            "inventory_id": inventory["inventory_id"],
            "inventory_version": inventory["inventory_version"],
            "entry_count": len(entries),
            "coverage": {
                state: sorted(grouped[state]) for state in sorted(_INVENTORY_STATES)
            },
            "unassessed_entry_ids": sorted(grouped["unassessed_legacy_surrogate"]),
        }
        return {**report, "report_sha256": canonical_sha256(report)}

    def evaluate_candidate(
        self,
        inventory: dict[str, object],
        *,
        case_id: str,
        criteria: list[dict[str, object]],
        cards: list[dict[str, object]],
    ) -> dict[str, object]:
        """Evaluate the one candidate using supplied invented fixture data only.

        Input validation precedes all package lifecycle writes, so malformed fixtures cannot leave
        a candidate or evaluation record behind.
        """

        coverage = self.assess_inventory(inventory)
        _require_candidate_entry(inventory)
        criterion_ids = _require_criteria(criteria)
        normalized_cards = _require_cards(cards, case_id=case_id, criterion_ids=criterion_ids)

        try:
            candidate, digest = self.registry.resolve_version(
                "skill", _CANDIDATE_ID, _CANDIDATE_VERSION
            )
        except ValidationError as exc:
            if any(issue.code != ErrorCode.EVENT_REFERENCE_MISSING for issue in exc.issues):
                raise
            candidate = synthetic_evidence_mapping_candidate(self.registry.clock())
            digest = self.registry.create_candidate(
                candidate,
                proposal_rationale="S4-A synthetic evidence-mapping baseline",
            )
        mapping = _map_cards(criterion_ids, normalized_cards)
        baseline = {
            "kind": "listed_cards_only",
            "criterion_ids": criterion_ids,
            "card_ids": sorted(card["card_id"] for card in normalized_cards),
        }
        result = {
            "schema_version": "1.0",
            "candidate_package": {
                "package_type": "skill",
                "package_id": _CANDIDATE_ID,
                "version": _CANDIDATE_VERSION,
                "digest": digest,
                "status": "candidate",
            },
            "coverage_report": coverage,
            "case_id": case_id,
            "baseline": baseline,
            "criterion_results": mapping,
            "limitations": [
                "synthetic caller-supplied fixtures only",
                "no owner decision, knowledge promotion, or external action",
                "no source, network, model, or host access",
            ],
        }
        result["result_sha256"] = canonical_sha256(result)
        fixture = {
            "fixture_id": f"fixture_{_CANDIDATE_ID}_s4a",
            "passed": True,
            "result_sha256": result["result_sha256"],
        }
        evaluation_event = self.registry.record_evaluation(
            "skill",
            _CANDIDATE_ID,
            _CANDIDATE_VERSION,
            fixture_results=[fixture],
            adjudicator_id="synthetic-s4a-adjudicator",
            suite_version="s4a-1.0.0",
        )
        review_event = self.registry.record_independent_review(
            "skill",
            _CANDIDATE_ID,
            _CANDIDATE_VERSION,
            reviewer_id="synthetic-s4a-independent-reviewer",
            outcome="pass",
            findings=[],
            rollback_plan="Keep the package candidate-only; do not create an active pointer.",
        )
        return {
            **result,
            "evaluation_event_id": evaluation_event["event_id"],
            "review_event_id": review_event["event_id"],
        }


def synthetic_evidence_mapping_candidate(created_at: datetime) -> dict[str, object]:
    """Return the immutable S4-A candidate package, never an active package pointer."""

    return {
        "schema_version": "1.0",
        "package_type": "skill",
        "package_id": _CANDIDATE_ID,
        "version": _CANDIDATE_VERSION,
        "display_name": "Synthetic evidence mapping",
        "purpose": "Map supplied invented evidence cards to explicit criteria without filling gaps",
        "non_purpose": [
            "owner decision",
            "knowledge promotion",
            "external action",
            "persistent agent memory",
        ],
        "requested_permissions": [],
        "prohibited_actions": [
            "external_send",
            "identity_change",
            "governance_change",
            "knowledge_promotion",
        ],
        "change_class": "initial",
        "change_summary": {
            "behavioral_fields": ["synthetic evidence-to-criterion mapping"],
            "rationale": "Establish the S4-A single-method synthetic baseline",
        },
        "supersedes_version": None,
        "affected_fixture_classes": [
            "positive",
            "near_miss",
            "adversarial",
            "permission",
            "regression",
        ],
        "rollback_plan": "Do not activate; preserve the immutable candidate history only.",
        "created_at": timestamp(created_at),
        "design_review": {
            "reviewer_id": "synthetic-s4a-design-reviewer",
            "outcome": "accepted",
            "rationale": "Caller-supplied invented fixtures with no external capability",
        },
        "evaluation_fixture_refs": [f"fixture_{_CANDIDATE_ID}_s4a"],
        "config": {
            "work_units": ["criterion_mapping", "gap_disclosure", "contradiction_disclosure"],
            "unique_contribution": "Links support only to exact supplied card identifiers",
            "compatible_frameworks": ["framework_synthesis"],
            "conflicts_with": [],
            "method": [
                "list supplied criteria",
                "link current cards",
                "surface stale, contradictory, and unmet criteria",
            ],
        },
    }


def _require_inventory(inventory: dict[str, object]) -> list[dict[str, str]]:
    issues: list[Issue] = []
    if set(inventory) != {"inventory_id", "inventory_version", "entries"}:
        issues.append(_issue("$inventory", "inventory has unexpected or missing fields"))
    if not isinstance(inventory.get("inventory_id"), str) or not inventory.get("inventory_id"):
        issues.append(_issue("$inventory_id", "inventory ID must be a nonempty string"))
    if inventory.get("inventory_version") != "1.0":
        issues.append(_issue("$inventory_version", "only synthetic inventory version 1.0 is supported"))
    raw_entries = inventory.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        issues.append(_issue("$entries", "inventory must declare at least one entry"))
        raw_entries = []
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        path = f"$entries/{index}"
        if not isinstance(raw, dict) or set(raw) != {
            "entry_id", "display_name", "family", "state", "rationale", "disposition", "package_id", "package_version"
        }:
            issues.append(_issue(path, "entry has unexpected or missing fields"))
            continue
        if any(not isinstance(raw.get(field), str) or not raw[field] for field in (
            "entry_id", "display_name", "family", "state", "rationale", "disposition"
        )):
            issues.append(_issue(path, "entry identity and disposition fields must be nonempty strings"))
            continue
        entry_id = raw["entry_id"]
        if entry_id in seen:
            issues.append(_issue(f"{path}/entry_id", "duplicate inventory entry ID"))
        seen.add(entry_id)
        if raw["state"] not in _INVENTORY_STATES:
            issues.append(_issue(f"{path}/state", "inventory state is unsupported"))
        package_id = raw["package_id"]
        package_version = raw["package_version"]
        if (package_id is None) != (package_version is None):
            issues.append(_issue(path, "package ID and version must be both present or both null"))
        if package_id is not None and (
            not isinstance(package_id, str) or not isinstance(package_version, str)
        ):
            issues.append(_issue(path, "package references must be strings"))
        normalized.append(raw)  # type: ignore[arg-type]
    states = {entry["state"] for entry in normalized}
    required_states = {
        "implemented_baseline",
        "candidate_pending",
        "unassessed_legacy_surrogate",
    }
    if not required_states.issubset(states):
        issues.append(
            _issue("$entries", "inventory must visibly cover baseline, candidate, and unassessed states")
        )
    if issues:
        raise ValidationError(issues)
    return normalized


def _require_candidate_entry(inventory: dict[str, object]) -> None:
    entries = inventory["entries"]
    assert isinstance(entries, list)
    matching = [
        entry for entry in entries
        if entry["entry_id"] == _CANDIDATE_ID
        and entry["state"] == "candidate_pending"
        and entry["package_id"] == _CANDIDATE_ID
        and entry["package_version"] == _CANDIDATE_VERSION
    ]
    if len(matching) != 1:
        raise ValidationError(
            [_issue("$entries", "inventory must declare exactly one pending S4-A candidate")]
        )


def _require_criteria(criteria: list[dict[str, object]]) -> list[str]:
    issues: list[Issue] = []
    ids: list[str] = []
    for index, criterion in enumerate(criteria):
        if not isinstance(criterion, dict) or set(criterion) != {"criterion_id"}:
            issues.append(_issue(f"$criteria/{index}", "criterion must contain only criterion_id"))
            continue
        value = criterion["criterion_id"]
        if not isinstance(value, str) or not value or value in ids:
            issues.append(_issue(f"$criteria/{index}/criterion_id", "criterion IDs must be nonempty and unique"))
            continue
        ids.append(value)
    if not ids:
        issues.append(_issue("$criteria", "at least one criterion is required"))
    if issues:
        raise ValidationError(issues)
    return sorted(ids)


def _require_cards(
    cards: list[dict[str, object]], *, case_id: str, criterion_ids: list[str]
) -> list[dict[str, object]]:
    issues: list[Issue] = []
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    allowed_criteria = set(criterion_ids)
    for index, card in enumerate(cards):
        path = f"$cards/{index}"
        if not isinstance(card, dict) or set(card) != {"card_id", "case_id", "state", "criterion_ids", "note"}:
            issues.append(_issue(path, "card has unexpected or missing fields"))
            continue
        card_id = card["card_id"]
        if not isinstance(card_id, str) or not card_id or card_id in seen:
            issues.append(_issue(f"{path}/card_id", "card IDs must be nonempty and unique"))
        seen.add(card_id) if isinstance(card_id, str) else None
        if card.get("case_id") != case_id:
            issues.append(_issue(f"{path}/case_id", "card is outside the selected synthetic case"))
        if card.get("state") not in _CARD_STATES:
            issues.append(_issue(f"{path}/state", "card state is unsupported"))
        ids = card.get("criterion_ids")
        if not isinstance(ids, list) or not ids or any(
            not isinstance(item, str) or item not in allowed_criteria for item in ids
        ) or len(ids) != len(set(ids)):
            issues.append(_issue(f"{path}/criterion_ids", "card criteria must be unique declared IDs"))
        if not isinstance(card.get("note"), str):
            issues.append(_issue(f"{path}/note", "card note must remain inert text"))
        normalized.append(card)
    if issues:
        raise ValidationError(issues)
    return normalized


def _map_cards(criteria: list[str], cards: list[dict[str, object]]) -> list[dict[str, object]]:
    by_criterion: dict[str, dict[str, list[str]]] = {
        criterion: {"current": [], "stale": [], "contradictory": []} for criterion in criteria
    }
    for card in cards:
        for criterion in card["criterion_ids"]:
            assert isinstance(criterion, str)
            by_criterion[criterion][str(card["state"])].append(str(card["card_id"]))
    results: list[dict[str, object]] = []
    for criterion in criteria:
        grouped = {state: sorted(ids) for state, ids in by_criterion[criterion].items()}
        if grouped["contradictory"]:
            status = "contradicted"
            support = []
        elif grouped["current"]:
            status = "supported"
            support = grouped["current"]
        elif grouped["stale"]:
            status = "ambiguous"
            support = []
        else:
            status = "unmet"
            support = []
        results.append(
            {
                "criterion_id": criterion,
                "status": status,
                "supporting_card_ids": support,
                "stale_card_ids": grouped["stale"],
                "contradictory_card_ids": grouped["contradictory"],
            }
        )
    return results


def _issue(path: str, message: str) -> Issue:
    return Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)
