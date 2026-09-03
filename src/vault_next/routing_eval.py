"""Deterministic adjudication for checked-in synthetic routing fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.triage import TriageRequest, UniversalTriage


@dataclass(frozen=True)
class RoutingAdjudication:
    """Machine-checkable results for one routing fixture suite."""

    passed: bool
    suite_sha256: str
    results: tuple[dict[str, Any], ...]

    def to_record(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "results": list(self.results),
            "suite_sha256": self.suite_sha256,
        }


def adjudicate_routing_fixtures(
    triage: UniversalTriage, fixture_path: Path
) -> RoutingAdjudication:
    """Run exact route/profile/composition expectations without model judgment."""

    suite = json.loads(fixture_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    for fixture in suite["fixtures"]:
        plan = triage.plan(
            TriageRequest(
                fixture["text"],
                supplied_inputs=fixture["supplied_inputs"],
                required_work_units=tuple(fixture["required_work_units"]),
                preferred_framework_id=fixture["preferred_framework_id"],
            )
        )
        actual = {
            "route_type": plan["route_type"],
            "profile_id": (
                plan["profile_match"]["package_id"]
                if plan["profile_match"]
                else None
            ),
            "skill_ids": [
                item["package_id"]
                for item in plan["selected_packages"]
                if item["package_type"] == "skill"
            ],
            "framework_id": plan["framework"]["package_id"],
        }
        expected = {
            "route_type": fixture["expected_route_type"],
            "profile_id": fixture["expected_profile_id"],
            "skill_ids": fixture["expected_skill_ids"],
            "framework_id": fixture["expected_framework_id"],
        }
        results.append(
            {
                "fixture_id": fixture["fixture_id"],
                "passed": actual == expected,
                "actual_sha256": canonical_sha256(actual),
                "expected_sha256": canonical_sha256(expected),
            }
        )
    return RoutingAdjudication(
        all(result["passed"] for result in results),
        canonical_sha256(suite),
        tuple(results),
    )
