"""Invented Phase 3 package definitions and lifecycle-driven test installation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.packages import PackageRegistry
from vault_next.records import timestamp

SKILL_DEFINITIONS = {
    "skill_comprehension": {
        "display_name": "Synthetic comprehension",
        "purpose": "Extract and attribute relevant supplied information",
        "work_units": ["source_comprehension", "context_assessment", "evidence_assessment"],
        "unique_contribution": "Separates supplied facts, gaps, and source provenance",
        "method": ["inventory supplied inputs", "extract claims", "mark gaps and provenance"],
    },
    "skill_option_design": {
        "display_name": "Synthetic option design",
        "purpose": "Generate and distinguish feasible alternatives",
        "work_units": ["option_design", "option_generation"],
        "unique_contribution": "Creates distinct feasible options before evaluation",
        "method": ["state constraints", "generate alternatives", "deduplicate options"],
    },
    "skill_synthesis": {
        "display_name": "Synthetic synthesis",
        "purpose": "Integrate attributed contributions into a recommendation",
        "work_units": ["synthesis", "recommendation", "artifact_drafting"],
        "unique_contribution": "Applies an explicit decision rule without claiming owner authority",
        "method": ["compare contributions", "apply decision rule", "state recommendation limits"],
    },
    "skill_red_team": {
        "display_name": "Synthetic red team",
        "purpose": "Challenge load-bearing assumptions and recommendation weaknesses",
        "work_units": ["red_team", "risk_challenge", "factual_review"],
        "unique_contribution": "Finds a material weakness and requires a linked disposition",
        "method": ["identify load-bearing claims", "attack strongest weakness", "record disposition"],
    },
}

FRAMEWORK_DEFINITIONS = {
    "framework_specialist": ["contribute", "complete"],
    "framework_committee": ["independent_contributions", "disagreement", "synthesis"],
    "framework_brainstorming": ["generation", "criteria", "evaluation"],
    "framework_consultation": ["question", "specialist_response", "integration"],
    "framework_synthesis": ["contributions", "integration", "recommendation"],
    "framework_red_team": ["target", "challenge", "disposition"],
}

FAMILY_DEFAULTS = {
    "profile_family_understand_research": ("understand_research", ["source_comprehension"]),
    "profile_family_analyze_decide": (
        "analyze_decide",
        ["context_assessment", "option_design", "synthesis", "red_team"],
    ),
    "profile_family_prepare_interact": (
        "prepare_interact",
        ["context_assessment", "synthesis", "red_team"],
    ),
    "profile_family_create_communicate": (
        "create_communicate",
        ["source_comprehension", "artifact_drafting", "factual_review"],
    ),
    "profile_family_plan_execute": (
        "plan_execute",
        ["context_assessment", "option_design", "synthesis"],
    ),
    "profile_family_review_learn": (
        "review_learn",
        ["evidence_assessment", "synthesis", "red_team"],
    ),
}

NAMED_PROFILES = {
    "profile_deep_dive": {
        "display_name": "Synthetic deep dive",
        "family": "profile_family_analyze_decide",
        "shortcuts": ["/deep-dive"],
        "phrases": ["deep dive into", "analyze this deeply"],
        "near_miss": ["mention the phrase deep dive"],
        "required_inputs": [],
        "work_units": ["source_comprehension", "option_design", "synthesis", "red_team"],
        "framework": "framework_synthesis",
        "output": "synthetic_deep_analysis",
    },
    "profile_meeting_prep": {
        "display_name": "Synthetic meeting prep",
        "family": "profile_family_prepare_interact",
        "shortcuts": ["/meeting-prep"],
        "phrases": ["meeting prep", "prepare me for my meeting"],
        "near_miss": ["summarize meeting prep notes after the meeting"],
        "required_inputs": ["meeting_purpose"],
        "work_units": ["context_assessment", "synthesis", "red_team"],
        "framework": "framework_synthesis",
        "output": "synthetic_meeting_brief",
    },
    "profile_interview_prep": {
        "display_name": "Synthetic interview prep",
        "family": "profile_family_prepare_interact",
        "shortcuts": ["/interview-prep"],
        "phrases": ["interview prep", "prepare me for this interview"],
        "near_miss": ["review an interview transcript"],
        "required_inputs": ["role"],
        "work_units": ["source_comprehension", "synthesis", "red_team"],
        "framework": "framework_consultation",
        "output": "synthetic_interview_brief",
    },
    "profile_resume": {
        "display_name": "Synthetic resume",
        "family": "profile_family_create_communicate",
        "shortcuts": ["/resume"],
        "phrases": ["update my resume", "tailor my resume"],
        "near_miss": ["resume the paused analysis"],
        "required_inputs": ["target_role"],
        "work_units": ["source_comprehension", "artifact_drafting", "factual_review"],
        "framework": "framework_synthesis",
        "output": "synthetic_resume_draft",
    },
}


def synthetic_packages(created_at: datetime) -> list[dict[str, Any]]:
    """Return broad invented families, named profiles, skills, and frameworks."""

    packages: list[dict[str, Any]] = []
    all_frameworks = sorted(FRAMEWORK_DEFINITIONS)
    for skill_id, definition in sorted(SKILL_DEFINITIONS.items()):
        packages.append(
            _base(
                "skill",
                skill_id,
                definition["display_name"],
                definition["purpose"],
                created_at,
                {
                    "work_units": definition["work_units"],
                    "unique_contribution": definition["unique_contribution"],
                    "compatible_frameworks": all_frameworks,
                    "conflicts_with": [],
                    "method": definition["method"],
                },
            )
        )
    for framework_id, stages in sorted(FRAMEWORK_DEFINITIONS.items()):
        kind = framework_id.removeprefix("framework_")
        packages.append(
            _base(
                "framework",
                framework_id,
                f"Synthetic {kind.replace('_', ' ')}",
                f"Orchestrate an invented {kind} run",
                created_at,
                {
                    "framework_kind": kind,
                    "stages": stages,
                    "preserve_independent_contributions": kind
                    in {"committee", "brainstorming", "consultation"},
                    "execution_rule": "Record each stage and contribution before synthesis",
                },
            )
        )
    for profile_id, (family, work_units) in sorted(FAMILY_DEFAULTS.items()):
        packages.append(
            _base(
                "profile",
                profile_id,
                f"Synthetic {family.replace('_', ' ')} family",
                f"Supply shared defaults for {family}",
                created_at,
                _profile_config(
                    kind="family",
                    family=family,
                    work_units=work_units,
                    framework="framework_synthesis",
                    output="synthetic_general_artifact",
                ),
            )
        )
    for profile_id, definition in sorted(NAMED_PROFILES.items()):
        config = _profile_config(
            kind="named",
            family=definition["family"],
            work_units=definition["work_units"],
            framework=definition["framework"],
            output=definition["output"],
        )
        config.update(
            {
                "defaults": {"depth": "deep", "max_questions": 1},
                "shortcuts": definition["shortcuts"],
                "phrase_aliases": definition["phrases"],
                "near_miss_phrases": definition["near_miss"],
                "required_inputs": definition["required_inputs"],
            }
        )
        packages.append(
            _base(
                "profile",
                profile_id,
                definition["display_name"],
                "Initialize an invented recurring workflow with minimal input",
                created_at,
                config,
            )
        )
    return packages


def install_synthetic_catalog(registry: PackageRegistry) -> dict[str, Any]:
    """Exercise the complete lifecycle for invented packages and return the catalog index."""

    packages = synthetic_packages(registry.clock())
    for package in packages:
        digest = registry.create_candidate(
            package,
            proposal_rationale="Synthetic Phase 3 package exercises governed routing only",
        )
        result = {
            "fixture_id": package["evaluation_fixture_refs"][0],
            "passed": True,
            "result_sha256": canonical_sha256(
                {"package_digest": digest, "result": "synthetic-pass"}
            ),
        }
        registry.record_evaluation(
            package["package_type"],
            package["package_id"],
            package["version"],
            fixture_results=[result],
            adjudicator_id="synthetic-adjudicator",
        )
        registry.record_independent_review(
            package["package_type"],
            package["package_id"],
            package["version"],
            reviewer_id="synthetic-independent-reviewer",
            outcome="pass",
            findings=[],
            rollback_plan="Restore the prior synthetic active pointer",
        )
        registry.approve(
            package["package_type"],
            package["package_id"],
            package["version"],
            owner_id="synthetic-owner",
            accepted_limitations=["synthetic fixtures only", "no model execution"],
        )
        registry.activate(
            package["package_type"], package["package_id"], package["version"]
        )
    return registry.generate_catalog_index()


def _base(
    package_type: str,
    package_id: str,
    display_name: str,
    purpose: str,
    created_at: datetime,
    config: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "package_type": package_type,
        "package_id": package_id,
        "version": "1.0.0",
        "display_name": display_name,
        "purpose": purpose,
        "non_purpose": ["owner decision", "external action", "persistent agent memory"],
        "requested_permissions": [],
        "prohibited_actions": ["external_send", "identity_change", "governance_change"],
        "change_class": "initial",
        "change_summary": {
            "behavioral_fields": ["initial package contract"],
            "rationale": "Introduce a bounded synthetic Phase 3 package",
        },
        "supersedes_version": None,
        "affected_fixture_classes": [
            "positive",
            "near_miss",
            "adversarial",
            "permission",
            "regression",
        ],
        "rollback_plan": "Restore the prior approved synthetic active pointer",
        "created_at": timestamp(created_at),
        "design_review": {
            "reviewer_id": "synthetic-design-reviewer",
            "outcome": "accepted",
            "rationale": "Bounded synthetic contract with explicit authority limits",
        },
        "evaluation_fixture_refs": [f"fixture_{package_id}_v1"],
        "config": config,
    }


def _profile_config(
    *,
    kind: str,
    family: str,
    work_units: list[str],
    framework: str,
    output: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "family": family,
        "shortcuts": [],
        "phrase_aliases": [],
        "near_miss_phrases": [],
        "required_inputs": [],
        "optional_inputs": ["audience", "depth", "time_budget"],
        "defaults": {"audience": "owner", "depth": "standard", "max_questions": 1},
        "case_behavior": "propose_existing",
        "planning_checklist": [
            "preserve original request",
            "separate facts and assumptions",
            "declare actual composition",
            "review completion conditions",
        ],
        "work_units": work_units,
        "skill_candidates": sorted(SKILL_DEFINITIONS),
        "framework_default": framework,
        "context_policy": "metadata_first_then_explicit_allowlist",
        "review_profile": "deterministic_plus_synthetic_red_team",
        "output_contract": output,
        "completion_checks": [
            "required work units covered",
            "attribution present",
            "owner decision remains separate",
        ],
    }
