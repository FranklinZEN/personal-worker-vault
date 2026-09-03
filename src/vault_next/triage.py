"""Deterministic Phase 3 triage, configuration layering, and skill composition."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime
from itertools import combinations
from typing import Any, Mapping

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.packages import PackagePointer, PackageRegistry
from vault_next.records import SchemaRegistry, aware_utc_now, timestamp

CONFIG_PRECEDENCE = (
    "governance",
    "owner_defaults",
    "family_profile",
    "named_profile",
    "session_inference",
    "owner_instruction",
)
PROTECTED_CONFIG_KEYS = frozenset({"permissions", "protected_paths", "safety_policy"})
INTERACTION_MODES = (
    "explore",
    "co_develop",
    "artifact_iterate",
    "rehearse",
    "status_review",
)


@dataclass(frozen=True)
class TriageRequest:
    """The small, explicit input surface for universal Phase 0 routing."""

    text: str
    supplied_inputs: Mapping[str, Any] = field(default_factory=dict)
    explicit_profile_id: str | None = None
    required_work_units: tuple[str, ...] = ()
    preferred_framework_id: str | None = None
    preferred_interaction_mode: str | None = None
    requested_permissions: tuple[str, ...] = ()
    granted_permissions: tuple[str, ...] = ()
    owner_overrides: Mapping[str, Any] = field(default_factory=dict)


def merge_configuration(layers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Apply precedence without allowing later layers to weaken governance keys."""

    return resolve_configuration(layers)["values"]


def resolve_configuration(layers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Return effective values, per-field sources, and denied protected overrides."""

    unknown = set(layers) - set(CONFIG_PRECEDENCE)
    if unknown:
        raise ValueError(f"unknown configuration layers: {sorted(unknown)}")
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    denied: list[dict[str, str]] = []
    governed: dict[str, Any] = {}
    for layer in CONFIG_PRECEDENCE:
        current = dict(layers.get(layer, {}))
        if layer == "governance":
            governed = {key: current[key] for key in PROTECTED_CONFIG_KEYS if key in current}
        else:
            for key in sorted(PROTECTED_CONFIG_KEYS & set(current)):
                denied.append(
                    {"key": key, "layer": layer, "reason": "governance_protected"}
                )
                current.pop(key)
        for key, value in current.items():
            values[key] = value
            sources[key] = layer
    for key, value in governed.items():
        values[key] = value
        sources[key] = "governance"
    return {"values": values, "sources": sources, "denied_overrides": denied}


class Composer:
    """Select the smallest active, compatible, permission-bounded skill set."""

    def __init__(self, registry: PackageRegistry) -> None:
        self.registry = registry

    def compose(
        self,
        required_work_units: list[str],
        framework_id: str,
        *,
        granted_permissions: list[str],
        skill_candidates: list[str] | None = None,
    ) -> dict[str, Any]:
        framework = self.registry.require_selectable("framework", framework_id)
        candidates = []
        allowed = set(skill_candidates or [])
        for package, pointer in self.registry.active_packages("skill"):
            if allowed and package["package_id"] not in allowed:
                continue
            if framework_id not in package["config"]["compatible_frameworks"]:
                continue
            if not set(package["requested_permissions"]).issubset(granted_permissions):
                continue
            candidates.append((package, pointer))
        candidates.sort(key=lambda item: item[0]["package_id"])
        required = set(required_work_units)
        selected: tuple[tuple[dict[str, Any], PackagePointer], ...] | None = None
        for size in range(1, len(candidates) + 1):
            for choice in combinations(candidates, size):
                ids = {item[0]["package_id"] for item in choice}
                if any(
                    set(item[0]["config"]["conflicts_with"]) & ids for item in choice
                ):
                    continue
                covered = set().union(
                    *(set(item[0]["config"]["work_units"]) for item in choice)
                )
                if required.issubset(covered):
                    selected = choice
                    break
            if selected is not None:
                break
        if selected is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$work_units",
                        "no active compatible package set covers the requested work",
                    )
                ]
            )
        unique: dict[str, list[str]] = {}
        contribution_map: dict[str, str] = {}
        for package, _ in selected:
            package_units = set(package["config"]["work_units"]) & required
            other_units = (
                set().union(
                    *(
                        set(other[0]["config"]["work_units"])
                        for other in selected
                        if other[0]["package_id"] != package["package_id"]
                    )
                )
                if len(selected) > 1
                else set()
            )
            exclusive = sorted(package_units - other_units)
            if not exclusive:
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                            "$skills",
                            "selected skill has no unique required contribution",
                        )
                    ]
                )
            unique[package["package_id"]] = exclusive
        for unit in sorted(required):
            contributor = next(
                package["package_id"]
                for package, _ in selected
                if unit in package["config"]["work_units"]
            )
            contribution_map[unit] = contributor
        selected_ids = {package["package_id"] for package, _ in selected}
        omitted = [
            {
                "package_id": package["package_id"],
                "reason": "not needed for minimal work-unit coverage",
            }
            for package, _ in candidates
            if package["package_id"] not in selected_ids
        ]
        framework_pointer = self.registry.read_pointer("framework", framework_id)
        return {
            "skills": [
                _selection(
                    package,
                    pointer,
                    f"covers {', '.join(unique[package['package_id']])}",
                )
                for package, pointer in selected
            ],
            "framework": _selection(
                framework,
                framework_pointer,
                "governs the selected work-unit sequence",
            ),
            "unique_contributions": unique,
            "work_unit_contributors": contribution_map,
            "omitted_skills": omitted,
        }


class UniversalTriage:
    """Route shortcuts, phrases, safe family inference, and novel dynamic requests."""

    def __init__(
        self,
        registry: PackageRegistry,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Any = aware_utc_now,
    ) -> None:
        self.registry = registry
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock
        self.composer = Composer(registry)

    def plan(self, request: TriageRequest) -> dict[str, Any]:
        profiles = self.registry.active_packages("profile")
        named = sorted(
            (item for item in profiles if item[0]["config"]["kind"] == "named"),
            key=lambda item: item[0]["package_id"],
        )
        route_type, match, rejected = self._match(request, named)
        family = self._family(request, match, profiles)
        named_config = match[0]["config"] if match else {}
        family_config = family[0]["config"] if family else {}
        layers = {
            "governance": {
                "permissions": list(request.granted_permissions),
                "protected_paths": ["legacy_vault", "backup_vault"],
                "safety_policy": "local_synthetic_only",
            },
            "owner_defaults": {
                "audience": "owner",
                "depth": "standard",
                "max_questions": 1,
            },
            "family_profile": family_config.get("defaults", {}),
            "named_profile": named_config.get("defaults", {}),
            "session_inference": {"response_mode": "concise"},
            "owner_instruction": dict(request.owner_overrides),
        }
        config = resolve_configuration(layers)
        default_units = named_config.get(
            "work_units", family_config.get("work_units", ["context_assessment"])
        )
        units = list(dict.fromkeys(request.required_work_units or tuple(default_units)))
        framework_id = (
            request.preferred_framework_id
            or named_config.get("framework_default")
            or family_config.get("framework_default")
            or "framework_specialist"
        )
        candidates = named_config.get("skill_candidates") or family_config.get(
            "skill_candidates"
        )
        composition = self.composer.compose(
            units,
            framework_id,
            granted_permissions=list(request.granted_permissions),
            skill_candidates=candidates,
        )
        interaction = resolve_interaction_contract(
            request,
            named_config=named_config,
            family_config=family_config,
        )
        self.schemas.require("interaction-contract", interaction)
        missing = [
            key
            for key in named_config.get("required_inputs", [])
            if key not in request.supplied_inputs
        ]
        clarification = {
            "needed": bool(missing),
            "missing_inputs": missing,
            "question": f"Please provide: {', '.join(missing)}." if missing else None,
        }
        now: datetime = self.clock()
        plan = {
            "schema_version": "1.0",
            "plan_id": self.ids.new("triage"),
            "plan_version": "1.0",
            "request_sha256": canonical_sha256(
                {
                    "text": request.text,
                    "supplied_inputs": dict(request.supplied_inputs),
                    "preferred_interaction_mode": request.preferred_interaction_mode,
                }
            ),
            "route_type": route_type,
            "profile_match": (
                _selection(
                    match[0],
                    match[1],
                    f"{route_type} matched at the accepted threshold",
                )
                if match
                else None
            ),
            "family_match": (
                _selection(family[0], family[1], "shared defaults") if family else None
            ),
            "rejected_profile_ids": rejected,
            "rejected_profiles": [
                {
                    "package_id": package_id,
                    "reason": "near-miss fixture or insufficient accepted match",
                }
                for package_id in rejected
            ],
            "configuration": config,
            "required_work_units": units,
            "selected_packages": (
                (
                    [_selection(family[0], family[1], "supplies family defaults")]
                    if family
                    else []
                )
                + (
                    [_selection(match[0], match[1], "initializes recurring workflow")]
                    if match
                    else []
                )
            )
            + composition["skills"],
            "framework": composition["framework"],
            "unique_contributions": composition["unique_contributions"],
            "work_unit_contributors": composition["work_unit_contributors"],
            "omitted_skills": composition["omitted_skills"],
            "profile_initialization": {
                "case_behavior": named_config.get(
                    "case_behavior", family_config.get("case_behavior", "none")
                ),
                "planning_checklist": named_config.get(
                    "planning_checklist",
                    family_config.get(
                        "planning_checklist", ["declare actual composition"]
                    ),
                ),
                "context_policy": named_config.get(
                    "context_policy",
                    family_config.get("context_policy", "explicit_allowlist"),
                ),
                "review_profile": named_config.get(
                    "review_profile",
                    family_config.get("review_profile", "deterministic"),
                ),
                "output_contract": named_config.get(
                    "output_contract",
                    family_config.get("output_contract", "synthetic_general_artifact"),
                ),
                "completion_checks": named_config.get(
                    "completion_checks",
                    family_config.get(
                        "completion_checks", ["required work units covered"]
                    ),
                ),
            },
            "interaction": interaction,
            "permissions": {
                "requested": list(request.requested_permissions),
                "granted": list(request.granted_permissions),
            },
            "clarification": clarification,
            "generated_at": timestamp(now),
            "plan_sha256": "0" * 64,
        }
        plan["plan_sha256"] = canonical_sha256(
            {**plan, "plan_sha256": "0" * 64}
        )
        self.schemas.require("triage-plan", plan)
        return plan

    def _match(
        self, request: TriageRequest, named: list[Any]
    ) -> tuple[str, Any, list[str]]:
        text = " ".join(request.text.casefold().split())
        first = text.split(maxsplit=1)[0] if text else ""
        if request.explicit_profile_id:
            package = self.registry.require_selectable(
                "profile", request.explicit_profile_id
            )
            pointer = self.registry.read_pointer(
                "profile", request.explicit_profile_id
            )
            if package["config"]["kind"] != "named":
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                            "$profile",
                            "explicit route must name a named profile",
                        )
                    ]
                )
            return "explicit_shortcut", (package, pointer), []
        for package, pointer in named:
            if first in package["config"]["shortcuts"]:
                return "explicit_shortcut", (package, pointer), []
        rejected: list[str] = []
        for package, pointer in named:
            config = package["config"]
            if any(near in text for near in config["near_miss_phrases"]):
                rejected.append(package["package_id"])
                continue
            if any(
                text.find(phrase) in range(0, 33) for phrase in config["phrase_aliases"]
            ):
                return "recognized_phrase", (package, pointer), rejected
        inference_rules = {
            "profile_deep_dive": (("deeply", "examine"), ("deep", "analysis")),
            "profile_meeting_prep": (("meeting", "prepare"), ("meeting", "ready")),
            "profile_interview_prep": (
                ("interview", "prepare"),
                ("interview", "ready"),
            ),
            "profile_resume": (("resume", "polish"), ("resume", "rewrite")),
        }
        for package, pointer in named:
            pairs = inference_rules.get(package["package_id"], ())
            if any(all(word in text for word in pair) for pair in pairs):
                return "inferred_profile", (package, pointer), rejected
        return "dynamic", None, rejected

    @staticmethod
    def _family(request: TriageRequest, match: Any, profiles: list[Any]) -> Any:
        by_id = {
            package["package_id"]: (package, pointer)
            for package, pointer in profiles
        }
        if match:
            return by_id.get(match[0]["config"]["family"])
        text = request.text.casefold()
        rules = (
            (
                "profile_family_understand_research",
                ("research", "understand", "investigate"),
            ),
            (
                "profile_family_analyze_decide",
                ("decide", "choose", "option", "tradeoff"),
            ),
            (
                "profile_family_prepare_interact",
                ("prepare", "conversation", "meeting", "interview"),
            ),
            (
                "profile_family_create_communicate",
                ("write", "draft", "create", "communicate"),
            ),
            ("profile_family_plan_execute", ("plan", "execute", "roadmap")),
            ("profile_family_review_learn", ("review", "retrospective", "learn")),
        )
        matches = [
            profile_id
            for profile_id, words in rules
            if any(word in text for word in words)
        ]
        return by_id.get(matches[0]) if len(matches) == 1 else None


def manifest_triage(
    plan: dict[str, Any], *, routing_event_id: str
) -> dict[str, Any]:
    """Create the compact, replayable triage summary embedded in a manifest."""

    return {
        "plan_id": plan["plan_id"],
        "plan_version": plan["plan_version"],
        "plan_sha256": plan["plan_sha256"],
        "routing_event_id": routing_event_id,
        "route_type": plan["route_type"],
        "profile_match": plan["profile_match"],
        "defaults": plan["configuration"]["values"],
        "overrides": {},
        "config_sources": plan["configuration"]["sources"],
        "rejected_profiles": plan["rejected_profiles"],
        "clarification": plan["clarification"],
        "initialization": plan["profile_initialization"],
    }


def resolve_interaction_contract(
    request: TriageRequest,
    *,
    named_config: Mapping[str, Any],
    family_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve an explicit, profile, inferred, or default interaction contract."""

    if request.preferred_interaction_mode is not None:
        mode = request.preferred_interaction_mode
        source = "owner_instruction"
        rationale = "the owner explicitly selected this interaction mode"
    elif named_config.get("defaults", {}).get("interaction_mode") is not None:
        mode = named_config["defaults"]["interaction_mode"]
        source = "named_profile"
        rationale = "the matched named profile supplies this interaction default"
    elif family_config.get("defaults", {}).get("interaction_mode") is not None:
        mode = family_config["defaults"]["interaction_mode"]
        source = "family_profile"
        rationale = "the matched family profile supplies this interaction default"
    else:
        normalized = " ".join(request.text.casefold().split())
        if any(phrase in normalized for phrase in ("what do i have today", "current work", "follow up")):
            mode = "status_review"
            source = "safe_inference"
            rationale = "the request asks to review current work"
        elif any(word in normalized for word in ("rehearse", "practice", "role-play", "roleplay", "mock")):
            mode = "rehearse"
            source = "safe_inference"
            rationale = "the request asks to practice a live interaction"
        elif any(word in normalized for word in ("draft", "rewrite", "polish", "resume")):
            mode = "artifact_iterate"
            source = "safe_inference"
            rationale = "the request asks to develop a working artifact"
        elif any(word in normalized for word in ("plan", "prepare", "decide", "design")):
            mode = "co_develop"
            source = "safe_inference"
            rationale = "the request benefits from iterative co-development"
        else:
            mode = "explore"
            source = "owner_default"
            rationale = "the default keeps artifact creation optional while understanding develops"
    if mode not in INTERACTION_MODES:
        raise ValidationError(
            [
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$interaction/mode",
                    "interaction mode is not supported",
                )
            ]
        )
    return interaction_contract_for_mode(mode, source=source, rationale=rationale)


def interaction_contract_for_mode(
    mode: str, *, source: str, rationale: str
) -> dict[str, Any]:
    """Build one strict interaction contract for a resolved supported mode."""

    if mode not in INTERACTION_MODES:
        raise ValidationError(
            [
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$interaction/mode",
                    "interaction mode is not supported",
                )
            ]
        )
    artifact_policy = {
        "artifact_iterate": "iterative",
        "status_review": "none",
    }.get(mode, "optional")
    completion = {
        "artifact_iterate": ["artifact_acceptance"],
        "status_review": ["status_review_complete"],
    }.get(mode, ["owner_checkpoint"])
    return {
        "mode": mode,
        "mode_source": source,
        "rationale": rationale,
        "owner_can_change_mode": True,
        "initiative": "owner_led" if mode == "explore" else "mixed",
        "artifact_policy": artifact_policy,
        "checkpoint_policy": "material_change",
        "completion_requires": completion,
        "allowed_mode_transitions": list(INTERACTION_MODES),
    }


def _selection(
    package: dict[str, Any], pointer: PackagePointer | None, rationale: str
) -> dict[str, Any]:
    if pointer is None or pointer.status != "active":
        raise ValidationError(
            [
                Issue(
                    ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                    "$package",
                    "selected package lacks an active pointer",
                )
            ]
        )
    return {
        "package_type": package["package_type"],
        "package_id": package["package_id"],
        "version": pointer.version,
        "digest": pointer.digest,
        "rationale": rationale,
    }


def revised_plan(
    plan: dict[str, Any],
    *,
    plan_id: str,
    framework: dict[str, Any],
    skills: list[dict[str, Any]],
    reason: str,
) -> dict[str, Any]:
    """Build a new owner-override plan without altering the original."""

    result = copy.deepcopy(plan)
    result["plan_id"] = plan_id
    result["selected_packages"] = [
        item
        for item in result["selected_packages"]
        if item["package_type"] == "profile"
    ] + skills
    result["framework"] = framework
    result["configuration"]["values"]["owner_override_reason"] = reason
    result["configuration"]["sources"]["owner_override_reason"] = "owner_instruction"
    result["plan_sha256"] = "0" * 64
    result["plan_sha256"] = canonical_sha256(result)
    return result
