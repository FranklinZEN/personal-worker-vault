"""Apply and explicitly override Phase 3 triage plans in canonical sessions."""

from __future__ import annotations

import copy
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.packages import PackageRegistry
from vault_next.runtime import CaseSessionRuntime
from vault_next.triage import Composer, interaction_contract_for_mode, manifest_triage


class RoutingRuntime:
    """Persist route proposals, attribution, and owner overrides without mutation."""

    def __init__(
        self, runtime: CaseSessionRuntime, registry: PackageRegistry
    ) -> None:
        self.runtime = runtime
        self.registry = registry
        self.composer = Composer(registry)

    def apply(self, session_id: str, plan: dict[str, Any]) -> dict[str, Any]:
        """Validate exact active versions, then persist a full routing manifest."""

        self._validate_plan(plan)
        proposed = self.runtime.record_reasoning_event(
            session_id,
            "routing.proposed",
            {"plan": plan, "plan_sha256": plan["plan_sha256"]},
            subject_refs=[plan["plan_id"]],
        )
        self._record_selection_events(session_id, plan)
        self.runtime.record_reasoning_event(
            session_id,
            "interaction.started",
            {
                "contract": plan["interaction"],
                "contract_sha256": canonical_sha256(plan["interaction"]),
                "plan_id": plan["plan_id"],
                "plan_sha256": plan["plan_sha256"],
            },
            subject_refs=[session_id, plan["plan_id"]],
        )
        changed = self.runtime.amend_scope(
            session_id,
            changes={
                "triage": manifest_triage(
                    plan, routing_event_id=proposed["event_id"]
                ),
                "selected_packages": plan["selected_packages"],
                "framework": plan["framework"],
                "interaction": plan["interaction"],
                "requested_permissions": plan["permissions"]["requested"],
                "granted_permissions": plan["permissions"]["granted"],
            },
            reason="apply governed Phase 3 triage plan",
        )
        state = self.runtime._session(session_id)
        if state.status == "draft":
            return self.runtime.transition_session(
                session_id, "routed", reason="triage plan applied"
            )
        return changed

    def override(
        self,
        session_id: str,
        original_plan: dict[str, Any],
        *,
        framework_id: str,
        skill_ids: list[str],
        reason: str,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Append a new owner-confirmed route while retaining the original event."""

        self._validate_plan(original_plan)
        composition = self.composer.compose(
            original_plan["required_work_units"],
            framework_id,
            granted_permissions=original_plan["permissions"]["granted"],
            skill_candidates=skill_ids,
        )
        revised = copy.deepcopy(original_plan)
        revised["plan_id"] = self.runtime.ids.new("triage")
        revised["selected_packages"] = [
            item
            for item in revised["selected_packages"]
            if item["package_type"] == "profile"
        ] + composition["skills"]
        revised["framework"] = composition["framework"]
        revised["unique_contributions"] = composition["unique_contributions"]
        revised["work_unit_contributors"] = composition["work_unit_contributors"]
        revised["omitted_skills"] = composition["omitted_skills"]
        revised["configuration"]["values"]["owner_override_reason"] = reason
        revised["configuration"]["sources"][
            "owner_override_reason"
        ] = "owner_instruction"
        revised["plan_sha256"] = "0" * 64
        revised["plan_sha256"] = canonical_sha256(revised)
        self.runtime.schemas.require("triage-plan", revised)
        event = self.runtime.record_reasoning_event(
            session_id,
            "routing.overridden",
            {
                "original_plan_sha256": original_plan["plan_sha256"],
                "revised_plan_sha256": revised["plan_sha256"],
                "revised_plan": revised,
                "reason": reason,
                "explicit_confirmation": True,
            },
            subject_refs=[original_plan["plan_id"], revised["plan_id"]],
            actor={"type": "owner", "id": owner_id},
        )
        self._record_selection_events(session_id, revised)
        return self.runtime.amend_scope(
            session_id,
            changes={
                "triage": manifest_triage(
                    revised, routing_event_id=event["event_id"]
                ),
                "selected_packages": revised["selected_packages"],
                "framework": revised["framework"],
                "interaction": revised["interaction"],
            },
            reason=f"owner route override: {reason}",
        )

    def change_interaction_mode(
        self,
        session_id: str,
        original_plan: dict[str, Any],
        *,
        new_mode: str,
        reason: str,
        required_work_units: list[str] | None = None,
        framework_id: str | None = None,
        skill_ids: list[str] | None = None,
        owner_id: str = "owner",
    ) -> dict[str, Any]:
        """Append an owner mode change and a fully recomposed manifest version."""

        self._validate_plan(original_plan)
        state = self.runtime._session(session_id)
        if state.manifest is None or state.manifest.get("interaction") is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$interaction",
                        "session has no active interaction contract",
                    )
                ]
            )
        if state.manifest["triage"].get("plan_sha256") != original_plan["plan_sha256"]:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.MANIFEST_HASH_MISMATCH,
                        "$plan_sha256",
                        "mode change must start from the current manifest plan",
                    )
                ]
            )
        previous_contract = state.manifest["interaction"]
        if new_mode == previous_contract["mode"]:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$interaction/mode",
                        "mode change must select a different mode",
                    )
                ]
            )
        if new_mode not in previous_contract["allowed_mode_transitions"]:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$interaction/mode",
                        "requested transition is not permitted by the current contract",
                    )
                ]
            )
        units = required_work_units or original_plan["required_work_units"]
        current_skills = [
            item["package_id"]
            for item in original_plan["selected_packages"]
            if item["package_type"] == "skill"
        ]
        composition = self.composer.compose(
            units,
            framework_id or original_plan["framework"]["package_id"],
            granted_permissions=original_plan["permissions"]["granted"],
            skill_candidates=skill_ids or current_skills,
        )
        revised = copy.deepcopy(original_plan)
        revised["plan_id"] = self.runtime.ids.new("triage")
        revised["required_work_units"] = list(units)
        revised["selected_packages"] = [
            item
            for item in revised["selected_packages"]
            if item["package_type"] == "profile"
        ] + composition["skills"]
        revised["framework"] = composition["framework"]
        revised["unique_contributions"] = composition["unique_contributions"]
        revised["work_unit_contributors"] = composition["work_unit_contributors"]
        revised["omitted_skills"] = composition["omitted_skills"]
        revised["interaction"] = interaction_contract_for_mode(
            new_mode,
            source="owner_instruction",
            rationale=reason,
        )
        revised["configuration"]["values"]["interaction_mode"] = new_mode
        revised["configuration"]["sources"]["interaction_mode"] = "owner_instruction"
        revised["plan_sha256"] = "0" * 64
        revised["plan_sha256"] = canonical_sha256(revised)
        self._validate_plan(revised)
        old_ids = set(current_skills)
        new_ids = {
            item["package_id"]
            for item in revised["selected_packages"]
            if item["package_type"] == "skill"
        }
        event = self.runtime.record_reasoning_event(
            session_id,
            "interaction.mode_changed",
            {
                "previous_contract": previous_contract,
                "previous_contract_sha256": canonical_sha256(previous_contract),
                "new_contract": revised["interaction"],
                "new_contract_sha256": canonical_sha256(revised["interaction"]),
                "previous_plan_sha256": original_plan["plan_sha256"],
                "new_plan_id": revised["plan_id"],
                "new_plan_sha256": revised["plan_sha256"],
                "revised_plan": revised,
                "added_skill_ids": sorted(new_ids - old_ids),
                "removed_skill_ids": sorted(old_ids - new_ids),
                "context_revalidated": True,
                "permissions_revalidated": True,
                "reason": reason,
                "explicit_confirmation": True,
            },
            subject_refs=[original_plan["plan_id"], revised["plan_id"]],
            actor={"type": "owner", "id": owner_id},
        )
        self._record_selection_events(session_id, revised)
        manifest_event = self.runtime.amend_scope(
            session_id,
            changes={
                "triage": manifest_triage(revised, routing_event_id=event["event_id"]),
                "selected_packages": revised["selected_packages"],
                "framework": revised["framework"],
                "interaction": revised["interaction"],
            },
            reason=f"owner interaction-mode change: {reason}",
        )
        return {"event": event, "manifest_event": manifest_event, "plan": revised}

    def _validate_plan(self, plan: dict[str, Any]) -> None:
        self.runtime.schemas.require("triage-plan", plan)
        required = {
            "plan_id",
            "plan_version",
            "request_sha256",
            "family_match",
            "rejected_profile_ids",
            "rejected_profiles",
            "configuration",
            "required_work_units",
            "selected_packages",
            "framework",
            "unique_contributions",
            "work_unit_contributors",
            "omitted_skills",
            "profile_initialization",
            "interaction",
            "permissions",
            "clarification",
            "generated_at",
            "plan_sha256",
        }
        missing = sorted(required - set(plan))
        if missing:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$plan",
                        f"Phase 3 triage plan is incomplete: {', '.join(missing)}",
                    )
                ]
            )
        material = {**plan, "plan_sha256": "0" * 64}
        if canonical_sha256(material) != plan["plan_sha256"]:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.HASH_CHAIN_INVALID,
                        "$plan_sha256",
                        "triage plan digest mismatch",
                    )
                ]
            )
        for selected in [*plan["selected_packages"], plan["framework"]]:
            pointer = self.registry.read_pointer(
                selected["package_type"], selected["package_id"]
            )
            if (
                pointer is None
                or pointer.status != "active"
                or pointer.version != selected["version"]
                or pointer.digest != selected["digest"]
            ):
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                            "$selected_packages",
                            "triage plan references a non-active or changed package",
                        )
                    ]
                )
        self.runtime.schemas.require("interaction-contract", plan["interaction"])

    def _record_selection_events(
        self, session_id: str, plan: dict[str, Any]
    ) -> None:
        for item in plan["selected_packages"]:
            if item["package_type"] != "skill":
                continue
            self.runtime.record_reasoning_event(
                session_id,
                "skill.selected",
                {
                    "package": item,
                    "unique_work_units": plan["unique_contributions"][
                        item["package_id"]
                    ],
                },
                subject_refs=[item["package_id"]],
            )
        framework_package = self.registry.require_selectable(
            "framework", plan["framework"]["package_id"]
        )
        self.runtime.record_reasoning_event(
            session_id,
            "framework.selected",
            {
                "package": plan["framework"],
                "stages": framework_package["config"]["stages"],
            },
            subject_refs=[plan["framework"]["package_id"]],
        )
