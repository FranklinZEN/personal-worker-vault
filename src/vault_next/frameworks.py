"""Synthetic Phase 3 framework execution with attributed canonical contributions."""

from __future__ import annotations

from typing import Any

from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.packages import PackageRegistry
from vault_next.runtime import CaseSessionRuntime


class FrameworkExecutor:
    """Execute only the active framework and skill versions in a session manifest."""

    def __init__(self, runtime: CaseSessionRuntime, registry: PackageRegistry) -> None:
        self.runtime = runtime
        self.registry = registry

    def run_specialist(
        self, session_id: str, *, skill_id: str, content: str
    ) -> list[dict[str, Any]]:
        framework, skills = self._selection(session_id, "specialist")
        self._require_selected_skill(skill_id, skills)
        events = [self._stage(session_id, framework, "contribute", 1)]
        events.append(
            self._contribution(session_id, framework, skill_id, content)
        )
        events.append(self._stage(session_id, framework, "complete", 2))
        return events

    def run_committee(
        self,
        session_id: str,
        *,
        contributions: dict[str, str],
        recommendation: str,
    ) -> dict[str, Any]:
        framework, skills = self._selection(session_id, "committee")
        self._require_all_selected(contributions, skills)
        self._stage(session_id, framework, "independent_contributions", 1)
        contribution_events = [
            self._contribution(session_id, framework, skill_id, content)
            for skill_id, content in sorted(contributions.items())
        ]
        self._stage(session_id, framework, "disagreement", 2)
        disagreement = None
        if len(set(contributions.values())) > 1:
            disagreement_id = f"disagreement_{self.runtime.ids.new_body()}"
            disagreement = self.runtime.record_reasoning_event(
                session_id,
                "disagreement.recorded",
                {
                    "disagreement_id": disagreement_id,
                    "statement": "Synthetic committee contributions differ",
                    "status": "open",
                },
                subject_refs=[disagreement_id],
            )
        self._stage(session_id, framework, "synthesis", 3)
        recommendation_event = self._recommend(session_id, recommendation)
        return {
            "contributions": contribution_events,
            "disagreement": disagreement,
            "recommendation": recommendation_event,
        }

    def run_brainstorming(
        self,
        session_id: str,
        *,
        options: list[str],
        selected_index: int,
        criteria: list[str],
    ) -> dict[str, Any]:
        framework, _ = self._selection(session_id, "brainstorming")
        if len(set(options)) != len(options) or not options:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$options",
                        "brainstorming options must be nonempty and distinct",
                    )
                ]
            )
        if selected_index not in range(len(options)):
            raise ValueError("selected_index is outside the option set")
        self._stage(session_id, framework, "generation", 1)
        alternatives = []
        for index, option in enumerate(options):
            alternative_id = f"alternative_synthetic_{index + 1}"
            alternatives.append(
                self.runtime.record_reasoning_event(
                    session_id,
                    "alternative.recorded",
                    {
                        "alternative_id": alternative_id,
                        "description": option,
                        "disposition": "open",
                    },
                    subject_refs=[alternative_id],
                )
            )
        self._stage(session_id, framework, "criteria", 2)
        self._contribution(
            session_id,
            framework,
            self._first_skill(session_id),
            f"Synthetic criteria: {', '.join(criteria)}",
        )
        self._stage(session_id, framework, "evaluation", 3)
        dispositions = []
        for index, event in enumerate(alternatives):
            alternative_id = event["payload"]["alternative_id"]
            disposition = "selected" if index == selected_index else "rejected"
            dispositions.append(
                self.runtime.record_reasoning_event(
                    session_id,
                    "alternative.disposition_changed",
                    {
                        "alternative_id": alternative_id,
                        "disposition": disposition,
                        "reason": "synthetic criteria evaluation",
                    },
                    subject_refs=[alternative_id],
                )
            )
        return {"alternatives": alternatives, "dispositions": dispositions}

    def run_consultation(
        self, session_id: str, *, question: str, response: str
    ) -> list[dict[str, Any]]:
        framework, _ = self._selection(session_id, "consultation")
        skill_id = self._first_skill(session_id)
        events = [self._stage(session_id, framework, "question", 1)]
        events.append(
            self._contribution(
                session_id, framework, skill_id, f"Question: {question}"
            )
        )
        events.append(self._stage(session_id, framework, "specialist_response", 2))
        events.append(self._contribution(session_id, framework, skill_id, response))
        events.append(self._stage(session_id, framework, "integration", 3))
        return events

    def run_synthesis(
        self,
        session_id: str,
        *,
        contributions: dict[str, str],
        recommendation: str,
    ) -> dict[str, Any]:
        framework, skills = self._selection(session_id, "synthesis")
        self._require_all_selected(contributions, skills)
        self._stage(session_id, framework, "contributions", 1)
        events = [
            self._contribution(session_id, framework, skill_id, content)
            for skill_id, content in sorted(contributions.items())
        ]
        self._stage(session_id, framework, "integration", 2)
        self._stage(session_id, framework, "recommendation", 3)
        return {
            "contributions": events,
            "recommendation": self._recommend(session_id, recommendation),
        }

    def run_red_team(
        self,
        session_id: str,
        *,
        recommendation_id: str,
        finding: str,
        revised_summary: str | None,
        uphold_reason: str | None = None,
    ) -> dict[str, Any]:
        framework, skills = self._selection(session_id, "red_team")
        if not any(
            event["session_id"] == session_id
            and event["event_type"]
            in {"recommendation.issued", "recommendation.revised"}
            and recommendation_id in event["subject_refs"]
            for event in self.runtime.semantic.read_all()
        ):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_REFERENCE_MISSING,
                        "$recommendation_id",
                        "red-team target recommendation does not exist in this session",
                    )
                ]
            )
        red_skill = next(
            (skill_id for skill_id in skills if skill_id == "skill_red_team"), None
        )
        if red_skill is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$skills",
                        "red-team framework requires the selected red-team skill",
                    )
                ]
            )
        self._stage(session_id, framework, "target", 1)
        self._stage(session_id, framework, "challenge", 2)
        contribution = self._contribution(
            session_id, framework, red_skill, finding
        )
        finding_id = f"finding_{self.runtime.ids.new_body()}"
        finding_event = self.runtime.record_reasoning_event(
            session_id,
            "review.finding_recorded",
            {
                "finding_id": finding_id,
                "recommendation_id": recommendation_id,
                "severity": "high",
                "finding": finding,
            },
            subject_refs=[finding_id, recommendation_id],
            actor={"type": "reviewer", "id": red_skill},
        )
        self._stage(session_id, framework, "disposition", 3)
        if revised_summary is not None:
            disposition = self.runtime.record_reasoning_event(
                session_id,
                "recommendation.revised",
                {
                    "recommendation_id": recommendation_id,
                    "revision": 2,
                    "summary": revised_summary,
                },
                subject_refs=[recommendation_id],
                provenance=[{"ref": finding_event["event_id"], "relation": "responds_to"}],
            )
        else:
            disposition = self.runtime.record_reasoning_event(
                session_id,
                "recommendation.upheld",
                {
                    "recommendation_id": recommendation_id,
                    "finding_id": finding_id,
                    "reason": uphold_reason or "finding does not change the decision rule",
                },
                subject_refs=[recommendation_id, finding_id],
                provenance=[{"ref": finding_event["event_id"], "relation": "responds_to"}],
            )
        return {
            "contribution": contribution,
            "finding": finding_event,
            "disposition": disposition,
        }

    def _selection(
        self, session_id: str, expected_kind: str
    ) -> tuple[dict[str, Any], set[str]]:
        state = self.runtime._session(session_id)
        manifest = state.manifest or {}
        selected_framework = manifest.get("framework")
        if not isinstance(selected_framework, dict):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$framework",
                        "session has no governed framework selection",
                    )
                ]
            )
        framework = self.registry.require_selectable(
            "framework", selected_framework["package_id"]
        )
        pointer = self.registry.read_pointer(
            "framework", selected_framework["package_id"]
        )
        if (
            pointer is None
            or pointer.version != selected_framework["version"]
            or pointer.digest != selected_framework["digest"]
            or framework["config"]["framework_kind"] != expected_kind
        ):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$framework",
                        "active framework does not match the session contract",
                    )
                ]
            )
        skills = {
            item["package_id"]
            for item in manifest.get("selected_packages", [])
            if item["package_type"] == "skill"
        }
        for skill_id in skills:
            self.registry.require_selectable("skill", skill_id)
        return framework, skills

    def _stage(
        self,
        session_id: str,
        framework: dict[str, Any],
        stage: str,
        sequence: int,
    ) -> dict[str, Any]:
        stages = framework["config"]["stages"]
        if sequence < 1 or sequence > len(stages) or stages[sequence - 1] != stage:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$stage",
                        "framework stage violates active package order",
                    )
                ]
            )
        return self.runtime.record_reasoning_event(
            session_id,
            "framework.stage_recorded",
            {
                "framework_id": framework["package_id"],
                "stage": stage,
                "sequence": sequence,
            },
            subject_refs=[framework["package_id"]],
        )

    def _contribution(
        self,
        session_id: str,
        framework: dict[str, Any],
        skill_id: str,
        content: str,
    ) -> dict[str, Any]:
        skill = self.registry.require_selectable("skill", skill_id)
        contribution_id = f"contribution_{self.runtime.ids.new_body()}"
        return self.runtime.record_reasoning_event(
            session_id,
            "contribution.recorded",
            {
                "contribution_id": contribution_id,
                "skill_id": skill_id,
                "framework_id": framework["package_id"],
                "work_units": skill["config"]["work_units"],
                "content": content,
            },
            subject_refs=[contribution_id],
            actor={"type": "skill", "id": skill_id},
        )

    def _recommend(self, session_id: str, summary: str) -> dict[str, Any]:
        recommendation_id = self.runtime.ids.new("recommendation")
        return self.runtime.record_reasoning_event(
            session_id,
            "recommendation.issued",
            {
                "recommendation_id": recommendation_id,
                "revision": 1,
                "summary": summary,
            },
            subject_refs=[recommendation_id],
        )

    @staticmethod
    def _require_selected_skill(skill_id: str, selected: set[str]) -> None:
        if skill_id not in selected:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$skill_id",
                        "contributor is not selected in the session manifest",
                    )
                ]
            )

    def _require_all_selected(
        self, contributions: dict[str, str], selected: set[str]
    ) -> None:
        if not contributions or not set(contributions).issubset(selected):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$contributions",
                        "all contributors must be selected skills",
                    )
                ]
            )

    def _first_skill(self, session_id: str) -> str:
        state = self.runtime._session(session_id)
        skills = sorted(
            item["package_id"]
            for item in (state.manifest or {}).get("selected_packages", [])
            if item["package_type"] == "skill"
        )
        if not skills:
            raise ValidationError(
                [Issue(ErrorCode.EVENT_TYPE_SEMANTICS_INVALID, "$skills", "no selected skill")]
            )
        return skills[0]
