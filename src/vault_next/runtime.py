"""Phase 2 case/session runtime over the immutable semantic ledger."""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any, Callable

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.ids import DEFAULT_FACTORY, ULIDFactory
from vault_next.ledger import SemanticLedger
from vault_next.lifecycle import CASE_TRANSITIONS, SESSION_TRANSITIONS, fold_case_states, fold_session_states
from vault_next.paths import RuntimePaths
from vault_next.records import SchemaRegistry, aware_utc_now, build_event, timestamp


class CaseSessionRuntime:
    """Create and evolve cases/sessions using complete event-embedded snapshots."""

    def __init__(
        self,
        paths: RuntimePaths,
        schemas: SchemaRegistry,
        *,
        id_factory: ULIDFactory = DEFAULT_FACTORY,
        clock: Callable[[], datetime] = aware_utc_now,
        correlation_id: str = "vault-next-phase2",
    ) -> None:
        self.paths = paths
        self.schemas = schemas
        self.ids = id_factory
        self.clock = clock
        self.correlation_id = correlation_id
        self.semantic = SemanticLedger(paths, schemas)

    def create_case(
        self,
        title: str,
        *,
        sensitivity_labels: list[str] | None = None,
        classification: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        case_id = self.ids.new("case")
        now = self.clock()
        manifest = {
            "schema_version": "1.0",
            "case_id": case_id,
            "title": title,
            "created_at": timestamp(now),
            "sensitivity_labels": sensitivity_labels or ["none"],
            "access_policy": "explicit_session_allowlist",
            "classification": classification or {},
            "related_case_ids": [],
            "provenance_refs": [],
        }
        self.schemas.require("case-manifest", manifest)
        return self._append(
            "case.created", case_id, None,
            {"title": title, "manifest": manifest, "manifest_sha256": canonical_sha256(manifest)},
            subject_refs=[case_id], when=now,
        )

    def change_case_status(self, case_id: str, to_status: str, *, reason: str) -> dict[str, Any]:
        events = self.semantic.read_all()
        states, _ = fold_case_states(events)
        if case_id not in states or to_status not in CASE_TRANSITIONS.get(states[case_id].status, ()):
            raise self._transition_error("case", states.get(case_id).status if case_id in states else None, to_status)
        if to_status == "closed":
            session_states, _ = fold_session_states(events)
            if any(
                state.case_id == case_id and not state.frozen
                for state in session_states.values()
            ):
                raise ValidationError(
                    [
                        Issue(
                            ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                            "$to_status",
                            "case cannot close while a session is nonterminal",
                        )
                    ]
                )
        return self._append(
            "case.status_changed", case_id, None,
            {"from_status": states[case_id].status, "to_status": to_status, "reason": reason},
            subject_refs=[case_id], causation=states[case_id].last_event_id,
        )

    def create_session(
        self,
        case_id: str,
        primary_question: str,
        *,
        deliverable_kind: str = "analysis",
        audience: str = "owner",
        sensitivity_labels: list[str] | None = None,
        authorized_context: list[dict[str, Any]] | None = None,
        continues_session_id: str | None = None,
    ) -> dict[str, Any]:
        case_states, _ = fold_case_states(self.semantic.read_all())
        if (
            case_id not in case_states
            or case_states[case_id].status not in {"open", "reopened"}
        ):
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$case_id",
                        "case is not available for a new session",
                    )
                ]
            )
        session_id = self.ids.new("session")
        now = self.clock()
        case_manifest = case_states[case_id].manifest or {}
        case_labels = set(case_manifest.get("sensitivity_labels", ["none"]))
        session_labels = set(sensitivity_labels or case_labels)
        session_labels.update(case_labels)
        if len(session_labels) > 1:
            session_labels.discard("none")
        manifest = {
            "schema_version": "1.0",
            "manifest_version": 1,
            "case_id": case_id,
            "session_id": session_id,
            "created_at": timestamp(now),
            "updated_at": timestamp(now),
            "status": "draft",
            "primary_question": primary_question,
            "normalized_problem": None,
            "deliverable": {"kind": deliverable_kind, "audience": audience},
            "triage": {
                "plan_id": self.ids.new("triage"),
                "plan_version": "1.0",
                "route_type": "dynamic",
                "profile_match": None,
                "defaults": {},
                "overrides": {},
            },
            "selected_packages": [],
            "framework": None,
            "interaction": None,
            "authorized_context": authorized_context or [],
            "sensitivity_labels": sorted(session_labels),
            "requested_permissions": [],
            "granted_permissions": [],
            "evidence_refs": [],
            "output_refs": [],
            "review_refs": [],
            "event_refs": [],
            "related_session_ids": [continues_session_id] if continues_session_id else [],
            "continues_session_id": continues_session_id,
            "closure_disposition": None,
            "closure_reason": None,
        }
        self.schemas.require("session-manifest", manifest)
        return self._append_manifest("session.created", manifest, previous_digest=None, when=now)

    def transition_session(self, session_id: str, to_status: str, *, reason: str) -> dict[str, Any]:
        state = self._session(session_id)
        if to_status not in SESSION_TRANSITIONS.get(state.status, ()):
            raise self._transition_error("session", state.status, to_status)
        if to_status == "closed":
            return self.close_session(session_id, disposition="completed", reason=reason)
        if to_status == "abandoned":
            return self.close_session(session_id, disposition="abandoned", reason=reason)
        manifest = self._next_manifest(state, status=to_status)
        event_type = "session.blocked" if to_status == "blocked" else "session.status_changed"
        return self._append_manifest(
            event_type,
            manifest,
            previous_digest=state.manifest_sha256,
            extra={
                "from_status": state.status,
                "to_status": to_status,
                "reason": reason,
            },
        )

    def amend_scope(self, session_id: str, *, changes: dict[str, Any], reason: str) -> dict[str, Any]:
        state = self._session(session_id)
        if state.frozen or state.manifest is None:
            raise self._transition_error("session", state.status, state.status)
        allowed = {
            "primary_question",
            "normalized_problem",
            "deliverable",
            "authorized_context",
            "sensitivity_labels",
            "requested_permissions",
            "granted_permissions",
            "evidence_refs",
            "output_refs",
            "review_refs",
            "related_session_ids",
            "triage",
            "selected_packages",
            "framework",
            "interaction",
        }
        unknown = sorted(set(changes) - allowed)
        if unknown:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$changes",
                        f"unsupported scope fields: {', '.join(unknown)}",
                    )
                ]
            )
        manifest = self._next_manifest(state, **changes)
        return self._append_manifest(
            "session.scope_changed",
            manifest,
            previous_digest=state.manifest_sha256,
            extra={
                "from_status": state.status,
                "to_status": state.status,
                "changed_fields": sorted(changes),
                "reason": reason,
            },
        )

    def close_session(self, session_id: str, *, disposition: str, reason: str) -> dict[str, Any]:
        state = self._session(session_id)
        self._require_semantic_review_clearance(session_id)
        target = "abandoned" if disposition == "abandoned" else "closed"
        if target not in SESSION_TRANSITIONS.get(state.status, ()):
            raise self._transition_error("session", state.status, target)
        manifest = self._next_manifest(
            state,
            status=target,
            closure_disposition=disposition,
            closure_reason=reason,
        )
        return self._append_manifest(
            "session.closed",
            manifest,
            previous_digest=state.manifest_sha256,
            frozen=True,
            extra={
                "from_status": state.status,
                "to_status": target,
                "disposition": disposition,
                "reason": reason,
            },
        )

    def resume_as_new_session(
        self,
        session_id: str,
        *,
        primary_question: str | None = None,
        authorized_context: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        prior = self._session(session_id)
        if not prior.frozen or prior.manifest is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$session_id",
                        "only a terminal session can resume as a new session",
                    )
                ]
            )
        return self.create_session(
            prior.case_id,
            primary_question or prior.manifest["primary_question"],
            deliverable_kind=prior.manifest["deliverable"]["kind"],
            audience=prior.manifest["deliverable"]["audience"],
            sensitivity_labels=list(prior.manifest["sensitivity_labels"]),
            authorized_context=authorized_context or [],
            continues_session_id=session_id,
        )

    def record_reasoning_event(
        self,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        subject_refs: list[str],
        provenance: list[dict[str, str]] | None = None,
        actor: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "question.clarified",
            "question.reframed",
            "question.resolved",
            "claim.recorded",
            "knowledge.candidate_recorded",
            "knowledge.candidate_superseded",
            "knowledge.candidate_withdrawn",
            "experience.candidate_recorded",
            "experience.candidate_superseded",
            "experience.candidate_withdrawn",
            "committee.run_recorded",
            "committee.finding_recorded",
            "committee.dissent_recorded",
            "committee.challenge_recorded",
            "committee.synthesis_recorded",
            "committee.comparison_recorded",
            "assumption.recorded",
            "assumption.revised",
            "alternative.recorded",
            "alternative.disposition_changed",
            "disagreement.recorded",
            "disagreement.resolved",
            "recommendation.issued",
            "recommendation.revised",
            "recommendation.withdrawn",
            "routing.proposed",
            "routing.overridden",
            "skill.selected",
            "framework.selected",
            "contribution.recorded",
            "framework.stage_recorded",
            "review.finding_recorded",
            "recommendation.upheld",
            "interaction.started",
            "interaction.mode_changed",
            "checkpoint.recorded",
            "owner_input.recorded",
            "artifact.version_created",
            "artifact.feedback_recorded",
            "artifact.accepted",
            "artifact.withdrawn",
            "work_item.recorded",
            "work_item.status_changed",
            "chat_ingress.save_committed",
            "outcome.assessed",
        }
        if event_type not in allowed:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.EVENT_TYPE_SEMANTICS_INVALID,
                        "$event_type",
                        "event is not a Phase 2 reasoning event",
                    )
                ]
            )
        state = self._session(session_id)
        if state.frozen:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                        "$session_id",
                        "terminal session cannot accept new reasoning events",
                    )
                ]
            )
        return self._append(
            event_type,
            state.case_id,
            session_id,
            payload,
            subject_refs=subject_refs,
            causation=self._last_session_event_id(session_id),
            provenance=provenance,
            actor=actor,
        )

    def record_owner_decision(self, session_id: str, decision: str) -> dict[str, Any]:
        state = self._session(session_id)
        self._require_semantic_review_clearance(session_id)
        decision_id = self.ids.new("decision")
        return self._append(
            "owner_decision.recorded",
            state.case_id,
            session_id,
            {"decision_id": decision_id, "decision": decision, "explicit_confirmation": True},
            subject_refs=[decision_id],
            causation=self._last_session_event_id(session_id),
            actor={"type": "owner", "id": "owner"},
        )

    def request_semantic_review(
        self,
        session_id: str,
        *,
        review_id: str,
        packet_sha256: str,
        target_type: str,
        target_ref: str,
        target_sha256: str,
    ) -> dict[str, Any]:
        """Bind a required semantic review to one exact immutable target before finalization."""

        state = self._session(session_id)
        if state.status != "active":
            raise self._transition_error("session", state.status, "review_pending")
        requested = self._append(
            "review.requested",
            state.case_id,
            session_id,
            {
                "review_id": review_id,
                "packet_sha256": packet_sha256,
                "target_type": target_type,
                "target_ref": target_ref,
                "target_sha256": target_sha256,
                "requires_semantic_review": True,
            },
            subject_refs=[review_id, target_ref],
            causation=self._last_session_event_id(session_id),
        )
        self.transition_session(session_id, "review_pending", reason="semantic review requested")
        return requested

    def record_semantic_review_completion(
        self,
        session_id: str,
        *,
        review_id: str,
        attempt: int,
        packet_sha256: str,
        result_sha256: str,
        target_sha256: str,
        status: str,
    ) -> dict[str, Any]:
        """Record a coordinator-attributed result; the reviewer itself never writes state."""

        state = self._session(session_id)
        if state.status not in {"review_pending", "blocked"}:
            raise self._transition_error("session", state.status, state.status)
        return self._append(
            "review.completed",
            state.case_id,
            session_id,
            {
                "review_id": review_id,
                "attempt": attempt,
                "packet_sha256": packet_sha256,
                "result_sha256": result_sha256,
                "target_sha256": target_sha256,
                "status": status,
            },
            subject_refs=[review_id],
            causation=self._last_session_event_id(session_id),
        )

    def waive_semantic_review(
        self,
        session_id: str,
        *,
        waiver_id: str,
        review_id: str,
        target_sha256: str,
        result_sha256: str,
        finding_ids: list[str],
    ) -> dict[str, Any]:
        """Record only an explicit owner waiver for the exact reviewed target/result."""

        state = self._session(session_id)
        return self._append(
            "review.waived",
            state.case_id,
            session_id,
            {
                "waiver_id": waiver_id,
                "review_id": review_id,
                "target_sha256": target_sha256,
                "result_sha256": result_sha256,
                "finding_ids": list(dict.fromkeys(finding_ids)),
                "explicit_confirmation": True,
            },
            subject_refs=[review_id, waiver_id],
            causation=self._last_session_event_id(session_id),
            actor={"type": "owner", "id": "owner"},
        )

    def revise_owner_decision(
        self,
        session_id: str,
        decision_id: str,
        decision: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        state = self._session(session_id)
        return self._append(
            "owner_decision.revised",
            state.case_id,
            session_id,
            {
                "decision_id": decision_id,
                "decision": decision,
                "explicit_confirmation": True,
                "reason": reason,
            },
            subject_refs=[decision_id],
            causation=self._last_session_event_id(session_id),
            actor={"type": "owner", "id": "owner"},
        )

    def supersede_owner_decision(
        self,
        session_id: str,
        decision_id: str,
        replacement_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        state = self._session(session_id)
        return self._append(
            "owner_decision.superseded",
            state.case_id,
            session_id,
            {
                "decision_id": decision_id,
                "superseded_by_decision_id": replacement_id,
                "explicit_confirmation": True,
                "reason": reason,
            },
            subject_refs=[decision_id, replacement_id],
            causation=self._last_session_event_id(session_id),
            actor={"type": "owner", "id": "owner"},
            provenance=[{"ref": decision_id, "relation": "supersedes"}],
        )

    def record_outcome_assessment(
        self,
        session_id: str,
        decision_id: str,
        *,
        observed_outcome: str,
        result_quality: str,
        process_quality: str,
        prediction_assessment: str,
        competing_explanation: str,
        attribution_confidence: str,
        matured_at: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        """Record an explicit owner assessment without altering the original decision."""

        state = self._session(session_id)
        return self._append(
            "outcome.assessed",
            state.case_id,
            session_id,
            {
                "decision_id": decision_id,
                "observed_outcome": observed_outcome,
                "result_quality": result_quality,
                "process_quality": process_quality,
                "prediction_assessment": prediction_assessment,
                "competing_explanation": competing_explanation,
                "attribution_confidence": attribution_confidence,
                "matured_at": matured_at,
                "evidence_refs": list(dict.fromkeys(evidence_refs)),
                "explicit_confirmation": True,
            },
            subject_refs=[decision_id, *list(dict.fromkeys(evidence_refs))],
            causation=self._last_session_event_id(session_id),
            actor={"type": "owner", "id": "owner"},
            provenance=[{"ref": decision_id, "relation": "responds_to"}],
        )

    def _session(self, session_id: str):
        states, issues = fold_session_states(self.semantic.read_all())
        if issues:
            raise ValidationError(issues)
        if session_id not in states:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        "$session_id",
                        "session does not exist",
                    )
                ]
            )
        return states[session_id]

    def _require_semantic_review_clearance(self, session_id: str) -> None:
        """Reject final owner decisions while a requested review lacks pass or owner waiver."""

        unresolved = _unresolved_semantic_reviews(self.semantic.read_all(), session_id)
        if unresolved:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.REVIEW_REQUIRED_UNRESOLVED,
                        "$review",
                        "required semantic review is not passed or explicitly waived: "
                        + ", ".join(unresolved),
                    )
                ]
            )

    def _next_manifest(self, state: Any, **changes: Any) -> dict[str, Any]:
        if state.manifest is None:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.MANIFEST_VERSION_INVALID,
                        "$manifest",
                        "Phase 1 compatibility session has no evolvable manifest",
                    )
                ]
            )
        manifest = copy.deepcopy(state.manifest)
        manifest.update(changes)
        manifest["manifest_version"] += 1
        manifest["updated_at"] = timestamp(self.clock())
        session_event_ids = [
            event["event_id"]
            for event in self.semantic.read_all()
            if event.get("session_id") == state.session_id
        ]
        manifest["event_refs"] = list(
            dict.fromkeys([*manifest["event_refs"], *session_event_ids])
        )
        self.schemas.require("session-manifest", manifest)
        return manifest

    def _append_manifest(
        self,
        event_type: str,
        manifest: dict[str, Any],
        *,
        previous_digest: str | None,
        when: datetime | None = None,
        frozen: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = dict(extra or {})
        key = "frozen_manifest" if frozen else "manifest"
        digest_key = "frozen_manifest_sha256" if frozen else "manifest_sha256"
        payload.update(
            {
                key: manifest,
                digest_key: canonical_sha256(manifest),
                "previous_manifest_sha256": previous_digest,
            }
        )
        causation = manifest["event_refs"][-1] if manifest["event_refs"] else None
        return self._append(
            event_type,
            manifest["case_id"],
            manifest["session_id"],
            payload,
            subject_refs=[manifest["session_id"]],
            causation=causation,
            when=when,
        )

    def _append(
        self,
        event_type: str,
        case_id: str,
        session_id: str | None,
        payload: dict[str, Any],
        *,
        subject_refs: list[str],
        causation: str | None = None,
        when: datetime | None = None,
        actor: dict[str, str] | None = None,
        provenance: list[dict[str, str]] | None = None,
        approval_ref: str | None = None,
        schema_version: str = "1.0",
    ) -> dict[str, Any]:
        instant = when or self.clock()
        candidate = build_event(
            event_type=event_type,
            case_id=case_id,
            session_id=session_id,
            payload=payload,
            subject_refs=subject_refs,
            correlation_id=self.correlation_id,
            causation_event_id=causation,
            occurred_at=instant,
            recorded_at=instant,
            id_factory=self.ids,
            actor=actor,
            provenance=provenance,
            approval_ref=approval_ref,
            schema_version=schema_version,
        )
        return self.semantic.append(candidate)

    def _last_session_event_id(self, session_id: str) -> str:
        event_ids = [
            event["event_id"]
            for event in self.semantic.read_all()
            if event.get("session_id") == session_id
        ]
        if not event_ids:
            raise ValidationError(
                [
                    Issue(
                        ErrorCode.SESSION_REFERENCE_MISSING,
                        "$session_id",
                        "session has no canonical events",
                    )
                ]
            )
        return event_ids[-1]

    @staticmethod
    def _transition_error(kind: str, source: str | None, target: str) -> ValidationError:
        return ValidationError(
            [
                Issue(
                    ErrorCode.LIFECYCLE_TRANSITION_INVALID,
                    "$to_status",
                    f"invalid {kind} transition: {source} -> {target}",
                )
            ]
        )


def _unresolved_semantic_reviews(events: list[dict[str, Any]], session_id: str) -> list[str]:
    """Return review IDs whose latest exact result is neither pass nor owner-waived."""

    requests = [
        event
        for event in events
        if event.get("session_id") == session_id and event["event_type"] == "review.requested"
    ]
    unresolved: list[str] = []
    for request in requests:
        payload = request["payload"]
        review_id = payload["review_id"]
        target_sha256 = payload["target_sha256"]
        completions = [
            event
            for event in events
            if event.get("session_id") == session_id
            and event["event_type"] == "review.completed"
            and event["payload"].get("review_id") == review_id
            and event["payload"].get("target_sha256") == target_sha256
        ]
        waivers = [
            event
            for event in events
            if event.get("session_id") == session_id
            and event["event_type"] == "review.waived"
            and event["payload"].get("review_id") == review_id
            and event["payload"].get("target_sha256") == target_sha256
        ]
        if (completions and completions[-1]["payload"].get("status") == "pass") or waivers:
            continue
        unresolved.append(review_id)
    return unresolved
