"""S4-C fixture-supplied sequential committee evaluation.

This is deliberately not an agent runner.  Every role finding and synthesis is caller-supplied
invented fixture data, recorded with a truthful execution mode and no authority effect.
"""

from __future__ import annotations

from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next.errors import ErrorCode, Issue, ValidationError
from vault_next.knowledge_library import SyntheticKnowledgeLibraryCoordinator
from vault_next.lifecycle import fold_session_states
from vault_next.runtime import CaseSessionRuntime


_EXECUTION_MODE = "fixture_supplied_sequential"
_CONCLUSIONS = frozenset({"supports", "challenges", "gap", "unavailable"})
_DELTA_KINDS = frozenset(
    {"gap_surfaced", "evidence_link_preserved", "conflict_retained"}
)


class SyntheticCommitteeEvaluationCoordinator:
    """Record a bounded, attributable, candidate-only synthetic committee run."""

    def __init__(self, runtime: CaseSessionRuntime) -> None:
        self.runtime = runtime
        self.library = SyntheticKnowledgeLibraryCoordinator(runtime, runtime.schemas)

    def create_run(self, session_id: str, packet: dict[str, object]) -> dict[str, object]:
        """Freeze one exact S4-A/B packet before any role finding is accepted."""

        session = self._active_session(session_id)
        normalized = self._normalize_packet(packet, session)
        event = self.runtime.record_reasoning_event(
            session_id,
            "committee.run_recorded",
            {"packet": normalized, "packet_sha256": normalized["packet_sha256"]},
            subject_refs=[normalized["committee_run_id"]],
        )
        return {
            "status": "complete",
            "committee_run_id": normalized["committee_run_id"],
            "packet_sha256": normalized["packet_sha256"],
            "execution_mode": _EXECUTION_MODE,
            "event_id": event["event_id"],
        }

    def record_first_pass(
        self, session_id: str, run_id: str, finding_input: dict[str, object]
    ) -> dict[str, object]:
        """Append exactly one supplied first-pass finding for one frozen role card."""

        run, state = self._run(session_id, run_id)
        packet = run["packet"]
        findings = state["findings"]
        finding = self._normalize_finding(packet, finding_input, findings)
        event = self.runtime.record_reasoning_event(
            session_id,
            "committee.finding_recorded",
            {"packet_sha256": packet["packet_sha256"], "finding": finding, "finding_sha256": finding["finding_sha256"]},
            subject_refs=[run_id, finding["finding_id"]],
            provenance=[{"ref": run["event_id"], "relation": "derives_from"}],
        )
        dissent = self._record_dissent_if_needed(session_id, run, finding, findings)
        return {
            "status": "complete",
            "finding_id": finding["finding_id"],
            "event_id": event["event_id"],
            "dissent_event_id": dissent["event_id"] if dissent else None,
        }

    def record_challenge(
        self, session_id: str, run_id: str, challenge_input: dict[str, object]
    ) -> dict[str, object]:
        """Record the single bounded challenge after all first-pass roles are present."""

        run, state = self._run(session_id, run_id)
        packet = run["packet"]
        if state["challenge"] is not None:
            raise _invalid("$challenge", "committee run already has its one permitted challenge")
        if set(state["findings_by_role"]) != {card["role_id"] for card in packet["role_cards"]}:
            raise _invalid("$challenge", "challenge requires every frozen first-pass role finding")
        if set(challenge_input) != {"role_id", "target_finding_id", "statement", "evidence_candidate_ids"}:
            raise _invalid("$challenge", "challenge has unexpected or missing fields")
        role_ids = {card["role_id"] for card in packet["role_cards"]}
        target = state["findings"].get(challenge_input["target_finding_id"])
        if (
            challenge_input["role_id"] not in role_ids
            or target is None
            or not isinstance(challenge_input["statement"], str)
            or not challenge_input["statement"].strip()
            or len(challenge_input["statement"].encode("utf-8")) > packet["challenge_budget_bytes"]
            or not _exact_candidate_ids(challenge_input["evidence_candidate_ids"], packet)
        ):
            raise _invalid("$challenge", "challenge escapes the frozen committee packet")
        challenge = {
            "challenge_id": self.runtime.ids.new("committee_challenge"),
            "role_id": challenge_input["role_id"],
            "target_finding_id": target["finding_id"],
            "statement": challenge_input["statement"],
            "evidence_candidate_ids": list(challenge_input["evidence_candidate_ids"]),
        }
        challenge["challenge_sha256"] = canonical_sha256(challenge)
        event = self.runtime.record_reasoning_event(
            session_id,
            "committee.challenge_recorded",
            {
                "packet_sha256": packet["packet_sha256"],
                "challenge": challenge,
                "challenge_sha256": challenge["challenge_sha256"],
            },
            subject_refs=[run_id, challenge["challenge_id"], target["finding_id"]],
            provenance=[{"ref": target["event_id"], "relation": "responds_to"}],
        )
        return {
            "status": "complete",
            "challenge_id": challenge["challenge_id"],
            "event_id": event["event_id"],
        }

    def synthesize(
        self, session_id: str, run_id: str, synthesis_input: dict[str, object]
    ) -> dict[str, object]:
        """Record a bounded non-authoritative synthesis and deterministic baseline comparison."""

        run, state = self._run(session_id, run_id)
        packet = run["packet"]
        if state["synthesis"] is not None:
            raise _invalid("$synthesis", "committee run already has a synthesis")
        if set(state["findings_by_role"]) != {card["role_id"] for card in packet["role_cards"]}:
            raise _invalid("$synthesis", "synthesis requires every frozen first-pass role finding")
        required = {"recommendation", "unaddressed_gaps", "change_of_mind_condition", "deltas"}
        if set(synthesis_input) != required:
            raise _invalid("$synthesis", "synthesis has unexpected or missing fields")
        if (
            not isinstance(synthesis_input["recommendation"], str)
            or not synthesis_input["recommendation"].strip()
            or len(synthesis_input["recommendation"].encode("utf-8")) > packet["synthesis_budget_bytes"]
            or not isinstance(synthesis_input["change_of_mind_condition"], str)
            or not synthesis_input["change_of_mind_condition"].strip()
            or not _strings(synthesis_input["unaddressed_gaps"])
        ):
            raise _invalid("$synthesis", "synthesis is incomplete or exceeds its frozen budget")
        deltas = self._validated_deltas(synthesis_input["deltas"], state, packet)
        unavailable_roles = sorted(
            role_id
            for role_id, finding in state["findings_by_role"].items()
            if finding["conclusion"] == "unavailable"
        )
        synthesis = {
            "synthesis_id": self.runtime.ids.new("committee_synthesis"),
            "recommendation": synthesis_input["recommendation"],
            "unaddressed_gaps": list(synthesis_input["unaddressed_gaps"]),
            "change_of_mind_condition": synthesis_input["change_of_mind_condition"],
            "open_dissent_ids": sorted(state["dissents"]),
            "unavailable_role_ids": unavailable_roles,
            "authority": "none",
        }
        synthesis["synthesis_sha256"] = canonical_sha256(synthesis)
        status = "partial" if unavailable_roles else "complete"
        synthesis_event = self.runtime.record_reasoning_event(
            session_id,
            "committee.synthesis_recorded",
            {
                "packet_sha256": packet["packet_sha256"],
                "synthesis": synthesis,
                "synthesis_sha256": synthesis["synthesis_sha256"],
            },
            subject_refs=[run_id, synthesis["synthesis_id"]],
            provenance=[
                {"ref": finding["event_id"], "relation": "summarizes"}
                for finding in state["findings"].values()
            ],
        )
        comparison = {
            "comparison_id": self.runtime.ids.new("committee_comparison"),
            "synthesis_id": synthesis["synthesis_id"],
            "baseline_digest": packet["s4a_baseline"]["baseline_digest"],
            "result": "no_demonstrated_increment" if not deltas else "attributable_delta",
            "deltas": deltas,
            "limitations": [
                "fixture-supplied sequential execution only",
                "does not establish model quality, independence, truth, or usefulness",
            ],
        }
        comparison["comparison_sha256"] = canonical_sha256(comparison)
        comparison_event = self.runtime.record_reasoning_event(
            session_id,
            "committee.comparison_recorded",
            {
                "packet_sha256": packet["packet_sha256"],
                "comparison": comparison,
                "comparison_sha256": comparison["comparison_sha256"],
            },
            subject_refs=[run_id, comparison["comparison_id"]],
            provenance=[{"ref": synthesis_event["event_id"], "relation": "derives_from"}],
        )
        return {
            "status": status,
            "synthesis_event_id": synthesis_event["event_id"],
            "comparison_event_id": comparison_event["event_id"],
            "comparison": comparison,
            "promotion": "unavailable: committee output is non-authoritative",
        }

    def _normalize_packet(self, packet: dict[str, object], session: Any) -> dict[str, Any]:
        required = {
            "question",
            "purpose",
            "execution_mode",
            "role_cards",
            "s4a_baseline",
            "s4b_scope",
            "first_pass_budget_bytes",
            "challenge_budget_bytes",
            "synthesis_budget_bytes",
        }
        if set(packet) != required:
            raise _invalid("$packet", "committee packet has unexpected or missing fields")
        if (
            not isinstance(packet["question"], str)
            or not packet["question"].strip()
            or not isinstance(packet["purpose"], str)
            or not packet["purpose"].strip()
        ):
            raise _invalid("$packet", "committee question and purpose must be nonempty")
        if packet["execution_mode"] != _EXECUTION_MODE:
            raise _invalid("$execution_mode", "only fixture_supplied_sequential execution is supported")
        roles = packet["role_cards"]
        if not isinstance(roles, list) or not 2 <= len(roles) <= 4:
            raise _invalid("$role_cards", "committee requires two to four frozen role cards")
        role_ids: set[str] = set()
        normalized_roles: list[dict[str, Any]] = []
        for card in roles:
            if not isinstance(card, dict) or set(card) != {
                "role_id",
                "lens",
                "allowed_claim_categories",
                "non_purpose",
            }:
                raise _invalid("$role_cards", "role card has unexpected or missing fields")
            role_id = card["role_id"]
            if (
                not isinstance(role_id, str)
                or not role_id
                or role_id in role_ids
                or not _strings(card["allowed_claim_categories"])
                or not _strings(card["non_purpose"])
            ):
                raise _invalid("$role_cards", "role cards must be distinct and explicitly limited")
            if any(
                any(
                    token in value.lower()
                    for token in ("authority", "approve", "approval", "decision", "promot")
                )
                for value in card["allowed_claim_categories"]
            ):
                raise _invalid("$role_cards", "role card cannot request authority")
            if not isinstance(card["lens"], str) or not card["lens"].strip():
                raise _invalid("$role_cards", "role lens must be nonempty")
            role_ids.add(role_id)
            normalized_roles.append(dict(card))
        baseline = packet["s4a_baseline"]
        if (
            not isinstance(baseline, dict)
            or set(baseline)
            != {"package_id", "version", "digest", "baseline_digest", "candidate_ids"}
            or baseline["package_id"] != "skill_evidence_mapping"
            or baseline["version"] != "0.1.0"
            or not _digest_fields(baseline, ("digest", "baseline_digest"))
            or not _strings(baseline["candidate_ids"])
        ):
            raise _invalid("$s4a_baseline", "S4-A baseline binding is invalid")
        scope = packet["s4b_scope"]
        if (
            not isinstance(scope, dict)
            or set(scope)
            != {
                "candidate_ids",
                "candidate_watermark",
                "source_watermark",
                "search_result_digest",
                "confidentiality_space",
            }
            or not _strings(scope["candidate_ids"])
            or not _digest_fields(
                scope,
                ("candidate_watermark", "source_watermark", "search_result_digest"),
            )
            or not isinstance(scope["confidentiality_space"], str)
            or not scope["confidentiality_space"]
        ):
            raise _invalid("$s4b_scope", "S4-B library scope binding is invalid")
        marks = self.library.watermarks(list(scope["candidate_ids"]))
        if (
            marks["candidate_watermark"] != scope["candidate_watermark"]
            or marks["source_watermark"] != scope["source_watermark"]
        ):
            raise _invalid("$s4b_scope", "S4-B candidate or source watermark is stale")
        state = self.library._state(self.runtime.semantic.read_all())
        for candidate_id in scope["candidate_ids"]:
            item = state.get(candidate_id)
            if (
                item is None
                or item["candidate"]["review_state"] != "provisional"
                or item["candidate"]["confidentiality_space"]
                != scope["confidentiality_space"]
                or not self.library._candidate_visible(
                    item["candidate"], item["event_id"], session
                )
            ):
                raise _invalid("$s4b_scope", "S4-B candidate is unavailable in the frozen committee scope")
        for name in ("first_pass_budget_bytes", "challenge_budget_bytes", "synthesis_budget_bytes"):
            if not isinstance(packet[name], int) or not 64 <= packet[name] <= 4096:
                raise _invalid(f"${name}", "committee budget must be 64 through 4096 bytes")
        normalized = {
            "schema_version": "0.1.0",
            "committee_run_id": self.runtime.ids.new("committee_run"),
            "question": packet["question"],
            "purpose": packet["purpose"],
            "execution_mode": _EXECUTION_MODE,
            "role_cards": normalized_roles,
            "s4a_baseline": dict(baseline),
            "s4b_scope": dict(scope),
            "first_pass_budget_bytes": packet["first_pass_budget_bytes"],
            "challenge_budget_bytes": packet["challenge_budget_bytes"],
            "synthesis_budget_bytes": packet["synthesis_budget_bytes"],
        }
        normalized["packet_sha256"] = canonical_sha256(normalized)
        self._validate_frozen_scope(normalized, session)
        return normalized

    def _normalize_finding(
        self, packet: dict[str, Any], value: dict[str, object], findings: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        required = {
            "role_id",
            "claim_id",
            "conclusion",
            "statement",
            "evidence_candidate_ids",
            "limitations",
        }
        if set(value) != required:
            raise _invalid("$finding", "finding has unexpected or missing fields")
        role_ids = {card["role_id"] for card in packet["role_cards"]}
        if value["role_id"] not in role_ids or value["role_id"] in {
            item["role_id"] for item in findings.values()
        }:
            raise _invalid("$finding/role_id", "finding role is unavailable or already recorded")
        if (
            value["conclusion"] not in _CONCLUSIONS
            or not isinstance(value["claim_id"], str)
            or not value["claim_id"]
            or not isinstance(value["statement"], str)
            or not value["statement"].strip()
            or len(value["statement"].encode("utf-8")) > packet["first_pass_budget_bytes"]
            or not _strings(value["limitations"])
        ):
            raise _invalid("$finding", "finding is malformed or exceeds its frozen budget")
        if value["conclusion"] == "unavailable":
            if value["evidence_candidate_ids"] != []:
                raise _invalid("$finding", "unavailable finding cannot claim evidence")
        elif not _exact_candidate_ids(value["evidence_candidate_ids"], packet):
            raise _invalid("$finding", "finding evidence escapes the frozen S4-B scope")
        finding = {
            "finding_id": self.runtime.ids.new("committee_finding"),
            "role_id": value["role_id"],
            "claim_id": value["claim_id"],
            "conclusion": value["conclusion"],
            "statement": value["statement"],
            "evidence_candidate_ids": list(value["evidence_candidate_ids"]),
            "limitations": list(value["limitations"]),
        }
        finding["finding_sha256"] = canonical_sha256(finding)
        return finding

    def _record_dissent_if_needed(
        self,
        session_id: str,
        run: dict[str, Any],
        finding: dict[str, Any],
        findings: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        opposing = next(
            (
                item
                for item in findings.values()
                if item["claim_id"] == finding["claim_id"]
                and item["conclusion"] != finding["conclusion"]
                and item["conclusion"] != "unavailable"
                and finding["conclusion"] != "unavailable"
            ),
            None,
        )
        if opposing is None:
            return None
        dissent = {
            "dissent_id": self.runtime.ids.new("committee_dissent"),
            "claim_id": finding["claim_id"],
            "finding_ids": sorted([opposing["finding_id"], finding["finding_id"]]),
            "status": "open",
        }
        dissent["dissent_sha256"] = canonical_sha256(dissent)
        return self.runtime.record_reasoning_event(
            session_id,
            "committee.dissent_recorded",
            {
                "packet_sha256": run["packet"]["packet_sha256"],
                "dissent": dissent,
                "dissent_sha256": dissent["dissent_sha256"],
            },
            subject_refs=[run["packet"]["committee_run_id"], dissent["dissent_id"]],
        )

    def _validated_deltas(
        self, value: object, state: dict[str, Any], packet: dict[str, Any]
    ) -> list[dict[str, str]]:
        if not isinstance(value, list):
            raise _invalid("$deltas", "comparison deltas must be a list")
        deltas: list[dict[str, str]] = []
        for delta in value:
            if (
                not isinstance(delta, dict)
                or set(delta) != {"kind", "finding_id"}
                or delta["kind"] not in _DELTA_KINDS
                or delta["finding_id"] not in state["findings"]
            ):
                raise _invalid("$deltas", "comparison delta is not attributable to a frozen finding")
            finding = state["findings"][delta["finding_id"]]
            if delta["kind"] == "gap_surfaced" and finding["conclusion"] != "gap":
                raise _invalid("$deltas", "gap delta requires a gap finding")
            if delta["kind"] == "evidence_link_preserved" and not (
                set(finding["evidence_candidate_ids"])
                - set(packet["s4a_baseline"]["candidate_ids"])
            ):
                raise _invalid("$deltas", "evidence delta requires evidence outside the declared baseline")
            if delta["kind"] == "conflict_retained" and not any(
                finding["finding_id"] in dissent["finding_ids"]
                for dissent in state["dissents"].values()
            ):
                raise _invalid("$deltas", "conflict delta requires an open dissent")
            deltas.append({"kind": delta["kind"], "finding_id": delta["finding_id"]})
        return deltas

    def _run(self, session_id: str, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        session = self._active_session(session_id)
        state = _fold_runs(self.runtime.semantic.read_all())
        run = state.get(run_id)
        if run is None or run["packet"]["case_id"] != session.case_id:
            raise _invalid("$committee_run_id", "committee run is unavailable in the current session")
        self._validate_frozen_scope(run["packet"], session)
        return run, run

    def _validate_frozen_scope(self, packet: dict[str, Any], session: Any) -> None:
        """Fail closed when a previously frozen synthetic S4-B scope is no longer current."""

        scope = packet["s4b_scope"]
        candidate_ids = scope["candidate_ids"]
        marks = self.library.watermarks(candidate_ids)
        if (
            marks["candidate_watermark"] != scope["candidate_watermark"]
            or marks["source_watermark"] != scope["source_watermark"]
        ):
            raise _invalid("$s4b_scope", "frozen S4-B candidate or source watermark is stale")
        events = self.runtime.semantic.read_all()
        state = self.library._state(events)
        for candidate_id in candidate_ids:
            item = state.get(candidate_id)
            if (
                item is None
                or item["lifecycle_state"] != "provisional"
                or item["candidate"]["confidentiality_space"]
                != scope["confidentiality_space"]
                or not self.library._candidate_visible(item["candidate"], item["event_id"], session)
                or self.library._source_is_stale(item["candidate"], events)
            ):
                raise _invalid("$s4b_scope", "frozen S4-B candidate is no longer available")

    def _active_session(self, session_id: str) -> Any:
        states, issues = fold_session_states(self.runtime.semantic.read_all())
        if issues:
            raise ValidationError(issues)
        state = states.get(session_id)
        if state is None or state.frozen or state.status != "active" or state.manifest is None:
            raise _invalid("$session_id", "selected active session is unavailable")
        return state


def _fold_runs(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    runs: dict[str, dict[str, Any]] = {}
    for event in events:
        event_type = event["event_type"]
        payload = event["payload"]
        if event_type == "committee.run_recorded":
            packet = dict(payload["packet"])
            packet["case_id"] = event["case_id"]
            runs[packet["committee_run_id"]] = {
                "packet": packet,
                "event_id": event["event_id"],
                "findings": {},
                "findings_by_role": {},
                "dissents": {},
                "challenge": None,
                "synthesis": None,
            }
        elif event_type.startswith("committee."):
            packet_sha = payload.get("packet_sha256")
            matching = next(
                (
                    run
                    for run in runs.values()
                    if run["packet"]["packet_sha256"] == packet_sha
                ),
                None,
            )
            if matching is None:
                continue
            if event_type == "committee.finding_recorded":
                finding = {**payload["finding"], "event_id": event["event_id"]}
                matching["findings"][finding["finding_id"]] = finding
                matching["findings_by_role"][finding["role_id"]] = finding
            elif event_type == "committee.dissent_recorded":
                matching["dissents"][payload["dissent"]["dissent_id"]] = payload["dissent"]
            elif event_type == "committee.challenge_recorded":
                matching["challenge"] = payload["challenge"]
            elif event_type == "committee.synthesis_recorded":
                matching["synthesis"] = payload["synthesis"]
    return runs


def _exact_candidate_ids(value: object, packet: dict[str, Any]) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and len(set(value)) == len(value)
        and set(value).issubset(set(packet["s4b_scope"]["candidate_ids"]))
    )


def _strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item for item in value)
    )


def _digest_fields(value: dict[str, object], names: tuple[str, ...]) -> bool:
    return all(
        isinstance(value[name], str)
        and len(value[name]) == 64
        and set(value[name]).issubset(set("0123456789abcdef"))
        for name in names
    )


def _invalid(path: str, message: str) -> ValidationError:
    return ValidationError([Issue(ErrorCode.CONTRACT_SEMANTICS_INVALID, path, message)])
