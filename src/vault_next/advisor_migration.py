"""Compatible advisor-migration contracts for attribution, retrieval evals, and audits.

The P1 contracts are deliberately read-only.  They normalize already-admitted weekly decision
records, prepare additive attribution supplements, evaluate frozen retrieval outcomes, and build
no-write amendment previews.  Nothing in this module publishes a supplement, grants authority,
promotes knowledge, or adopts current work.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from vault_next.canonical import canonical_bytes, canonical_sha256, sha256_hex
from vault_next.records import SchemaRegistry


ATTRIBUTION_COMPONENT = "historical_decision_attribution_supplement/1.0.0"
RETRIEVAL_EVAL_COMPONENT = "advisor_retrieval_evaluation/1.0.0"
AMENDMENT_PREVIEW_COMPONENT = "migration_amendment_preview/1.0.0"

_CLAIM_BASES = frozenset(
    {
        "contemporary_source",
        "later_owner_recollection",
        "model_inference",
        "not_stated",
    }
)
_ACTOR_STATES = frozenset({"known", "unknown"})
_AUDIT_DISPOSITIONS = frozenset(
    {
        "retained_as_is",
        "projection_only",
        "missing_relationship",
        "missing_attribution",
        "extraction_revision",
        "unresolved",
        "deferred",
    }
)
_PILOT_ROLES = frozenset(
    {
        "executive_owned_decision_with_owner_input",
        "redirected_or_discontinuous_initiative",
        "career_relevant_artifact",
    }
)


class AdvisorMigrationError(RuntimeError):
    """A P1 record is incomplete, mutated, ambiguous, or claims excess authority."""


@dataclass(frozen=True)
class ActorAttribution:
    """One role attribution with explicit known/unknown state and evidence basis."""

    role: str
    identity_state: Literal["known", "unknown"]
    party_ref: str | None
    claim_basis: Literal[
        "contemporary_source", "later_owner_recollection", "model_inference", "not_stated"
    ]
    evidence_refs: tuple[str, ...] = ()

    def material(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "identity_state": self.identity_state,
            "party_ref": self.party_ref,
            "claim_basis": self.claim_basis,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class RationaleAttribution:
    """A stated rationale or an explicit not-stated marker."""

    state: Literal["stated", "not_stated"]
    text: str | None
    attributed_to: tuple[str, ...]
    claim_basis: Literal[
        "contemporary_source", "later_owner_recollection", "model_inference", "not_stated"
    ]
    evidence_refs: tuple[str, ...] = ()

    def material(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "text": self.text,
            "attributed_to": list(self.attributed_to),
            "claim_basis": self.claim_basis,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class HistoricalDecisionView:
    """A compatibility view over either a legacy decision or an additive supplement."""

    decision_ref: str
    decision_statement: str
    historical_status: str
    parent_event_id: str
    parent_package_digest: str
    publication_receipt_ref: str | None
    decision_makers: tuple[dict[str, Any], ...]
    owner_roles: tuple[dict[str, Any], ...]
    reporters: tuple[dict[str, Any], ...]
    record_approvers: tuple[dict[str, Any], ...]
    rationale: dict[str, Any]
    evidence_anchors: tuple[str, ...]
    supplement_digest: str | None
    candidate_only: bool
    current_authority: bool


@dataclass(frozen=True)
class RetrievalEvaluation:
    """Deterministic assessment of one future retrieval result against a frozen case."""

    case_id: str
    passed: bool
    failures: tuple[str, ...]


class AdvisorMigrationCoordinator:
    """Read legacy packages and prepare compatibility-only P1 records."""

    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas

    def read_legacy_decisions(
        self,
        *,
        event: dict[str, Any],
        package: dict[str, Any],
        supplements: tuple[dict[str, Any], ...] = (),
    ) -> tuple[HistoricalDecisionView, ...]:
        """Read old weekly decisions without upgrading their authority or changing their bytes."""

        self._parent(event, package)
        decisions = package.get("weekly_wave", {}).get("decisions")
        if not isinstance(decisions, list):
            raise AdvisorMigrationError("weekly decision list is unavailable")
        by_ref: dict[str, dict[str, Any]] = {}
        citation_catalog = self._citations(package)
        allowed_evidence = set(citation_catalog)
        if isinstance(event.get("receipt_id"), str):
            allowed_evidence.add(f"receipt:{event['receipt_id']}")
        for supplement in supplements:
            self._supplement(supplement)
            parent = supplement["parent_binding"]
            if (
                parent["event_id"] != event["event_id"]
                or parent["event_sha256"] != sha256_hex(self._event_bytes(event))
                or parent["package_digest"] != package["package_digest"]
            ):
                raise AdvisorMigrationError("attribution supplement names another parent")
            if set(supplement["evidence_anchors"]) - citation_catalog:
                raise AdvisorMigrationError("supplement evidence is outside the admitted parent")
            if self._supplement_evidence(supplement) - allowed_evidence:
                raise AdvisorMigrationError("attribution evidence is outside the admitted parent")
            self._recollections(tuple(supplement["retrospective_recollections"]), citation_catalog)
            decision_ref = parent["decision_ref"]
            if decision_ref in by_ref:
                raise AdvisorMigrationError("more than one supplement targets a legacy decision")
            by_ref[decision_ref] = supplement

        views: list[HistoricalDecisionView] = []
        for index, decision in enumerate(decisions):
            if not isinstance(decision, dict) or not isinstance(decision.get("label"), str):
                raise AdvisorMigrationError("legacy weekly decision is malformed")
            decision_ref = self._decision_ref(package["package_digest"], index)
            supplement = by_ref.pop(decision_ref, None)
            if supplement is None:
                unknown = self._unknown_actor("unknown")
                rationale = RationaleAttribution(
                    "not_stated", None, (), "not_stated", ()
                ).material()
                roles = ((unknown,), (unknown,), (unknown,), (unknown,))
                anchors: tuple[str, ...] = tuple(decision.get("citation_refs", ()))
                supplement_digest = None
            else:
                if supplement["decision_statement"] != decision["label"]:
                    raise AdvisorMigrationError("supplement changes the legacy decision statement")
                roles = tuple(
                    tuple(supplement[name])
                    for name in (
                        "decision_makers",
                        "owner_roles",
                        "reporters",
                        "record_approvers",
                    )
                )
                rationale = supplement["rationale"]
                anchors = tuple(supplement["evidence_anchors"])
                supplement_digest = supplement["supplement_digest"]
            views.append(
                HistoricalDecisionView(
                    decision_ref=decision_ref,
                    decision_statement=decision["label"],
                    historical_status=str(decision.get("status", decision.get("state", "unknown"))),
                    parent_event_id=event["event_id"],
                    parent_package_digest=package["package_digest"],
                    publication_receipt_ref=event.get("receipt_id"),
                    decision_makers=roles[0],
                    owner_roles=roles[1],
                    reporters=roles[2],
                    record_approvers=roles[3],
                    rationale=rationale,
                    evidence_anchors=anchors,
                    supplement_digest=supplement_digest,
                    candidate_only=True,
                    current_authority=False,
                )
            )
        if by_ref:
            raise AdvisorMigrationError("supplement targets an unavailable legacy decision")
        return tuple(views)

    def prepare_attribution_supplement(
        self,
        *,
        supplement_id: str,
        event: dict[str, Any],
        package: dict[str, Any],
        decision_index: int,
        decision_makers: tuple[ActorAttribution, ...],
        owner_roles: tuple[ActorAttribution, ...],
        reporters: tuple[ActorAttribution, ...],
        record_approvers: tuple[ActorAttribution, ...],
        rationale: RationaleAttribution,
        evidence_anchors: tuple[str, ...],
        event_time: str | None,
        effective_time: str | None,
        recorded_at: str,
        owner_known_at: str | None = None,
        retrospective_recollections: tuple[dict[str, Any], ...] = (),
    ) -> dict[str, Any]:
        """Prepare one additive supplement; the caller still has no publication authority."""

        self._parent(event, package)
        decisions = package.get("weekly_wave", {}).get("decisions", [])
        if decision_index < 0 or decision_index >= len(decisions):
            raise AdvisorMigrationError("supplement decision index is unavailable")
        decision = decisions[decision_index]
        if not isinstance(decision, dict) or not isinstance(decision.get("label"), str):
            raise AdvisorMigrationError("supplement decision parent is malformed")
        roles = (decision_makers, owner_roles, reporters, record_approvers)
        if any(not values for values in roles):
            raise AdvisorMigrationError("every authority dimension requires an explicit value")
        for values in roles:
            for actor in values:
                self._actor(actor.material())
        self._rationale(rationale.material())
        if not evidence_anchors or len(evidence_anchors) != len(set(evidence_anchors)):
            raise AdvisorMigrationError("supplement evidence anchors are missing or repeated")
        citation_catalog = self._citations(package)
        if set(evidence_anchors) - citation_catalog:
            raise AdvisorMigrationError("supplement evidence is outside the admitted parent")
        allowed_evidence = set(citation_catalog)
        if isinstance(event.get("receipt_id"), str):
            allowed_evidence.add(f"receipt:{event['receipt_id']}")
        role_evidence = {
            evidence_ref
            for values in roles
            for actor in values
            for evidence_ref in actor.evidence_refs
        }
        rationale_evidence = set(rationale.evidence_refs)
        if (role_evidence | rationale_evidence) - allowed_evidence:
            raise AdvisorMigrationError("attribution evidence is outside the admitted parent")
        self._recollections(retrospective_recollections, citation_catalog)
        material = {
            "schema_version": "1.0",
            "record_type": "historical_decision_attribution_supplement/1.0",
            "component": ATTRIBUTION_COMPONENT,
            "supplement_id": supplement_id,
            "parent_binding": {
                "event_id": event["event_id"],
                "event_sha256": sha256_hex(self._event_bytes(event)),
                "package_digest": package["package_digest"],
                "decision_ref": self._decision_ref(package["package_digest"], decision_index),
            },
            "decision_statement": decision["label"],
            "decision_makers": [actor.material() for actor in decision_makers],
            "owner_roles": [actor.material() for actor in owner_roles],
            "reporters": [actor.material() for actor in reporters],
            "record_approvers": [actor.material() for actor in record_approvers],
            "rationale": rationale.material(),
            "evidence_anchors": list(evidence_anchors),
            "event_time": event_time,
            "effective_time": effective_time,
            "recorded_at": recorded_at,
            "owner_known_at": owner_known_at,
            "retrospective_recollections": list(retrospective_recollections),
            "candidate_only": True,
            "no_current_work": True,
            "no_promotion": True,
            "no_activation": True,
            "no_u1": True,
            "no_u2": True,
            "parent_records_unchanged": True,
        }
        supplement = {**material, "supplement_digest": canonical_sha256(material)}
        self._supplement(supplement)
        return supplement

    def load_retrieval_cases(self, fixture_path: Path) -> tuple[dict[str, Any], ...]:
        """Load immutable synthetic A2 acceptance cases from a checked-in fixture."""

        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
            raise AdvisorMigrationError("retrieval fixture envelope is malformed")
        if payload.get("component") != RETRIEVAL_EVAL_COMPONENT:
            raise AdvisorMigrationError("retrieval fixture component changed")
        cases = tuple(payload["cases"])
        seen: set[str] = set()
        for case in cases:
            self.schemas.require("advisor-retrieval-evaluation-case", case)
            case_id = case["case_id"]
            if case_id in seen:
                raise AdvisorMigrationError("retrieval fixture case is duplicated")
            seen.add(case_id)
        if payload.get("fixture_digest") != canonical_sha256(
            {key: value for key, value in payload.items() if key != "fixture_digest"}
        ):
            raise AdvisorMigrationError("retrieval fixture digest changed")
        return cases

    def evaluate_retrieval_result(
        self, case: dict[str, Any], result: dict[str, Any]
    ) -> RetrievalEvaluation:
        """Evaluate an implementation result without changing the frozen expected outcome."""

        self.schemas.require("advisor-retrieval-evaluation-case", case)
        self.schemas.require("advisor-retrieval-evaluation-result", result)
        failures: list[str] = []
        if result["case_id"] != case["case_id"]:
            failures.append("case identity changed")
        selected = set(result["selected_record_ids"])
        if not set(case["expected_record_ids"]).issubset(selected):
            failures.append("required evidence was not retrieved")
        if selected & set(case["forbidden_record_ids"]):
            failures.append("forbidden or hindsight evidence was retrieved")
        if not set(case["required_labels"]).issubset(set(result["labels"])):
            failures.append("required authority or temporal labels are missing")
        if not result["coverage_boundary"].strip():
            failures.append("coverage boundary is missing")
        if not result["citations"] and result["status"] == "complete":
            failures.append("complete result has no citations")
        if case["intent"] == "public_practice_comparison":
            if not result["public_sources"]:
                failures.append("public-practice result has no dated public source")
            if not result["source_recommended_questions"]:
                failures.append("source-recommended questions are missing")
            if not result["advisor_derived_questions"]:
                failures.append("advisor-derived questions are missing")
        if not result["no_persistence"] or not result["no_authority_effect"]:
            failures.append("retrieval created a write or authority effect")
        if result["current_work_adopted"] or result["knowledge_promoted"]:
            failures.append("retrieval adopted current work or promoted knowledge")
        return RetrievalEvaluation(case["case_id"], not failures, tuple(failures))

    def build_amendment_preview(self, entries: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        """Build an exhaustive three-history P1 preview with no persistence route."""

        if len(entries) != 3:
            raise AdvisorMigrationError("P1 pilot requires exactly three history entries")
        roles = {entry.get("pilot_role") for entry in entries}
        if roles != _PILOT_ROLES:
            raise AdvisorMigrationError("P1 pilot does not cover the three required history roles")
        identities: set[str] = set()
        for entry in entries:
            self.schemas.require("migration-amendment-preview-entry", entry)
            if entry["disposition"] not in _AUDIT_DISPOSITIONS:
                raise AdvisorMigrationError("amendment preview disposition is invalid")
            if entry["entry_id"] in identities:
                raise AdvisorMigrationError("amendment preview entry is duplicated")
            identities.add(entry["entry_id"])
        counts = {
            disposition: sum(entry["disposition"] == disposition for entry in entries)
            for disposition in sorted(_AUDIT_DISPOSITIONS)
        }
        material = {
            "schema_version": "1.0",
            "component": AMENDMENT_PREVIEW_COMPONENT,
            "scope": "three_admitted_histories",
            "entries": sorted(entries, key=lambda entry: entry["entry_id"]),
            "disposition_counts": counts,
            "coverage_denominator": len(entries),
            "coverage_dispositioned": len(entries),
            "no_write": True,
            "no_u1": True,
            "no_current_work": True,
            "no_promotion": True,
            "parent_records_unchanged": True,
        }
        return {**material, "preview_digest": canonical_sha256(material)}

    def _parent(self, event: dict[str, Any], package: dict[str, Any]) -> None:
        if (
            not isinstance(event, dict)
            or not isinstance(package, dict)
            or event.get("package_digest") != package.get("package_digest")
            or event.get("event_id") is None
            or package.get("candidate_only") is not True
            or package.get("no_current_work") is not True
        ):
            raise AdvisorMigrationError("weekly event/package binding is invalid")
        package_material = {key: value for key, value in package.items() if key != "package_digest"}
        if package["package_digest"] != canonical_sha256(package_material):
            raise AdvisorMigrationError("weekly package digest changed")

    def _supplement(self, supplement: dict[str, Any]) -> None:
        self.schemas.require("historical-decision-attribution-supplement", supplement)
        material = {key: value for key, value in supplement.items() if key != "supplement_digest"}
        if supplement["supplement_digest"] != canonical_sha256(material):
            raise AdvisorMigrationError("attribution supplement digest changed")
        for name in ("decision_makers", "owner_roles", "reporters", "record_approvers"):
            for actor in supplement[name]:
                self._actor(actor)
        self._rationale(supplement["rationale"])

    @staticmethod
    def _actor(actor: dict[str, Any]) -> None:
        state = actor.get("identity_state")
        basis = actor.get("claim_basis")
        party = actor.get("party_ref")
        evidence = actor.get("evidence_refs")
        if (
            state not in _ACTOR_STATES
            or basis not in _CLAIM_BASES
            or not isinstance(actor.get("role"), str)
            or not actor["role"].strip()
            or not isinstance(evidence, list)
            or len(evidence) != len(set(evidence))
            or (state == "known" and not isinstance(party, str))
            or (state == "unknown" and party is not None)
            or (basis == "contemporary_source" and not evidence)
            or (basis == "not_stated" and evidence)
        ):
            raise AdvisorMigrationError("actor attribution is inconsistent")

    @staticmethod
    def _rationale(rationale: dict[str, Any]) -> None:
        state = rationale.get("state")
        basis = rationale.get("claim_basis")
        text = rationale.get("text")
        evidence = rationale.get("evidence_refs")
        if (
            state not in {"stated", "not_stated"}
            or basis not in _CLAIM_BASES
            or not isinstance(evidence, list)
            or (state == "stated" and (not isinstance(text, str) or not text.strip()))
            or (state == "not_stated" and (text is not None or basis != "not_stated" or evidence))
        ):
            raise AdvisorMigrationError("rationale attribution is inconsistent")

    @staticmethod
    def _recollections(
        recollections: tuple[dict[str, Any], ...], citation_catalog: set[str]
    ) -> None:
        for recollection in recollections:
            if (
                recollection.get("claim_basis") != "later_owner_recollection"
                or not isinstance(recollection.get("recorded_at"), str)
                or not isinstance(recollection.get("text"), str)
                or not recollection["text"].strip()
                or not set(recollection.get("evidence_refs", ())).issubset(citation_catalog)
            ):
                raise AdvisorMigrationError("retrospective recollection is not separately attributed")

    @staticmethod
    def _citations(package: dict[str, Any]) -> set[str]:
        refs: set[str] = set()
        for observation_name in ("item_observations", "conversation_observations"):
            for observation in package.get(observation_name, []):
                refs.update(observation.get("citation_refs", ()))
        for decision in package.get("weekly_wave", {}).get("decisions", []):
            refs.update(decision.get("citation_refs", ()))
        for record in package.get("logical_records", []):
            refs.update(anchor.get("anchor_id", "") for anchor in record.get("anchors", []))
        refs.discard("")
        return refs

    @staticmethod
    def _supplement_evidence(supplement: dict[str, Any]) -> set[str]:
        refs = set(supplement["rationale"]["evidence_refs"])
        for name in ("decision_makers", "owner_roles", "reporters", "record_approvers"):
            for actor in supplement[name]:
                refs.update(actor["evidence_refs"])
        return refs

    @staticmethod
    def _unknown_actor(role: str) -> dict[str, Any]:
        return ActorAttribution(role, "unknown", None, "not_stated", ()).material()

    @staticmethod
    def _decision_ref(package_digest: str, index: int) -> str:
        return f"legacy-decision:{package_digest}:{index}"

    @staticmethod
    def _event_bytes(event: dict[str, Any]) -> bytes:
        return canonical_bytes(event)
