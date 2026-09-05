"""Synthetic-only Phase 1 fixture and end-to-end scenario builder."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vault_next.canonical import canonical_sha256
from vault_next import __version__
from vault_next.context import ExplicitContextLoader
from vault_next.catalog import install_synthetic_catalog
from vault_next.evidence import SyntheticEvidenceStore
from vault_next.evaluation import EvaluationRegistry
from vault_next.ids import ULIDFactory
from vault_next.interaction import InteractionRuntime
from vault_next.ledger import OperationalLedger, SemanticLedger
from vault_next.paths import RuntimePaths
from vault_next.packages import PackageRegistry
from vault_next.policy import PolicyEngine, Proposal
from vault_next.projection import build_session_trace, write_session_trace
from vault_next.readable_projections import (
    build_artifact_history,
    build_case_journal,
    build_current_work_view,
    build_decision_memo,
    write_markdown_projection,
)
from vault_next.records import SchemaRegistry, build_audit_record, build_event, timestamp
from vault_next.runtime import CaseSessionRuntime
from vault_next.review import ReviewRepository, SemanticReviewCoordinator, SemanticReviewWorkflow
from vault_next.routing import RoutingRuntime
from vault_next.frameworks import FrameworkExecutor
from vault_next.triage import TriageRequest, UniversalTriage
from vault_next.state import build_current_work_state, fold_artifact_state
from vault_next.validator import KernelValidator


@dataclass(frozen=True)
class SyntheticRunResult:
    case_id: str
    session_id: str
    triage_plan_id: str
    event_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    projection_path: Path
    projection_sha256: str

    def to_record(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "event_ids": list(self.event_ids),
            "operation_ids": list(self.operation_ids),
            "projection_path": str(self.projection_path),
            "projection_sha256": self.projection_sha256,
            "session_id": self.session_id,
            "triage_plan_id": self.triage_plan_id,
        }


@dataclass(frozen=True)
class SyntheticPhase2Result:
    """Stable summary of the synthetic Phase 2 end-to-end proof."""

    case_id: str
    session_ids: tuple[str, ...]
    evidence_id: str
    semantic_fixture_hash: str
    operational_fixture_hash: str
    session_projection_hashes: tuple[str, ...]
    context_report_hashes: tuple[str, ...]
    event_count: int
    projection_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "context_report_hashes": list(self.context_report_hashes),
            "evidence_id": self.evidence_id,
            "event_count": self.event_count,
            "operational_fixture_hash": self.operational_fixture_hash,
            "projection_count": self.projection_count,
            "session_projection_hashes": list(self.session_projection_hashes),
            "semantic_fixture_hash": self.semantic_fixture_hash,
            "session_ids": list(self.session_ids),
        }


@dataclass(frozen=True)
class SyntheticPhase3Result:
    """Stable summary of the synthetic Phase 3 routing and execution proof."""

    case_id: str
    session_id: str
    triage_plan_hash: str
    catalog_hash: str
    package_lifecycle_hash: str
    semantic_fixture_hash: str
    operational_fixture_hash: str
    session_projection_hash: str
    event_count: int
    active_package_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "active_package_count": self.active_package_count,
            "case_id": self.case_id,
            "catalog_hash": self.catalog_hash,
            "event_count": self.event_count,
            "operational_fixture_hash": self.operational_fixture_hash,
            "package_lifecycle_hash": self.package_lifecycle_hash,
            "semantic_fixture_hash": self.semantic_fixture_hash,
            "session_id": self.session_id,
            "session_projection_hash": self.session_projection_hash,
            "triage_plan_hash": self.triage_plan_hash,
        }


@dataclass(frozen=True)
class SyntheticPhase3AResult:
    """Stable summary of the synthetic P3A interaction-first proof."""

    case_id: str
    session_ids: tuple[str, ...]
    initial_plan_hash: str
    revised_plan_hash: str
    checkpoint_event_id: str
    artifact_content_hashes: tuple[str, ...]
    accepted_version_id: str
    current_work_hash: str
    semantic_fixture_hash: str
    operational_fixture_hash: str
    session_projection_hashes: tuple[str, ...]
    event_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "accepted_version_id": self.accepted_version_id,
            "artifact_content_hashes": list(self.artifact_content_hashes),
            "case_id": self.case_id,
            "checkpoint_event_id": self.checkpoint_event_id,
            "current_work_hash": self.current_work_hash,
            "event_count": self.event_count,
            "initial_plan_hash": self.initial_plan_hash,
            "operational_fixture_hash": self.operational_fixture_hash,
            "revised_plan_hash": self.revised_plan_hash,
            "semantic_fixture_hash": self.semantic_fixture_hash,
            "session_ids": list(self.session_ids),
            "session_projection_hashes": list(self.session_projection_hashes),
        }


@dataclass(frozen=True)
class SyntheticPhase4Result:
    """Stable summary of the synthetic Phase 4 generated-view proof."""

    case_id: str
    session_id: str
    artifact_id: str
    decision_id: str
    semantic_fixture_hash: str
    operational_fixture_hash: str
    markdown_projection_hashes: tuple[str, ...]
    event_count: int
    projection_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "decision_id": self.decision_id,
            "event_count": self.event_count,
            "markdown_projection_hashes": list(self.markdown_projection_hashes),
            "operational_fixture_hash": self.operational_fixture_hash,
            "projection_count": self.projection_count,
            "semantic_fixture_hash": self.semantic_fixture_hash,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class SyntheticPhase5Result:
    """Stable summary of the synthetic P5 review and regression proof."""

    phase4_case_id: str
    review_case_id: str
    review_session_id: str
    review_target_sha256: str
    review_result_sha256: str
    evaluation_run_sha256: str
    baseline_sha256: str
    semantic_fixture_hash: str
    operational_fixture_hash: str
    event_count: int

    def to_record(self) -> dict[str, Any]:
        return {
            "baseline_sha256": self.baseline_sha256,
            "evaluation_run_sha256": self.evaluation_run_sha256,
            "event_count": self.event_count,
            "operational_fixture_hash": self.operational_fixture_hash,
            "phase4_case_id": self.phase4_case_id,
            "review_case_id": self.review_case_id,
            "review_result_sha256": self.review_result_sha256,
            "review_session_id": self.review_session_id,
            "review_target_sha256": self.review_target_sha256,
            "semantic_fixture_hash": self.semantic_fixture_hash,
        }


class SyntheticClock:
    """Deterministic aware clock advancing one second per call."""

    def __init__(self) -> None:
        self.current = datetime(2026, 9, 1, 16, 0, tzinfo=UTC)

    def next(self) -> datetime:
        value = self.current
        self.current += timedelta(seconds=1)
        return value


class _SyntheticPassingReviewer:
    """Fixed synthetic reviewer used only to prove the tool-less interface and replay path."""

    reviewer_id = "synthetic-phase5-reviewer"
    reviewer_version = "1.0"

    def review(self, packet: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
        return "pass", "synthetic rubric found no blocking defect", []


def run_synthetic_session(root: Path, schema_root: Path) -> SyntheticRunResult:
    """Prove request-to-trace behavior using invented, non-personal content only."""

    paths = RuntimePaths(root)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    semantic = SemanticLedger(paths, schemas)
    operational = OperationalLedger(paths, schemas)
    policy = PolicyEngine(paths, schemas)
    clock = SyntheticClock()
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes(range(length)),
    )
    case_id = id_factory.new("case")
    session_id = id_factory.new("session")
    triage_plan_id = id_factory.new("triage")
    recommendation_id = id_factory.new("recommendation")
    correlation_id = "synthetic-phase1-run"

    triage_plan = {
        "schema_version": "1.0",
        "triage_plan_id": triage_plan_id,
        "version": "1.0",
        "session_id": session_id,
        "created_at": timestamp(clock.next()),
        "route_type": "dynamic",
        "classification": {"purpose": "demonstrate", "stakes": "synthetic"},
        "profile_match": None,
        "applied_config_sources": ["governance", "owner-defaults"],
        "package_pointers": [],
    }
    schemas.require("triage-plan", triage_plan)
    manifest_created_at = timestamp(clock.next())
    manifest = {
        "schema_version": "1.0",
        "manifest_version": 1,
        "case_id": case_id,
        "session_id": session_id,
        "created_at": manifest_created_at,
        "updated_at": manifest_created_at,
        "status": "active",
        "primary_question": "Which reversible synthetic option best proves the Phase 1 kernel?",
        "normalized_problem": None,
        "deliverable": {"kind": "synthetic proof", "audience": "owner"},
        "triage": {
            "plan_id": triage_plan_id,
            "plan_version": "1.0",
            "route_type": "dynamic",
            "profile_match": None,
            "defaults": {},
            "overrides": {},
        },
        "selected_packages": [],
        "framework": None,
        "interaction": None,
        "authorized_context": [
            {
                "ref": "phase0://implementation-roadmap",
                "purpose": "synthetic compatibility proof",
                "sensitivity_labels": ["none"],
            }
        ],
        "sensitivity_labels": ["none"],
        "requested_permissions": ["local.synthetic.write"],
        "granted_permissions": ["local.synthetic.write"],
        "evidence_refs": [],
        "output_refs": [],
        "review_refs": [],
        "event_refs": [],
        "related_session_ids": [],
        "continues_session_id": None,
        "closure_disposition": None,
        "closure_reason": None,
    }
    schemas.require("session-manifest", manifest)

    event_specs = [
        (
            "case.created",
            None,
            {"title": "Synthetic Phase 1 proof", "sensitivity": "none"},
            [case_id],
        ),
        (
            "session.started",
            session_id,
            {"manifest_sha256": canonical_sha256(manifest)},
            [session_id],
        ),
        (
            "question.recorded",
            session_id,
            {"question": manifest["primary_question"]},
            [],
        ),
        (
            "triage.completed",
            session_id,
            {"route_type": "dynamic", "triage_plan_sha256": canonical_sha256(triage_plan)},
            [triage_plan_id],
        ),
        (
            "recommendation.issued",
            session_id,
            {"summary": "Use the local append-and-replay vertical slice."},
            [recommendation_id],
        ),
        (
            "session.closed",
            session_id,
            {"disposition": "no_decision", "reason": "synthetic proof only"},
            [session_id],
        ),
    ]
    committed_events: list[dict[str, Any]] = []
    prior_event_id: str | None = None
    for event_type, scoped_session, payload, subjects in event_specs:
        when = clock.next()
        candidate = build_event(
            event_type=event_type,
            case_id=case_id,
            session_id=scoped_session,
            payload=payload,
            subject_refs=subjects,
            correlation_id=correlation_id,
            causation_event_id=prior_event_id,
            occurred_at=when,
            recorded_at=when,
            id_factory=id_factory,
        )
        committed = semantic.append(candidate)
        committed_events.append(committed)
        prior_event_id = committed["event_id"]

    proposal = Proposal(
        operation_class="write",
        targets=(str(paths.projection_root / "sessions"),),
        consequence_class="generated_projection",
        actor_id=f"vault-next-runtime/{__version__}",
        source_refs=tuple(item["event_id"] for item in committed_events),
    ).finalized()
    policy_result = policy.evaluate(proposal, now=clock.next())
    audit_policy = policy_result.to_record()
    audit_policy.pop("schema_version")
    projection = build_session_trace(semantic.read_all(), session_id, schemas)
    write_result = write_session_trace(projection, paths)
    audit_candidate = build_audit_record(
        operation_class=proposal.operation_class,
        target_summary="generated synthetic session projection",
        input_digest=proposal.proposal_digest,
        policy=audit_policy,
        attempt_status="attempted" if policy_result.result == "allow" else "not_attempted",
        result="succeeded" if policy_result.result == "allow" else "denied",
        case_id=case_id,
        session_id=session_id,
        semantic_event_refs=[item["event_id"] for item in committed_events],
        output_refs=[f"projection_sha256_{write_result.projection_sha256}"],
        attempted_at=clock.next(),
        id_factory=id_factory,
    )
    committed_audit = operational.append(audit_candidate)
    return SyntheticRunResult(
        case_id,
        session_id,
        triage_plan_id,
        tuple(item["event_id"] for item in committed_events),
        (committed_audit["operation_id"],),
        write_result.path,
        write_result.projection_sha256,
    )


def run_synthetic_phase2(root: Path, schema_root: Path) -> SyntheticPhase2Result:
    """Exercise the complete Phase 2 gate with invented local fixtures only."""

    paths = RuntimePaths(root)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    clock = SyntheticClock()
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes(range(length)),
    )
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase2-run",
    )
    case_event = runtime.create_case("Synthetic Phase 2 continuity proof")
    case_id = case_event["case_id"]
    first = runtime.create_session(case_id, "Which invented option is reversible?")
    first_id = first["session_id"]
    for status in ("routed", "authorized", "active"):
        runtime.transition_session(first_id, status, reason=f"synthetic {status}")

    evidence_store = SyntheticEvidenceStore(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase2-run",
    )
    evidence = evidence_store.register(
        case_id=case_id,
        session_id=first_id,
        content=b"Invented evidence: option blue is reversible.",
        display_name="invented-phase2-evidence.txt",
    )
    assumption = runtime.record_reasoning_event(
        first_id,
        "assumption.recorded",
        {
            "assumption_id": "assumption_phase2_open",
            "statement": "Invented dependency remains available",
            "status": "open",
        },
        subject_refs=["assumption_phase2_open"],
    )
    alternative = runtime.record_reasoning_event(
        first_id,
        "alternative.recorded",
        {
            "alternative_id": "alternative_phase2_open",
            "description": "Use invented option green",
            "disposition": "open",
        },
        subject_refs=["alternative_phase2_open"],
    )
    recommendation_id = id_factory.new("recommendation")
    runtime.record_reasoning_event(
        first_id,
        "recommendation.issued",
        {
            "recommendation_id": recommendation_id,
            "revision": 1,
            "summary": "Try invented option blue",
        },
        subject_refs=[recommendation_id],
    )
    runtime.record_reasoning_event(
        first_id,
        "recommendation.revised",
        {
            "recommendation_id": recommendation_id,
            "revision": 2,
            "summary": "Try invented option green first",
        },
        subject_refs=[recommendation_id],
    )
    original_decision = runtime.record_owner_decision(
        first_id, "Choose invented option blue"
    )
    evidence_id = evidence.metadata["evidence_id"]
    runtime.amend_scope(
        first_id,
        changes={
            "authorized_context": [
                {
                    "ref": evidence_id,
                    "purpose": "support synthetic continuity proof",
                    "sensitivity_labels": ["none"],
                }
            ],
            "evidence_refs": [evidence_id],
            "review_refs": ["review_trigger_synthetic"],
        },
        reason="authorize invented evidence and review trigger",
    )
    runtime.transition_session(first_id, "blocked", reason="invented dependency")
    runtime.transition_session(first_id, "active", reason="invented dependency resolved")
    runtime.close_session(first_id, disposition="decided", reason="explicit synthetic decision")
    first_context = ExplicitContextLoader(paths, schemas).load_from_repository(
        session_id=first_id, requested_refs=[evidence_id]
    )

    continuity_refs = [
        assumption["event_id"],
        alternative["event_id"],
        original_decision["event_id"],
    ]
    authorizations = [
        {
            "ref": ref,
            "purpose": "resume unresolved synthetic state",
            "sensitivity_labels": ["none"],
        }
        for ref in continuity_refs
    ]
    second = runtime.resume_as_new_session(
        first_id,
        primary_question="Should the invented decision change?",
        authorized_context=authorizations,
    )
    second_id = second["session_id"]
    for status in ("routed", "authorized", "active"):
        runtime.transition_session(second_id, status, reason=f"synthetic {status}")
    replacement = runtime.record_owner_decision(
        second_id, "Choose invented option green"
    )
    runtime.supersede_owner_decision(
        second_id,
        original_decision["payload"]["decision_id"],
        replacement["payload"]["decision_id"],
        reason="invented constraint changed",
    )
    runtime.close_session(second_id, disposition="decided", reason="explicit replacement")
    second_context = ExplicitContextLoader(paths, schemas).load_from_repository(
        session_id=second_id, requested_refs=continuity_refs
    )

    events = runtime.semantic.read_all()
    projection_hashes: list[str] = []
    for session_id in (first_id, second_id):
        projection = build_session_trace(events, session_id, schemas)
        projection_hashes.append(write_session_trace(projection, paths).projection_sha256)
    report = KernelValidator(paths, schemas).validate()
    if not report.passed:
        raise RuntimeError("synthetic Phase 2 fixture failed repository validation")
    return SyntheticPhase2Result(
        case_id,
        (first_id, second_id),
        evidence_id,
        report.semantic_fixture_hash,
        report.operational_fixture_hash,
        tuple(projection_hashes),
        (
            canonical_sha256(first_context.report),
            canonical_sha256(second_context.report),
        ),
        report.semantic_event_count,
        report.projection_count,
    )


def run_synthetic_phase3(root: Path, schema_root: Path) -> SyntheticPhase3Result:
    """Exercise governed package activation, triage, composition, and execution."""

    paths = RuntimePaths(root)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    clock = SyntheticClock()
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes(range(length)),
    )
    registry = PackageRegistry(
        paths, schemas, id_factory=id_factory, clock=clock.next
    )
    catalog = install_synthetic_catalog(registry)
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase3-run",
    )
    case_event = runtime.create_case("Synthetic Phase 3 composition proof")
    case_id = case_event["case_id"]
    session_event = runtime.create_session(
        case_id, "Deep dive into an invented reversible choice"
    )
    session_id = session_event["session_id"]
    plan = UniversalTriage(
        registry, schemas, id_factory=id_factory, clock=clock.next
    ).plan(
        TriageRequest(
            "/deep-dive invented reversible choice",
            required_work_units=(
                "source_comprehension",
                "option_design",
                "red_team",
            ),
            preferred_framework_id="framework_committee",
        )
    )
    RoutingRuntime(runtime, registry).apply(session_id, plan)
    runtime.transition_session(session_id, "authorized", reason="synthetic local work")
    runtime.transition_session(session_id, "active", reason="synthetic local work")
    skills = [
        item["package_id"]
        for item in plan["selected_packages"]
        if item["package_type"] == "skill"
    ]
    FrameworkExecutor(runtime, registry).run_committee(
        session_id,
        contributions={
            skill_id: f"Invented independent contribution from {skill_id}"
            for skill_id in skills
        },
        recommendation="Prefer the reversible invented choice while preserving dissent",
    )
    runtime.close_session(
        session_id, disposition="no_decision", reason="synthetic proof only"
    )
    events = runtime.semantic.read_all()
    projection = build_session_trace(events, session_id, schemas)
    projection_hash = write_session_trace(projection, paths).projection_sha256
    report = KernelValidator(paths, schemas).validate()
    if not report.passed:
        raise RuntimeError("synthetic Phase 3 fixture failed repository validation")
    lifecycle = registry.lifecycle.read_all()
    return SyntheticPhase3Result(
        case_id,
        session_id,
        plan["plan_sha256"],
        catalog["catalog_sha256"],
        lifecycle[-1]["integrity"]["event_sha256"],
        report.semantic_fixture_hash,
        report.operational_fixture_hash,
        projection_hash,
        report.semantic_event_count,
        len(catalog["entries"]),
    )


def run_synthetic_phase3a(root: Path, schema_root: Path) -> SyntheticPhase3AResult:
    """Exercise interaction, checkpoint, artifact, and current-work contracts."""

    paths = RuntimePaths(root)
    paths.initialize()
    schemas = SchemaRegistry(schema_root)
    clock = SyntheticClock()
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes(range(length)),
    )
    registry = PackageRegistry(paths, schemas, id_factory=id_factory, clock=clock.next)
    install_synthetic_catalog(registry)
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase3a-run",
    )
    triage = UniversalTriage(
        registry,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
    )
    router = RoutingRuntime(runtime, registry)
    interaction = InteractionRuntime(runtime, id_factory=id_factory, clock=clock.next)

    case_event = runtime.create_case("Synthetic P3A interaction proof")
    case_id = case_event["case_id"]
    first = runtime.create_session(case_id, "Explore an invented reversible choice")
    first_id = first["session_id"]
    initial_plan = triage.plan(
        TriageRequest(
            "Explore an invented reversible choice",
            required_work_units=("source_comprehension",),
            preferred_framework_id="framework_specialist",
            preferred_interaction_mode="explore",
        )
    )
    router.apply(first_id, initial_plan)
    runtime.transition_session(first_id, "authorized", reason="synthetic local scope")
    runtime.transition_session(first_id, "active", reason="begin synthetic exploration")
    interaction.record_owner_input(
        first_id,
        "The invented choice must remain reversible.",
        role="constraint",
    )
    checkpoint = interaction.record_checkpoint(
        first_id,
        "The reversible constraint is explicit; synthesis remains open.",
        state={
            "working_question": "How should the invented reversible choice be explained?",
            "assumptions": ["No external action is needed"],
            "alternatives": ["brief explanation", "detailed explanation"],
        },
        open_questions=["Which level of detail will the owner accept?"],
    )
    changed = router.change_interaction_mode(
        first_id,
        initial_plan,
        new_mode="artifact_iterate",
        reason="develop a reviewed synthetic brief",
        required_work_units=["source_comprehension", "synthesis"],
        framework_id="framework_synthesis",
        skill_ids=["skill_comprehension", "skill_synthesis"],
    )
    version_1 = interaction.create_artifact_version(
        first_id,
        b"# Synthetic brief\n\nInitial reversible choice.\n",
        purpose="synthetic interaction proof",
        change_summary="initial working version",
    )
    feedback = interaction.record_artifact_feedback(
        first_id,
        version_1.version["artifact_id"],
        version_1.version["version_id"],
        feedback="Make the reversibility condition explicit.",
    )
    version_2 = interaction.create_artifact_version(
        first_id,
        b"# Synthetic brief\n\nProceed only while the invented choice remains reversible.\n",
        artifact_id=version_1.version["artifact_id"],
        prior_version_id=version_1.version["version_id"],
        addressed_feedback_ids=[feedback["payload"]["feedback_id"]],
        purpose="synthetic interaction proof",
        change_summary="make the owner constraint explicit",
    )
    interaction.accept_artifact(
        first_id,
        version_2.version["artifact_id"],
        version_2.version["version_id"],
        purpose="accepted synthetic interaction proof",
    )
    runtime.close_session(
        first_id,
        disposition="no_decision",
        reason="artifact acceptance does not create an owner decision",
    )

    second = runtime.resume_as_new_session(
        first_id,
        primary_question="What do I have today in the invented case?",
        authorized_context=[
            {
                "ref": checkpoint["event_id"],
                "purpose": "resume from the explicit checkpoint",
                "sensitivity_labels": ["none"],
            }
        ],
    )
    second_id = second["session_id"]
    status_plan = triage.plan(
        TriageRequest(
            "What do I have today in the invented case?",
            required_work_units=("context_assessment",),
            preferred_framework_id="framework_specialist",
            preferred_interaction_mode="status_review",
        )
    )
    router.apply(second_id, status_plan)
    runtime.transition_session(second_id, "authorized", reason="synthetic local scope")
    runtime.transition_session(second_id, "active", reason="begin synthetic status review")
    proposal = interaction.propose_work_item(
        second_id,
        "Consider the accepted synthetic brief",
        due_on="2026-09-02",
    )
    interaction.change_work_item_status(
        second_id,
        proposal["payload"]["work_item_id"],
        "open",
        reason="owner explicitly accepts the synthetic follow-up",
    )
    current_work = build_current_work_state(
        runtime.semantic.read_all(),
        as_of_date="2026-09-02",
        time_zone="America/New_York",
    )
    runtime.close_session(
        second_id,
        disposition="no_decision",
        reason="status review completed without a decision",
    )

    events = runtime.semantic.read_all()
    projection_hashes = tuple(
        write_session_trace(build_session_trace(events, session_id, schemas), paths).projection_sha256
        for session_id in (first_id, second_id)
    )
    report = KernelValidator(paths, schemas).validate()
    if not report.passed:
        raise RuntimeError(f"synthetic P3A fixture failed repository validation: {report.issues}")
    artifact = fold_artifact_state(events, case_id=case_id)[version_1.version["artifact_id"]]
    ordered_versions = sorted(
        artifact["versions"].values(), key=lambda item: item["version_number"]
    )
    return SyntheticPhase3AResult(
        case_id,
        (first_id, second_id),
        initial_plan["plan_sha256"],
        changed["plan"]["plan_sha256"],
        checkpoint["event_id"],
        tuple(version["content_sha256"] for version in ordered_versions),
        artifact["accepted_version_id"],
        canonical_sha256(current_work),
        report.semantic_fixture_hash,
        report.operational_fixture_hash,
        projection_hashes,
        report.semantic_event_count,
    )


def run_synthetic_phase4(root: Path, schema_root: Path) -> SyntheticPhase4Result:
    """Render decision, case, artifact, and current-work views from synthetic records only."""

    phase3a = run_synthetic_phase3a(root, schema_root)
    paths = RuntimePaths(root)
    schemas = SchemaRegistry(schema_root)
    clock = SyntheticClock()
    clock.current = datetime(2026, 9, 2, 16, 0, tzinfo=UTC)
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes(reversed(range(length))),
    )
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase4-run",
    )
    registry = PackageRegistry(paths, schemas, id_factory=id_factory, clock=clock.next)
    triage = UniversalTriage(registry, schemas, id_factory=id_factory, clock=clock.next)
    router = RoutingRuntime(runtime, registry)

    resumed = runtime.resume_as_new_session(
        phase3a.session_ids[-1],
        primary_question="What is the explicit outcome of the invented reversible choice?",
    )
    session_id = resumed["session_id"]
    plan = triage.plan(
        TriageRequest(
            "What is the explicit outcome of the invented reversible choice?",
            required_work_units=("source_comprehension", "synthesis"),
            preferred_framework_id="framework_synthesis",
            preferred_interaction_mode="co_develop",
        )
    )
    router.apply(session_id, plan)
    runtime.transition_session(session_id, "authorized", reason="synthetic projection review")
    runtime.transition_session(session_id, "active", reason="begin synthetic decision review")
    recommendation_id = id_factory.new("recommendation")
    runtime.record_reasoning_event(
        session_id,
        "recommendation.issued",
        {
            "recommendation_id": recommendation_id,
            "revision": 1,
            "summary": "Preserve the invented reversible constraint in the selected explanation.",
        },
        subject_refs=[recommendation_id],
    )
    decision = runtime.record_owner_decision(
        session_id, "Use the invented explanation that preserves reversibility."
    )
    decision_id = decision["payload"]["decision_id"]
    runtime.revise_owner_decision(
        session_id,
        decision_id,
        "Use the invented explanation only while reversibility remains explicit.",
        reason="owner clarified the acceptance boundary",
    )
    outcome_evidence = SyntheticEvidenceStore(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase4-run",
    ).register(
        case_id=phase3a.case_id,
        session_id=session_id,
        content=b"Invented later outcome: the reversible condition remained visible.",
        display_name="invented-phase4-outcome.txt",
    )
    runtime.record_outcome_assessment(
        session_id,
        decision_id,
        observed_outcome="The invented explanation remained reversible in the synthetic review.",
        result_quality="mixed",
        process_quality="strong",
        prediction_assessment="The explicit boundary was preserved, though the synthetic result is limited.",
        competing_explanation="The favorable observation may reflect the constrained synthetic fixture.",
        attribution_confidence="medium",
        matured_at=timestamp(clock.next()),
        evidence_refs=[outcome_evidence.metadata["evidence_id"]],
    )
    runtime.close_session(
        session_id,
        disposition="decided",
        reason="explicit synthetic decision recorded",
    )

    events = runtime.semantic.read_all()
    for prior_session_id in (*phase3a.session_ids, session_id):
        write_session_trace(
            build_session_trace(events, prior_session_id, schemas), paths
        )
    artifacts = fold_artifact_state(events, case_id=phase3a.case_id)
    artifact_id = next(iter(artifacts))
    projections = (
        build_decision_memo(events, phase3a.case_id, schemas),
        build_case_journal(events, phase3a.case_id, schemas),
        build_artifact_history(events, artifact_id, schemas),
        build_current_work_view(
            events,
            as_of_date="2026-09-02",
            time_zone="America/New_York",
            schemas=schemas,
        ),
    )
    hashes = tuple(
        write_markdown_projection(projection, paths).projection_sha256
        for projection in projections
    )
    report = KernelValidator(paths, schemas).validate()
    if not report.passed:
        raise RuntimeError(f"synthetic Phase 4 fixture failed repository validation: {report.issues}")
    return SyntheticPhase4Result(
        phase3a.case_id,
        session_id,
        artifact_id,
        decision_id,
        report.semantic_fixture_hash,
        report.operational_fixture_hash,
        hashes,
        report.semantic_event_count,
        report.projection_count,
    )


def run_synthetic_phase5(root: Path, schema_root: Path) -> SyntheticPhase5Result:
    """Replay the P4 question-to-outcome proof and a separate exact-review finalization journey."""

    phase4 = run_synthetic_phase4(root, schema_root)
    paths = RuntimePaths(root)
    schemas = SchemaRegistry(schema_root)
    clock = SyntheticClock()
    clock.current = datetime(2026, 9, 3, 16, 0, tzinfo=UTC)
    id_factory = ULIDFactory(
        now_ms=lambda: int(clock.current.timestamp() * 1000),
        random_source=lambda length: bytes((length - index - 1) for index in range(length)),
    )
    runtime = CaseSessionRuntime(
        paths,
        schemas,
        id_factory=id_factory,
        clock=clock.next,
        correlation_id="synthetic-phase5-run",
    )
    coordinator = SemanticReviewCoordinator(
        ReviewRepository(paths, schemas), schemas, id_factory=id_factory, clock=clock.next
    )
    workflow = SemanticReviewWorkflow(coordinator, runtime)
    case = runtime.create_case("Synthetic Phase 5 semantic review proof")
    case_id = case["case_id"]
    session = runtime.create_session(
        case_id, "Can the invented recommendation pass an exact, tool-less semantic review?"
    )
    session_id = session["session_id"]
    for status in ("routed", "authorized", "active"):
        runtime.transition_session(session_id, status, reason=f"synthetic {status}")
    recommendation_id = id_factory.new("recommendation")
    runtime.record_reasoning_event(
        session_id,
        "recommendation.issued",
        {
            "recommendation_id": recommendation_id,
            "revision": 1,
            "summary": "Use the invented reversible explanation with its stated limit.",
        },
        subject_refs=[recommendation_id],
    )
    packet, packet_sha256 = workflow.request(
        session_id, target_type="recommendation", target_ref=recommendation_id
    )
    review = workflow.run(
        session_id, packet, packet_sha256, _SyntheticPassingReviewer(), attempt=1
    )
    runtime.record_owner_decision(
        session_id, "Choose the invented explanation after the explicit synthetic review."
    )
    runtime.close_session(session_id, disposition="decided", reason="synthetic review passed")
    # Current-work views intentionally cover all canonical cases, so refresh the inherited P4 view
    # after adding the separate P5 review case. The semantic ledger itself is never rewritten.
    write_markdown_projection(
        build_current_work_view(
            runtime.semantic.read_all(),
            as_of_date="2026-09-02",
            time_zone="America/New_York",
            schemas=schemas,
        ),
        paths,
    )
    report = KernelValidator(paths, schemas).validate()
    if not report.passed:
        raise RuntimeError(f"synthetic Phase 5 fixture failed repository validation: {report.issues}")
    evaluation = EvaluationRegistry(paths, schemas, id_factory=id_factory, clock=clock.next)
    phase4_routing = next(
        (
            event["payload"].get("plan", {})
            for event in runtime.semantic.read_all()
            if event["session_id"] == phase4.session_id
            and event["event_type"] == "routing.proposed"
        ),
        {},
    )
    run = evaluation.run(
        {"suite_id": "synthetic-phase5-core", "suite_version": "1.0"},
        {
            "event-invariants": lambda: {"passed": report.passed, "semantic_hash": report.semantic_fixture_hash},
            "projections": lambda: {"passed": report.projection_count >= 4},
            "reviewer-rubric": lambda: {"passed": review.result["status"] == "pass"},
            "routing": lambda: {
                "passed": phase4_routing.get("route_type") == "dynamic"
                and bool(phase4_routing.get("selected_packages")),
                "plan_sha256": phase4_routing.get("plan_sha256"),
            },
        },
    )
    baseline = evaluation.establish_or_change_baseline(
        run,
        reviewed_change_record_sha256=review.result_sha256,
        explicit_confirmation=True,
    )
    final_report = KernelValidator(paths, schemas).validate()
    if not final_report.passed:
        raise RuntimeError(f"synthetic Phase 5 post-evaluation validation failed: {final_report.issues}")
    return SyntheticPhase5Result(
        phase4.case_id,
        case_id,
        session_id,
        packet["subject"]["target_sha256"],
        review.result_sha256,
        run.sha256,
        baseline["baseline_sha256"],
        final_report.semantic_fixture_hash,
        final_report.operational_fixture_hash,
        final_report.semantic_event_count,
    )
